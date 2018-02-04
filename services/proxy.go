/* Copyright 2017 Robert Christian Taylor. All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//The proxy package implements a http proxy that supports hooks to modify the
//request and response. The package also provides basic functionality for
//implementing a https interception proxy which generates https certs on the fly
//for each request via TLSCertGen.
package services

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type ProxyHookType int

const (
	//A handler with this flag will run before the upstream request is sent to
	//the remote server. Handlers can modify the request or hijack the request
	//and return their own custom reply if they want. Handlers that wish to
	//both modify the request and modify its reply should install a before
	//and after handler and hijack the request in the before issue downstream
	//request handler.
	BeforeIssueUpstreamRequest ProxyHookType = iota

	//A handler with this flag will run after the upstream request headers have
	//been sent, and the response headers have been received. The body has not
	//been received yet so handlers can hijack the the request and modify and
	//return the body has they see fit.
	BeforeIssueDownstreamResponse
)

const proxyErrorPrefix = "Proxy Core Server: "
const proxyComponentError = "Proxy Handler Error: "

//Context passed through a proxy hook chain.
type ProxyChainContext struct {

	//Request received from the remote client
	DownstreamRequest *http.Request

	//Response to send to the remote client
	DownstreamResponse http.ResponseWriter

	//Request to send to the upstream server
	UpstreamRequest *http.Request

	//Response from the upstream server
	UpstreamResponse *http.Response

	//State of the request
	RequestState ProxyHookType

	//Context object
	Context context.Context

	//Proxy instance
	Proxy *ProxyServer

	//Function used to cancel the request
	cancelReq func()
}

//Signature of a proxy hook function
type ProxyHook func(context *ProxyChainContext) (stopProcessingChain, connHijacked bool, err error)

//Proxy server is an implementation of a http proxy server using go's http
//library. The proxy server exposes a pre and post request hook to allow
//modification of the server's behavior. The primary use of this server
//is to support content filtering in the advertsieve project.
//
//By default, this server disables http/2.0, however it can be turned back on
//by modifying the TLS config.
type ProxyServer struct {

	//When set to true, the proxy permit tcp tunneling through this web server.
	//If set to false, CONNECT method will be rejected. This is set to false
	//by default because of its potential for abuse.
	AllowConnect bool

	//When set to true, websocket upgrade requests will be passed through this proxy.
	//This is enabled by default.
	AllowWebsocket bool

	//Logger used to handle messages generated during the operation of the proxy
	//server.
	MsgLogger *log.Logger

	//Maximum number of attempts to contact upstream server. Set to zero by
	//default meaning the server will keep attempting to connect to the remote
	//server until it runs out of time.
	MaxNumberOfConnectAttempts int

	//Max number of time to spend attempting to connect to upstream server. This
	//is set to 30 seconds by default.
	MaxTimeTryingToConnect time.Duration

	//Amount of time to wait before retrying a failed request. Set to 0 seconds
	//by default.
	MinRequestRetryTimeout time.Duration

	//Time duration to multiply the exponential back off coefficient by. Set to
	//500ms by default.
	RetryBackoffCoefficient time.Duration

	//Chain of handlers to call before each proxied request.
	beforeIssueUpstreamRequest []ProxyHook

	//Chain of handlers to call before each proxied response.
	beforeIssueDownstreamResponse []ProxyHook

	//Mutex to make this thread safe
	mutex sync.RWMutex

	//Round Tripper used to make HTTP requests. By default this is set to
	//http.Transport and uses the initial instance of TlsConfig on this structure for its
	//TLS configuration.
	//
	//Default configuration:
	//	proxy.Transport = &http.Transport{
	//	TLSHandshakeTimeout:   time.Duration(10) * time.Second,
	//	MaxIdleConns:          128,
	//	IdleConnTimeout:       time.Duration(2) * time.Minute,
	//	ExpectContinueTimeout: time.Duration(1) * time.Second,
	//	ResponseHeaderTimeout: time.Duration(30) * time.Second,
	//	TLSClientConfig:       proxy.TlsConfig,
	//	TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper), // Disable HTTP2
	//}
	Transport http.RoundTripper

	//Tls config used by proxy to make upstream TLS connections. Note,
	//if the instance of this field is replaced with a new instance of tls.Config,
	//the tls config, if one exists, on Transport will not be updated.
	TlsConfig *tls.Config
}

//Creates a new proxy server and sets up any hidden fields on ProxyServer.
func NewProxyServer() (proxy *ProxyServer) {
	proxy = new(ProxyServer)

	proxy.MaxNumberOfConnectAttempts = 0
	proxy.MaxTimeTryingToConnect = time.Duration(30) * time.Second
	proxy.MinRequestRetryTimeout = 0
	proxy.RetryBackoffCoefficient = time.Duration(500) * time.Millisecond
	proxy.AllowWebsocket = true
	proxy.TlsConfig = SecureTLSConfig()

	proxy.MsgLogger = log.New(os.Stderr, "Proxy ", log.Lmicroseconds|log.Ldate)

	proxy.Transport = &http.Transport{
		TLSHandshakeTimeout:   time.Duration(10) * time.Second,
		MaxIdleConns:          128,
		IdleConnTimeout:       time.Duration(2) * time.Minute,
		ExpectContinueTimeout: time.Duration(1) * time.Second,
		ResponseHeaderTimeout: time.Duration(30) * time.Second,
		TLSClientConfig:       proxy.TlsConfig,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper), // Disable HTTP2
	}
	return
}

//Adds a hook to the proxy server. The parameter hookType determines when the
//hook gets executed.
func (proxy *ProxyServer) AddHook(hook ProxyHook, hookType ProxyHookType) {

	proxy.mutex.Lock()
	defer proxy.mutex.Unlock()

	switch hookType {
	case BeforeIssueUpstreamRequest:
		proxy.beforeIssueUpstreamRequest = append(proxy.beforeIssueUpstreamRequest, hook)
	case BeforeIssueDownstreamResponse:
		proxy.beforeIssueDownstreamResponse = append(proxy.beforeIssueDownstreamResponse, hook)
	default:
		panic("Invalid enum value passed in to AddHook in proxy server.")
	}

	return
}

//Helper function that sends an error to the remote client and logs an internal
//description of the error via the http logger.
func (proxy *ProxyServer) HttpError(w http.ResponseWriter, code int, internalMessage string, externalMessage string) {
	proxy.emitHttpError(w, code, internalMessage, externalMessage, false)
}

func (proxy *ProxyServer) coreHttpError(w http.ResponseWriter, code int, internalMessage string, externalMessage string) {
	proxy.emitHttpError(w, code, internalMessage, externalMessage, true)
}

func (proxy *ProxyServer) emitHttpError(w http.ResponseWriter, code int, internalMessage string, externalMessage string, coreError bool) {
	var prefix string

	if coreError {
		prefix = proxyErrorPrefix
	} else {
		prefix = proxyComponentError
	}

	proxy.MsgLogger.Printf("%s HTTP request error \"%s.\" External message sent was \"%s.\" with error code %d.", prefix, internalMessage, externalMessage, code)
	http.Error(w, externalMessage, code)
}

func (proxy *ProxyServer) logError(context string, errorMessage string) {
	proxy.MsgLogger.Printf("%s Internal error \"%s.\" while %s.", proxyErrorPrefix, errorMessage, context)
}

func (proxy *ProxyServer) logWarning(warning string) {
	proxy.MsgLogger.Printf("%s Warning \"%s.\"", proxyErrorPrefix, warning)
}

//Standard function that handles a proxy request.
func (proxy *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	proxy.mutex.RLock()
	defer proxy.mutex.RUnlock()

	if !proxy.allowRequest(r, w) {
		return
	}

	path := *r.URL

	if path.Host == "" {
		path.Host = r.Host
	}

	if r.Method != http.MethodConnect {
		//Only support http(s) requests.
		if r.URL.Scheme != "http" && r.URL.Scheme != "https" && r.URL.Scheme != "" {
			proxy.coreHttpError(w, http.StatusBadRequest, "Received non http URI scheme from "+r.RemoteAddr+". URI was "+r.URL.String(), "Bad Request")
			return
		}

		if path.Scheme == "" {
			if r.TLS != nil {
				path.Scheme = "https"
			} else {
				path.Scheme = "http"
			}
		}
	}

	rsr, err := http.NewRequest(r.Method, path.String(), r.Body)
	if err != nil {
		proxy.coreHttpError(w, http.StatusInternalServerError, err.Error(), http.StatusText(http.StatusInternalServerError))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	rsr = rsr.WithContext(ctx)

	//Copy over headers for sending to the remote server
	setUpRemoteServerRequest(r, rsr)

	reqIsWebsocket := IsWebSocketRequest(r)

	//Remove headers that should not be forwarded to the remote server.
	RemoveHopByHopHeaders(&rsr.Header)

	//Add back hop-by-hop headers needed to establish a websocket connection.
	if reqIsWebsocket {
		rsr.Header.Add("Connection", "Upgrade")
		rsr.Header.Add("Upgrade", "websocket")
	}

	var proxyContext ProxyChainContext = ProxyChainContext{
		DownstreamRequest:  r,
		UpstreamRequest:    rsr,
		DownstreamResponse: w,
		Proxy:              proxy,
		RequestState:       BeforeIssueUpstreamRequest,
		cancelReq:          cancel,
	}

	//Run Before Request hooks
	var connHijacked bool
	connHijacked, err = RunHandlerChain(proxy.beforeIssueUpstreamRequest, &proxyContext)

	if connHijacked || err != nil {
		if err != nil {
			proxy.coreHttpError(w, http.StatusInternalServerError, err.Error(), http.StatusText(http.StatusInternalServerError))
		}
		return
	}

	if IsWebSocketRequest(rsr) {
		proxy.proxyWebSocket(rsr, w)
	} else if rsr.Method == http.MethodConnect {
		proxy.proxyMethodConnect(rsr, w)
	} else {
		proxy.returnHTTPResponse(rsr, w, r, &proxyContext)
	}

	return
}

//Determines if a request is permitted based on active access control policies
func (proxy *ProxyServer) allowRequest(r *http.Request, w http.ResponseWriter) bool {

	//(*r0wbrt) - Should we expose a new proxy chain that could run here to perform
	//     		  access control operations?

	if r.Method == http.MethodConnect && !proxy.AllowConnect {
		proxy.coreHttpError(w, http.StatusForbidden, "Request for CONNECT from "+r.RemoteAddr+" to path \""+r.URL.String()+"\" was denied because AllowConnect is set to false.", http.StatusText(http.StatusForbidden))
		return false
	}

	isWebSocket := IsWebSocketRequest(r)

	if isWebSocket && !proxy.AllowWebsocket {
		proxy.coreHttpError(w, http.StatusForbidden, "HTTP websocket upgrade request from "+r.RemoteAddr+" to path \""+r.URL.String()+"\" was denied because AllowWebsocket is set to false.", http.StatusText(http.StatusForbidden))
		return false
	}

	return true
}

//Helper function to determine if a request is a websocket upgrade request.
func IsWebSocketRequest(r *http.Request) bool {
	upgradeType := r.Header.Get("Upgrade")

	if strings.ToLower(upgradeType) == "websocket" {
		return true
	}

	return false
}

//Runs a proxy handler chain.
func RunHandlerChain(chain []ProxyHook, context *ProxyChainContext) (connHijacked bool, err error) {
	var stopProcessingChain bool = false

	for i := 0; i < len(chain); i++ {
		stopProcessingChain, connHijacked, err = chain[i](context)

		if stopProcessingChain || connHijacked || err != nil {
			break
		}
	}

	return
}

func setUpRemoteServerRequest(clientRequest *http.Request, remoteRequest *http.Request) {

	for k, v := range clientRequest.Header {
		values := append([]string(nil), v...)
		remoteRequest.Header[k] = values
	}

	remoteRequest.ContentLength = clientRequest.ContentLength
}

func (proxy *ProxyServer) returnHTTPResponse(rsr *http.Request, w http.ResponseWriter, r *http.Request, context *ProxyChainContext) {

	proxy.removeBodyFromRequest(rsr)

	rresp, err := proxy.attemptHttpConnectionToUpstreamServer(rsr, r.Context(), context.cancelReq)

	if err != nil {
		proxy.coreHttpError(w, http.StatusBadGateway, err.Error(), "Could not contact upstream server")
		return
	}

	defer rresp.Body.Close()

	for k, v := range rresp.Header {
		values := append([]string(nil), v...)
		w.Header()[k] = values
	}

	context.RequestState = BeforeIssueDownstreamResponse
	context.UpstreamResponse = rresp

	var connHijacked bool
	connHijacked, err = RunHandlerChain(proxy.beforeIssueDownstreamResponse, context)
	if connHijacked {
		return
	}

	if err != nil {
		proxy.coreHttpError(w, http.StatusInternalServerError, err.Error(), http.StatusText(http.StatusInternalServerError))
		return
	}

	w.WriteHeader(rresp.StatusCode)
	io.Copy(w, rresp.Body)
}

func (proxy *ProxyServer) removeBodyFromRequest(rsr *http.Request) {

	//Per RFC specs, if neither of these fields are set, the request should not
	//have a body.
	if rsr.Header.Get("Content-Length") == "" && rsr.Header.Get("Transfer-Encoding") == "" {
		rsr.Body = nil
	}

	//(*r0wbrt) - Per RFC specs, these methods should not have a body. In theory they could
	//			  but in practice they do not. Since any request could have a body, it is not safe
	//			  to just nil the body just because these methods are in use so instead
	//			  Log a warning.
	//
	//			  Cloud flare CDN servers will return a malform request error if
	//			  body is defined on a GET request.
	if ((rsr.Method == http.MethodGet || rsr.Method == http.MethodHead) || rsr.Method == http.MethodDelete) || rsr.Method == http.MethodTrace {

		if rsr.Body != nil {

			proxy.logWarning("Warning, http method " + rsr.Method + " for resource " + rsr.URL.String() + " has a body. This could cause problems with upstream servers.")
		}
	}
}

func (proxy *ProxyServer) attemptHttpConnectionToUpstreamServer(rsr *http.Request, reqContext context.Context, cancel func()) (rresp *http.Response, err error) {

	var counter int = 0
	var start time.Time = time.Now()

	for {

		counter += 1

		quitChan := make(chan interface{})

		go monitorRequest(cancel, quitChan, reqContext)

		rresp, err = proxy.Transport.RoundTrip(rsr)

		close(quitChan)

		if rsr.Context().Err() == context.Canceled {
			panic(http.ErrAbortHandler)
		}

		if err == nil {
			return
		}

		now := time.Now()

		if proxy.MaxTimeTryingToConnect != 0 && now.Sub(start) >= proxy.MaxTimeTryingToConnect {
			return
		}

		if proxy.MaxNumberOfConnectAttempts != 0 && counter >= proxy.MaxNumberOfConnectAttempts {
			return
		}

		urlErr, ok := err.(net.Error)
		if !ok {
			return
		}

		if !urlErr.Temporary() {
			return
		}

		if urlErr.Timeout() {
			panic(http.ErrAbortHandler)
		}

		//Cancel request if client has disconnected
		select {
		case <-reqContext.Done():
			panic(http.ErrAbortHandler)
		default:
		}

		exponentialBackoffPause(proxy.MinRequestRetryTimeout, proxy.RetryBackoffCoefficient, counter)
	}

}

func monitorRequest(cancel func(), quit chan interface{}, clientContext context.Context) {
	select {
	case <-clientContext.Done():
		cancel()
	case <-quit:
		//Do Nothing
	}

}

func (proxy *ProxyServer) proxyWebSocket(rsr *http.Request, w http.ResponseWriter) {
	var buf bytes.Buffer
	var tls bool = false

	proxy.removeBodyFromRequest(rsr)

	rsr.Write(&buf)

	tls = rsr.URL.Scheme == "https"

	host := rsr.Host
	if rsr.URL.Port() == "" {
		if rsr.URL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	proxy.proxyTCPTunnel(host, &buf, w, false, tls)
}

func (proxy *ProxyServer) proxyMethodConnect(rsr *http.Request, w http.ResponseWriter) {

	host := rsr.Host
	proxy.proxyTCPTunnel(host, nil, w, true, false)
}

func (proxy *ProxyServer) proxyTCPTunnel(remoteAddress string, preambleWriter io.Reader, w http.ResponseWriter, writeOK bool, tlsConn bool) {

	hj, ok := w.(http.Hijacker)
	if !ok {
		proxy.coreHttpError(w, http.StatusNotImplemented, "Could not Hijack client http connection. Hijack not supported by implementation.", "Proxying TCP connection failed")
		return
	}

	fromRemoteServerConn, err := proxy.attemptTcpConnectionToUpstreamServer(remoteAddress, tlsConn)

	if err != nil {
		proxy.coreHttpError(w, http.StatusBadGateway, err.Error(), "Could not contact upstream server")
		return
	}

	defer fromRemoteServerConn.Close()

	toClientConn, _, err := hj.Hijack()

	if err != nil {
		proxy.coreHttpError(w, http.StatusInternalServerError, err.Error(), "Proxying TCP connection failed")
		return
	}

	defer toClientConn.Close()

	//Clear timeouts
	toClientConn.SetDeadline(time.Time{})
	toClientConn.SetReadDeadline(time.Time{})
	toClientConn.SetWriteDeadline(time.Time{})

	if writeOK {
		_, err = toClientConn.Write([]byte("HTTP/1.1 200 OK \r\n\r\n"))
		if err != nil {
			proxy.logError("attempting to write HTTP OK for connect", err.Error())
			panic(http.ErrAbortHandler)
		}
	}

	if preambleWriter != nil {
		_, err := io.Copy(fromRemoteServerConn, preambleWriter)
		if err != nil {
			proxy.logError("attempting to write a preamble to hijacked HTTP connection", err.Error())
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go proxy.pipeConn(toClientConn, fromRemoteServerConn, &wg)
	go proxy.pipeConn(fromRemoteServerConn, toClientConn, &wg)

	wg.Wait()
}

func (proxy *ProxyServer) pipeConn(from net.Conn, to net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	_, err := io.Copy(to, from)
	if err != nil {

		//Suppress error logging from TCP connections closes
		neterr, ok := err.(net.Error)

		if !ok || !neterr.Timeout() {
			proxy.logError("piping data between two connections as part of a websocket or connect request", err.Error())
		}
	}
}

func (proxy *ProxyServer) attemptTcpConnectionToUpstreamServer(remoteAddress string, tlsConn bool) (conn net.Conn, err error) {

	var counter int = 0
	var start time.Time = time.Now()

	for {

		counter += 1

		if tlsConn {
			conn, err = tls.Dial("tcp", remoteAddress, proxy.TlsConfig)
		} else {
			conn, err = net.Dial("tcp", remoteAddress)
		}

		if err != nil {
			return
		}

		now := time.Now()

		if proxy.MaxTimeTryingToConnect != 0 && now.Sub(start) >= proxy.MaxTimeTryingToConnect {
			return
		}

		if proxy.MaxNumberOfConnectAttempts != 0 && counter >= proxy.MaxNumberOfConnectAttempts {
			return
		}

		netErr, ok := err.(*net.OpError)
		if !ok {
			return
		}

		if !netErr.Temporary() {
			return
		}

		exponentialBackoffPause(proxy.MinRequestRetryTimeout, proxy.RetryBackoffCoefficient, counter)
	}
}
