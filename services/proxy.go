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
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type ProxyHookType int

const (
	BeforeIssueUpstreamRequest ProxyHookType = iota
	BeforeIssueDownstreamResponse
)

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

	//Proxy instance
	Proxy *ProxyServer

	//Function used to cancel the request
	cancel func()
}

type ProxyHook func(context *ProxyChainContext) (stopProcessingChain, connHijacked bool, err error)

type ProxyServer struct {

	//When set to true, the proxy permit tcp tunneling through this web server.
	//If set to false, CONNECT method will be rejected
	AllowConnect bool

	//When set to true, upgrade requests will be passed through this proxy.
	AllowUpgrade bool

	//Logger used to handle messages generated during the operation of the proxy
	//server.
	MsgLogger *log.Logger

	//Maximum number of attempts to contact upstream server
	MaxNumberOfConnectAttempts int

	//Max number of time to spend attempting to connect to upstream server
	MaxTimeTryingToConnect time.Duration

	//Amount of time to wait before retrying a failed request.
	MinRequestRetryTimeout time.Duration

	//Time duration to multiply the exponential back off coefficient by.
	RetryBackoffCoefficient time.Duration

	//Chain of handlers to call before each proxied request.
	beforeIssueUpstreamRequest []ProxyHook

	//Chain of handlers to call before each proxied response.
	beforeIssueDownstreamResponse []ProxyHook

	//Mutex to make this thread safe
	mutex sync.RWMutex

	//Round Tripper used to make HTTP requests
	Transport http.RoundTripper
}

//*****************************************************************************
//
//		                   Public Methods on ProxyServer
//
//*****************************************************************************

//Creates a new proxy server
func NewProxyServer() (proxy *ProxyServer) {
	proxy = new(ProxyServer)

	proxy.MaxNumberOfConnectAttempts = 0
	proxy.MaxTimeTryingToConnect = time.Duration(30) * time.Second
	proxy.MinRequestRetryTimeout = 0
	proxy.RetryBackoffCoefficient = time.Duration(500) * time.Millisecond

	proxy.MsgLogger = log.New(os.Stderr, "Proxy ", log.Lmicroseconds|log.Ldate)

	proxy.Transport = &http.Transport{
		TLSHandshakeTimeout:   time.Duration(10) * time.Second,
		MaxIdleConns:          128,
		IdleConnTimeout:       time.Duration(2) * time.Minute,
		ExpectContinueTimeout: time.Duration(1) * time.Second,
		ResponseHeaderTimeout: time.Duration(10) * time.Second,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper), // Disable HTTP2
	}
	return
}

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
	proxy.MsgLogger.Println(internalMessage)
	http.Error(w, externalMessage, code)
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
		//Guard against using this proxy to open FTP or other strange connections.
		if r.URL.Scheme != "http" && r.URL.Scheme != "https" && r.URL.Scheme != "" {
			proxy.HttpError(w, http.StatusBadRequest, "Received non http URI scheme from "+r.RemoteAddr+". URI was "+r.URL.String(), "Bad Request")
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
		proxy.HttpError(w, http.StatusInternalServerError, err.Error(), http.StatusText(http.StatusInternalServerError))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	rsr = rsr.WithContext(ctx)
	//Copy over headers for sending to the remote server
	setUpRemoteServerRequest(r, rsr)

	reqIsWebsocket := IsWebSocketRequest(r)
	
	RemoveHopByHopHeaders(&rsr.Header)

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
		cancel:             cancel,
	}

	//Run Before Request hooks
	var connHijacked bool
	connHijacked, err = RunHandlerChain(proxy.beforeIssueUpstreamRequest, &proxyContext)

	if connHijacked {
		return
	}

	if err != nil {
		proxy.HttpError(w, http.StatusInternalServerError, err.Error(), http.StatusText(http.StatusInternalServerError))
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

//*****************************************************************************
//
//		                   Access Control Logic
//
//*****************************************************************************

func (proxy *ProxyServer) allowRequest(r *http.Request, w http.ResponseWriter) bool {

	if r.Method == http.MethodConnect && !proxy.AllowConnect {

		proxy.HttpError(w, http.StatusForbidden, "Request for CONNECT from "+r.RemoteAddr+" but CONNECT is disabled", "Use of CONNECT method is not allowed")
		return false
	}

	isUpgrade := r.Header.Get("Upgrade") != ""
	isWebSocket := IsWebSocketRequest(r)

	if isUpgrade && !proxy.AllowUpgrade {
		proxy.HttpError(w, http.StatusForbidden, "Request for HTTP upgrade from  "+r.RemoteAddr+" but HTTP upgrade is disabled", "Use of HTTP upgrade is not allowed")
		return false
	}

	if isUpgrade && !isWebSocket {
		proxy.HttpError(w, http.StatusNotImplemented, "Request for HTTP upgrade from  "+r.RemoteAddr+" was not web socket", "Only upgrades for websocket are supported")
		return false
	}

	return true
}

func IsWebSocketRequest(r *http.Request) bool {
	upgradeType := r.Header.Get("Upgrade")

	if strings.ToLower(upgradeType) == "websocket" {
		return true
	}

	return false
}

//*****************************************************************************
//
//		                   Internal Proxy Hook Logic
//
//*****************************************************************************

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

//*****************************************************************************
//
//		                   Standard HTTP Proxying Logic
//
//*****************************************************************************

func (proxy *ProxyServer) returnHTTPResponse(rsr *http.Request, w http.ResponseWriter, r *http.Request, context *ProxyChainContext) {

	if rsr.Header.Get("Content-Length") == "" && rsr.Header.Get("Transfer-Encoding") == "" {
		rsr.Body = nil
	}

	if ((rsr.Method == http.MethodGet || rsr.Method == http.MethodHead) || rsr.Method == http.MethodDelete) || rsr.Method == http.MethodTrace {
		rsr.Body = nil
	}

	rresp, err := proxy.attemptHttpConnectionToUpstreamServer(rsr, r.Context(), context.cancel)

	if err != nil {
		proxy.HttpError(w, http.StatusBadGateway, err.Error(), "Could not contact upstream server")
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
		proxy.HttpError(w, http.StatusInternalServerError, err.Error(), http.StatusText(http.StatusInternalServerError))
		return
	}

	w.WriteHeader(rresp.StatusCode)
	io.Copy(w, rresp.Body)

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

		urlErr, ok := err.(*url.Error)
		if !ok {
			return
		}

		if !urlErr.Temporary() {
			return
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

//*****************************************************************************
//
//		                   TCP Tunneling Logic
//
//*****************************************************************************

func (proxy *ProxyServer) proxyWebSocket(rsr *http.Request, w http.ResponseWriter) {
	var buf bytes.Buffer

	if ((rsr.Method == http.MethodGet || rsr.Method == http.MethodHead) || rsr.Method == http.MethodDelete) || rsr.Method == http.MethodTrace {
		rsr.Body = nil
	}
	
	rsr.Write(&buf)
	
	host := rsr.Host
	if rsr.URL.Port() == "" {

		if rsr.URL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}

	}
	proxy.proxyTCPTunnel(host, &buf, w, false)
}

func (proxy *ProxyServer) proxyMethodConnect(rsr *http.Request, w http.ResponseWriter) {

	host := rsr.Host
	proxy.proxyTCPTunnel(host, nil, w, true)
}

func (proxy *ProxyServer) proxyTCPTunnel(remoteAddress string, preambleWriter io.Reader, w http.ResponseWriter, writeOK bool) {

	hj, ok := w.(http.Hijacker)
	if !ok {
		proxy.HttpError(w, http.StatusNotImplemented, "Could not Hijack client http connection. Hijack not supported by implementation.", "Proxying TCP connection failed")
		return
	}

	fromRemoteServerConn, err := proxy.attemptTcpConnectionToUpstreamServer(remoteAddress)

	if err != nil {
		proxy.HttpError(w, http.StatusBadGateway, err.Error(), "Could not contact upstream server")
		return
	}

	defer fromRemoteServerConn.Close()

	toClientConn, _, err := hj.Hijack()

	if err != nil {
		proxy.HttpError(w, http.StatusInternalServerError, err.Error(), "Proxying TCP connection failed")
		return
	}

	defer toClientConn.Close()

	if writeOK {
		_, err = toClientConn.Write([]byte("HTTP/1.1 200 OK \r\n\r\n"))
		if err != nil {
			proxy.MsgLogger.Println(err)
			panic(http.ErrAbortHandler)
		}
	}

	if preambleWriter != nil {
		_, err := io.Copy(fromRemoteServerConn, preambleWriter)
		if err != nil {
			proxy.MsgLogger.Println(err.Error())
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
			proxy.MsgLogger.Println(err.Error())
		}
	}
}

func (proxy *ProxyServer) attemptTcpConnectionToUpstreamServer(remoteAddress string) (conn net.Conn, err error) {

	var counter int = 0
	var start time.Time = time.Now()

	for {

		counter += 1

		conn, err = net.Dial("tcp", remoteAddress)
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

//*****************************************************************************
//
//		                   Utility Functions
//
//*****************************************************************************

func setUpRemoteServerRequest(clientRequest *http.Request, remoteRequest *http.Request) {

	for k, v := range clientRequest.Header {
		values := append([]string(nil), v...)
		remoteRequest.Header[k] = values
	}

}
