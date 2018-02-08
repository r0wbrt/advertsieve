/* Copyright 2017-2018 Robert Christian Taylor. All Rights Reserved
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

package services

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

//ErrRequestHijacked should be return from InterceptResponse to indicate the request has been handled
//and the proxy should do no further processing.
var ErrRequestHijacked = errors.New("Proxy Server: The InterceptResponse function has handled the request")

//Format used to log messages.
const logFormat = "Proxy Server: Error on path \"%s\" sent by \"%s\" : %s"

//CopyBackProxyResponse pipes a http.response output to a http.ResponseWriter.
func CopyBackProxyResponse(w http.ResponseWriter, r *http.Response) {

	for k, v := range r.Header {
		values := append([]string(nil), v...)
		w.Header()[k] = values
	}

	w.WriteHeader(r.StatusCode)
	io.Copy(w, r.Body)
}

//ProxyAgentError is a more rich error format that instructs
//the proxy on how to represent the error message to the end user.
type ProxyAgentError interface {

	//Error to write to the log.
	Error() string

	//HTTP error code to send.
	ErrorCode() int

	//HTTP response to write to the client.
	BodyMessage() string
}

//ProxyServer is a proxy server which takes requests from a downstream client,
//proxies them to an upstream server, and then sends the response back
//to the downstream client. Supports websocket and connect.
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
	Logger *log.Logger

	//The agent which takes a request and gets a response from the remote server
	ProxyAgent HTTPProxyAgent

	//Function that can modify the response before before it is sent to the client.
	//This function can also handle the entire response and the function indicates this
	//by returning ErrRequestHijacked.
	InterceptResponse func(http.ResponseWriter, *http.Response) error

	//Root Context used to shutdown the server
	ctx context.Context

	//Function used to close the context and shutdown the server
	shutdownFunc func()
}

//NewProxyServer creates a proxy server.
func NewProxyServer() (proxy *ProxyServer) {
	proxy = new(ProxyServer)

	proxy.AllowWebsocket = true
	proxy.Logger = log.New(os.Stderr, "", log.Lmicroseconds|log.Ldate)

	proxy.ProxyAgent = &ProxyServerAgent{}

	proxy.ctx, proxy.shutdownFunc = context.WithCancel(context.Background())

	return
}

//Close shutsdown the server interrupting all active http transactions.
func (proxy *ProxyServer) Close() error {
	proxy.shutdownFunc()
	return nil
}

//Standard function that handles a proxy request.
func (proxy *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if proxy.ctx.Err() != nil {
		panic(http.ErrAbortHandler)
	}

	if !proxy.allowRequest(r, w) {
		panic(http.ErrAbortHandler)
	}

	//Link this to the core proxy context so if the server
	//is shutdown, the close is propagated to all child
	//transactions.
	ctx, cancel := context.WithCancel(proxy.ctx)
	defer cancel() //Must call cancel to prevent resource leaks

	go shutdownReqCtx(r.Context(), ctx, cancel)

	resp, err := proxy.ProxyAgent.RoundTrip(r)

	if err != nil {
		if err == ErrUseConnect {
			conn, err := proxy.ProxyAgent.Connect(r)
			if err != nil {
				proxy.handleError(w, err, r)
			} else {
				proxy.proxyTCPConnection(ctx, w, conn, !IsWebSocketRequest(r))
			}
		} else {
			proxy.handleError(w, err, r)
		}
	} else {
		defer resp.Body.Close()
		if proxy.InterceptResponse != nil {
			err = proxy.InterceptResponse(w, resp)
			if err != ErrRequestHijacked && err != nil {
				proxy.handleError(w, err, r)
			}
		}

		if err == nil {
			CopyBackProxyResponse(w, resp)
		}
	}

	return
}

//Helper function which monitors a request context and server context.
//If the request context is closed, it closes the response's context via
//the cancel function.
func shutdownReqCtx(requestctx context.Context, handlerctx context.Context, cancel func()) {
	select {
	case <-requestctx.Done():
		cancel()

	case <-handlerctx.Done():
		//No operation
	}

	return
}

func (proxy *ProxyServer) proxyTCPConnection(ctx context.Context, w http.ResponseWriter, fromRemoteServerConn net.Conn, writeOK bool) {

	defer fromRemoteServerConn.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		proxy.Logger.Println("Proxy Server: Hijacking not supported by your implementation")
		panic(http.ErrAbortHandler)
	}

	toClientConn, _, err := hj.Hijack()

	if err != nil {
		proxy.Logger.Printf("Proxy Server: Could not hijack client request: %s", err.Error())
		panic(http.ErrAbortHandler)
	}

	defer toClientConn.Close()

	//Clear timeouts
	toClientConn.SetDeadline(time.Time{})
	toClientConn.SetReadDeadline(time.Time{})
	toClientConn.SetWriteDeadline(time.Time{})

	if writeOK {
		_, err = toClientConn.Write([]byte("HTTP/1.1 200 OK \r\n\r\n"))
		if err != nil {
			proxy.Logger.Printf("Proxy Server: attempting to write 200 ok to the connection failed: %s", err.Error())
			panic(http.ErrAbortHandler)
		}

	}

	var wg sync.WaitGroup
	wg.Add(2)

	go proxy.pipeConn(toClientConn, fromRemoteServerConn, &wg) //Copy client data to server
	go proxy.pipeConn(fromRemoteServerConn, toClientConn, &wg) //Copy server data to client

	go closeConnectionOnCtxDone(ctx, toClientConn)
	go closeConnectionOnCtxDone(ctx, fromRemoteServerConn)

	wg.Wait()
}

//Copies a net.Conn read end to a a write end.
func (proxy *ProxyServer) pipeConn(from net.Conn, to net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	_, err := io.Copy(to, from)
	if err != nil {

		//Suppress error logging when a TCP connection closes
		neterr, ok := err.(net.Error)

		if !ok || !neterr.Timeout() {
			proxy.Logger.Printf("Proxy Server: unexpected error while piping data between two connections as part of a websocket or connect request: %s", err.Error())
		}
	}
}

//Closes a TCP connection if the context is closed.
func closeConnectionOnCtxDone(ctx context.Context, conn net.Conn) {
	select {
	case <-ctx.Done():
	}

	conn.Close()
}

//Determines if a request is permitted based on active access control policies
func (proxy *ProxyServer) allowRequest(r *http.Request, w http.ResponseWriter) bool {

	//(*r0wbrt) - Should we expose a new proxy chain that could run here to perform
	//     		  access control operations?

	if r.Method == http.MethodConnect && !proxy.AllowConnect {
		proxy.Logger.Printf(logFormat, r.URL.String(), r.RemoteAddr, "Connect is disabled")
		return false
	}

	isWebSocket := IsWebSocketRequest(r)

	if isWebSocket && !proxy.AllowWebsocket {
		proxy.Logger.Printf(logFormat, r.URL.String(), r.RemoteAddr, "Websocket is disabled")
		return false
	}

	return true
}

//Error handling function
func (proxy *ProxyServer) handleError(w http.ResponseWriter, err error, r *http.Request) {

	if err == nil {
		panic("expected non nil error")
	}

	var statusCode int
	var message string
	var bodyMessage string

	custErr, ok := err.(ProxyAgentError)

	if ok {
		message = custErr.Error()
		statusCode = custErr.ErrorCode()
		bodyMessage = custErr.BodyMessage()
	} else {
		statusCode = http.StatusInternalServerError
		message = "Unknown error occurred: " + err.Error()
		bodyMessage = http.StatusText(statusCode)
	}

	http.Error(w, bodyMessage, statusCode)

	if message != "" {
		proxy.Logger.Printf(logFormat, r.URL.String(), r.RemoteAddr, message)
	}
}
