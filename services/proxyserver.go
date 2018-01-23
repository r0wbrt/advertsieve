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

package services

import (
	"context"
	"log"
	"net/http"
	"os"
	"io"
	"net"
	"sync"
	"time"
)

const proxyErrorPrefix = "Proxy Core Server: "

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
	
	//The agent which takes a request and gets a response from the remote server
	ProxyAgent HttpProxyAgent

	//Transport used to dial TCP and http requests
	Transport ProxyTransport
	
	//Root Context used to shutdown the server
	ctx context.Context
	
	//Function used to close the context and shutdown the server
	shutdownFunc func()
	
}

//Creates a new proxy server and sets up any hidden fields on ProxyServer.
func NewProxyServer() (proxy *ProxyServer) {
	proxy = new(ProxyServer)

	proxy.AllowWebsocket = true
	proxy.MsgLogger = log.New(os.Stderr, "", log.Lmicroseconds|log.Ldate)
	
	proxy.Transport = NewProxyServerTransport()
	proxy.ProxyAgent = &ProxyServerAgent{Transport: proxy.Transport}
	
	proxy.ctx, proxy.shutdownFunc = context.WithCancel(context.Background())
	
	return
}

//Shutdown the server interrupting all active http transactions
func (proxy *ProxyServer) Close() error {
	proxy.shutdownFunc()
	return nil
}

func (proxy *ProxyServer) emitHttpError(w http.ResponseWriter, code int, internalMessage string, externalMessage string) {
	var prefix string
	prefix = proxyErrorPrefix
	proxy.MsgLogger.Printf("%s HTTP request error \"%s.\" External message sent was \"%s.\" with error code %d.", prefix, internalMessage, externalMessage, code)
	http.Error(w, externalMessage, code)
}

//Standard function that handles a proxy request.
func (proxy *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	
	if proxy.ctx.Err() != nil {
		panic(http.ErrAbortHandler)
	}
	
	if !proxy.allowRequest(r, w) {
		return
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
				proxy.handleError(w, err)
			} else{
				proxy.proxyTcpConnection(w, conn, !IsWebSocketRequest(r), ctx)
			}
		} else {
			proxy.handleError(w, err)	
		}
	} else {
		defer resp.Body.Close()
		CopyBackProxyResponse(w, resp)
	}
	
	return
}

func CopyBackProxyResponse(w http.ResponseWriter, r *http.Response) {
	
	for k, v := range r.Header {
			values := append([]string(nil), v...)
			w.Header()[k] = values
	}
	
	w.WriteHeader(r.StatusCode)
	io.Copy(w, r.Body)
}

func (proxy *ProxyServer) proxyTcpConnection(w http.ResponseWriter, fromRemoteServerConn net.Conn, writeOK bool, ctx context.Context) {
	
	defer fromRemoteServerConn.Close()
	
	hj, ok := w.(http.Hijacker)
	if !ok {
		proxy.MsgLogger.Println("Hijacking not supported by your implementation")
		panic(http.ErrAbortHandler)
	}


	toClientConn, _, err := hj.Hijack()

	if err != nil {
		panic("Proxy Server: Could not hijack client request: " + err.Error())
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
			proxy.MsgLogger.Println("Proxy Server: attempting to write 200 ok to the connection failed: " + err.Error())
			panic(http.ErrAbortHandler)
		}
			
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go proxy.pipeConn(toClientConn, fromRemoteServerConn, &wg)
	go proxy.pipeConn(fromRemoteServerConn, toClientConn, &wg)

	go closeConnectionOnCtxDone(toClientConn, ctx)
	go closeConnectionOnCtxDone(fromRemoteServerConn, ctx)
	
	wg.Wait()
}

func (handler *ProxyServer) pipeConn(from net.Conn, to net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	_, err := io.Copy(to, from)
	if err != nil {

		//Suppress error logging from TCP connections closes
		neterr, ok := err.(net.Error)

		if !ok || !neterr.Timeout() {
			handler.MsgLogger.Println("Proxy Server: unexpected error while piping data between two connections as part of a websocket or connect request: " + err.Error())
		}
	}
}

func closeConnectionOnCtxDone(conn net.Conn,  ctx context.Context) {
	select {
		case <- ctx.Done():
	}
	
	conn.Close()
}


func shutdownReqCtx(requestctx context.Context, handlerctx context.Context, cancel func() ) {
	select {
			case <- requestctx.Done():
				cancel()
				
			case <- handlerctx.Done():
				//No operation
	}
	
	return
}

//Determines if a request is permitted based on active access control policies
func (proxy *ProxyServer) allowRequest(r *http.Request, w http.ResponseWriter) bool {

	//(*r0wbrt) - Should we expose a new proxy chain that could run here to perform
	//     		  access control operations?
	
	if r.Method == http.MethodConnect && !proxy.AllowConnect {
		proxy.emitHttpError(w, http.StatusForbidden, "Request for CONNECT from "+r.RemoteAddr+" to path \""+r.URL.String()+"\" was denied because AllowConnect is set to false.", http.StatusText(http.StatusForbidden))
		return false
	}

	isWebSocket := IsWebSocketRequest(r)

	if isWebSocket && !proxy.AllowWebsocket {
		proxy.emitHttpError(w, http.StatusForbidden, "HTTP websocket upgrade request from "+r.RemoteAddr+" to path \""+r.URL.String()+"\" was denied because AllowWebsocket is set to false.", http.StatusText(http.StatusForbidden))
		return false
	}

	return true
}

func (proxy *ProxyServer) handleError(w http.ResponseWriter, err error) {
	
	if err == nil {
		panic("expected non nil error")
	}
	
	httpError, ok := err.(ProxyAgentError)
	
	if !ok {
		proxy.emitHttpError(w, http.StatusInternalServerError, "Unknown internal server error. Error received was \"" + err.Error() + "\"", http.StatusText(http.StatusInternalServerError))
	} else {
		
		abortRequest := httpError.AbortRequest()
		
		if !httpError.SkipLogging() {
			internalErrorMessage := httpError.InternalErrorString()
			sourceError := httpError.SourceError()
			abortRequestMessage := "was not aborted"
			
			if abortRequest {
				abortRequestMessage = "was aborted"
			}
			
			if sourceError == nil {
				proxy.MsgLogger.Printf("%s Error occurred while processing the request. Error message was \"%s\" and the request %s.", proxyErrorPrefix, internalErrorMessage, abortRequestMessage)
			} else {
				proxy.MsgLogger.Printf("%s Error occurred while processing the request. Error message was \"%s\" with an internal source error with message \"%s.\" The request %s.", proxyErrorPrefix, internalErrorMessage, sourceError.Error(), abortRequestMessage)
			}
		}
		
		if abortRequest {
			panic(http.ErrAbortHandler)
		}
				
		http.Error(w, httpError.ExternalErrorString(), httpError.ErrorCode())
	}
}


