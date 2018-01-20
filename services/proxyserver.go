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

	//Function to get a proxy handler
	GetProxyRequestAgent func(w http.ResponseWriter, r *http.Request, transport ProxyTransport) (*ProxyRequestHandler, error)

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
	proxy.GetProxyRequestAgent = NewProxyAgent
	proxy.MsgLogger = log.New(os.Stderr, "", log.Lmicroseconds|log.Ldate)
	
	proxy.Transport = NewProxyServerTransport()
	
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
	go shutdownReqCtx(r.Context(), ctx, cancel)
	
	defer cancel() //Must call cancel to prevent resource leaks
	
	requestHandler, err := proxy.GetProxyRequestAgent(w, r, proxy.Transport)
	defer requestHandler.Close()
	
	rreqctx, err := requestHandler.ProxyRequest(ctx)
	
	if err != nil {
		proxy.handleError(w, err)
		return
	}
	
	select {
		case <-rreqctx.Done():
	}

	if requestHandler.Err() != nil {
		proxy.handleError(w, err)
	}
	
	return
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


