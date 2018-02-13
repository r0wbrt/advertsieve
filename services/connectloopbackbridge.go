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
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

//Set up enums used to control access into the bridge.
const (
	HTTPConnectBridge = iota
	HTTPSConnectBridge
	DenyConnect
)

//ConnectLoopBackBridge is a HTTP termination proxy that forwards all regular HTTP requests
//to Handler. For CONNECT, and upgrade requests, Bridge hijacks the http requests to get the
//underlying connection and exposes the connection to consuming code via the net.Listener interface.
//Routes HTTPS requests to one listener interface and standard HTTP requests to another.
type ConnectLoopBackBridge struct {
	//Handler to forward http requests not using the forward method.
	Handler http.Handler

	//Address of loop back bridge. This needs to be set for the listen
	//interface to work correctly.
	Address string

	//Function used to determine where a request should go. If nil,
	//then port 443 is mapped to https, port 80 to http, and all other
	//ports are blocked.
	PortMapper func(r *http.Request) int

	//Channel https connections will be sent over.
	httpsConnChannel chan net.Conn

	//Channel http connections will be sent over
	httpConnChannel chan net.Conn

	//A channel which when closed means the connections are no longer being
	//accepted.
	done chan interface{}

	//Closing this channel signals that the listener is no longer accepting
	//connections.
	channelClosed bool

	//Mutex uses to control access to Close.
	mutex sync.Mutex

	//Logger used to generate messages.
	Logger *log.Logger
}

//NewConnectLoopBackBridge sets up a loopback bridge.
func NewConnectLoopBackBridge(handler http.Handler, address string) (bridge *ConnectLoopBackBridge) {

	bridge = new(ConnectLoopBackBridge)

	bridge.done = make(chan interface{})
	bridge.httpConnChannel = make(chan net.Conn)
	bridge.httpsConnChannel = make(chan net.Conn)
	bridge.Logger = log.New(os.Stderr, "Connect Loopback Bridge ", log.Lmicroseconds|log.Ldate|log.Lshortfile)
	bridge.Address = address
	bridge.Handler = handler

	return
}

func (bridge *ConnectLoopBackBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	select {
	case _ = <-bridge.done:

		w.WriteHeader(http.StatusServiceUnavailable)
		http.Error(w, "This server is no longer accepting connections", http.StatusServiceUnavailable)
		return

	default:
	}

	if r.Method == http.MethodConnect {

		hj, ok := w.(http.Hijacker)
		if !ok {

			http.Error(w, "This implementation does not support the CONNECT method.", http.StatusNotImplemented)
			bridge.Logger.Print("Implementation does not support connection hijacking, CONNECT request aborted")
			return
		}

		var connChannel chan net.Conn
		var res int

		if bridge.PortMapper != nil {
			res = bridge.PortMapper(r)
		} else {
			res = defaultPortMapper(r)
		}

		switch res {
		case HTTPConnectBridge:
			connChannel = bridge.httpConnChannel
		case HTTPSConnectBridge:
			connChannel = bridge.httpsConnChannel
		case DenyConnect:
			http.Error(w, "CONNECT request is denied.", http.StatusForbidden)
		default:
			http.Error(w, "Unrecoverable internal server error", http.StatusInternalServerError)
		}

		if connChannel == nil {
			return
		}

		conn, _, err := hj.Hijack()
		if err != nil {
			bridge.Logger.Println(err.Error())
			return
		}

		_, err = conn.Write([]byte("HTTP/1.1 200 OK \r\n\r\n"))
		if err != nil {
			bridge.Logger.Println(err)
			panic(http.ErrAbortHandler)
		}

		select {
		case _ = <-bridge.done:
			//If we come here for any reason, this channel has closed.
			conn.Close()
		case connChannel <- conn:
		}

	} else {
		bridge.Handler.ServeHTTP(w, r)
	}

	return
}

func defaultPortMapper(r *http.Request) int {
	if r.URL.Port() == "80" {
		return HTTPConnectBridge
	} else if r.URL.Port() == "443" {
		return HTTPSConnectBridge
	} else {
		return DenyConnect
	}
}

//Accept returns a hijacked connection that should be handled by an HTTPS server.
func (bridge *ConnectLoopBackBridge) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-bridge.httpsConnChannel:

	case _ = <-bridge.done:
		err = errors.New("connectLoopBackBridge: No longer accepting new connections")
	}

	return
}

//Close shutsdown the bridge. Any subsequent recieved http requests are aborted.
func (bridge *ConnectLoopBackBridge) Close() error {
	bridge.mutex.Lock()
	defer bridge.mutex.Unlock()

	if bridge.channelClosed {
		return nil
	}

	close(bridge.done)
	bridge.channelClosed = true

	return nil
}

type proxyBridgeAdd struct {
	addr string
}

func (addr proxyBridgeAdd) Network() string {
	return "tcp"
}

func (addr proxyBridgeAdd) String() string {
	return addr.addr
}

//Addr returns the address the bridge is listening on. For consistency,
//this should match whatever the HTTP server hosting the bridge is listening on.
func (bridge *ConnectLoopBackBridge) Addr() net.Addr {
	return proxyBridgeAdd{addr: bridge.Address}
}

type httpListener struct {
	bridge *ConnectLoopBackBridge
}

//GetHTTPListener returns the connections that should be passed to
//a standard http server for further processing.
func (bridge *ConnectLoopBackBridge) GetHTTPListener() net.Listener {
	return &httpListener{bridge: bridge}
}

func (l *httpListener) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-l.bridge.httpConnChannel:

	case _ = <-l.bridge.done:
		err = errors.New("connectLoopBackBridge: No longer accepting new connections")
	}

	return
}

func (l *httpListener) Close() error {
	return l.bridge.Close()
}

func (l *httpListener) Addr() net.Addr {
	return proxyBridgeAdd{addr: l.bridge.Address}
}
