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

type ConnectLoopBackBridge struct {
	//Handler to forward http requests not using the forward method.
	Handler http.Handler

	//Address of loop back bridge. This needs to be set for the listen
	//interface to work correctly.
	Address string

	//Channel connections will be sent over.
	connChannel chan net.Conn

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

func NewConnectLoopBackBridge(handler http.Handler, address string) (bridge *ConnectLoopBackBridge) {

	bridge = new(ConnectLoopBackBridge)

	bridge.done = make(chan interface{})
	bridge.connChannel = make(chan net.Conn)
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
		case bridge.connChannel <- conn:
		}

	} else {
		bridge.Handler.ServeHTTP(w, r)
	}

	return
}

func (bridge *ConnectLoopBackBridge) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-bridge.connChannel:

	case _ = <-bridge.done:
		err = errors.New("No longer accepting new connections.")
	}

	return
}

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

func (bridge *ConnectLoopBackBridge) Addr() net.Addr {
	return proxyBridgeAdd{addr: bridge.Address}
}
