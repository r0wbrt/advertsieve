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
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

//ProxyTransport is used by ProxyServerAgent to open TCP connections and issue HTTP(s)
//requests and get back the associated response.
type ProxyTransport interface {

	//Dials a connection
	Dial(ctx context.Context, host string, tls bool) (net.Conn, error)

	//Handles a http request.
	RoundTrip(request *http.Request) (*http.Response, error)
}

//ProxyServerTransport is an implementation of ProxyTransport featuring exponential backoff. It is the
//default implementation used by ProxyServerAgent.
type ProxyServerTransport struct {

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
	TLSConfig *tls.Config

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
}

//NewProxyServerTransport creates a new instance of ProxyServerTransport.
func NewProxyServerTransport() (serverTransport *ProxyServerTransport) {

	serverTransport = &ProxyServerTransport{}

	serverTransport.Transport = &http.Transport{
		TLSHandshakeTimeout:   time.Duration(10) * time.Second,
		MaxIdleConns:          128,
		IdleConnTimeout:       time.Duration(2) * time.Minute,
		ExpectContinueTimeout: time.Duration(1) * time.Second,
		ResponseHeaderTimeout: time.Duration(30) * time.Second,
		TLSClientConfig:       serverTransport.TLSConfig,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper), // Disable HTTP2
	}

	serverTransport.TLSConfig = SecureTLSConfig()
	serverTransport.MaxNumberOfConnectAttempts = 0
	serverTransport.MaxTimeTryingToConnect = time.Duration(30) * time.Second
	serverTransport.MinRequestRetryTimeout = 0
	serverTransport.RetryBackoffCoefficient = time.Duration(500) * time.Millisecond

	return
}

//RoundTrip takes a request and returns an HTTP response. If the request could not reach the
//remote server, it returns an error. To cancel the outbound request at any time, just close
//the context bound to the passed in http.Request.
func (sTrans *ProxyServerTransport) RoundTrip(rsr *http.Request) (*http.Response, error) {

	var counter int
	var start = time.Now()

	for {

		counter++

		ctx := rsr.Context()
		rresp, err := sTrans.Transport.RoundTrip(rsr)

		if rsr.Context().Err() == context.Canceled {
			return nil, rsr.Context().Err()
		}

		if err == nil {
			return rresp, nil
		}

		now := time.Now()

		if sTrans.MaxTimeTryingToConnect != 0 && now.Sub(start) >= sTrans.MaxTimeTryingToConnect {
			return nil, err
		}

		if sTrans.MaxNumberOfConnectAttempts != 0 && counter >= sTrans.MaxNumberOfConnectAttempts {
			return nil, err
		}

		netErr, ok := err.(net.Error)
		if !ok {
			return nil, err
		}

		if !netErr.Temporary() {
			return nil, netErr
		}

		if netErr.Timeout() {
			return nil, err
		}

		//Cancel request if client has disconnected
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		exponentialBackoffPause(sTrans.MinRequestRetryTimeout, sTrans.RetryBackoffCoefficient, counter)
	}

}

//Dial attempts to connect to the remote address. If Dial will attempt to mitigate
//temporary network issues by using an exponential back off algorithm. However,
//if Dial encounters an unrecoverable error, the number of tries is exceeded, or the
//amount of time trying to request elapses, Dial will return an error.
//
//To cancel an ongoing request, cancel the passed in context.
func (sTrans *ProxyServerTransport) Dial(ctx context.Context, remoteAddress string, tlsConn bool) (conn net.Conn, err error) {

	var counter = 0
	var start = time.Now()

	for {

		counter++

		if tlsConn {
			conn, err = tls.Dial("tcp", remoteAddress, sTrans.TLSConfig)
		} else {
			conn, err = net.Dial("tcp", remoteAddress)
		}

		if err == nil {
			return
		}

		now := time.Now()

		if sTrans.MaxTimeTryingToConnect != 0 && now.Sub(start) >= sTrans.MaxTimeTryingToConnect {
			return
		}

		if sTrans.MaxNumberOfConnectAttempts != 0 && counter >= sTrans.MaxNumberOfConnectAttempts {
			return
		}

		netErr, ok := err.(*net.OpError)
		if !ok {
			return
		}

		if !netErr.Temporary() {
			return
		}

		//Cancel request if client has disconnected
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		exponentialBackoffPause(sTrans.MinRequestRetryTimeout, sTrans.RetryBackoffCoefficient, counter)
	}
}
