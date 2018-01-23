package services

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

type ProxyTransport interface {

	//Dials a connection
	Dial(host string, tls bool, ctx context.Context) (net.Conn, error)

	//Handles a http request.
	RoundTrip(request *http.Request) (*http.Response, error)
}

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
	TlsConfig *tls.Config

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

func NewProxyServerTransport() (serverTransport *ProxyServerTransport) {

	serverTransport = &ProxyServerTransport{}

	serverTransport.Transport = &http.Transport{
		TLSHandshakeTimeout:   time.Duration(10) * time.Second,
		MaxIdleConns:          128,
		IdleConnTimeout:       time.Duration(2) * time.Minute,
		ExpectContinueTimeout: time.Duration(1) * time.Second,
		ResponseHeaderTimeout: time.Duration(30) * time.Second,
		TLSClientConfig:       serverTransport.TlsConfig,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper), // Disable HTTP2
	}

	serverTransport.TlsConfig = SecureTLSConfig()
	serverTransport.MaxNumberOfConnectAttempts = 0
	serverTransport.MaxTimeTryingToConnect = time.Duration(30) * time.Second
	serverTransport.MinRequestRetryTimeout = 0
	serverTransport.RetryBackoffCoefficient = time.Duration(500) * time.Millisecond

	return
}

func (sTrans *ProxyServerTransport) RoundTrip(rsr *http.Request) (*http.Response, error) {

	var counter int = 0
	var start time.Time = time.Now()

	for {

		counter += 1

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

func (proxy *ProxyServerTransport) Dial(remoteAddress string, tlsConn bool, ctx context.Context) (conn net.Conn, err error) {

	var counter int = 0
	var start time.Time = time.Now()

	for {

		counter += 1

		if tlsConn {
			conn, err = tls.Dial("tcp", remoteAddress, proxy.TlsConfig)
		} else {
			conn, err = net.Dial("tcp", remoteAddress)
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

		exponentialBackoffPause(proxy.MinRequestRetryTimeout, proxy.RetryBackoffCoefficient, counter)
	}
}
