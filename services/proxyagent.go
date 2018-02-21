package services

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
)

type proxyAgentError struct {
	errorString string
	errorCode   int
	bodyMessage string
}

func (err *proxyAgentError) Error() string {
	return err.errorString
}

func (err *proxyAgentError) ErrorCode() int {
	return err.errorCode
}

func (err *proxyAgentError) BodyMessage() string {
	return err.bodyMessage
}

//ErrUseConnect indicates the request should be handled by Connect instead of RoundTrip.
var ErrUseConnect = errors.New("HttpProxyAgent: Use Connect method to handle the request")

//ErrUseRoundTrip indicates the request should be handled by RoundTrip instead of Connect.
var ErrUseRoundTrip = errors.New("HttpProxyAgent: Use RoundTrip method to handle the request")

//ErrBadRequest indicates the request can not be handled because it is incorrect in some way.
var ErrBadRequest ProxyAgentError = &proxyAgentError{errorString: "HttpProxyAgent: Bad Request", errorCode: http.StatusBadRequest, bodyMessage: http.StatusText(http.StatusBadRequest)}

//ErrBadGateway means the remote host could not be reached
var ErrBadGateway ProxyAgentError = &proxyAgentError{errorString: "HttpProxyAgent: Request could not be completed since the upstream server could not be reached", errorCode: http.StatusBadGateway, bodyMessage: http.StatusText(http.StatusBadGateway)}

//ProxyServerAgent is the default implementation of HTTPProxyAgent for ProxyServer.
type ProxyServerAgent struct {
	//Dials a connection
	Dial func(ctx context.Context, host string, tls bool) (net.Conn, error)

	//RoundTrip Sends the input request to the remote server and gets a response.
	RoundTrip func(request *http.Request) (*http.Response, error)
}

var defaultTransport = NewProxyServerTransport()
var defaultProxyAgent = &ProxyServerAgent{RoundTrip: defaultTransport.RoundTrip, Dial: defaultTransport.Dial}

//Connect takes a HTTP Connect of HTTP Web Socket request and opens a
//remote connection to the host sending any extra data needed to set up the connection.
func Connect(r *http.Request) (net.Conn, error) {
	return defaultProxyAgent.Connect(r)
}

//ProxyHTTPRequest sends a request to the remote server and gets back the response.
func ProxyHTTPRequest(r *http.Request) (*http.Response, error) {
	return defaultProxyAgent.RoundTrip(r)
}

//Connect takes a HTTP Connect or HTTP Web Socket request and opens a remote connection to
//the host sending any extra data needed to set up the connection.
func (agent *ProxyServerAgent) Connect(r *http.Request) (net.Conn, error) {

	if !requiresConnect(r) {
		return nil, ErrUseRoundTrip
	}

	requestToSend, err := convertToProxyRequest(r)

	if err != nil {
		return nil, err
	}

	var conn net.Conn

	if IsWebSocketRequest(r) {
		var buf bytes.Buffer
		var tls = false

		requestToSend.Write(&buf)

		tls = requestToSend.URL.Scheme == "https"

		host := requestToSend.Host
		if requestToSend.URL.Port() == "" {
			if requestToSend.URL.Scheme == "https" {
				host = host + ":443"
			} else {
				host = host + ":80"
			}
		}

		conn, err = agent.openTCPTunnel(requestToSend.Context(), host, &buf, tls)
	} else {
		conn, err = agent.openTCPTunnel(requestToSend.Context(), requestToSend.Host, nil, false)
	}

	return conn, err
}

//ProxyHTTPRequest sends a request to the remote server and gets back the response.
func (agent *ProxyServerAgent) ProxyHTTPRequest(r *http.Request) (*http.Response, error) {

	if requiresConnect(r) {
		return nil, ErrUseConnect
	}

	requestToSend, err := convertToProxyRequest(r)

	if err != nil {
		return nil, err
	}

	resp, err := agent.getRoundTrip()(requestToSend)

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (agent *ProxyServerAgent) getRoundTrip() func(request *http.Request) (*http.Response, error) {
	if agent.RoundTrip == nil {
		return defaultTransport.RoundTrip
	}

	return agent.RoundTrip
}

func (agent *ProxyServerAgent) getDial() func(ctx context.Context, host string, tls bool) (net.Conn, error) {
	if agent.RoundTrip == nil {
		return defaultTransport.Dial
	}

	return agent.Dial
}

func convertToProxyRequest(r *http.Request) (*http.Request, error) {

	path := *r.URL
	if path.Host == "" {
		path.Host = r.Host
	}

	if r.Method != http.MethodConnect {
		//Only support http(s) requests.
		if r.URL.Scheme != "http" && r.URL.Scheme != "https" && r.URL.Scheme != "" {

			return nil, ErrBadRequest
		}

		if path.Scheme == "" {
			if r.TLS != nil {
				path.Scheme = "https"
			} else {
				path.Scheme = "http"
			}
		}
	}

	newRequest, err := http.NewRequest(r.Method, path.String(), r.Body)

	if err != nil {
		return nil, err
	}

	for k, v := range r.Header {
		values := append([]string(nil), v...)
		newRequest.Header[k] = values
	}

	//Remove headers that should not be forwarded to the remote server.
	RemoveHopByHopHeaders(&newRequest.Header)

	//Remove body if it should not be present
	RemoveBodyFromRequest(newRequest)

	//Add back hop-by-hop headers needed to establish a websocket connection.
	if IsWebSocketRequest(r) {
		newRequest.Header.Add("Connection", "Upgrade")
		newRequest.Header.Add("Upgrade", "websocket")
	}

	newRequest.ContentLength = r.ContentLength

	return newRequest, nil
}

func (agent *ProxyServerAgent) openTCPTunnel(ctx context.Context, remoteAddress string, preambleWriter io.Reader, tlsConn bool) (net.Conn, error) {

	conn, err := agent.getDial()(ctx, remoteAddress, tlsConn)

	if err != nil {
		return nil, ErrBadGateway
	}

	if preambleWriter != nil {
		_, err := io.Copy(conn, preambleWriter)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func requiresConnect(r *http.Request) bool {
	return r.Method == http.MethodConnect || IsWebSocketRequest(r)
}
