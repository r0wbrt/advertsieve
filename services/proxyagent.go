package services

import (
	"net"
	"net/http"
	"context"
	"io"
	"bytes"
	"sync"
	"time"
	"errors"
)

//Proxy agent shall return this to abort a proxy request
var AbortProxyRequest error = errors.New("HTTP transaction should be aborted")

//Proxy agent shall return this to notify consuming code that the transaction 
//has finished.
var ProxyHTTPTransactionHandled error = errors.New("HTTP transaction has been handled")


//TODO 	- rename to proxy agent
type ProxyRequest interface {
	//Gets the downstream request associated with this request
	DownstreamRequest() *http.Request
	
	//Gets the downstream response associated with this request
	DownstreamResponse() http.ResponseWriter
	
	//Gets the upstream response associated with this request
	UpstreamRequest() *http.Request
	
	//Gets the upstream response associated with this request
	UpstreamResponse() *http.Response
	
	//Issue this proxy's request to the remote server. Supply
	//a context to enable the proxy request to be cancelled. 
	IssueRequest(ctx context.Context) (context.Context, error)
	
	//Indicates if the server can call issue response. Some methods,
	//like CONNECT or web socket upgrade requests, do not have a response.
	CanCallIssueResponse() bool
	
	//Issues response to client. This can only be called if CanCallIssueResponse 
	//is true.
	IssueResponse(ctx context.Context) (context.Context, error)
	
	//Frees any resources held by this request
	Close() error
	
	//If the request encountered an error, this field will not be nil.
	Err() error 
}

//Reference implementation for handling a proxy request
//TODO - Rename to ProxyServerAgent
type ProxyRequestHandler struct {
	
	//Optional handler to modify a request before it is sent to the upstream server.
	ModifyRequest func(agent ProxyRequest) error

	//Optional handler to modify a response before it is sent to the downstream client.
	ModifyResponse func(agent ProxyRequest) error
	
	//Request received from the remote client
	downstreamRequest *http.Request

	//Response to send to the remote client
	downstreamResponse http.ResponseWriter

	//Request to send to the upstream server
	upstreamRequest *http.Request

	//Response from the upstream server
	upstreamResponse *http.Response
	
	//Transport interface used to open connections and send http requests.
	transport ProxyTransport
	
	//Return value for CanCallIssueResponse
	canCallIssueResponse bool
	
	//Error if one has been encountered
	err error
}

func NewProxyAgent(w http.ResponseWriter, r *http.Request, transport ProxyTransport) (*ProxyRequestHandler, error) {
	
	handler := &ProxyRequestHandler {
		downstreamResponse: w,
		downstreamRequest: r,
		transport: transport,
	}
	
	path := *r.URL

	if path.Host == "" {
		path.Host = r.Host
	}

	if r.Method != http.MethodConnect {
		//Only support http(s) requests.
		if r.URL.Scheme != "http" && r.URL.Scheme != "https" && r.URL.Scheme != "" {
			
			retError := &proxyRequestError {
				httpErrorCode: http.StatusBadRequest,
				internalErrorString: "Received non http URI scheme from "+r.RemoteAddr+". URI was "+r.URL.String(),
				externalErrorString: "Bad Request",
				
			}
			
			return nil, retError
		}

		if path.Scheme == "" {
			if r.TLS != nil {
				path.Scheme = "https"
			} else {
				path.Scheme = "http"
			}
		}
	}
	
	rsr, err := convertToProxyRequest(r, path.String())
	
	if err != nil {
		return nil, err
	}
	
	reqIsWebsocket := IsWebSocketRequest(r)

	//Remove headers that should not be forwarded to the remote server.
	RemoveHopByHopHeaders(&rsr.Header)

	//Add back hop-by-hop headers needed to establish a websocket connection.
	if reqIsWebsocket {
		rsr.Header.Add("Connection", "Upgrade")
		rsr.Header.Add("Upgrade", "websocket")
	}
	
	handler.upstreamRequest = rsr
	
	return handler, nil

}

func convertToProxyRequest(r *http.Request, path string) (*http.Request, error) {
	newRequest, err := http.NewRequest(r.Method, path, r.Body)
	
	if err != nil {
		return nil, err
	}
	
	for k, v := range r.Header {
		values := append([]string(nil), v...)
		newRequest.Header[k] = values
	}

	newRequest.ContentLength = r.ContentLength
	
	return newRequest, nil
}

func (handler *ProxyRequestHandler) IssueRequest(ctx context.Context) (context.Context, error) {
	ctx, done := context.WithCancel(ctx)
	
	if handler.ModifyRequest != nil {
		err := handler.ModifyRequest(handler)
		
		if err != nil {
			
			if err == ProxyHTTPTransactionHandled {
				done()
				return ctx, nil
			} else if err == AbortProxyRequest {
				err = &proxyRequestError {
					skipLogging: true,
					abortRequest: true,
					sourceError: err, 
					internalErrorString: err.Error(),
				}
			} else {
				err = &proxyRequestError{ 
					sourceError: err, 
					internalErrorString: "Something went wrong with the before request HTTP hook", 
					externalErrorString: "Internal Server Error", 
					httpErrorCode: http.StatusInternalServerError, 
				}
			}
			return nil, err
		}
	}
	
	
	if handler.upstreamRequest.Method == http.MethodConnect {
		go handler.proxyConnect(ctx, done)
	} else if IsWebSocketRequest(handler.upstreamRequest) {
		go handler.proxyWebsocket(ctx, done)
	} else {
		go handler.issueHttpRequest(ctx, done)
	}
	
	return ctx, nil
}

func (handler *ProxyRequestHandler) issueHttpRequest(ctx context.Context, done func()) {
	
	defer done()
	
	resp, err := handler.transport.RoundTrip(handler.upstreamRequest, ctx)
	if err != nil {
		handler.err = err
		return
	}
	
	//If resp is nil with no error, this means the RoundTrip handled the 
	//response and there is nothing left to do.
	if resp != nil {
		handler.upstreamResponse = resp
		handler.canCallIssueResponse = true
		
		for k, v := range resp.Header {
			values := append([]string(nil), v...)
			handler.downstreamResponse.Header()[k] = values
		}
	}
}

func (handler *ProxyRequestHandler) IssueResponse(ctx context.Context) (context.Context, error) {
	ctx, done := context.WithCancel(ctx)
	
	w := handler.downstreamResponse
	
	if !handler.canCallIssueResponse {
		return nil, &proxyRequestError{abortRequest: true, internalErrorString: "Issue response can not be called upon this kind of request or is not ready to be called"}
	}
	
	go handler.returnResponse(ctx, done)
	
	return ctx, nil
}
	
func (handler *ProxyRequestHandler) returnResponse(ctx context.Context, done func()) {
	defer done()
	handler.downstreamResponse.WriteHeader(handler.upstreamResponse.StatusCode)
	io.Copy(handler.downstreamResponse, handler.upstreamResponse.Body)
}

func (handler *ProxyRequestHandler) proxyConnect(ctx context.Context, done func()) {
	defer done()
	
	handler.proxyTCPTunnel(handler.upstreamRequest.Host, nil, true, false, ctx)
}

func (handler *ProxyRequestHandler) proxyWebsocket(ctx context.Context, done func()) {	
	done()
	
	var buf bytes.Buffer
	var tls bool = false
	rsr := handler.upstreamRequest
	
	handler.removeBodyFromRequest(rsr)

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
	
	handler.proxyTCPTunnel(host, &buf, false, tls, ctx)
}

func  (handler *ProxyRequestHandler) removeBodyFromRequest(rsr *http.Request) {
	
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
			//TODO (r0wbrt) - Add back if agents gain ability to log
			//handler.transport.LogMessage("Warning, http method " + rsr.Method + " for resource " + rsr.URL.String() + " has a body. This could cause problems with upstream servers.")
		}
	}
}

func (handler *ProxyRequestHandler) proxyTCPTunnel(remoteAddress string, preambleWriter io.Reader, writeOK bool, tlsConn bool, ctx context.Context) {

	w := handler.downstreamResponse
	hj, ok := w.(http.Hijacker)
	if !ok {
		
		handler.err = &proxyRequestError {
			httpErrorCode: http.StatusNotImplemented,
			internalErrorString:  "Could not Hijack client http connection. Hijack not supported by implementation.",
			externalErrorString: "Proxying TCP connection failed",
		}
		
		return
	}

	fromRemoteServerConn, err := handler.transport.Dial(remoteAddress, tlsConn, ctx)

	if err != nil {
		handler.err = &proxyRequestError {
			httpErrorCode: http.StatusBadGateway,
			internalErrorString:  "Cound not contact upstream server because of: " + err.Error(),
			externalErrorString: "Could not contact upstream server",
			sourceError: err,
		}
		return
	}

	defer fromRemoteServerConn.Close()

	toClientConn, _, err := hj.Hijack()

	if err != nil {
		handler.err = &proxyRequestError {
			httpErrorCode: http.StatusInternalServerError,
			internalErrorString:  "cound not hijack connection",
			externalErrorString: "Proxying TCP connection failed",
			sourceError: err,
		}
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
			handler.err = &proxyRequestError {
				internalErrorString:  "attempting to write 200 ok to the connection failed",
				sourceError: err,
				abortRequest: true,
			}
			return
		}
			
	}

	if preambleWriter != nil {
		_, err := io.Copy(fromRemoteServerConn, preambleWriter)
		if err != nil {
			handler.err = &proxyRequestError {
				internalErrorString:  "attempting to write a preamble to hijacked HTTP connection",
				sourceError: err,
				abortRequest: true,
			}
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go handler.pipeConn(toClientConn, fromRemoteServerConn, &wg)
	go handler.pipeConn(fromRemoteServerConn, toClientConn, &wg)

	go closeConnectionOnCtxDone(toClientConn, ctx)
	go closeConnectionOnCtxDone(fromRemoteServerConn, ctx)
	
	wg.Wait()
}

func (handler *ProxyRequestHandler) pipeConn(from net.Conn, to net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	_, err := io.Copy(to, from)
	if err != nil {

		//Suppress error logging from TCP connections closes
		neterr, ok := err.(net.Error)

		if !ok || !neterr.Timeout() {
			handler.err = &proxyRequestError {
				internalErrorString:  "unexpected error while piping data between two connections as part of a websocket or connect request",
				sourceError: err,
				abortRequest: true,
			}
		}
	}
}

func closeConnectionOnCtxDone(conn net.Conn,  ctx context.Context) {
	select {
		case <- ctx.Done():
	}
	
	conn.Close()
}

func (handler *ProxyRequestHandler) Close() error {
	
	if handler.upstreamResponse.Body != nil {
		handler.upstreamResponse.Body.Close()
	}
	return nil
}

func (handler *ProxyRequestHandler) Err() error {
	return handler.err
}

func (handler *ProxyRequestHandler) CanCallIssueResponse() bool {
	return handler.canCallIssueResponse
}

func (handler *ProxyRequestHandler) DownstreamRequest() *http.Request {
	return handler.downstreamRequest
}

func (handler *ProxyRequestHandler) DownstreamResponse() http.ResponseWriter {
	return handler.downstreamResponse
}
	
func (handler *ProxyRequestHandler) UpstreamRequest() *http.Request {
	return handler.upstreamRequest
}
	
func (handler *ProxyRequestHandler)	UpstreamResponse() *http.Response {
	return handler.upstreamResponse
}



