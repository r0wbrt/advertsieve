package services

type ProxyAgentError interface {
	
	//Error string as required by the go error interface 
	Error() string
	
	//HTTP error code to send.
	ErrorCode() int
	
	//The external error message to send to the client
	ExternalErrorString() string
	
	//The error message to write to the internal log
	InternalErrorString() string
	
	//Original source of this error if there is one
	SourceError() error
	
	//If set, the request is immediately aborted.
	AbortRequest() bool
	
	//If set to true, this message should not be logged.
	SkipLogging() bool
}

type proxyRequestError struct {
	err error
	httpErrorCode int
	externalErrorString string
	internalErrorString string
	sourceError error
	abortRequest bool
	skipLogging bool
}

func (err *proxyRequestError) Error() string {
	
	if err.sourceError != nil {
		return "Proxy request error " + err.internalErrorString + " with cause by error \"" + err.sourceError.Error() +"\""
	} else {
		return "Proxy request error " + err.internalErrorString
	}
}

func (err *proxyRequestError) ErrorCode() int {
	return err.httpErrorCode
}

func (err *proxyRequestError) ExternalErrorString() string {
	return err.externalErrorString
}
	
func (err *proxyRequestError) InternalErrorString() string {
	return err.internalErrorString
}
	
func (err *proxyRequestError) SourceError() error {
	return err.sourceError
}

func (err *proxyRequestError) AbortRequest() bool {
	return err.abortRequest
}

func (err *proxyRequestError) SkipLogging() bool {
	return err.skipLogging
}
