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
 *  limitations under the License.
 */

package advertsieve

import (
	"localhost/rtaylor/advertsieve/accesscontrol"
	"localhost/rtaylor/advertsieve/httpserver"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type AccessControlServerHook struct {
	//When set to true, connections to localhost are permitted. Note,
	//this will generate additional DNS traffic as hosts will need to be
	//resolved to determine if they map to local host.
	//
	//This should only be set to true if you know what you are doing. Setting
	//this to true has the potential to expose services on the server that
	//expected only local programs to be able to connect to them.
	AllowConnectToLocalhost bool

	//When set to true, loop detection is turned off exposing this server
	//to resource exhaustion attacks. Only set this to true if you know what
	//you are doing.
	DisableLoopDetection bool

	//When set to true, requests with no refer are still filtered. Set this to true
	//if you want to use this server for content filtering. Eg: parental controls.
	FilterOnReferFreeRequests bool

	HostAccessControl *accesscontrol.HostAccessControl

	//Must be compiled
	PathAccessControl *accesscontrol.PathAccessControl

	//RW mutex to control access to this structure
	Mutex sync.RWMutex
}

func (instance *AccessControlServerHook) Hook(context *httpserver.ProxyChainContext) (stopProcessingChain, connHijacked bool, err error) {

	instance.Mutex.RLock()
	defer instance.Mutex.RUnlock()

	var rsr *http.Request = context.UpstreamRequest
	var w http.ResponseWriter = context.DownstreamResponse

	if context.RequestState == httpserver.BeforeIssueUpstreamRequest {
		connHijacked, err = PerformBasicServerProtections(context, instance.AllowConnectToLocalhost, instance.DisableLoopDetection)
		if err != nil || connHijacked {
			return
		}
	}

	if instance.HostAccessControl != nil {
		var requestHost string = GetRequestHost(rsr)
		if !instance.HostAccessControl.AllowHost(requestHost) {
			PassiveAggressiveBlockRequest(w)
			connHijacked = true
			return
		}
	}

	//Don't run path access control on connect. It makes no sense.
	if rsr.Method == http.MethodConnect {
		return
	}

	if instance.PathAccessControl != nil {
		var filterHost string
		var ok bool

		filterHost, ok = GetRequestFilterHost(rsr, instance.FilterOnReferFreeRequests)
		if !ok {
			return
		}

		var requestTypeBitMap int64 = SniffRequestType(rsr, context.UpstreamResponse)
		var isThirdParty bool = IsThirdParty(rsr)
		var path string = GetRequestPath(rsr)
		var block bool

		block, err = instance.PathAccessControl.EvaluateRequest(filterHost, path, isThirdParty, requestTypeBitMap)
		if err != nil {
			return
		}

		if block {
			PassiveAggressiveBlockRequest(w)
			connHijacked = true
			return
		}
	}

	return
}

func SniffRequestType(r *http.Request, resp *http.Response) int64 {

	if httpserver.IsWebSocketRequest(r) {
		return accesscontrol.ContentTypeWebSocket
	}

	//Many popular libraries add X-Request-With to signify an ajax request.
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return accesscontrol.ContentTypeXMLHTTPRequest
	}

	//If we have an http response, the server should have sent us a Content-Type
	//field. So we can use that to figure out what type of content this
	//request is.
	if resp != nil {
		var contentTypeField string = resp.Header.Get("Content-Type")
		mimeType := extractMimeType(contentTypeField)

		if len(mimeType) > 0 {
			return mimeStringToType(mimeType)
		}
	}

	//The browser will also send an accept header, though many times this is
	//will be useless as many popular browsers send */* for a variety
	//of different request types.
	var acceptHeader string = r.Header.Get("Accept")

	if len(acceptHeader) > 0 {

		var res int64 = sniffAcceptHeader(acceptHeader)
		if res != accesscontrol.ContentTypeOther {
			return res
		}
	}

	//Lastly, if we did not find anything using the methods above, use a
	//crude method of trying to determine what this content type is based
	//on the extension at the end of the path.
	return mimeStringToType(mime.TypeByExtension(r.URL.Path))
}

func extractMimeType(field string) string {
	field = strings.TrimSpace(field)
	var mimeType string = ""

	if len(field) > 0 {

		//application/json;q=0.5,

		mimeSemiColonIndex := strings.Index(field, ";")

		if mimeSemiColonIndex != -1 {
			mimeType = field[:mimeSemiColonIndex]
		} else {
			mimeType = field
		}
	}

	return mimeType
}

func sniffAcceptHeader(s string) int64 {

	// Accept: audio/*; q=0.2, audio/basic

	pieces := strings.Split(s, ",")

	for i := 0; i < len(pieces); i++ {
		var mimeType string = extractMimeType(pieces[i])
		res := mimeStringToType(mimeType)
		if res != accesscontrol.ContentTypeOther {
			return res
		}
	}

	return accesscontrol.ContentTypeOther
}

func mimeStringToType(mimeType string) int64 {

	var imagePrefix string = "image/"
	lenImagePrefix := len(imagePrefix)

	if lenImagePrefix < len(mimeType) {
		if mimeType[:lenImagePrefix] == imagePrefix {
			return accesscontrol.ContentTypeImage
		}
	}

	switch mimeType {
	case "application/javascript":
		return accesscontrol.ContentTypeScript
	case "text/css":
		return accesscontrol.ContentTypeStylesheet
	default:
		return accesscontrol.ContentTypeOther
	}
}

func PassiveAggressiveBlockRequest(w http.ResponseWriter) {

	for k := range w.Header() {
		w.Header().Del(k)
	}
	
	//Do not ask again for 7 days.
	w.Header().Set("Cache-Control", "604800")
	w.WriteHeader(http.StatusNoContent)
}

func GetRequestHost(r *http.Request) string {
	return r.URL.Hostname()
}

func GetRequestPath(r *http.Request) string {
	var path string = r.URL.String()

	index := strings.Index(path, "//")

	if index != -1 && index+2 <= len(path) {
		path = path[index+2:]
	}

	return path

}

func IsThirdParty(r *http.Request) bool {

	var refer string = r.Referer()

	if len(refer) <= 0 {
		return false
	}

	var referUrl *url.URL
	var err error

	referUrl, err = url.Parse(refer)
	if err != nil {
		return false
	}

	var referHost, requestHost string

	referHost = referUrl.Hostname()
	requestHost = r.URL.Hostname()

	return !IsSubdomain(referHost, requestHost)

}

func IsSubdomain(base, sub string) bool {
	if len(sub) < len(base) {
		return false
	}

	var basepieces []string
	var subpieces []string

	//TODO - Consider using a more efficient method
	//then split.
	basepieces = strings.Split(base, ".")
	subpieces = strings.Split(sub, ".")

	if len(basepieces) > len(subpieces) {
		return false
	}

	for i := 0; i < len(basepieces); i++ {
		if basepieces[i] != subpieces[i] {
			return false
		}
	}

	return true
}

func PerformBasicServerProtections(context *httpserver.ProxyChainContext, allowConnectToLocalhost bool, disableLoopDetection bool) (connHijacked bool, err error) {

	var handlers []httpserver.ProxyHook

	if !allowConnectToLocalhost {
		handlers = append(handlers, accesscontrol.PreventConnectionsToLocalhost)
	}

	if !disableLoopDetection {
		handlers = append(handlers, httpserver.DetectHTTPLoop)
	}

	connHijacked, err = httpserver.RunHandlerChain(handlers, context)

	return
}

func GetRequestFilterHost(r *http.Request, returnRequestHostIfNoReferHeader bool) (host string, ok bool) {
	var referer string = r.Referer()

	if len(referer) > 0 {
		var URL *url.URL
		var err error

		URL, err = url.Parse(referer)

		if err != nil && !returnRequestHostIfNoReferHeader {
			return
		}

		host = URL.Hostname()

		if len(host) <= 0 && !returnRequestHostIfNoReferHeader {
			return
		}

		ok = true
	}

	if returnRequestHostIfNoReferHeader && !ok {
		host = r.URL.Hostname()
		ok = true
	}

	return
}
