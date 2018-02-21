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

package contentpolicy

import (
	"github.com/r0wbrt/advertsieve/services"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

type ContentPolicyServerHook struct {
	
	//When set to true, requests with no refer are still filtered. Set this to true
	//if you want to use this server for content filtering. Eg: parental controls.
	FilterOnReferFreeRequests bool

	HostAccessControl *HostAccessControl

	//Must be compiled
	PathAccessControl *PathAccessControl
}

func (instance *ContentPolicyServerHook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	
	requestBlocked, err := instance.IsRequestBlocked(r, nil)
	
	if err != nil {
		panic(err)
	}
	
	if requestBlocked {
		PassiveAggressiveBlockRequest(w)
	}
}

func (instance *ContentPolicyServerHook) InterceptResponse(w http.ResponseWriter, resp *http.Response) error {
	
	requestBlocked, err := instance.IsRequestBlocked(resp.Request, resp)
	
	if err != nil {
		panic(err)
	}
	
	if requestBlocked {
		PassiveAggressiveBlockRequest(w)
		return services.ErrRequestHijacked
	}
	
	return nil	
}

func (instance *ContentPolicyServerHook) IsRequestBlocked(clientRequest *http.Request, remoteResponse *http.Response) (bool, error) {

	//Check if we can filter the response if no refer header is present
	filterHost, ok := GetRequestFilterHost(clientRequest, instance.FilterOnReferFreeRequests)
	if !ok {
		return false, nil
	}
	
	if instance.HostAccessControl != nil {
		var requestHost string = GetRequestHost(clientRequest)
		
		//Block the host if AllowHost returns false
		if !instance.HostAccessControl.AllowHost(requestHost) {
			return true, nil
		}
	}

	//Don't run path access control on connect. It makes no sense.
	if clientRequest.Method == http.MethodConnect {
		return false, nil
	}

	if instance.PathAccessControl != nil {

		var requestTypeBitMap int64 = SniffRequestType(clientRequest, remoteResponse)
		var isThirdParty bool = IsThirdParty(clientRequest)
		var path string = GetRequestPath(clientRequest)

		//Don't block HTML and plain text pages to match Ad Block Plus behavior
		if requestTypeBitMap&ContentTypeDoNotBlock == ContentTypeDoNotBlock {
			return
		}

		var block bool

		block, err := instance.PathAccessControl.EvaluateRequest(filterHost, path, isThirdParty, requestTypeBitMap)
		if err != nil {
			return false, err
		}

		if block {
			return true, nil
		}
	}

	return false, nil
}

func SniffRequestType(r *http.Request, resp *http.Response) int64 {

	if services.IsWebSocketRequest(r) {
		return ContentTypeWebSocket
	}

	//Many popular libraries add X-Request-With to signify an ajax request.
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return ContentTypeXMLHTTPRequest
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
		if res != ContentTypeOther {
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
		if res != ContentTypeOther {
			return res
		}
	}

	return ContentTypeOther
}

func mimeStringToType(mimeType string) int64 {

	var imagePrefix string = "image/"
	lenImagePrefix := len(imagePrefix)

	if lenImagePrefix < len(mimeType) {
		if mimeType[:lenImagePrefix] == imagePrefix {
			return ContentTypeImage
		}
	}

	switch mimeType {
	case "application/javascript":
		return ContentTypeScript
	case "text/css":
		return ContentTypeStylesheet
	case "text/html", "text/plain":
		return ContentTypeDoNotBlock
	default:
		return ContentTypeOther
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
