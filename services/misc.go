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
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
)

//DetectHTTPLoop Configuration structure. DetectHTTPLoop detects http proxy loops by
//checking and adding via headers to incoming http requests.
type DetectHTTPLoop struct {

	//Host name of the server. Should be something
	//unique.
	Hostname string

	//The next handler to run after this one assuming the
	//incoming request does not have a via header with the Hostname
	//contained in it. THe next handler will receive request with
	//the via header added to it.
	Next http.Handler
}

//Http handler for the loop detection functionality. If the validation passes,
//this function will call Next with the a Via header containing the server's hostname.
//Any subsequent handlers should make sure to include the Via header in any HTTP requests
//issued.
func (config *DetectHTTPLoop) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	viaHeader := r.Header.Get("Via")

	if strings.Contains(viaHeader, config.Hostname) {
		http.Error(w, http.StatusText(http.StatusLoopDetected), http.StatusLoopDetected)
	} else {
		if viaHeader != "" {
			viaHeader = viaHeader + ", "
		}

		viaHeader = viaHeader + "HTTP/1.1 " + config.Hostname
		r.Header.Set("Via", viaHeader)
	}

	if reflect.ValueOf(config.Next).IsValid() {
		config.Next.ServeHTTP(w, r)
	}
}

//PreventConnectionsToLocalhost that will do some basic sanity checks to prevent a remote client
//from attempting to access the server with a host field that redirects
//to localhost.
//
//Checks if host is localhost or a loopback address. Does not do a DNS
//lookup on the address because of https://github.com/r0wbrt/advertsieve/issues/21.
type PreventConnectionsToLocalhost struct {
	Next http.Handler //Next handler to run if this check passes.
}

//HTTP handler used to reject http requests that circle back to the host.
func (config *PreventConnectionsToLocalhost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var host = r.Host
	var ip = net.ParseIP(host)

	//Originally was doing a DNS lookup on all hostnames to see if they resolved
	//to localhost. Ended up deprecating this approach since it resulted in
	//extra DNS latency. We also expect the server this is set up on to be
	//set up properly and not have extra HOST entries that resolve to localhost.
	if host == "localhost" || ip != nil && ip.IsLoopback() {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if reflect.ValueOf(config.Next).IsValid() {
		config.Next.ServeHTTP(w, r)
	}

	return
}

func exponentialBackoffPause(setPause time.Duration, baseDuration time.Duration, kthTry int) {

	//Algorithm based on the one used by ethernet following a collision.

	var maxNumber int64 = (1 << uint(kthTry)) - 1 // 2^c - 1
	var multiplier = rand.Int63n(maxNumber)
	var waitDuration = time.Duration(multiplier) * baseDuration

	time.Sleep(setPause + waitDuration)
}

//RemoveBodyFromRequest removes the body from requests that should not have one. If this is not
//done, certain upstream CDN will throw an error.
func RemoveBodyFromRequest(rsr *http.Request) {

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

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

//RemoveHopByHopHeaders takes a list of headers and removes any headers
//that should not be forwarded by the proxy.
func RemoveHopByHopHeaders(header *http.Header) {
	// Remove hop-by-hop headers listed in the "Connection" header.
	// See RFC 2616, section 14.10.
	if c := header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				header.Del(f)
			}
		}
	}

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	for _, h := range hopHeaders {
		if header.Get(h) != "" {
			header.Del(h)
		}
	}
}

//SecureTLSConfig returns a TLS config with some settings modified to make it
//more secure.
func SecureTLSConfig() (tlsConfig *tls.Config) {

	tlsConfig = new(tls.Config)

	//Min version is TLS 1.1 since TLS 1.0 has some serious flaws.
	tlsConfig.MinVersion = tls.VersionTLS11

	return tlsConfig
}

//IsWebSocketRequest determines if a request is a websocket upgrade request.
func IsWebSocketRequest(r *http.Request) bool {
	upgradeType := r.Header.Get("Upgrade")

	if strings.ToLower(upgradeType) == "websocket" {
		return true
	}

	return false
}
