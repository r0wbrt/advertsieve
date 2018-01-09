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
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
	"crypto/tls"
)

func DetectHTTPLoop(context *ProxyChainContext) (stopProcessingChain, connHijacked bool, err error) {

	var addresses []net.Addr
	addresses, err = net.InterfaceAddrs()

	if err != nil {
		return
	}

	if len(addresses) <= 0 {
		err = errors.New("No addresses returned from local interfaces. Is the server connected to the internet?")
		return
	}

	var localMap map[string]bool = make(map[string]bool)

	for i := 0; i < len(addresses); i++ {

		var address string = addresses[i].String()

		//Remove the cdir slash if it exists
		slashIndex := strings.Index(address, "/")
		if slashIndex != -1 {
			address = address[:slashIndex]
		}

		localMap[address] = true
	}

	var host string = context.UpstreamRequest.URL.Hostname()
	var hostIP net.IP = net.ParseIP(host)
	var IPList []net.IP

	if hostIP != nil {
		IPList = append(IPList, hostIP)
	} else {
		IPList, err = lookupIP(host, context.Proxy)
		if err != nil {
			return
		}
	}

	for i := 0; i < len(IPList); i++ {
		_, ok := localMap[IPList[i].String()]
		if ok {
			connHijacked = true
			http.Error(context.DownstreamResponse, http.StatusText(http.StatusLoopDetected), http.StatusLoopDetected)
			return
		}
	}
	return
}

func PreventConnectionsToLocalhost(context *ProxyChainContext) (stopProcessingChain, connHijacked bool, err error) {
	var host string = context.UpstreamRequest.URL.Hostname()
	var ip net.IP = net.ParseIP(host)
	var IPList []net.IP

	if ip != nil {
		IPList = append(IPList, ip)
	} else {
		IPList, err = lookupIP(host, context.Proxy)
		if err != nil {
			return
		}
	}

	//Loop over the IP's making sure none of them connects back to the local
	//link back.
	for i := 0; i < len(IPList); i++ {
		if IPList[i].IsLoopback() {
			connHijacked = true
			http.Error(context.DownstreamResponse, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}

	return
}

func lookupIP(host string, proxy *ProxyServer) (IPList []net.IP, err error) {

	var counter int = 0
	var start time.Time = time.Now()

	for {

		counter += 1

		IPList, err = net.LookupIP(host)
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

		dnsErr, ok := err.(*net.DNSError)
		if !ok {
			return
		}

		if !dnsErr.Temporary() {
			return
		}

		exponentialBackoffPause(proxy.MinRequestRetryTimeout, proxy.RetryBackoffCoefficient, counter)

	}

}

func exponentialBackoffPause(setPause time.Duration, baseDuration time.Duration, kthTry int) {

	//Algorithm based on the one used by ethernet following a collision.

	var maxNumber int64 = (1 << uint(kthTry)) - 1 // 2^c - 1
	var multiplier int64 = rand.Int63n(maxNumber)
	var waitDuration time.Duration = time.Duration(multiplier) * baseDuration

	time.Sleep(setPause + waitDuration)
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

func SecureTLSConfig() (tlsConfig *tls.Config) {

	tlsConfig = new(tls.Config)

	//Min version is TLS 1.1 since TLS 1.0 has some serious flaws.
	tlsConfig.MinVersion = tls.VersionTLS11

	return tlsConfig
}
