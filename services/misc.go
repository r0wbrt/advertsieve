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
	"net"
	"net/http"
	"strings"
	"time"
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

		time.Sleep(proxy.RequestRetryTimeout)

	}

}
