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

package accesscontrol

import (
	"localhost/rtaylor/advertsieve/httpserver"
	"net"
	"net/http"
	"strings"
	"sync"
)

//Host filter provides functionality to fitler out certain hosts. The behavior
//of hosts filter is based of the behavior of the AdBlockPlus $domain modifier.
//When a host is added to the block list, it and its sub domains are blocked.
//However, a specific sub domain can be unblocked by adding it as an
//exception. Exceptions only apply to the exact host
//added to the list. The exception does not apply to its sub domains.
//
//Host must be formatted as valid domain names or a valid ip address. Host
//entries should not include a port number or ipv6 square brackets.
//
//Note, unless otherwise indicated, the functionality of HostAccessControl is thread
//safe.
type HostAccessControl struct {
	blockMap     map[string]bool
	exceptionMap map[string]bool

	mutex sync.RWMutex
}

//Creates a new host filter.
func NewHostAccessControl() *HostAccessControl {
	hostAC := new(HostAccessControl)

	hostAC.blockMap = make(map[string]bool)
	hostAC.exceptionMap = make(map[string]bool)

	return hostAC
}

//Adds a new host to the block list.
func (hostAC *HostAccessControl) AddBlockedHost(host string) {
	hostAC.mutex.Lock()
	defer hostAC.mutex.Unlock()

	hostAC.blockMap[host] = true
}

//Adds a host as an exception to the block list. Note, a corresponding block
//rule that this would exist as an exception to need not exist.
func (hostAC *HostAccessControl) AddException(host string) {
	hostAC.mutex.Lock()
	defer hostAC.mutex.Unlock()
	hostAC.exceptionMap[host] = true
}

//This function will check to see if the supplied host is allowed. The host must
//be formatted as a domain name or an IP address. The host string must not
//include the port number. Doing so will result in undefined behavior. IPv6
//addresses should be formatted as a valid IPv6 address. It should not be
//enclosed inside of square brackets.
func (hostAC *HostAccessControl) AllowHost(host string) bool {

	//If the host string is less then or equal to zero,
	//it is unsupported by this framework. So let it pass.
	if len(host) <= 0 {
		return true
	}

	hostAC.mutex.RLock()
	defer hostAC.mutex.RUnlock()

	if hostAC.checkHostStatus(host) == -1 {
		return false
	} else {
		return true
	}
}

func (hostAC *HostAccessControl) checkHostStatus(host string) int {

	//Predictably test if an exception exists first since if one
	//does, why check if a block rule exists?
	_, ok := hostAC.exceptionMap[host]
	if ok {
		return 1
	}

	//Handle IP branch
	ip := net.ParseIP(host)
	if ip != nil {
		_, ok = hostAC.blockMap[host]
		if ok {
			return -1
		} else {
			return 0
		}
	} else {

		//This part of the function check each part of the domain to see if a block
		//rule exists. Basically if the supplied host is www.example.com it does a
		//check for www.example.com, example.com, com.
		var dotIndex int = -1
		var subHost = host

		for {

			subHost = subHost[dotIndex+1:]
			_, ok = hostAC.blockMap[subHost]
			if ok {
				return -1
			}

			//Find the next dot in the host.
			dotIndex = strings.Index(subHost, ".")

			if dotIndex == -1 || dotIndex+1 > len(subHost) {
				break
			}
		}

		return 0
	}
}

func PreventConnectionsToLocalhost(context *httpserver.ProxyChainContext) (stopProcessingChain, connHijacked bool, err error) {
	var host string = context.UpstreamRequest.URL.Hostname()
	var ip net.IP = net.ParseIP(host)
	var IPList []net.IP

	if ip != nil {
		IPList = append(IPList, ip)
	} else {
		IPList, err = net.LookupIP(host)
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
