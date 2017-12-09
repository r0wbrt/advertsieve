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
	"localhost/rtaylor/advertsieve/httpserver"
	"net/http"
)

type RedirectServerHook struct {

	//The host to redirect incoming http requests to. If not set,
	//the redirect server automatically uses localhost:8081.
	HttpHost string

	//The host to redirect all incoming https requests to. If not set,
	//the redirect server automatically uses localhost:8082
	HttpsHost string

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
}

func (instance *RedirectServerHook) Hook(context *httpserver.ProxyChainContext) (stopProcessingChain, connHijacked bool, err error) {

	if context.RequestState != httpserver.BeforeIssueUpstreamRequest {
		return
	}

	var rsr *http.Request = context.UpstreamRequest
	var r *http.Request = context.DownstreamRequest

	connHijacked, err = PerformBasicServerProtections(context, instance.AllowConnectToLocalhost, instance.DisableLoopDetection)
	if err != nil || connHijacked {
		return
	}

	if r.Method != http.MethodConnect {

		var rewriteHost = instance.HttpHost

		if len(rewriteHost) <= 0 {
			rewriteHost = "localhost:8081"
		}

		rsr.Host = rsr.URL.Host

		rsr.URL.Host = rewriteHost
	}

	if r.Method == http.MethodConnect {

		var rewriteHost = instance.HttpsHost

		if len(rewriteHost) <= 0 {
			rewriteHost = "localhost:8082"
		}

		rsr.Host = rewriteHost
	}

	//Kill proxy specific headers
	rsr.Header.Del("Proxy-Connection")
	rsr.Header.Del("Proxy-Authorization")

	return
}
