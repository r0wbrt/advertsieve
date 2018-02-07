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

package server

import (
	"crypto/tls"
	"errors"
	"github.com/r0wbrt/advertsieve/config"
	"github.com/r0wbrt/advertsieve/contentpolicy"
	"github.com/r0wbrt/advertsieve/services"
	"github.com/r0wbrt/advertsieve/tlsutils"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

type AdvertsieveServer struct {
	Config *AdvertSieveConfig

	Logger *log.Logger

	endServer    chan interface{}
	chanClosed   bool
	mutex        sync.Mutex
	certDatabase *tlsutils.InMemoryCertDatabase
}

type errorMonad struct {
	err    error
	server *AdvertsieveServer
}

func (monad *errorMonad) inErrorState() bool {
	return monad.err != nil
}

func (monad *errorMonad) loadContentPolicy() (postAccessControlHook *contentpolicy.ContentPolicyServerHook) {

	if monad.inErrorState() {
		return nil
	}

	var hostAcl *contentpolicy.HostAccessControl = contentpolicy.NewHostAccessControl()

	for i := 0; i < len(monad.server.Config.HostsAclFiles); i++ {
		err := ReadInHostAclFile(monad.server.Config.HostsAclFiles[i], hostAcl)
		if err != nil {
			monad.err = err
			return nil
		}
	}

	var pathAcl *contentpolicy.PathAccessControl = contentpolicy.NewPathAccessControl()

	for i := 0; i < len(monad.server.Config.PathAclFiles); i++ {
		err := ReadInPathACLFile(monad.server.Config.PathAclFiles[i], pathAcl)
		if err != nil {
			monad.err = err
			return nil
		}
	}

	pathAcl.Compile()

	postAccessControlHook = new(contentpolicy.ContentPolicyServerHook)
	postAccessControlHook.HostAccessControl = hostAcl
	postAccessControlHook.PathAccessControl = pathAcl

	return postAccessControlHook
}

/*func (monad *errorMonad) setupProxyServer() *services.ProxyServer {

	if monad.inErrorState() {
		return nil
	}

	var proxyServer *services.ProxyServer = services.NewProxyServer()
	proxyServer.AllowWebsocket = true
	proxyServer.MsgLogger = monad.server.getLogger()

	var beforeIssueUpstreamRequest func(context services.ProxyRequest) error = nil

	preAccessControlHook, postAccessControlHook := monad.loadContentPolicy()

	//Need to guard against a null ref exception
	if monad.inErrorState() {
		return nil
	}

	preAccessControlHook.Next = beforeIssueUpstreamRequest
	beforeIssueUpstreamRequest = preAccessControlHook.Hook

	if !monad.server.Config.DisableHttpLoopDetection {

		if len(monad.server.Config.ServerName) <= 0 {
			monad.err = errors.New("Must defined advertsieve server name using directive " + config.ServerHostnameStatement.Name + " when loop detection is active.")
			return nil
		}

		loopDetecter := services.DetectHTTPLoop{Hostname: monad.server.Config.ServerName, Next: beforeIssueUpstreamRequest}
		beforeIssueUpstreamRequest = loopDetecter.Hook
	}

	if !monad.server.Config.AllowConnectionsToLocalhost {
		hook := services.PreventConnectionsToLocalhost { Next: beforeIssueUpstreamRequest}
		beforeIssueUpstreamRequest = hook.Hook
	}

	proxyServer.GetProxyRequestAgent = services.NewProxyAgentWithHandlers(beforeIssueUpstreamRequest, postAccessControlHook.Hook)

	return proxyServer
}*/

func (monad *errorMonad) setupProxyServer() *services.ProxyServer {

	if monad.inErrorState() {
		return nil
	}

	proxyHandler := services.NewProxyServer()
	accessControlHook := monad.loadContentPolicy()

	//Need to guard against a null ref exception
	if monad.inErrorState() {
		return nil
	}

	proxyHandler.InterceptResponse = accessControlHook.InterceptResponse

	return proxyHandler
}

func (monad *errorMonad) setupServerGuards(handle http.Handler) http.Handler {

	if monad.inErrorState() {
		return nil
	}

	if !monad.server.Config.DisableHttpLoopDetection {

		if len(monad.server.Config.ServerName) <= 0 {
			monad.err = errors.New("Must defined advertsieve server name using directive " + config.ServerHostnameStatement.Name + " when loop detection is active.")
			return nil
		}

		loopDetecter := services.DetectHTTPLoop{Hostname: monad.server.Config.ServerName, Next: handle}
		handle = &loopDetecter
	}

	if !monad.server.Config.AllowConnectionsToLocalhost {
		hook := services.PreventConnectionsToLocalhost{Next: handle}
		handle = &hook
	}

	return handle
}

func (monad *errorMonad) setupVHost(proxyServer http.Handler) *services.VirtualHostFileServer {

	if monad.inErrorState() {
		return nil
	}

	var vhost *services.VirtualHostFileServer = new(services.VirtualHostFileServer)
	vhost.VHosts = make(map[string]*services.VirtualHost)
	vhost.Handler = proxyServer

	for k, v := range monad.server.Config.VirtualHosts {
		def := services.VirtualHost{Host: k, Root: v.Directory}
		vhost.VHosts[k] = &def
	}

	return vhost
}

func (monad *errorMonad) setupBridgeServer(vhostServer *services.VirtualHostFileServer) *services.ConnectLoopBackBridge {

	if monad.inErrorState() {
		return nil
	}

	//Start direct proxy server
	var bridge *services.ConnectLoopBackBridge = services.NewConnectLoopBackBridge(vhostServer, "127.0.0.1") //Set address to localhost
	bridge.Logger = monad.server.getLogger()

	if len(monad.server.Config.ConnectAccessControl) > 0 {
		bridge.PortMapper = monad.server.Config.mapPort
	}

	return bridge
}

func (monad *errorMonad) getVHostCerts() map[string]*tls.Certificate {

	if monad.inErrorState() {
		return nil
	}

	var certMap map[string]*tls.Certificate = make(map[string]*tls.Certificate)

	for k, v := range monad.server.Config.VirtualHosts {

		if !v.HasCustomCert {
			continue
		}

		cert, err := tls.LoadX509KeyPair(v.CertPath, v.KeyPath)

		if err != nil {
			monad.err = err
			return nil
		}

		certMap[k] = &cert
	}

	return certMap
}

func (monad *errorMonad) setupHttpServers(mainHandle http.Handler, auxHandler http.Handler) (*http.Server, *http.Server) {

	if monad.inErrorState() {
		return nil, nil
	}

	tlsConfig := services.SecureTLSConfig()

	config := monad.server.Config
	if config.CertificatePath != "" && config.PrivateKeyPath != "" {

		database, err := SetupTlsCertGen(monad.server.Config.CertificatePath, monad.server.Config.PrivateKeyPath)
		if err != nil {
			monad.err = err
			return nil, nil
		}

		monad.server.certDatabase = database

		tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
			return monad.server.certDatabase.GetCert(hello.ServerName)
		}
	}

	tlsConfig.NameToCertificate = monad.getVHostCerts()

	var auxServer *http.Server = new(http.Server)
	auxServer.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	auxServer.Handler = auxHandler
	auxServer.ErrorLog = monad.server.getLogger()
	auxServer.TLSConfig = tlsConfig

	var mainServer *http.Server = new(http.Server)
	mainServer.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	mainServer.Handler = mainHandle
	mainServer.ErrorLog = monad.server.getLogger()
	mainServer.TLSConfig = tlsConfig

	return mainServer, auxServer
}

func (monad *errorMonad) spawnServers(mainServer, auxServer *http.Server) {

	if monad.inErrorState() {
		return
	}

	configuration := monad.server.Config

	for i := 0; i < len(configuration.ServerInstances); i++ {

		if monad.inErrorState() {
			return
		}

		var addr *net.TCPAddr
		var err error
		addr, err = net.ResolveTCPAddr("tcp", configuration.ServerInstances[i].Address)

		if err != nil {
			monad.err = err
			return
		}

		var l *net.TCPListener

		l, err = net.ListenTCP("tcp", addr)

		if err != nil {
			monad.err = err
			return
		}

		var httpServer *http.Server
		var tls bool

		switch configuration.ServerInstances[i].Type {
		case config.ServerTypeHttp:
			httpServer = auxServer
		case config.ServerTypeHttps:
			httpServer = auxServer
			tls = true
		}

		if tls && monad.server.certDatabase == nil {
			monad.err = errors.New("A master and private key must be supplied to use https proxy functions.")
			return
		}

		go monad.httpServerGo(httpServer, l, tls)
	}

	return
}

func (monad *errorMonad) httpServerGo(httpServer *http.Server, l net.Listener, tls bool) {

	var err error

	if tls {
		err = httpServer.ServeTLS(l, "", "")
	} else {
		err = httpServer.Serve(l)
	}
	monad.err = err
	monad.server.Close()

}

func (server *AdvertsieveServer) getLogger() *log.Logger {
	return server.Logger
}

func (server *AdvertsieveServer) ListenAndServe() error {

	var monad errorMonad = errorMonad{err: nil, server: server}

	server.endServer = make(chan interface{})
	server.chanClosed = false

	if server.Logger == nil {
		server.Logger = log.New(os.Stderr, "", log.Lmicroseconds|log.Ldate)
	}

	if server.Config == nil {
		panic("Server.Config can not be nil") //Panic because this is not a normal runtime condition
	}

	proxyHandler := monad.setupProxyServer()

	proxyWrapper := monad.setupServerGuards(proxyHandler)

	vhostHandler := monad.setupVHost(proxyWrapper)

	bridgeHandler := monad.setupBridgeServer(vhostHandler)

	httpMainServer, httpBridgeServer := monad.setupHttpServers(vhostHandler, bridgeHandler)

	monad.spawnServers(httpMainServer, httpBridgeServer)

	//Setup loop server if cert database is popuplated
	if !monad.inErrorState() {

		if monad.server.certDatabase != nil {
			go monad.httpServerGo(httpMainServer, bridgeHandler, true)
		}

		go monad.httpServerGo(httpMainServer, bridgeHandler.GetHTTPListener(), false)

		select {
		case <-server.endServer:
			if monad.err == nil {
				monad.err = errors.New("Advertsieve server had method Close called.")
			}
		}
	}

	if httpMainServer != nil {
		httpMainServer.Close()
	}

	if httpBridgeServer != nil {
		httpBridgeServer.Close()
	}

	if proxyHandler != nil {
		proxyHandler.Close()
	}

	return monad.err
}

func (server *AdvertsieveServer) Close() {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	if !server.chanClosed {
		server.chanClosed = true
		close(server.endServer)
	}
}
