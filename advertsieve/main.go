package main

import (
	"log"
	"os"
	"strings"
	"errors"
	"io"
	//"io/ioutil"
	"crypto/tls"
	"localhost/rtaylor/advertsieve"
	"localhost/rtaylor/advertsieve/config"
	"localhost/rtaylor/advertsieve/httpserver"
	"localhost/rtaylor/advertsieve/accesscontrol"
	"net/http"
	"bufio"
	"crypto/x509"
)

type VirtualHost struct {
	Host      string
	KeyPath   string
	CertPath  string
	Directory string
}

type AdvertSieveConfig struct {
	HttpsServerAddresses        []string
	HttpServerAddresses         []string
	RedirectServerAddresses     []string
	CertificatePath             string
	PrivateKeyPath              string
	HostsAclFiles               []string
	PathAclFiles                []string
	AllowConnectionsToLocalhost bool
	DisableHttpLoopDetection    bool
	VirtualHosts                map[string]VirtualHost
	Err 						error
	TlsCertGen *httpserver.TLSCertGen
	TlsCertDatabase *httpserver.InMemoryCertDatabase
}

func main() {

	log.Printf("Starting %s version %s %s.", CONST_BRAND_NAME, CONST_VERSION, CONST_BUILD_TYPE)

	//Show arguments passed into this server. However, only show them if 
	//there are actually arguments passed in.
	var argString string = ""
	if len(os.Args) > 1 {
		for i := 0; i < len(os.Args[1:]); i++ {
			argString = argString + "\"" + os.Args[i+1] + "\" "
		}

		log.Printf("Program %s started with arguments: %s", CONST_BRAND_NAME, argString)
	}

	//Accept a single command line option, the path to the configuration file
	var config_path string = CONST_CONFIG_FILE_PATH
	if len(os.Args) > 1 {
		config_path = strings.Join(os.Args[1:], " ")
	}
	log.Printf("Using configuration file: %s", config_path)

	//First load the configuration
	var configuration *AdvertSieveConfig
	configuration = LoadConfiguration(config_path)
	
	if configuration.Err == nil {
		if len(configuration.HttpServerAddresses) <= 0 && len(configuration.HttpsServerAddresses) <= 0 {
			configuration.Err = errors.New("No addresses specified for this server to listen on")
		}
	}
	
	//Next load the host based access control files
	var hostAcl *accesscontrol.HostAccessControl = accesscontrol.NewHostAccessControl()
	configuration.LoadHostAcl(hostAcl)
	
	//Load the path acl
	var pathAcl *accesscontrol.PathAccessControl = accesscontrol.NewPathAccessControl()
	configuration.LoadPathAcl(pathAcl)

	var proxyServer *httpserver.ProxyServer = httpserver.NewProxyServer()
	proxyServer.AllowConnect = false
	
	//Pre access hook does host based filtering. We want this to run in
	//the pre-issue upstream hook since the only information this needs
	//is the host name.
	var preAccessControlHook advertsieve.AccessControlServerHook
	preAccessControlHook.AllowConnectToLocalhost = configuration.AllowConnectionsToLocalhost
	preAccessControlHook.DisableLoopDetection = configuration.DisableHttpLoopDetection
	preAccessControlHook.HostAccessControl = hostAcl
	proxyServer.AddHook(configuration.VhostHook, httpserver.BeforeIssueUpstreamRequest)
	proxyServer.AddHook(preAccessControlHook.Hook, httpserver.BeforeIssueUpstreamRequest)
	
	
	//Post access hook does path based and type based filtering. Want this 
	//to run post issue request since then we will have access to the remote
	//server http replay which is full of useful information like the type
	//of resource this request was for.
	var postAccessControlHook advertsieve.AccessControlServerHook
	postAccessControlHook.PathAccessControl = pathAcl
	proxyServer.AddHook(postAccessControlHook.Hook, httpserver.BeforeIssueDownstreamResponse)
	
	if len(configuration.HttpsServerAddresses) > 0 {
		var tlsConfig *tls.Config = configuration.LoadTlsSettings()
		configuration.SpawnHttpsListeners(proxyServer, tlsConfig)
	}
	configuration.SpawnHttpListeners(proxyServer)
	
	
	//Configuration object stores the first error. Any subsequent calls 
	//to a configuration function does nothing. This means this err object
	//will have the first error the system encountered.
	if configuration.Err != nil {
		log.Fatal(configuration.Err)
	}
	
	log.Print("%s is fully operational.", CONST_BRAND_NAME)
	
	//Block forever
	select{}

	return
}

func (configuration *AdvertSieveConfig) VhostHook(context *httpserver.ProxyChainContext) (stopProcessingChain, connHijacked bool, err error) {
	
	vhost, ok := configuration.VirtualHosts[context.UpstreamRequest.URL.Hostname()]
	if !ok {
		return
	} 
	
	http.FileServer(http.Dir(vhost.Directory)).ServeHTTP(context.DownstreamResponse, context.DownstreamRequest)
	
	connHijacked = true
	stopProcessingChain = true
	
	return
}

func GetStandardHttpServerConfig() *http.Server {
	return new(http.Server)
}

func (configuration *AdvertSieveConfig) GenServerCertificate(hello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	return configuration.TlsCertDatabase.GetCert(hello.ServerName)
}

func (configuration *AdvertSieveConfig) InErrorState() bool {
	return configuration.Err != nil
}

func (configuration *AdvertSieveConfig) SetUpServerCertGen() {
	
	if configuration.InErrorState() {
		return
	}
	
	configuration.TlsCertGen = new(httpserver.TLSCertGen)
	
	cert, err := tls.LoadX509KeyPair(configuration.CertificatePath, configuration.PrivateKeyPath)
	if err != nil {
		configuration.Err = err
		return
	}
	
	caCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		configuration.Err = err
		return
	}
	
	configuration.TlsCertGen.RootAuthorityPrivateKey = cert.PrivateKey
	configuration.TlsCertGen.RootAuthorityCert = caCert
	configuration.TlsCertGen.OrganizationPrefix = CONST_CERT_ORG_PREFIX
	
	configuration.TlsCertDatabase = httpserver.NewInMemoryCertDatabase(configuration.TlsCertGen.GenerateCertificate)
	
	return
}

func (configuration *AdvertSieveConfig) LoadTlsSettings() (tlsConfig *tls.Config) {
	
	if configuration.InErrorState() {
		return
	}
	
	tlsConfig = new(tls.Config)
	
	configuration.SetUpServerCertGen()
	
	tlsConfig.NameToCertificate = configuration.GetVHostCerts()
	tlsConfig.GetCertificate = configuration.GenServerCertificate
	
	if CONST_ENABLE_KEY_DUMP {
		if CONST_IS_PRODUCTION {
			log.Fatal("TLS key data can not be logged in production mode.")
		}
		tlsConfig.KeyLogWriter = LogKeys()
		log.Printf("WARNING! TLS security is compromised. Key data is being logged to file [%s].", CONST_KEY_DUMP_FILE)
	}
	
	//Min version is TLS 1.1 since TLS 1.0 has some serious flaws.
	tlsConfig.MinVersion = tls.VersionTLS11
	
	//Only support secure ciphers
	tlsConfig.CipherSuites = []uint16 {
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}
	
	return tlsConfig
}

func (configuration *AdvertSieveConfig) GetVHostCerts() map[string]*tls.Certificate {
	
	if configuration.InErrorState() {
		return nil
	}
	
	var certMap map[string]*tls.Certificate = make(map[string]*tls.Certificate)
	
	for k, v := range configuration.VirtualHosts {
		cert, err := tls.LoadX509KeyPair(v.CertPath, v.KeyPath)
		
		if err != nil {
			configuration.Err = err
			return nil
		}
		
		certMap[k] = &cert
	}
	
	return certMap
}

func LogKeys() io.Writer {
	file, err := os.Open(CONST_KEY_DUMP_FILE)
	if err != nil {
		log.Fatal(err)
	}
	
	return file
}

func (configuration *AdvertSieveConfig) LoadHostAcl(hostAcl *accesscontrol.HostAccessControl) {
	
	if configuration.InErrorState() {
		return
	}
	
	for i := 0; i < len(configuration.HostsAclFiles); i++ {
		file, err := os.Open(configuration.HostsAclFiles[i])
		if err != nil {
			configuration.Err = err
			return
		}
		
		defer file.Close()
		
		scanner := bufio.NewScanner(file)
		
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			
			if len(line) <= 0 {
				continue
			}
			
			var filterIsExclude bool = (line[0] == '@')
			
			if filterIsExclude {
				line = line[1:]
			}
			
			if len(line) <= 0 {
				configuration.Err = errors.New("Invalid entry in Host File: " + configuration.HostsAclFiles[i])
				return
			}
			
			if filterIsExclude {
				hostAcl.AddException(line)
			} else {
				hostAcl.AddBlockedHost(line)
			}
		}
	}
}

func (configuration *AdvertSieveConfig) LoadPathAcl(pathAcl *accesscontrol.PathAccessControl) {
	
	if configuration.InErrorState() {
		return
	}
	
	for i := 0; i < len(configuration.PathAclFiles); i++ {
		file, err := os.Open(configuration.PathAclFiles[i])
		if err != nil {
			configuration.Err = err
			return
		}
		
		defer file.Close()
		
		scanner := bufio.NewScanner(file)
		
		for scanner.Scan() {
			err = pathAcl.AddFilter(scanner.Text())
			if err != nil {
				configuration.Err = err
				return
			}
		}
		
		if err = scanner.Err(); err != nil {
			configuration.Err = err
			return
		}
	}
	
	pathAcl.Compile()
	
}

func (configuration *AdvertSieveConfig) SpawnHttpListeners(proxyServer *httpserver.ProxyServer) {
	
	if configuration.InErrorState() {
		return
	}
	
	for i := 0; i < len(configuration.HttpServerAddresses); i++ {
		var server *http.Server = GetStandardHttpServerConfig()
		server.Handler = proxyServer
		server.Addr = configuration.HttpServerAddresses[i]
		go log.Fatal(server.ListenAndServe())
	}
}

func (configuration *AdvertSieveConfig) SpawnHttpsListeners(proxyServer *httpserver.ProxyServer, tlsConfig *tls.Config) {
	
	if configuration.InErrorState() {
		return
	}
	
	for i := 0; i < len(configuration.HttpsServerAddresses); i++ {
		var server *http.Server = GetStandardHttpServerConfig()
		server.TLSConfig = tlsConfig
		server.Handler = proxyServer
		server.Addr = configuration.HttpsServerAddresses[i]
		go log.Fatal(server.ListenAndServeTLS("",""))
	}
}

func LoadConfiguration(path string) (configuration *AdvertSieveConfig) {
	
	var grammar *config.Grammar = config.GetProxyGrammar()
	var configVals map[string]interface{}
	configuration = new(AdvertSieveConfig)
	configuration.VirtualHosts = make(map[string]VirtualHost)
	
	file, err := os.Open(path)
	if err != nil {
		configuration.Err = err
		return
	}

	configVals, err = grammar.Parse(file)
	if err != nil {
		configuration.Err = err
		return
	}

	for k, v := range configVals {

		configResults, ok := v.(*config.SyntaxStatement)

		if !ok {
			continue
		}

		for i := 0; i < len(configResults.ParsedResult); i++ {

			vals := configResults.ParsedResult[i]

			switch k {
			case config.ListenStatement.Name:
				var serverType int = vals[0].(int)

				switch serverType {
				case config.ServerTypeHttp:
					configuration.HttpServerAddresses = append(configuration.HttpServerAddresses, string(vals[1].([]rune)))
				case config.ServerTypeHttps:
					configuration.HttpsServerAddresses = append(configuration.HttpsServerAddresses, string(vals[1].([]rune)))
				default:
					continue
				}

			case config.HttpsCertStatement.Name:
				configuration.CertificatePath = string(vals[0].([]rune))
				configuration.PrivateKeyPath = string(vals[1].([]rune))

			case config.HostACLStatement.Name:
				configuration.HostsAclFiles = append(configuration.HostsAclFiles, string(vals[0].([]rune)))

			case config.PathACLStatement.Name:
				configuration.PathAclFiles = append(configuration.PathAclFiles, string(vals[0].([]rune)))

			case config.AllowLocalhostStatement.Name:
				configuration.AllowConnectionsToLocalhost = vals[0].(bool)

			case config.LoopDetectionStatement.Name:
				configuration.DisableHttpLoopDetection = !vals[0].(bool)

			case config.StaticSiteStatement.Name:

				var site string = string(vals[0].([]rune))
				var directory string = string(vals[1].([]rune))
				var virtualHost VirtualHost

				virtualHost, _ = configuration.VirtualHosts[site]

				virtualHost.Host = site
				virtualHost.Directory = directory

				configuration.VirtualHosts[site] = virtualHost

			case config.StaticSiteHttpsCert.Name:

				var site string = string(vals[0].([]rune))
				var cert string = string(vals[1].([]rune))
				var key string = string(vals[2].([]rune))

				var virtualHost VirtualHost

				virtualHost, _ = configuration.VirtualHosts[site]

				virtualHost.Host = site
				virtualHost.CertPath = cert
				virtualHost.KeyPath = key

				configuration.VirtualHosts[site] = virtualHost

			default:
				//Ignore unrecognized values
				continue
			}
		}
	}
	
	return
}
