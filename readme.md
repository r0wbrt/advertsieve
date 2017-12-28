# Advertsieve

Advertsieve is a HTTP(S) transparent proxy for blocking unwanted content such as 
advertisements. Supports a subset of adblock filter syntax as well as a discrete 
list of domains to block. Note this software is in the early phases of development
and should be considered experimental.

## Getting Started

### Prerequisites

To get started with Advertsieve, first make sure you have go version 1.9.2 or higher. 

To fetch the source run:

```
go get -v github.com/r0wbrt/advertsieve
```

### Installing

To install run the following command after fetching the source.

```
go install github.com/r0wbrt/advertsieve
```

### Testing 

Several of the sub modules have automated tests written. To run these tests, 
navigate to the directory of the module and run 

```
go test
```

As of right now the following modules have tests and more will be written time
permitting.

```
advertsieve/contentpolicy
```

## Deployment

To run advertsieve simply call advertsieve and supply the path to the configuration file.

```
advertseive /my/path/to the configuration/file/.config
```

###Configuration options

Advertsieve configuration files have a very simple syntax. Each directive is places on its
own line. The list of command directives are below.

* **listen (http|https|proxy) "IP:Port"**  
Specifies the address and port to bind a server to.
    * First field selects which server to apply to. http is the http intercept proxy. https is the https intercept proxy. proxy is the explicit proxy. 
    * The second field argument specifies what address and port to listen on. Valid options include localhost:80, :8081, 192.168.100.20:8081.

* **httpscert "Path to key file in pem format" "Path to cert in pem format"**  
   Sets the certificate and key used to sign https responses

* **hostacl "Path to host access control file"**  
Adds a host access control file.

* **pathacl "Path to path access control file"**  
Adds a path access control file.

* **allowlocalhost (on|off)**   
Controls if the proxy can connect to localhost. This is off by default and should only be turned on with extreme care.

* **loopdetection (on|off)**  
Used to control if the proxy loop detection is active. This is on by default. Proxy resolves the host of each request and compares it to the addresses on the host. If any match, the server redirects the request. Only turn off if some other method is deployed on the proxy to prevent loop backs. 

* **staticsite "hostname" "path to content directory"**   
This runs before the localhost and loop detection checks. Serves a static website. If the host matches a full qualified name such as example.com, then this content will be served instead of the fully qualified site. 

* **staticsitecert "hostname" "key path>" "cert path"**  
Sets the certificate of a static site. By default the https cert for static sites is generated on the fly using the cert provided in httpcert. This directive can be used to override this behavior if a custom cert for a static site is desired. 

## Versioning 

Format of version numbering of this project is based on Ubuntu's versioning scheme:

```
[Year 2 digits].[Month Number 1 - 12].[Day 1 - 31].[Unstable|Preview|Production].
```

## Contributing 

Contributions must be licensed to this project under the BSD, MIT, or Apache 2.0 license.
Assignment of copyright is not needed.

## Authors

* **Robert Christian Taylor** - *Initial Work* - [r0wbrt](https://github.com/r0wbrt)

## License

All work contributed to by Robert C. Taylor is under the Apache 2.0 license. This project
also includes work developed by the go authors under the BSD license.

