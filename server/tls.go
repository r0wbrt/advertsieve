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
	"crypto/x509"
	"github.com/r0wbrt/advertsieve/tlsutils"
)

func SetupTlsCertGen(certPath string, keyPath string) (*tlsutils.InMemoryCertDatabase, error) {

	tlsCertGen := new(tlsutils.TLSCertGen)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	tlsCertGen.RootAuthorityPrivateKey = cert.PrivateKey
	tlsCertGen.RootAuthorityCert = caCert
	tlsCertGen.OrganizationPrefix = ""

	tlsCertDatabase := tlsutils.NewInMemoryCertDatabase(tlsCertGen.GenerateCertificate)

	return tlsCertDatabase, nil
}

func SecureTLSConfig() (tlsConfig *tls.Config) {

	tlsConfig = new(tls.Config)

	//Min version is TLS 1.1 since TLS 1.0 has some serious flaws.
	tlsConfig.MinVersion = tls.VersionTLS11

	//Only support secure ciphers
	tlsConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}

	return tlsConfig
}
