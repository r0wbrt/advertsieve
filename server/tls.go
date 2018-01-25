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
	"crypto/rand"
	"crypto/rsa"
)

func SetupTlsCertGenDatabase(certPath string, keyPath string, enableTurboTls bool) (*tlsutils.InMemoryCertDatabase, error) {
	
	tlsCertGen, err := SetupTlsCertGen(certPath, keyPath, enableTurboTls)
	
	if err != nil {
		return nil, err
	}

	tlsCertDatabase := tlsutils.NewInMemoryCertDatabase(tlsCertGen.GenerateCertificate)

	return tlsCertDatabase, nil
}


func SetupTlsCertGen(certPath string, keyPath string, turboTlsMode bool) (*tlsutils.TLSCertGen, error) {

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
	tlsCertGen.TurboCertGen = turboTlsMode
	
	if turboTlsMode {
		key, err := rsa.GenerateKey(rand.Reader, 2048)	
		if err != nil {
			return nil, err
		}
		
		tlsCertGen.SharedRsaKey = key
	}

	return tlsCertGen, nil
}
