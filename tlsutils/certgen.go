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

package tlsutils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"time"
)

type TLSCertGen struct {

	//Cert used to sign other ceritifcates. If left blank, all certs are self
	//signed. This cert should be installed in the clients accessing the proxy
	//to avoid cert error messages.
	RootAuthorityCert *x509.Certificate

	//Private key of the root cert
	RootAuthorityPrivateKey interface{}

	//Prefix to stick before the organization field of the generated certs which
	//automatically gets set to the requested host
	OrganizationPrefix string
}

func (certGen *TLSCertGen) GetCertificate(hello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {

	certPem, pkeyPem, err := certGen.GenerateCertificate(hello.ServerName)

	if err != nil {
		return
	}

	certTemp, err := tls.X509KeyPair(certPem, pkeyPem)

	if err != nil {
		return
	}

	cert = &certTemp

	return
}

// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2017 Robert Christian Taylor. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

func (certGen *TLSCertGen) GenerateCertificate(host string) (certPem []byte, keyPem []byte, err error) {

	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certGen.OrganizationPrefix + host},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	var derBytes []byte

	if certGen.RootAuthorityCert != nil {
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, certGen.RootAuthorityCert, &priv.PublicKey, certGen.RootAuthorityPrivateKey)
	} else {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	}
	if err != nil {
		return
	}

	var certOut, keyOut bytes.Buffer

	pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	certPem = certOut.Bytes()
	keyPem = keyOut.Bytes()

	return
}
