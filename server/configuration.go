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
	"bufio"
	"errors"
	"github.com/r0wbrt/advertsieve/config"
	"github.com/r0wbrt/advertsieve/contentpolicy"
	"os"
	"strings"
)

type VirtualHost struct {
	Host          string
	KeyPath       string
	CertPath      string
	Directory     string
	HasCustomCert bool
}

type ServerInstance struct {
	Address string
	Type    int
}

type AdvertSieveConfig struct {
	ServerInstances []ServerInstance

	CertificatePath string

	PrivateKeyPath string

	HostsAclFiles []string

	PathAclFiles []string

	AllowConnectionsToLocalhost bool

	DisableHttpLoopDetection bool

	VirtualHosts map[string]VirtualHost

	ServerName string
}

func ReadInHostAclFile(path string, hostAcl *contentpolicy.HostAccessControl) error {

	file, err := os.Open(path)
	if err != nil {
		return err
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
			return errors.New("Invalid entry in Host File: " + path)
		}

		if filterIsExclude {
			hostAcl.AddException(line)
		} else {
			hostAcl.AddBlockedHost(line)
		}
	}

	return nil
}

func ReadInPathACLFile(path string, pathAcl *contentpolicy.PathAccessControl) error {

	file, err := os.Open(path)
	if err != nil {
		return err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		err = pathAcl.AddFilter(scanner.Text())
		if err != nil {
			return err
		}
	}

	if err = scanner.Err(); err != nil {
		return err
	}

	return nil
}

func ReadConfigurationInFromFile(path string) (*AdvertSieveConfig, error) {

	var err error
	var grammar *config.Grammar = config.GetProxyGrammar()
	var configVals map[string]interface{}
	var configuration *AdvertSieveConfig = new(AdvertSieveConfig)

	configuration.VirtualHosts = make(map[string]VirtualHost)

	file, err := os.Open(path)
	if err != nil {
		return configuration, err
	}

	configVals, err = grammar.Parse(file)
	if err != nil {
		return configuration, err
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

				configuration.ServerInstances = append(configuration.ServerInstances, ServerInstance{Address: string(vals[1].([]rune)), Type: serverType})

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
				virtualHost.HasCustomCert = true

				configuration.VirtualHosts[site] = virtualHost

			default:
				//Ignore unrecognized values
				continue
			}
		}
	}

	return configuration, err
}
