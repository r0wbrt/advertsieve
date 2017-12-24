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

package main 

import (
	"log"
	"os"
	"strings"
	"github.com/r0wbrt/advertsieve/server"
)

func main() {
	
	logger := log.New(os.Stderr, "", log.LstdFlags)
	
	logger.Printf("Starting %s version %s %s.", CONST_BRAND_NAME, CONST_VERSION, CONST_BUILD_TYPE)
	
	var argString string = ""
	if len(os.Args) > 1 {
		for i := 0; i < len(os.Args[1:]); i++ {
			argString = argString + "\"" + os.Args[i+1] + "\" "
		}

		logger.Printf("Program %s started with arguments: %s", CONST_BRAND_NAME, argString)
	}
	
	var config_path string = CONST_CONFIG_FILE_PATH
	if len(os.Args) > 1 {
		config_path = strings.Join(os.Args[1:], " ")
	}
	logger.Printf("Using configuration file: %s", config_path)
	
	config, err := server.ReadConfigurationInFromFile(config_path)
	if err != nil {
		logger.Fatal(err)
	}
	
	var s *server.AdvertsieveServer = new(server.AdvertsieveServer)
	
	s.Config = config
	s.Logger = logger
	
	err = s.ListenAndServe()
	if err != nil {
		logger.Fatal(err)
	}
	
	
}
