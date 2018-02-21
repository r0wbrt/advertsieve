/* Copyright 2018 Robert Christian Taylor. All Rights Reserved
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
	"os"
	"strings"
	"bufio"
	"fmt"
) 

func main() {
	hostFile := strings.Join(os.Args[1:], " ")
	file, err := os.Open(hostFile)
	if err != nil {
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
		
		if line[0] == '#' {
			continue
		}
		
		pieces := strings.Split(line, " ")
		
		if len(pieces) != 2 {
			continue
		}
		
		fmt.Println(pieces[1])
		
	}
}
