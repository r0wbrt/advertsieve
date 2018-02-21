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

package services

import (
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

//VirtualHost describes a single virtual website host.
type VirtualHost struct {
	Host                   string
	Root                   string
	AllowDirectoryIndexing bool
	AllowDotFiles          bool
}

//VirtualHostFileServer serves a set of static websites indexed by the HTTP Host field.
type VirtualHostFileServer struct {
	VHosts  map[string]*VirtualHost
	Handler http.Handler
}

func (server *VirtualHostFileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if server.VHosts == nil {
		return
	}

	vhost, ok := server.VHosts[r.Host]
	if !ok {
		if server.Handler != nil {
			server.Handler.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}

	} else {
		http.FileServer(vhost).ServeHTTP(w, r)
	}
}

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

func mapDirOpenError(originalErr error, name string) error {
	if os.IsNotExist(originalErr) || os.IsPermission(originalErr) {
		return originalErr
	}

	parts := strings.Split(name, string(filepath.Separator))
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		fi, err := os.Stat(strings.Join(parts[:i+1], string(filepath.Separator)))
		if err != nil {
			return originalErr
		}
		if !fi.IsDir() {
			return os.ErrNotExist
		}
	}
	return originalErr
}

//Open returns a file to be served to the remote client unless that file
//is a dot file or a directory. If the file is a dot file or directory, Open
//will only return dot files if AllowDotFiles true. Similarly, Open will
//only return a directory if AllowDirectoryIndexing is set to true.
func (d *VirtualHost) Open(name string) (http.File, error) {
	if filepath.Separator != '/' && strings.ContainsRune(name, filepath.Separator) {
		return nil, errors.New("services: invalid character in file path")
	}
	dir := d.Root
	if dir == "" {
		dir = "."
	}
	fullName := filepath.Join(dir, filepath.FromSlash(path.Clean("/"+name)))

	if !d.AllowDotFiles && len(filepath.Base(fullName)) > 0 && filepath.Base(fullName)[0] == '.' {
		return nil, os.ErrNotExist
	}

	if !d.AllowDirectoryIndexing {
		info, err := os.Stat(fullName)
		if err != nil {
			return nil, err
		}

		if info.IsDir() {
			index := strings.TrimSuffix(fullName, "/") + "/index.html"
			ff, err := os.Open(index)
			defer ff.Close()
			if err == nil {
				_, err := ff.Stat()
				if err != nil {
					return nil, os.ErrNotExist
				}
			} else {
				return nil, os.ErrNotExist
			}
		}
	}

	f, err := os.Open(fullName)
	if err != nil {
		return nil, mapDirOpenError(err, fullName)
	}

	return f, nil
}
