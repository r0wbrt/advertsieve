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

package accesscontrol

import "testing"

func TestConstructHostAccessControl(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	if hostAC == nil {
		t.Errorf("NewHostAccessControl should never return a nil pointer")
	}
}

func TestEmptyHostAccessControlFunctions(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	if !hostAC.AllowHost("www.zebra.game") {
		t.Errorf("There are no blocked or exception rules in host filter. So zebra should have been allowed.")
	}
}

func TestAddBlockedHost(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	hostAC.AddBlockedHost("www.example.com")

	if hostAC.AllowHost("www.example.com") {
		t.Errorf("Blocked host www.example.com was not blocked. It should have been.")
	}

	var result int = hostAC.checkIfHostInFilter("www.example.com")
	if result != -1 {
		t.Errorf("www.example.com is blocked but checkIfHostInFilter returned %d. It should have returned -1", result)
	}
}

func TestAddExceptionHost(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	hostAC.AddException("www.example.com")

	if !hostAC.AllowHost("www.example.com") {
		t.Errorf("www.example.com should have been allowed since it was added as an exception host")
	}

	var result int = hostAC.checkIfHostInFilter("www.example.com")
	if result != 1 {
		t.Errorf("www.example.com is an exception but checkIfHostInFilter returned %d. It should have returned 1", result)
	}
}

func TestExceptionRespectedForBlockRule(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	hostAC.AddBlockedHost("www.google.com")
	hostAC.AddException("www.google.com")

	if !hostAC.AllowHost("www.google.com") || hostAC.checkIfHostInFilter("www.google.com") != 1 {
		t.Errorf("www.google.com is both a block rule and an exception rule. Exception rules take precendence so this domain should be allowed through")
	}
}

func TestSubDomainsAreBlocked(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	hostAC.AddBlockedHost("adsite.ty")

	if hostAC.AllowHost("zzz.adsite.ty") || hostAC.checkIfHostInFilter("zzz.adsite.ty") != -1 {
		t.Errorf("zzz.adsite.ty should be blocked since it is a sub domain of blocking rule adsite.ty")
	}
}

func TestParentDomainsArenotBlocked(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	hostAC.AddBlockedHost("www.kalm.ghz")

	if !hostAC.AllowHost("kakm.ghz") || hostAC.checkIfHostInFilter("kakm.ghz") != 0 {
		t.Errorf("kakm.gz should be allowed. The only blocking rule is www.kalm.ghz and this is a subdomain of kakm.gz")
	}
}

func TestUnblockedHostsArePermitted(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	hostAC.AddBlockedHost("www.kalm.ghz")

	if !hostAC.AllowHost("www.google.com") || hostAC.checkIfHostInFilter("www.google.com") != 0 {
		t.Errorf("www.google.com is not listed as a blocked rule so it should have passed")
	}
}

func TestExceptionSubDomainsArePermitted(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	hostAC.AddBlockedHost("kalm.ghz")
	hostAC.AddException("wwy.kalm.ghz")

	if !hostAC.AllowHost("wwy.kalm.ghz") || hostAC.checkIfHostInFilter("wwy.kalm.ghz") != 1 {
		t.Errorf("wwy.kakm.gz should be allowed. There is an exception for this domain for blocking rule kalm.ghz")
	}
}

func TestExceptionSubDomainsAreNotPermitted(t *testing.T) {
	var hostAC *HostAccessControl = NewHostAccessControl()
	hostAC.AddBlockedHost("kalm.ghz")
	hostAC.AddException("wwy.kalm.ghz")

	if hostAC.AllowHost("zzz.wwy.kalm.ghz") || hostAC.checkIfHostInFilter("zzz.wwy.kalm.ghz") != -1 {
		t.Errorf("zzz.wwy.kakm.gz should not be allowed. There is an exception for wwy.kalm.ghz and a blocking rule kalm.ghz")
	}
}
