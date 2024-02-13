////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2023 Dell, Inc.                                                 //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

//go:build testapp
// +build testapp

package transformer_test

import (
	"testing"
	"time"
)

func Test_openconfig_subintf(t *testing.T) {
	var url, url_input_body_json string

	t.Log("\n\n+++++++++++++ CONFIGURING AND REMOVING IPv4 ADDRESS AT SUBINTERFACES ++++++++++++")
	t.Log("\n\n--- Delete IPv4 address ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/addresses"
	t.Run("Test delete on subinterface", processDeleteRequest(url, true))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Get IPv4 address at subinterfaces ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces"
	expected_get_json := "{\"openconfig-interfaces:subinterfaces\": {\"subinterface\": [{\"config\": {\"index\": 0}, \"index\": 0, \"openconfig-if-ip:ipv6\": {\"config\": {\"enabled\": false}}, \"state\": {\"index\": 0}}]}}"
	t.Run("Test Get at subinterfaces", processGetRequest(url, nil, expected_get_json, false))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- PATCH IPv4 address at addresses ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/addresses"
	url_input_body_json = "{\"openconfig-if-ip:addresses\": {\"address\": [{\"ip\": \"4.4.4.4\", \"openconfig-if-ip:config\": {\"ip\": \"4.4.4.4\", \"prefix-length\": 24}}]}}"
	time.Sleep(1 * time.Second)
	t.Run("Test patch/set on subinterfaces", processSetRequest(url, url_input_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Verify PATCH IPv4 addresses ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/addresses"
	expected_get_json = "{\"openconfig-if-ip:addresses\": {\"address\": [{\"config\": {\"ip\": \"4.4.4.4\", \"prefix-length\": 24}, \"ip\": \"4.4.4.4\", \"state\":{ \"family\":\"ipv4\", \"ip\": \"4.4.4.4\", \"prefix-length\": 24}}]}}"
	t.Run("Test Get at subinterfaces", processGetRequest(url, nil, expected_get_json, false))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Verify IPv4 address at subinterfaces ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces"
	expected_get_json = "{\"openconfig-interfaces:subinterfaces\": {\"subinterface\": [{\"config\": {\"index\": 0}, \"index\": 0, \"openconfig-if-ip:ipv4\": {\"addresses\": {\"address\": [{\"config\": {\"ip\": \"4.4.4.4\", \"prefix-length\": 24}, \"ip\": \"4.4.4.4\", \"state\":{ \"family\":\"ipv4\", \"ip\": \"4.4.4.4\", \"prefix-length\": 24}}]}}, \"openconfig-if-ip:ipv6\": {\"config\": {\"enabled\": false}}, \"state\": {\"index\": 0}}]}}"
	t.Run("Test Get at subinterfaces", processGetRequest(url, nil, expected_get_json, false))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Delete IPv4 address ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/addresses/address[ip=4.4.4.4]"
	t.Run("Test delete on subinterface", processDeleteRequest(url, true))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Verify Delete IPv4 address at subinterfaces ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces"
	expected_get_json = "{\"openconfig-interfaces:subinterfaces\": {\"subinterface\": [{\"config\": {\"index\": 0}, \"index\": 0, \"openconfig-if-ip:ipv6\": {\"config\": {\"enabled\": false}}, \"state\": {\"index\": 0}}]}}"
	t.Run("Test Get at subinterfaces", processGetRequest(url, nil, expected_get_json, false))
	time.Sleep(1 * time.Second)

	t.Log("\n\n+++++++++++++ DONE CONFIGURING AND REMOVING IPV4 ADDRESSES ON SUBINTERFACES  ++++++++++++")

	t.Log("\n\n+++++++++++++ CONFIGURING AND REMOVING IPv6 ADDRESS AT SUBINTERFACES ++++++++++++")
	t.Log("\n\n--- Delete IPv6 address ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv6/addresses"
	t.Run("Test delete on subinterface", processDeleteRequest(url, true))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Get IPv6 address at subinterfaces ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces"
	expected_get_json = "{\"openconfig-interfaces:subinterfaces\": {\"subinterface\": [{\"config\": {\"index\": 0}, \"index\": 0, \"openconfig-if-ip:ipv6\": {\"config\": {\"enabled\": false}}, \"state\": {\"index\": 0}}]}}"
	t.Run("Test Get at subinterfaces", processGetRequest(url, nil, expected_get_json, false))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- PATCH IPv6 address at addresses ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv6/addresses"
	url_input_body_json = "{\"openconfig-if-ip:addresses\": {\"address\": [{\"ip\": \"a::e\", \"openconfig-if-ip:config\": {\"ip\": \"a::e\", \"prefix-length\": 64}}]}}"
	time.Sleep(1 * time.Second)
	t.Run("Test patch/set on subinterfaces", processSetRequest(url, url_input_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Verify PATCH IPv6 addresses ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv6/addresses"
	expected_get_json = "{\"openconfig-if-ip:addresses\":{\"address\":[{\"config\":{\"ip\":\"a::e\",\"prefix-length\":64},\"ip\":\"a::e\",\"state\":{\"family\":\"ipv6\",\"ip\":\"a::e\",\"prefix-length\":64}}]}}"

	t.Run("Test Get at subinterfaces", processGetRequest(url, nil, expected_get_json, false))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Verify IPv6 address at subinterfaces ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces"
	expected_get_json = "{\"openconfig-interfaces:subinterfaces\":{\"subinterface\":[{\"config\":{\"index\":0},\"index\":0,\"openconfig-if-ip:ipv6\":{\"addresses\":{\"address\":[{\"config\":{\"ip\":\"a::e\",\"prefix-length\":64},\"ip\":\"a::e\",\"state\":{\"family\":\"ipv6\",\"ip\":\"a::e\",\"prefix-length\":64}}]},\"config\":{\"enabled\":false}},\"state\":{\"index\":0}}]}}"
	t.Run("Test Get at subinterfaces", processGetRequest(url, nil, expected_get_json, false))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Delete IPv4 address ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv6/addresses/address[ip=a::e]"
	t.Run("Test delete on subinterface", processDeleteRequest(url, true))
	time.Sleep(1 * time.Second)

	t.Log("\n\n--- Verify Delete IPv6 address at subinterfaces ---")
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces"
	expected_get_json = "{\"openconfig-interfaces:subinterfaces\": {\"subinterface\": [{\"config\": {\"index\": 0}, \"index\": 0, \"openconfig-if-ip:ipv6\": {\"config\": {\"enabled\": false}}, \"state\": {\"index\": 0}}]}}"
	t.Run("Test Get at subinterfaces", processGetRequest(url, nil, expected_get_json, false))
	time.Sleep(1 * time.Second)

	t.Log("\n\n+++++++++++++ DONE CONFIGURING AND REMOVING IPV6 ADDRESSES ON SUBINTERFACES  ++++++++++++")
}
