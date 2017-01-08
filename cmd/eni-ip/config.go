// Copyright 2015 CNI authors
// Modifications copyright (C) 2016 Lincoln Stoll
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import "net"

// IPAMConfig is the config for this driver
type IPAMConfig struct {
	Name string
	Type string `json:"type"`
	// Interface is the interface to query additional IP allocations
	// from.
	Interface string `json:"interface"`
	// OverrideIPs will override the IP list to allocate from over
	// using the metadata API.
	OverrideIPs []net.IP `json:"override_ips"`
	// OverrideSubnet will override the subnet mask on the returned
	// IP. Only the net size component is used, to calculate the mask.
	// TODO - could this be override mask?
	OverrideSubnet string `json:"override_subnet"`
	// Dynamic will cause this module to request/release IP addresses
	// from the AWS API on demand. Requires instance role IAM
	// permissons to do this.
	Dynamic bool `json:"dynamic"`
	// SkipRoutes will cause the plugin to output no routes. This is
	// useful for use in bridging when it has 'isDefaultGateway' set.
	// In this case override subnet likely should be set to 0.0.0.0/32
	SkipRoutes bool `json:"skip_routes"`
}
