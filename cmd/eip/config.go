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

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
)

// IPAMConfig is the config for this driver
type IPAMConfig struct {
	Name           string
	Type           string    `json:"type"`
	Interface      string    `json:"interface"`
	OverrideIPs    []net.IP  `json:"override_ips"`
	OverrideSubnet string    `json:"override_subnet"`
	Args           *IPAMArgs `json:"-"`
}

// IPAMArgs is the arguments to this ipam plugin
type IPAMArgs struct {
	types.CommonArgs
	MetadataEndpoint string `json:"metadata_endpoint,omitempty"`
}

type Net struct {
	Name string      `json:"name"`
	IPAM *IPAMConfig `json:"ipam"`
}

// LoadIPAMConfig creates a NetworkConfig from the given network name.
func LoadIPAMConfig(bytes []byte, args string) (*IPAMConfig, error) {
	n := Net{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, err
	}

	if args != "" {
		n.IPAM.Args = &IPAMArgs{}
		err := types.LoadArgs(args, n.IPAM.Args)
		if err != nil {
			return nil, err
		}
	}

	if n.IPAM == nil {
		return nil, fmt.Errorf("IPAM config missing 'ipam' key")
	}

	// Copy net name into IPAM so not to drag Net struct around
	n.IPAM.Name = n.Name

	return n.IPAM, nil
}
