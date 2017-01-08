// Copyright 2015 CNI authors
// Modifications copyright 2016 Lincoln Stoll
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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"

	"github.com/lstoll/cni-ipam-eni-private-ips/pkg/eniip"
	"github.com/pkg/errors"

	"github.com/containernetworking/cni/pkg/types"
)

// ErrEmptyPool is returned if the IP pool is configured with 0 IPs, e.g no
// additional IPs attached to the interface
var ErrEmptyPool = errors.New("No free private IPs found on interface")

// IPAllocator is the implementation of the actual allocator
type IPAllocator struct {
	netConf  *eniip.Net
	conf     *IPAMConfig
	args     *eniip.IPAMArgs
	bridgeGw net.IP
	store    eniip.Store
}

// Init will return initialize the IPAllocator
func (a *IPAllocator) Init(nc *eniip.Net, args *eniip.IPAMArgs, store eniip.Store) error {
	a.store = store
	a.netConf = nc
	if nc.Type != "bridge" && nc.Type != "ipvlan" {
		return fmt.Errorf("Only bridge or ipvlan supported, network set to %s", nc.Type)
	}
	a.conf = &IPAMConfig{}
	err := json.Unmarshal(nc.IPAM, a.conf)
	if err != nil {
		return errors.Wrap(err, "Error unmarshaling IPAMConfig")
	}
	if a.netConf.Bridge != "" {
		i, err := net.InterfaceByName(a.netConf.Bridge)
		if err != nil {
			return errors.Wrapf(err, "Error finding bridge interface")
		}
		braddrs, err := i.Addrs()
		if err != nil {
			return errors.Wrapf(err, "Error looking up bridge interface %s addresses",
				a.netConf.Bridge)
		}
		var brv4s []net.IP
		for _, a := range braddrs {
			v, ok := a.(*net.IPNet)
			if ok {
				if v4 := v.IP.To4(); v4 != nil {
					brv4s = append(brv4s, v4)
				}
			}
		}
		if len(brv4s) != 1 {
			return fmt.Errorf("Bridge %s needs exactly one address, has %d",
				a.netConf.Bridge,
				len(brv4s),
			)
		}
		a.bridgeGw = brv4s[0]
	}
	return nil
}

// Get returns newly allocated IP along with its config
func (a *IPAllocator) Get(id string) (*types.IPConfig, error) {
	a.store.Lock()
	defer a.store.Unlock()

	var ips []net.IP
	var subnet *net.IPNet

	ret := &types.IPConfig{}

	var err error
	if a.netConf.Type == "ipvlan" {
		_, subnet, err = net.ParseCIDR(a.conf.Subnet)
		if err != nil {
			return nil, err
		}
		_, defnet, err := net.ParseCIDR("0.0.0.0/0")
		if err != nil {
			panic(err)
		}
		ret.Routes = []types.Route{
			// Hope no GW makes for a interface route. In L3 mode we
			// use the host interface in L2 mode we should be smarter
			// here (accept passed in routes?)
			types.Route{Dst: *defnet},
		}
	} else {
		// bridge mode is always this, and routed via host
		_, subnet, err = net.ParseCIDR("0.0.0.0/32")
		if err != nil {
			panic(err)
		}
		// route to brip/32 is a interface route
		brNet := net.IPNet{
			IP:   a.bridgeGw,
			Mask: net.IPv4Mask(255, 255, 255, 255),
		}

		_, defNet, err := net.ParseCIDR("0.0.0.0/0")
		if err != nil {
			panic(err)
		}

		ret.Routes = []types.Route{
			{
				Dst: brNet,
			},
			{
				Dst: *defNet,
				GW:  a.bridgeGw,
			},
		}
	}
	ips = a.conf.StubAddresses

	if len(ips) == 0 {
		return nil, ErrEmptyPool
	}

	// Sort to ensure consistent ordering, for handling last used etc.
	sort.Sort(netIps(ips))

	lastReservedIP, err := a.store.LastReservedIP()
	if err != nil || lastReservedIP == nil {
		// Likely no last reserved. Just start from the beginning
	} else {
		// Shuffle IPs so last reserved is at the end
		for i := 0; i < len(ips); i++ {
			if ips[i].Equal(lastReservedIP) {
				ips = append(ips[i+1:], ips[:i+1]...)
			}
		}
	}

	// Walk until we find a free IPs
	var reservedIP net.IP
	for _, ip := range ips {
		reserved, err := a.store.Reserve(id, ip)
		if err != nil {
			return nil, err
		}
		if reserved {
			reservedIP = ip
			break
		}
	}

	if reservedIP == nil {
		return nil, fmt.Errorf("No free IPs in network: %s", a.conf.Name)
	}

	ret.IP = net.IPNet{
		IP:   reservedIP,
		Mask: subnet.Mask,
	}

	return ret, nil
}

// Release releases all IPs allocated for the container with given ID
func (a *IPAllocator) Release(id string) error {
	a.store.Lock()
	defer a.store.Unlock()

	_, err := a.store.ReleaseByIDReturning(id)
	if err != nil {
		return err
	}
	return nil
}

// Classic Golang
type netIps []net.IP

func (n netIps) Len() int {
	return len(n)
}

func (n netIps) Less(i, j int) bool {
	return bytes.Compare(n[i][:], n[j][:]) < 0
}

func (n netIps) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}
