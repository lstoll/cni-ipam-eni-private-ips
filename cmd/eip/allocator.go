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
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/plugins/ipam/host-local/backend"
)

// ErrInvalidConfig is returned when the IPAMConfig is not valid
var ErrInvalidConfig = errors.New("Either Interface or Override must be set")

// ErrEmptyPool is returned if the IP pool is configured with 0 IPs, e.g no
// EIP's attached
var ErrEmptyPool = errors.New("No EIPs found on interface")

// IPAllocator is the implementation of the actual allocator
type IPAllocator struct {
	conf  *IPAMConfig
	store backend.Store
	md    mdClient
}

type mdClient interface {
	GetMetadata(path string) (result string, err error)
}

// NewIPAllocator will return an initialized IPAllocator
func NewIPAllocator(conf *IPAMConfig, store backend.Store) (*IPAllocator, error) {
	if conf.Interface == "" && (len(conf.OverrideIPs) == 0 || conf.OverrideSubnet == "") {
		return nil, ErrInvalidConfig
	}
	return &IPAllocator{conf, store, ec2metadata.New(session.New())}, nil
}

// Get returns newly allocated IP along with its config
func (a *IPAllocator) Get(id string) (*types.IPConfig, error) {
	a.store.Lock()
	defer a.store.Unlock()

	var ips []net.IP
	var subnet *net.IPNet

	if len(a.conf.OverrideIPs) > 0 {
		var err error
		_, subnet, err = net.ParseCIDR(a.conf.OverrideSubnet)
		if err != nil {
			return nil, err
		}
		ips = a.conf.OverrideIPs
	} else {
		var err error
		ips, subnet, err = a.fetchMDApiIPs(a.conf.Interface)
		if err != nil {
			return nil, err
		}
	}

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

	return &types.IPConfig{
		IP: net.IPNet{IP: reservedIP, Mask: subnet.Mask},
	}, nil
}

// Release releases all IPs allocated for the container with given ID
func (a *IPAllocator) Release(id string) error {
	a.store.Lock()
	defer a.store.Unlock()

	return a.store.ReleaseByID(id)
}

func (a *IPAllocator) fetchMDApiIPs(iface string) (ips []net.IP, subnet *net.IPNet, err error) {
	var boundIps []net.IP
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := i.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, a := range addrs {
		ifIP, _, err := net.ParseCIDR(a.String())
		if err == nil {
			boundIps = append(boundIps, ifIP)
		}
	}
	mdIps, err := a.md.GetMetadata(fmt.Sprintf("/network/interfaces/macs/%s/local-ipv4s/", i.HardwareAddr.String()))
	if err != nil {
		return nil, nil, err
	}
	mdNet, err := a.md.GetMetadata(fmt.Sprintf("/network/interfaces/macs/%s/subnet-ipv4-cidr-block", i.HardwareAddr.String()))
	if err != nil {
		return nil, nil, err
	}
	_, subnet, err = net.ParseCIDR(mdNet)
	if err != nil {
		return nil, nil, err
	}

OUTER:
	for _, mi := range strings.Split(mdIps, "\n") {
		for _, bi := range boundIps {
			if bi.String() == mi {
				continue OUTER
			}
		}
		ips = append(ips, net.ParseIP(mi))
	}
	return ips, subnet, nil
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
