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
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/glog"

	"github.com/containernetworking/cni/pkg/types"
)

// ErrInvalidConfig is returned when the IPAMConfig is not valid
var ErrInvalidConfig = errors.New("Either Interface or Override must be set")

// ErrEmptyPool is returned if the IP pool is configured with 0 IPs, e.g no
// additional IPs attached to the interface
var ErrEmptyPool = errors.New("No free private IPs found on interface")

// IPAllocator is the implementation of the actual allocator
type IPAllocator struct {
	conf  *IPAMConfig
	store Store
	md    mdClient
	ec2   ec2Client
	iface *net.Interface
	eniID string
}

type mdClient interface {
	GetMetadata(path string) (string, error)
	GetDynamicData(path string) (string, error)
}

type ec2Client interface {
	AssignPrivateIpAddresses(*ec2.AssignPrivateIpAddressesInput) (*ec2.AssignPrivateIpAddressesOutput, error)
	UnassignPrivateIpAddresses(*ec2.UnassignPrivateIpAddressesInput) (*ec2.UnassignPrivateIpAddressesOutput, error)
}

// NewIPAllocator will return an initialized IPAllocator
func NewIPAllocator(conf *IPAMConfig, store Store) (*IPAllocator, error) {
	if conf.Interface == "" && (len(conf.OverrideIPs) == 0 || conf.OverrideSubnet == "") {
		return nil, ErrInvalidConfig
	}
	i, err := net.InterfaceByName(conf.Interface)
	if err != nil {
		return nil, err
	}
	sess := session.New()
	alloc := &IPAllocator{
		conf:  conf,
		store: store,
		md:    ec2metadata.New(sess),
		iface: i,
	}
	alloc.eniID, err = alloc.fetchEniID()
	if err != nil {
		return nil, err
	}
	if conf.Dynamic {
		// need to set up EC2. And find the region
		type iidoc struct {
			Region string `json:"region"`
		}
		riid, err := alloc.md.GetDynamicData("instance-identity/document")
		if err != nil {
			return nil, err
		}
		iid := &iidoc{}
		if err := json.Unmarshal([]byte(riid), iid); err != nil {
			return nil, err
		}
		config := aws.NewConfig().
			WithCredentials(ec2rolecreds.NewCredentials(sess)).
			WithRegion(iid.Region)
		alloc.ec2 = ec2.New(session.New(config))
	}

	return alloc, nil
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
		ips, subnet, err = a.fetchMDApiIPs()
		if err != nil {
			return nil, err
		}
		if a.conf.Dynamic {
			var requestedIP net.IP
			if a.conf.Args != nil {
				requestedIP = a.conf.Args.IP
			}
			// allocate a new one, spin until we have it
			if err := a.allocateIP(requestedIP); err != nil {
				return nil, err
			}
			iterations := 0
		OUTER:
			for {
				time.Sleep(500 * time.Millisecond)
				newIPs, _, err := a.fetchMDApiIPs()
				if err != nil {
					return nil, err
				}
				if len(newIPs) > len(ips) {
					// Got one!
					for _, ip := range newIPs {
						var found bool
						for _, oip := range ips {
							if ip.Equal(oip) {
								found = true
							}
						}
						if !found {
							// This is our new one
							ips = []net.IP{ip}
							break OUTER
						}
					}
				}
				if iterations > 60 {
					return nil, errors.New("Timeout generating new IP")
				}
				iterations++
			}
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

	_, defnet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		panic(err)
	}

	ret := &types.IPConfig{
		IP: net.IPNet{
			IP:   reservedIP,
			Mask: subnet.Mask,
		},
	}
	if !a.conf.SkipRoutes {
		ret.Routes = []types.Route{
			// Hope no GW makes for a interface route
			types.Route{Dst: *defnet},
		}
	}
	return ret, nil
}

// Release releases all IPs allocated for the container with given ID
func (a *IPAllocator) Release(id string) error {
	a.store.Lock()
	defer a.store.Unlock()

	freed, err := a.store.ReleaseByIDReturning(id)
	if err != nil {
		return err
	}
	if a.conf.Dynamic && freed != nil {
		if err := a.freeIps([]string{freed.String()}); err != nil {
			return err
		}
	}
	return nil
}

func (a *IPAllocator) fetchMDApiIPs() (ips []net.IP, subnet *net.IPNet, err error) {
	var boundIps []net.IP
	addrs, err := a.iface.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, a := range addrs {
		ifIP, _, err := net.ParseCIDR(a.String())
		if err == nil {
			boundIps = append(boundIps, ifIP)
		}
	}
	mdIps, err := a.md.GetMetadata(fmt.Sprintf("/network/interfaces/macs/%s/local-ipv4s/", a.iface.HardwareAddr.String()))
	if err != nil {
		return nil, nil, err
	}
	mdNet, err := a.md.GetMetadata(fmt.Sprintf("/network/interfaces/macs/%s/subnet-ipv4-cidr-block", a.iface.HardwareAddr.String()))
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

func (a *IPAllocator) fetchEniID() (string, error) {
	eniid, err := a.md.GetMetadata(fmt.Sprintf("/network/interfaces/macs/%s/interface-id", a.iface.HardwareAddr.String()))
	if err != nil {
		return "", err
	}
	return eniid, nil
}

// allocateIp a new IP on the ENI. Annoyingly, doesn't return it.
func (a *IPAllocator) allocateIP(requestedIP net.IP) error {
	glog.Infof("Request to allocate IP address, IP: %q", requestedIP.String)
	ipReq := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: &a.eniID,
	}
	if requestedIP != nil {
		ipReq.PrivateIpAddresses = []*string{
			aws.String(requestedIP.String()),
		}
	} else {
		ipReq.SecondaryPrivateIpAddressCount = aws.Int64(1)
	}
	glog.Infof("call AssignPrivateIpAddresses: %#v", ipReq)
	_, err := a.ec2.AssignPrivateIpAddresses(ipReq)
	return err
}

// freeIp frees up the given ip(s) from the ENI
func (a *IPAllocator) freeIps(ips []string) error {
	glog.Infof("Request to free IPs: %q", ips)
	req := []*string{}
	for _, ip := range ips {
		req = append(req, aws.String(ip))
	}
	_, err := a.ec2.UnassignPrivateIpAddresses(&ec2.UnassignPrivateIpAddressesInput{
		NetworkInterfaceId: &a.eniID,
		PrivateIpAddresses: req,
	})
	return err
}
