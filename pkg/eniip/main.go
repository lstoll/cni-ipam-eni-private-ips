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

package eniip

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

type Allocator interface {
	Init(nc *Net, args *IPAMArgs, store Store) error
	Get(id string) (*types.IPConfig, error)
	Release(id string) error
}

// IPAMArgs is the arguments to this ipam plugin
type IPAMArgs struct {
	types.CommonArgs
	//MetadataEndpoint string `json:"metadata_endpoint,omitempty"`
	IP net.IP `json:"ip,omitempty"`
}

type Net struct {
	Name string `json:"name"`
	// Type is the type of network, we support ipvlan and bridge
	Type string `json:"type"`
	// Bridge is the bridge interface, if type is bridge
	Bridge string          `json:"bridge"`
	IPAM   json.RawMessage `json:"ipam,omitempty"`
}

// LoadIPAMConfig creates a NetworkConfig from the given network name.
func LoadConfig(bytes []byte, args string) (*Net, *IPAMArgs, error) {
	n := &Net{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, nil, err
	}

	var a *IPAMArgs
	if args != "" {
		a = &IPAMArgs{}
		err := types.LoadArgs(args, a)
		if err != nil {
			return nil, nil, err
		}
	}

	if n.IPAM == nil {
		return nil, nil, fmt.Errorf("IPAM config missing 'ipam' key")
	}

	return n, a, nil
}

func Main(a Allocator) {
	// Drive glog via env vars
	if os.Getenv("ENI_IP_GLOG_STDERR") == "1" {
		flag.Lookup("alsologtostderr").Value.Set("true")
	}
	if lvl := os.Getenv("ENI_IP_GLOG_LEVEL"); lvl != "" {
		flag.Lookup("v").Value.Set(lvl)
	}

	flag.Parse()
	skel.PluginMain(cmdAdd(a), cmdDel(a), version.PluginSupports("0.1.0", "0.2.0", "0.3.0"))
}

func cmdAdd(a Allocator) func(*skel.CmdArgs) error {
	return func(args *skel.CmdArgs) error {
		glog.V(2).Info("starting cmdAdd")
		nc, ac, err := LoadConfig(args.StdinData, args.Args)
		if err != nil {
			glog.Errorf("Error loading IPAM config: %q", err)
			return err
		}
		store, err := NewStore(nc.Name, "")
		if err != nil {
			glog.Errorf("Error loading store: %q", err)
			return err
		}
		defer store.Close()

		err = a.Init(nc, ac, store)
		if err != nil {
			return errors.Wrap(err, "Error initializing allocator")
			glog.Errorf("Error creating IP allocator: %q", err)
			return err
		}

		ipConf, err := a.Get(args.ContainerID)
		if err != nil {
			glog.Errorf("Error getting allocation: %q", err)
			return err
		}

		r := &types.Result{
			IP4: ipConf,
		}
		glog.V(2).Info("completed cmdAdd")
		return r.Print()
	}
}

func cmdDel(a Allocator) func(*skel.CmdArgs) error {
	return func(args *skel.CmdArgs) error {
		nc, ac, err := LoadConfig(args.StdinData, args.Args)
		if err != nil {
			return err
		}

		store, err := NewStore(nc.Name, "")
		if err != nil {
			return err
		}
		defer store.Close()

		err = a.Init(nc, ac, store)
		if err != nil {
			return errors.Wrap(err, "Error initializing allocator")
		}

		return a.Release(args.ContainerID)
	}
}
