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
	"flag"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/golang/glog"
)

func main() {
	// Drive glog via env vars
	if os.Getenv("ENI_IP_GLOG_STDERR") == "1" {
		flag.Lookup("alsologtostderr").Value.Set("true")
	}
	if lvl := os.Getenv("ENI_IP_GLOG_LEVEL"); lvl != "" {
		flag.Lookup("v").Value.Set(lvl)
	}

	flag.Parse()
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports("0.1.0", "0.2.0", "0.3.0"))
}

func cmdAdd(args *skel.CmdArgs) error {
	glog.V(2).Info("starting cmdAdd")
	ipamConf, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		glog.Errorf("Error loading IPAM config: %q", err)
		return err
	}
	store, err := NewStore(ipamConf.Name)
	if err != nil {
		glog.Errorf("Error loading store: %q", err)
		return err
	}
	defer store.Close()

	allocator, err := NewIPAllocator(ipamConf, store)
	if err != nil {
		glog.Errorf("Error creating IP allocator: %q", err)
		return err
	}

	ipConf, err := allocator.Get(args.ContainerID)
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

func cmdDel(args *skel.CmdArgs) error {
	ipamConf, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	store, err := NewStore(ipamConf.Name)
	if err != nil {
		return err
	}
	defer store.Close()

	allocator, err := NewIPAllocator(ipamConf, store)
	if err != nil {
		return err
	}

	return allocator.Release(args.ContainerID)
}
