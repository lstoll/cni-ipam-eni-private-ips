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

package eniip

import (
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"

	"github.com/containernetworking/cni/plugins/ipam/host-local/backend/disk"
)

type Store interface {
	Lock() error
	Unlock() error
	Close() error
	Reserve(id string, ip net.IP) (bool, error)
	LastReservedIP() (net.IP, error)
	Release(ip net.IP) error
	ReleaseByID(id string) error
	// Our extensions
	ReleaseByIDReturning(id string) (net.IP, error)
}

// has to match upstream
var defaultDataDir = "/var/lib/cni/networks"

type DiskStore struct {
	disk.Store
	// this is hidden, so re-do it here
	DataDir string
}

// NewStore returns a new store. If dataDir is empty, a default dir
// will be used
func NewStore(network, dataDir string) (*DiskStore, error) {
	if dataDir == "" {
		dataDir = defaultDataDir
	}
	dir := filepath.Join(dataDir, network)
	ds, err := disk.New(network, dataDir)
	if err != nil {
		return nil, err
	}
	return &DiskStore{*ds, dir}, nil
}

// N.B. This function eats errors to be tolerant and
// release as much as possible
func (s *DiskStore) ReleaseByIDReturning(id string) (net.IP, error) {
	var ret net.IP
	err := filepath.Walk(s.DataDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := ioutil.ReadFile(p)
		if err != nil {
			return nil
		}
		if string(data) == id {
			ip := path.Base(p)
			ret = net.ParseIP(ip)
			if err := os.Remove(p); err != nil {
				return nil
			}
		}
		return nil
	})
	return ret, err
}
