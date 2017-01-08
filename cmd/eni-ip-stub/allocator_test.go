package main

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"

	ts "github.com/containernetworking/cni/plugins/ipam/host-local/backend/testing"
)

func TestIPSorting(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.168.50.1"), net.ParseIP("192.168.100.5"), net.ParseIP("192.168.100.2")}

	sort.Sort(netIps(ips))
	if !reflect.DeepEqual([]net.IP{net.ParseIP("192.168.50.1"), net.ParseIP("192.168.100.2"), net.ParseIP("192.168.100.5")},
		ips) {
		t.Errorf("Sorted output does not match expected, got: %#v", ips)
	}
}

// func TestAllocatorOverride(t *testing.T) {
// 	_, err := NewIPAllocator(&IPAMConfig{}, newStore())
// 	if err == nil {
// 		t.Error("Empty config should raise error!")
// 	}
// 	orCfg := &IPAMConfig{
// 		OverrideIPs: []net.IP{
// 			net.ParseIP("1.2.3.4"),
// 			net.ParseIP("2.3.4.5"),
// 			net.ParseIP("3.4.5.6"),
// 		},
// 		OverrideSubnet: "0.0.0.0/4",
// 	}
// 	a, err := NewIPAllocator(orCfg, newStore())
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	testAllocator(a, t)
// }

// func TestAllocatorMD(t *testing.T) {
// 	ifs, err := net.Interfaces()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	var iface net.Interface
// 	for _, i := range ifs {
// 		if i.HardwareAddr.String() != "" {
// 			iface = i
// 			break
// 		}
// 	}
// 	orCfg := &IPAMConfig{
// 		Interface: iface.Name,
// 	}
// 	a, err := NewIPAllocator(orCfg, newStore())
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	ifAddr, err := iface.Addrs()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	ifIP, _, err := net.ParseCIDR(ifAddr[0].String())
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	mdips := fmt.Sprintf("%s\n2.3.4.5\n1.2.3.4\n3.4.5.6", ifIP)
// 	a.md = &testMd{
// 		mac:    iface.HardwareAddr.String(),
// 		ips:    mdips,
// 		subnet: "0.0.0.0/4",
// 	}
// 	testAllocator(a, t)
// }

type testMd struct {
	mac    string
	ips    string
	subnet string
}

func (t *testMd) GetMetadata(key string) (string, error) {
	if key == fmt.Sprintf("/network/interfaces/macs/%s/local-ipv4s/", t.mac) {
		return t.ips, nil
	}
	if key == fmt.Sprintf("/network/interfaces/macs/%s/subnet-ipv4-cidr-block", t.mac) {
		return t.subnet, nil
	}
	return "", errors.New("Not found!")
}

func testAllocator(a *IPAllocator, t *testing.T) {
	ip1, err := a.Get("one")
	if err != nil {
		t.Fatal(err)
	}
	if !ip1.IP.IP.Equal(net.ParseIP("1.2.3.4")) {
		t.Error("ip1 not expected")
	}
	if ip1.IP.Mask.String() != "f0000000" {
		t.Error("mask not expected")
	}
	ip2, err := a.Get("two")
	if err != nil {
		t.Fatal(err)
	}
	if !ip2.IP.IP.Equal(net.ParseIP("2.3.4.5")) {
		t.Error("ip2 not expected")
	}
	ip3, err := a.Get("three")
	if err != nil {
		t.Fatal(err)
	}
	if !ip3.IP.IP.Equal(net.ParseIP("3.4.5.6")) {
		t.Error("ip3 not expected")
	}
	_, err = a.Get("four")
	if err == nil || !strings.HasPrefix(err.Error(), "No free IPs in network") {
		t.Error("Allocating a fourth should have errored")
	}
	err = a.Release("one")
	if err != nil {
		t.Error(err)
	}
	err = a.Release("three")
	if err != nil {
		t.Error(err)
	}
	// Next assignment should get 3, even though 1 is free too.
	ip4, err := a.Get("four")
	if err != nil {
		t.Error(err)
	}
	if !ip4.IP.IP.Equal(net.ParseIP("1.2.3.4")) {
		t.Error("ip4 not expected")
	}
}

func newStore() *ts.FakeStore {
	m := map[string]string{}
	return ts.NewFakeStore(m, nil)
}
