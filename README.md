# CNI IPAM For AWS EIPs

This is an [IPAM plugin](https://github.com/containernetworking/cni/blob/master/SPEC.md#ip-allocation) for [CN](https://github.com/containernetworking/cni)I.

It uses the instance metadata API to get a list of EIPs on a given interface to
determine the available allocation pool. It is particularly useful with the
ipvlan driver in L3 mode for allocating container IPs. The process will need
access to this API.

It can optionally take a list of override IPs to allocate from, which can be
useful in testing.

This will use the [host-local disk backend](https://github.com/containernetworking/cni/tree/master/plugins/ipam/host-local) for allocation persistence.

Sample network config, will look for EIPs on eth2

```json
{
    "name": "default",
    "ipam": {
        "type": "eip",
        "interface": "eth2"
    }
}
```


Overriding (for testing)

```json
{
    "name": "default",
    "ipam": {
        "type": "eip",
        "override": [
            "192.168.51.100",
            "192.168.98.34"
        ]
    }
}
```
