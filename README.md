# CNI IPAM For AWS ENI Private IPs

This is an [IPAM plugin](https://github.com/containernetworking/cni/blob/master/SPEC.md#ip-allocation) for [CNI](https://github.com/containernetworking/cni).

It uses the instance metadata API to get a list of Private IPs on a given
interface to determine the available allocation pool. It is particularly useful
with the ipvlan driver in L3 mode for allocating container IPs. The process will
need access to this API.

It can optionally take a list of override IPs to allocate from, which can be
useful in testing.

This will use the [host-local disk backend](https://github.com/containernetworking/cni/tree/master/plugins/ipam/host-local) for allocation persistence.

Sample network config, will look for additional pre-assigned free IPs on eth2

```json
{
    "name": "default",
    "ipam": {
        "type": "eni-ip",
        "interface": "eth2"
    }
}
```

In dynamic mode, the IPs do not be pre-allocated, the driver will request/free them on demand. This requires the correct instance IAM permissions.

```json
{
    "name": "default",
    "ipam": {
        "type": "eni-ip",
        "interface": "eth2",
        "dynamic": true
    }
}
```

Will need an IAM policy assigned to the instance like

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1476573934000",
            "Effect": "Allow",
            "Action": [
                "ec2:AssignPrivateIpAddresses",
                "ec2:UnassignPrivateIpAddresses"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```



Overriding (for testing)

```json
{
    "name": "default",
    "ipam": {
        "type": "eni-ip",
        "override": [
            "192.168.51.100",
            "192.168.98.34"
        ]
    }
}
```

## Future plans

Private IP slack pool, real error handling
