# netstack

The userspace network stack behind the tunnel's WireGuard device (gVisor's netstack as a
`tun.Device`, with dialers and listeners on it), copied from the package `tun/netstack` of
the module [`github.com/amnezia-vpn/amneziawg-go`](https://github.com/amnezia-vpn/amneziawg-go)
v0.2.20-0.20260724121833-457d920a1a7d (module checksum
`h1:X/D+VZITnGJCaajBdcBTYQxcR93EcVRDjXLd/ytH/b4=`), which has it from wireguard-go.

Three changes: the notice at the top is in line comments, `Dial` parses the port with
`strconv.ParseUint` as 16 bits (the same check, in a form code scanning follows), and `Close` no longer closes the channel of outgoing packets. gVisor's channel
endpoint calls `WriteNotify` outside its lock, so a TCP worker could still send a packet,
such as a reset, after `Close`, and panic on the closed channel. A separate `closed` channel
now ends `Read` and `WriteNotify` instead.

The code is under the MIT license in [LICENSE](LICENSE), not under the AGPL; the file keeps
its original copyright notice. cbb release archives carry this notice.

To update it, copy `tun/netstack/tun.go` of a newer version over this one, apply the change
again unless upstream fixed it, record the version and checksum here, and run the tests.
