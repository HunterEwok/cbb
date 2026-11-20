#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Runs a second member on a Linux host in a network namespace of its own, so
# that its traffic takes another way out than the host's own member: through
# a SOCKS5 proxy, such as a VPN client's local inbound (a device with
# os = "netns" in the inventory; docs/maintainers/testbench.md). Run it as root, or as a
# user with sudo for it:
#
#   sh setup-netns.sh setup NAME SOCKS TUN2SOCKS  # once: the namespace, its way out, the units
#   sh setup-netns.sh up NAME CBB                 # the cbb binary CBB, its state empty, started (R1)
#   sh setup-netns.sh down NAME                   # the service stopped, its state gone (R3)
#   sh setup-netns.sh teardown NAME               # all of it gone again
#
# NAME is the device's name in the inventory (1 to 10 small letters and
# digits). SOCKS is the proxy's host:port as the host reaches it, such as
# 127.0.0.1:1080. Without UDP (SOCKS5 UDP ASSOCIATE) the member goes away
# from home with VLESS, which runs over TCP; WireGuard needs the UDP.
# TUN2SOCKS is a tun2socks binary (github.com/xjasonlyu/tun2socks) for this
# host's CPU.
#
# Everything lives in /opt/cbbbench-netns/NAME and two units,
# cbbbench-NAME-net (tun2socks) and cbbbench-NAME (the service). tun2socks
# runs in the host's namespace, where it reaches the proxy, and its TUN
# interface is moved into the member's namespace as the only way out, so
# nothing of the member reaches the host's own network. The namespace
# resolves names over TCP (use-vc), which any SOCKS proxy carries, and
# reaches IPv4 and IPv6 addresses alike, so a name's AAAA does not hang.
set -eu

base=/opt/cbbbench-netns

usage() {
	echo "usage: setup-netns.sh setup NAME SOCKS TUN2SOCKS | up NAME CBB | down NAME | teardown NAME" >&2
	exit 2
}

[ "$(id -u)" -eq 0 ] || exec sudo -n sh "$0" "$@"

[ $# -ge 2 ] || usage
name=$2
case $name in '' | *[!a-z0-9]*) usage ;; esac
[ ${#name} -le 10 ] || usage
dir=$base/$name
ns=cbbbench-$name
link=cbbt-$name
unit=cbbbench-$name

case $1 in
setup)
	[ $# -eq 4 ] || usage
	socks=$3
	t2s=$4
	command -v ip >/dev/null || { echo "setup-netns.sh: needs ip (iproute2)" >&2; exit 1; }
	mkdir -p "$dir/bin" "$dir/state" "$dir/run"
	chmod 0700 "$dir/state"
	[ "$t2s" -ef "$dir/bin/tun2socks" ] || install -m 0755 "$t2s" "$dir/bin/tun2socks"
	mkdir -p "/etc/netns/$ns"
	printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\noptions use-vc\n' >"/etc/netns/$ns/resolv.conf"

	# The member's way out: the namespace, and in it tun2socks's interface.
	cat >"$dir/net-up" <<EOF
#!/bin/sh
# Written by tools/bench/setup-netns.sh: moves tun2socks's interface into
# the member's namespace and routes everything through it.
set -eu
i=0
until ip link show $link >/dev/null 2>&1; do
	i=\$((i + 1)); [ \$i -le 50 ] || { echo "no interface $link" >&2; exit 1; }
	sleep 0.1
done
ip link set $link netns $ns
ip -n $ns addr add 198.18.0.1/15 dev $link
ip -n $ns -6 addr add fd00:cbb::1/64 dev $link nodad
ip -n $ns link set $link up
ip -n $ns route add default dev $link
ip -n $ns -6 route add default dev $link
EOF
	chmod 0755 "$dir/net-up"
	# The bench's cbb: in the namespace, at the member's own socket.
	cat >"$dir/cbb" <<EOF
#!/bin/sh
# Written by tools/bench/setup-netns.sh: cbb of the member $name.
exec ip netns exec $ns env CBB_SOCKET=$dir/run/cbb.sock $dir/bin/cbb "\$@"
EOF
	chmod 0755 "$dir/cbb"

	cat >"/etc/systemd/system/$unit-net.service" <<EOF
# Written by tools/bench/setup-netns.sh: the way out of the member $name.
[Unit]
Description=cbb bench: the way out of $name through $socks
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=-/usr/bin/ip netns delete $ns
ExecStartPre=/usr/bin/ip netns add $ns
ExecStartPre=/usr/bin/ip -n $ns link set lo up
ExecStart=$dir/bin/tun2socks -device tun://$link -proxy socks5://$socks -loglevel warn
ExecStartPost=$dir/net-up
ExecStopPost=-/usr/bin/ip netns delete $ns
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
	cat >"/etc/systemd/system/$unit.service" <<EOF
# Written by tools/bench/setup-netns.sh: the member $name.
[Unit]
Description=cbb bench: the member $name in its namespace
BindsTo=$unit-net.service
After=$unit-net.service

[Service]
ExecStart=/usr/bin/ip netns exec $ns $dir/bin/cbb service -state $dir/state -socket $dir/run/cbb.sock
Restart=always
RestartSec=1
MemorySwapMax=0

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable --now "$unit-net.service"
	echo "The namespace $ns goes out through $socks:"
	ip netns exec "$ns" sh -c 'command -v curl >/dev/null && curl -fsS -m 15 https://ifconfig.me && echo' || echo "(no curl, or the proxy did not answer)"
	;;
up)
	[ $# -eq 3 ] || usage
	[ -x "$dir/cbb" ] || { echo "setup-netns.sh: run setup for $name first" >&2; exit 1; }
	systemctl stop "$unit.service" 2>/dev/null || true
	install -m 0755 "$3" "$dir/bin/cbb"
	rm -rf "${dir:?}/state" && mkdir -m 0700 "$dir/state"
	systemctl enable --now "$unit-net.service" "$unit.service"
	systemctl restart "$unit.service"
	;;
down)
	[ $# -eq 2 ] || usage
	systemctl stop "$unit.service" 2>/dev/null || true
	rm -rf "${dir:?}/state" && mkdir -m 0700 "$dir/state"
	;;
teardown)
	[ $# -eq 2 ] || usage
	systemctl disable --now "$unit.service" "$unit-net.service" 2>/dev/null || true
	rm -f "/etc/systemd/system/$unit.service" "/etc/systemd/system/$unit-net.service"
	systemctl daemon-reload
	ip netns delete "$ns" 2>/dev/null || true
	rm -rf "/etc/netns/$ns" "${dir:?}"
	rmdir "$base" 2>/dev/null || true
	;;
*)
	usage
	;;
esac
