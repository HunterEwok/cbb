#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Runs the open blind relay of the bench's relay suite (P12) beside the
# forwarder on a server, and takes it away again. Run it on the server with
# sudo, after cbb is installed at /usr/local/bin/cbb:
#
#   sudo sh setup-relay.sh setup [PORT]      PORT: 8765 by default
#   sudo sh setup-relay.sh teardown [--purge]
#
# setup writes the systemd unit cbb-relay (no group keys, no logs, its own
# dynamic user), starts it, opens PORT for TCP and UDP in ufw when ufw is on
# and prints the relay's key for the inventory. A hosting provider's own
# firewall must allow the port too. teardown stops and removes the unit and
# the ufw rules; --purge also removes the relay's key.
set -eu

unit=/etc/systemd/system/cbb-relay.service
keys=/var/lib/private/cbb-relay

[ "$(id -u)" -eq 0 ] || {
	echo "setup-relay.sh: run it with sudo" >&2
	exit 1
}

ufw_on() { command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; }

case ${1:-} in
setup)
	port=${2:-8765}
	cat >"$unit" <<EOF
[Unit]
Description=cbb blind relay (holds no group keys, keeps no logs)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/cbb relay -open -listen :$port
DynamicUser=yes
StateDirectory=cbb-relay
StateDirectoryMode=0700
StandardOutput=null
StandardError=null
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable --now cbb-relay
	if ufw_on; then
		ufw allow "$port/tcp" comment "cbb relay" >/dev/null
		ufw allow "$port/udp" comment "cbb relay" >/dev/null
	fi
	# The service makes its key on its first run.
	for _ in $(seq 50); do
		[ ! -f "$keys/relay.pem" ] || break
		sleep 0.2
	done
	echo "The relay listens on port $port; open it in the hosting provider's firewall too. Its key for the inventory:"
	/usr/local/bin/cbb relay -open -key "$keys/relay.pem" -show-key
	;;
teardown)
	port=$(sed -n 's/^ExecStart=.*-listen :\([0-9]*\).*/\1/p' "$unit" 2>/dev/null)
	systemctl disable --now cbb-relay 2>/dev/null || true
	rm -f "$unit"
	systemctl daemon-reload
	if [ -n "$port" ] && ufw_on; then
		ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
		ufw delete allow "$port/udp" >/dev/null 2>&1 || true
	fi
	[ "${2:-}" != --purge ] || rm -rf "$keys"
	echo "The relay is gone."
	;;
*)
	echo "usage: sudo sh setup-relay.sh setup [PORT] | teardown [--purge]" >&2
	exit 2
	;;
esac
