#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Counts the server's traffic for the money and traffic budget
# (docs/relay-budget.md, "Money and traffic"): every run adds a sample of
# the bytes through the network interface, keeps the last 25 hours of
# them, and writes the bytes of the last 24 hours to
# /srv/cbb.tools/status/traffic.json, which tools/monitor reads from
# outside. Totals only: nothing about a group, a device or an address.
# Run by cbb-traffic.timer as /usr/local/lib/cbb/cbb-traffic.sh.
set -eu

IFACE=${CBB_TRAFFIC_IFACE:-$(ip route show default | awk '{ print $5; exit }')}
STATE=${STATE_DIRECTORY:-/var/lib/cbb-traffic}/samples
OUT=${CBB_TRAFFIC_OUT:-/srv/cbb.tools/status/traffic.json}

now=$(date +%s)
rx=$(cat "/sys/class/net/$IFACE/statistics/rx_bytes")
tx=$(cat "/sys/class/net/$IFACE/statistics/tx_bytes")
echo "$now $rx $tx" >>"$STATE"
awk -v cut=$((now - 25 * 3600)) '$1 >= cut' "$STATE" >"$STATE.new"
mv "$STATE.new" "$STATE"

# Sums the growth between the samples of the last 24 hours; a counter that
# went down started again at a reboot, and its new value is all growth.
awk -v cut=$((now - 24 * 3600)) -v now="$now" '
	# The last sample before the 24 hours is where they start.
	$1 < cut { first = $1; prx = $2; ptx = $3; have = 1; next }
	{
		if (!have) { first = $1; prx = $2; ptx = $3; have = 1; next }
		drx = $2 - prx; if (drx < 0) drx = $2
		dtx = $3 - ptx; if (dtx < 0) dtx = $3
		srx += drx; stx += dtx; prx = $2; ptx = $3
	}
	END {
		if (!first) first = now
		printf "{\"updated_ms\":%d,\"hours\":%.1f,\"rx_bytes\":%.0f,\"tx_bytes\":%.0f,\"day_bytes\":%.0f}\n",
			now * 1000, (now - first) / 3600, srx, stx, srx + stx
	}
' "$STATE" >"$OUT.new"
mv "$OUT.new" "$OUT"
