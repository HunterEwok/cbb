#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The Go tests under the race detector, as the macOS job runs them, and as a
# Mac runs them before a push. Usage: go-test-race.sh COVERPROFILE.
#
# The packages whose tests carry packets through gVisor's network stack (the
# tunnel, VLESS, the forwarder) run one at a time, after the others: under
# -race on macOS that stack is about a hundred times slower than without it
# (on Linux, a few times), and a test binary that shares the runner's three
# cores with others gets less than one. WireGuard's and TCP's own timers then
# take over (a lost handshake goes again after 5 s), and the tests miss their
# waits, as TestHubOverXHTTP did. The others run side by side as go test
# runs them.
#
# CBB_RACE_CPU sets -cpu for the network stack's packages, so that a Mac,
# whose cores are faster than the runner's, can give them fewer.
set -eu

out=$1
pkgs=$(go list ./...)
# A package's tests use the network stack when gvisor's tcpip/stack is among
# the dependencies of its test binary.
net=$(go list -test -f '{{if .ForTest}}{{.ForTest}}{{range .Deps}} {{.}}{{end}}{{end}}' ./... |
	awk '/ gvisor\.dev\/gvisor\/pkg\/tcpip\/stack( |$)/ {print $1}' | sort -u)
rest=$(printf '%s\n' "$pkgs" | grep -vxF "$net" || true)

status=0
# shellcheck disable=SC2086 # the package lists split on purpose
go test -race -timeout 20m -coverprofile="$out.rest" $rest || status=1
cpu=
[ -n "${CBB_RACE_CPU:-}" ] && cpu="-cpu=$CBB_RACE_CPU"
# shellcheck disable=SC2086
go test -race -timeout 20m -p 1 $cpu -coverprofile="$out.net" $net || status=1

# One profile, as before: the second's mode line goes.
{
	cat "$out.rest"
	tail -n +2 "$out.net"
} >"$out"
rm -f "$out.rest" "$out.net"
exit $status
