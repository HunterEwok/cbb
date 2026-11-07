#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs cbb's full member or lite member for the user who
# runs it, without root (a rootless install, D-79; docs/design.md,
# "Rootless installs"):
#
#   sh install.sh --rootless [--port N] [--home-cgnat on|off] [--auto-update on|off] [--no-pair] path/to/cbb
#
# install.sh runs this script for --rootless. It puts the binary in
# ~/.local/bin, the service (and the full member's desktop agent) in the
# user's systemd user units, the tmux configuration in
# ~/.local/share/cbb, the settings in ~/.config/cbb
# and the state in ~/.local/state/cbb, and starts the service.
# Every program of the user can read the device's keys, so the device is
# never the group's root, an admin or a hub. It has no firewall rules, no
# TPM, no uinput or console helper and no polkit rule, and it runs while
# the user is logged in unless the user may linger. uninstall.sh, run as
# the same user, removes it again.
set -eu

if [ "${CBB_ERROR_DETAILS:-}" = 1 ]; then
	set -x
fi
failed() {
	rc=$1
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ] && [ "${CBB_ERROR_DETAILS:-}" != 1 ]; then
		echo "install.sh: failed (exit status $rc). For every command it ran: CBB_ERROR_DETAILS=1, and run it again." >&2
	fi
}
trap 'failed $?' EXIT
export LC_ALL=C

usage() {
	echo "usage: sh install.sh --rootless [--port N] [--home-cgnat on|off] [--auto-update on|off] [--no-pair] path/to/cbb" >&2
	exit 2
}
port=
cgnat=${CBB_HOME_CGNAT:-}
auto=
while [ $# -gt 1 ]; do
	case $1 in
	--rootless) ;;
	--no-pair) CBB_PAIR=no ;;
	--port)
		port=$2
		shift
		;;
	--home-cgnat)
		case $2 in
		on) cgnat=1 ;;
		off) cgnat=0 ;;
		*) usage ;;
		esac
		shift
		;;
	--auto-update)
		case $2 in
		on | off) auto=$2 ;;
		*) usage ;;
		esac
		shift
		;;
	--console | --uinput)
		echo "install.sh: $1 needs root; a rootless install has no console or uinput helper" >&2
		exit 2
		;;
	*) usage ;;
	esac
	shift
done
[ $# -eq 1 ] || usage
case $cgnat in
'' | 0 | 1) ;;
*)
	echo "install.sh: CBB_HOME_CGNAT is 1 or 0, not $cgnat" >&2
	exit 2
	;;
esac
case $port in
'') ;;
*[!0-9]*) usage ;;
*)
	if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
		echo "install.sh: --port takes a port from 1024 to 65535" >&2
		exit 2
	fi
	;;
esac
bin=$1
case $bin in
*/*) ;;
*) bin=./$bin ;;
esac
here=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -eq 0 ]; then
	echo "install.sh: --rootless installs for your own user: run it without sudo. With sudo, install.sh without --rootless installs the system service, which is safer." >&2
	exit 1
fi
if ! systemctl --user show-environment >/dev/null 2>&1; then
	echo "install.sh: a rootless install runs as a systemd user unit, and this session has no systemd user manager; log in to a desktop or over ssh and run it again" >&2
	exit 1
fi
if ! "$bin" version >/dev/null 2>&1; then
	echo "install.sh: $bin does not run on this machine; is it built for $(uname -m)?" >&2
	exit 1
fi
kind=full
if "$bin" version 2>/dev/null | grep -q 'lite member'; then
	kind=lite
fi
if [ "$kind" = lite ] && [ "$cgnat" = 1 ]; then
	echo "install.sh: --home-cgnat is for the full member" >&2
	exit 2
fi
for f in /usr/local/bin/cbb /opt/cbb/bin/cbb /etc/systemd/system/cbb.service; do
	if [ -e "$f" ]; then
		echo "install.sh: CBB is installed for the whole system here ($f), and one device runs one service; remove it first or keep it" >&2
		exit 1
	fi
done

# The program finds the user's service by this too (internal/rootless).
export CBB_ROOTLESS=1
home=${HOME:?install.sh: HOME is not set}
cbb=$home/.local/bin/cbb
share=${XDG_DATA_HOME:-$home/.local/share}/cbb
config=${XDG_CONFIG_HOME:-$home/.config}
units=$config/systemd/user
state=${XDG_STATE_HOME:-$home/.local/state}/cbb
env=$config/cbb/cbb.env

# place FILE DEST installs FILE, a unit or the autostart entry, with the
# binary's path here.
place() {
	sed "s|/usr/local/bin/cbb|$cbb|g" "$1" >"$2.new"
	chmod 0644 "$2.new"
	mv "$2.new" "$2"
}
install -d -m 0755 "${cbb%/*}" "$share" "$units"
install -d -m 0700 "$state" "${env%/*}"
install -m 0755 "$bin" "$cbb.new"
mv "$cbb.new" "$cbb"
install -m 0644 "$here/uninstall.sh" "$share/uninstall.sh"
install -m 0644 "$here/../tmux/cbb.conf" "$share/tmux.conf"
place "$here/cbb-rootless.service" "$units/cbb.service"
# The lite member has no desktop clipboard, so no agent.
if [ "$kind" = full ]; then
	install -d -m 0755 "$config/autostart"
	place "$here/cbb-agent.service" "$units/cbb-agent.service"
	place "$here/cbb-desktop.desktop" "$config/autostart/cbb-desktop.desktop"
fi

# The settings: the ones given, else the ones kept from before, else the
# defaults.
if [ -z "$port" ]; then
	port=$(sed -n 's/^CBB_PORT=//p' "$env" 2>/dev/null | tail -n 1)
fi
port=${port:-8764}
if [ -z "$cgnat" ]; then
	cgnat=$(sed -n 's/^CBB_HOME_CGNAT=//p' "$env" 2>/dev/null | tail -n 1)
fi
[ "$cgnat" = 1 ] || cgnat=0
if [ "$port" = 8764 ] && [ "$cgnat" = 0 ]; then
	rm -f "$env"
else
	{
		echo "# Written by cbb's install.sh --rootless; change it with install.sh --rootless --port N and --home-cgnat on|off."
		if [ "$port" != 8764 ]; then
			echo "CBB_PORT=$port"
		fi
		if [ "$cgnat" = 1 ]; then
			echo "CBB_HOME_CGNAT=1"
		fi
	} >"$env"
	chmod 0600 "$env"
fi

systemctl --user daemon-reload
systemctl --user enable cbb.service
systemctl --user reset-failed cbb.service >/dev/null 2>&1 || true
systemctl --user restart cbb.service
if [ "$kind" = full ]; then
	systemctl --user enable cbb-agent.service >/dev/null 2>&1 || true
	if systemctl --user is-active -q graphical-session.target 2>/dev/null; then
		systemctl --user restart cbb-agent.service >/dev/null 2>&1 ||
			echo "install.sh: the desktop agent did not start; it starts at your next login" >&2
	fi
fi
# Without lingering the user's services stop at the last logout.
if [ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null)" != yes ]; then
	if ! loginctl enable-linger "$(id -un)" >/dev/null 2>&1; then
		echo "CBB runs while you are logged in. To keep it running after you log out, an administrator runs: sudo loginctl enable-linger $(id -un)"
	fi
fi

answers() { # cbb
	i=0
	while [ $i -lt 40 ]; do
		out=$("$1" status 2>&1) && return 0
		case $out in *"in a group"* | *"no group"*) return 0 ;; esac
		sleep 0.25
		i=$((i + 1))
	done
	echo "install.sh: the service did not answer within 10 s: $out" >&2
	return 1
}
answers "$cbb" || true

# shellcheck source=packaging/update.sh
. "$here/../update.sh"
update_setup "$cbb" "$bin" "$auto"

echo "CBB is running for $(id -un) on TCP port $port, installed without root: it can never be"
echo "the group's root, an admin or the hub. If a firewall limits incoming connections here, an administrator"
echo "allows TCP $port and UDP 5353 from the home network. To remove it: sh $share/uninstall.sh"
run=cbb
case ":$PATH:" in
*":${cbb%/*}:"*) ;;
*) run=$cbb ;;
esac
echo "For copy and paste in tmux, add this line to ~/.tmux.conf: source-file -q $share/tmux.conf"
if [ "$kind" = lite ]; then
	# shellcheck source=packaging/pair.sh
	. "$here/../pair.sh"
	if ! pair_now "$cbb" ""; then
		echo "Next: see member/README.md; in short, $run pair here, and scan its QR code with the phone app."
	fi
else
	echo "Next: run $run pair and scan its QR code with the CBB app on your phone."
fi
