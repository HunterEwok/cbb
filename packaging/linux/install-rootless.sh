#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs cbb, with its helper when the archive has one, for the user who
# runs it, without root (a rootless install, D-79; docs/design.md,
# "Rootless installs"):
#
#   sh install.sh --rootless [--port N] [--home-cgnat on|off] [--auto-update on|off] [--no-helper] [--no-pair] path/to/cbb
#
# install.sh runs this script for --rootless. It puts the binary in
# ~/.local/bin, the service (and, with the helper, the desktop agent) in the
# user's systemd user units, the tmux configuration in
# ~/.local/share/cbb, the settings in ~/.config/cbb
# and the state in ~/.local/state/cbb, and starts the service.
# Every program of the user can read the device's keys, so the device is
# never the group's root, an admin or a hub. It has no firewall rules, no
# TPM, no uinput or console helper and no polkit rule, and it runs while
# the user is logged in unless the user may linger. --no-helper leaves
# cbb-helper out, and a device installed without it stays so on later runs
# and updates. uninstall.sh, run as the same user, removes it again.
set -eu

if [ "${CBB_ERROR_DETAILS:-}" = 1 ]; then
	set -x
fi
failed() {
	rc=$1
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ] && [ "${CBB_ERROR_DETAILS:-}" != 1 ]; then
		note install.sh "failed (exit status %s). For every command it ran: CBB_ERROR_DETAILS=1, and run it again." "$rc"
	fi
}
trap 'failed $?' EXIT
# The messages in the user's language (packaging/l10n.sh), read before
# LC_ALL=C below.
cbb_l10n=$(cd "$(dirname "$0")" && pwd)/../l10n
# shellcheck source=packaging/l10n.sh
. "$cbb_l10n.sh"
export LC_ALL=C

usage() {
	echo "usage: sh install.sh --rootless [--port N] [--home-cgnat on|off] [--auto-update on|off] [--no-helper] [--no-pair] path/to/cbb" >&2
	exit 2
}
port=
cgnat=${CBB_HOME_CGNAT:-}
auto=
nohelper=no
while [ $# -gt 1 ]; do
	case $1 in
	--rootless) ;;
	--no-pair) CBB_PAIR=no ;;
	--no-helper) nohelper=yes ;;
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
		note install.sh "%s needs root; a rootless install has no console or uinput helper" "$1"
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
	note install.sh "CBB_HOME_CGNAT is 1 or 0, not %s" "$cgnat"
	exit 2
	;;
esac
case $port in
'') ;;
*[!0-9]*) usage ;;
*)
	if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
		note install.sh "--port takes a port from 1024 to 65535"
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
	note install.sh "--rootless installs for your own user: run it without sudo. With sudo, install.sh without --rootless installs the system service, which is safer."
	exit 1
fi
if ! systemctl --user show-environment >/dev/null 2>&1; then
	note install.sh "a rootless install runs as a systemd user unit, and this session has no systemd user manager; log in to a desktop or over ssh and run it again"
	exit 1
fi
if ! "$bin" version >/dev/null 2>&1; then
	note install.sh "%s does not run on this machine; is it built for %s?" "$bin" "$(uname -m)"
	exit 1
fi
for f in /usr/local/bin/cbb /opt/cbb/bin/cbb /etc/systemd/system/cbb.service; do
	if [ -e "$f" ]; then
		note install.sh "CBB is installed for the whole system here (%s), and one device runs one service; remove it first or keep it" "$f"
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
# cbb runs with its helper when the archive has one, unless --no-helper
# says otherwise or cbb runs here without it already; then it stays so.
helper=no
if [ -f "$(dirname "$bin")/cbb-helper" ] && [ "$nohelper" = no ]; then
	helper=yes
	if [ -x "$cbb" ] && [ ! -f "${cbb%/*}/cbb-helper" ]; then
		helper=no
	fi
fi

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
if [ "$helper" = yes ]; then
	install -m 0755 "$(dirname "$bin")/cbb-helper" "${cbb%/*}/cbb-helper.new"
	mv "${cbb%/*}/cbb-helper.new" "${cbb%/*}/cbb-helper"
else
	rm -f "${cbb%/*}/cbb-helper"
fi
install -m 0644 "$here/uninstall.sh" "$share/uninstall.sh"
# uninstall.sh speaks the user's language too.
install -m 0644 "$here/../l10n.sh" "$share/l10n.sh"
rm -rf "$share/l10n"
cp -R "$here/../l10n" "$share/l10n"
install -m 0644 "$here/../tmux/cbb.conf" "$share/tmux.conf"
place "$here/cbb-rootless.service" "$units/cbb.service"
# The desktop agent is the helper's.
if [ "$helper" = yes ]; then
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
if [ "$helper" = yes ]; then
	systemctl --user enable cbb-agent.service >/dev/null 2>&1 || true
	if systemctl --user is-active -q graphical-session.target 2>/dev/null; then
		systemctl --user restart cbb-agent.service >/dev/null 2>&1 ||
			note install.sh "the desktop agent did not start; it starts at your next login"
	fi
fi
# Without lingering the user's services stop at the last logout.
if [ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null)" != yes ]; then
	if ! loginctl enable-linger "$(id -un)" >/dev/null 2>&1; then
		say "CBB runs while you are logged in. To keep it running after you log out, an administrator runs: sudo loginctl enable-linger %s" "$(id -un)"
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
	note install.sh "the service did not answer within 10 s: %s" "$out"
	return 1
}
answers "$cbb" || true

# shellcheck source=packaging/update.sh
. "$here/../update.sh"
update_setup "$cbb" "$bin" "$auto"

say "CBB is running for %s on TCP port %s, installed without root: it can never be the group's root, an admin or the hub. If a firewall limits incoming connections here, an administrator allows TCP %s and UDP 5353 from the home network. To remove it: %s" "$(id -un)" "$port" "$port" "sh $share/uninstall.sh"
run=cbb
case ":$PATH:" in
*":${cbb%/*}:"*) ;;
*) run=$cbb ;;
esac
say "For copy and paste in tmux, add this line to ~/.tmux.conf: source-file -q %s/tmux.conf" "$share"
if [ "$helper" = no ]; then
	# shellcheck source=packaging/pair.sh
	. "$here/../pair.sh"
	if ! pair_now "$cbb" ""; then
		say "Next: see member/README.md; in short, %s pair here, and scan its QR code with the phone app." "$run"
	fi
else
	say "Next: run %s pair and scan its QR code with the CBB app on your phone." "$run"
fi
