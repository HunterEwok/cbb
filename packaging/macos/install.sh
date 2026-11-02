#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs clipboardbridge on a Mac:
#
#   sudo sh install.sh [--in-place] [--port N] [--home-cgnat on|off] [--auto-update on|off] [--express | --no-firewall] path/to/cbb
#
# It creates the hidden _clipboardbridge user and group, installs the binary to
# /usr/local/bin, the service as a LaunchDaemon and the pasteboard agent as
# a LaunchAgent, adds the user who ran sudo to the group, asks whether the
# application firewall may let the service take connections, and starts or
# restarts both. --express (CBB_FIREWALL=express) allows it without asking
# and says so, --no-firewall (CBB_FIREWALL=no) does not and prints the
# commands that would; the answer is kept for later runs. With --in-place the agent and cbb in PATH run the binary
# where it is instead of a copy, for Homebrew, whose upgrades replace it
# there: the formula's caveats pass its opt path, and running this again
# after an upgrade restarts them on the new one. The service always runs a
# copy that only root can change, since it holds the group's keys and a
# Homebrew prefix belongs to the user. --port moves the member port from 8764
# to N, kept in /etc/clipboardbridge/clipboardbridge.env as on Linux until the
# next --port; --port 8764 goes back. --home-cgnat on (or CBB_HOME_CGNAT=1)
# counts 100.64.0.0/10, the carrier-grade NAT range, as the home network
# too, kept in the same file; --home-cgnat off goes back. --auto-update
# on|off (or CBB_AUTO_UPDATE) answers whether it updates itself once a day to
# a signed release, which it asks otherwise and keeps (packaging/update.sh);
# a Homebrew copy is left to brew upgrade. uninstall.sh removes it all again.
set -eu

# A failure says so with its exit status; CBB_ERROR_DETAILS=1 shows every
# command as it runs, so that the output shows where and why it failed.
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

usage() {
	echo "usage: sudo sh install.sh [--in-place] [--port N] [--home-cgnat on|off] [--auto-update on|off] [--express | --no-firewall] path/to/cbb" >&2
	exit 2
}
inplace=no
port=
cgnat=${CBB_HOME_CGNAT:-}
firewall=${CBB_FIREWALL:-ask}
auto=
while [ $# -gt 1 ]; do
	case $1 in
	--in-place) inplace=yes ;;
	--express) firewall=express ;;
	--no-firewall) firewall=no ;;
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
case $firewall in
ask | express | no) ;;
yes) firewall=ask ;; # what get.sh passed before --express
*)
	echo "install.sh: CBB_FIREWALL is ask, express or no, not $firewall" >&2
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
# A bare file name would be looked up in PATH, not here.
case $bin in
*/*) ;;
*) bin=./$bin ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: run it with sudo" >&2
	exit 1
fi
if ! "$bin" version >/dev/null 2>&1; then
	echo "install.sh: $bin does not run on this Mac" >&2
	exit 1
fi
# A build without cgo has no pasteboard: its agent would only exit, and
# launchd start it again, over and over.
if "$bin" version | grep -q 'no pasteboard support'; then
	echo "install.sh: $bin was built without cgo, so it cannot link this Mac's clipboard; use a release build, or build it with CGO_ENABLED=1" >&2
	exit 1
fi

# Up to 0.2.0 clipboardbridge was called clipbridge, and its protocol does
# not reach this one: remove it, with its keys and user, so this Mac pairs
# again.
old=io.github.hunterewok.clipbridge
if [ -e /usr/local/bin/clipbridge ] || [ -e "/Library/LaunchDaemons/$old.plist" ]; then
	launchctl bootout "system/$old" 2>/dev/null || true
	if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		launchctl bootout "gui/$(id -u "$SUDO_USER")/$old.agent" 2>/dev/null || true
	fi
	rm -f "/Library/LaunchDaemons/$old.plist" "/Library/LaunchAgents/$old.agent.plist" /usr/local/bin/clipbridge
	rm -rf "/Library/Application Support/clipbridge" /Library/Logs/clipbridge
	dscl . -delete /Users/_clipbridge 2>/dev/null || true
	dscl . -delete /Groups/_clipbridge 2>/dev/null || true
	echo "Removed clipbridge, as Clipboard Bridge was called before; pair this Mac again."
fi

name=_clipboardbridge
if ! dscl . -read "/Groups/$name" >/dev/null 2>&1; then
	# A free ID below 500, so the account stays hidden.
	id=$(dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | sort -n | awk 'BEGIN{n=300} $1==n{n++} END{print n}')
	dscl . -create "/Groups/$name" PrimaryGroupID "$id"
	dscl . -create "/Groups/$name" RealName "clipboardbridge"
fi
gid=$(dscl . -read "/Groups/$name" PrimaryGroupID | awk '{print $2}')
if ! dscl . -read "/Users/$name" >/dev/null 2>&1; then
	uid=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | awk -v n="$gid" '$1==n{n++} END{print n}')
	dscl . -create "/Users/$name" UniqueID "$uid"
	dscl . -create "/Users/$name" PrimaryGroupID "$gid"
	dscl . -create "/Users/$name" UserShell /usr/bin/false
	dscl . -create "/Users/$name" NFSHomeDirectory /var/empty
	dscl . -create "/Users/$name" RealName "Clipboard Bridge service"
	dscl . -create "/Users/$name" IsHidden 1
fi

if [ "$inplace" = yes ]; then
	# launchd takes the path as it is: absolute, and plain enough for the plists.
	run=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")
	case $run in
	*[!A-Za-z0-9/._+-]*)
		echo "install.sh: --in-place needs a path of letters, digits and / . _ + -, not $run" >&2
		exit 2
		;;
	esac
	# A copy from an install without --in-place would shadow it in PATH;
	# on an Intel Mac /usr/local/bin/cbb is Homebrew's own link.
	if [ -f /usr/local/bin/cbb ] && [ ! -L /usr/local/bin/cbb ]; then
		rm -f /usr/local/bin/cbb
	fi
else
	run=/usr/local/bin/cbb
	if [ -L "$run" ]; then
		echo "install.sh: $run is a link, likely Homebrew's; run this with --in-place $run" >&2
		exit 1
	fi
	install -d -m 0755 /usr/local/bin
	install -m 0755 "$bin" "$run"
fi
# The socket's directory: members of the group may reach the socket, and
# only the service its state.
install -d -o "$name" -g "$name" -m 0750 "/Library/Application Support/clipboardbridge"
install -d -o "$name" -g "$name" -m 0700 "/Library/Application Support/clipboardbridge/state"
install -d -o "$name" -g "$name" -m 0750 /Library/Logs/clipboardbridge
# The service's own copy: a binary the user or another program can replace
# would get the service's keys at its next start.
service="/Library/Application Support/clipboardbridge/bin/cbb"
install -d -o root -g wheel -m 0755 "/Library/Application Support/clipboardbridge/bin"
install -o root -g wheel -m 0755 "$run" "$service.new"
mv -f "$service.new" "$service"

daemon=io.github.hunterewok.clipboardbridge
agent=io.github.hunterewok.clipboardbridge.agent
for p in "/Library/LaunchDaemons/$daemon.plist" "/Library/LaunchAgents/$agent.plist"; do
	exe=$run
	[ "$p" = "/Library/LaunchDaemons/$daemon.plist" ] && exe=$service
	sed "s|<string>/usr/local/bin/cbb</string>|<string>$exe</string>|" "$here/$(basename "$p")" >"$p.new"
	chmod 0644 "$p.new"
	mv "$p.new" "$p"
done

user=${SUDO_USER:-}
if [ -n "$user" ] && [ "$user" != root ]; then
	dseditgroup -o edit -a "$user" -t user "$name"
fi

# The settings, in the file the service and cbb read as on Linux: the ones
# given, else the ones kept from before, else the defaults (port 8764,
# 100.64.0.0/10 outside the home network).
env=/etc/clipboardbridge/clipboardbridge.env
install -d -m 0755 /etc/clipboardbridge
if [ -z "$port" ]; then
	port=$(sed -n 's/^CBB_PORT=//p' "$env" 2>/dev/null | tail -n 1)
fi
port=${port:-8764}
if [ -z "$cgnat" ]; then
	cgnat=$(sed -n 's/^CBB_HOME_CGNAT=//p' "$env" 2>/dev/null | tail -n 1)
fi
[ "$cgnat" = 1 ] || cgnat=0
# CBB_INTERFACES has no option: a line set by hand stays.
interfaces=$(sed -n 's/^CBB_INTERFACES=//p' "$env" 2>/dev/null | tail -n 1)
if [ "$port" = 8764 ] && [ "$cgnat" = 0 ] && [ -z "$interfaces" ]; then
	rm -f "$env"
else
	{
		echo "# Written by clipboardbridge's install.sh; change it with install.sh --port N and --home-cgnat on|off. A CBB_INTERFACES line is kept."
		if [ "$port" != 8764 ]; then
			echo "CBB_PORT=$port"
		fi
		if [ "$cgnat" = 1 ]; then
			echo "CBB_HOME_CGNAT=1"
		fi
		if [ -n "$interfaces" ]; then
			echo "CBB_INTERFACES=$interfaces"
		fi
	} >"$env"
	chmod 0644 "$env"
fi
if [ "$cgnat" = 1 ]; then
	echo "100.64.0.0/10 counts as the home network on this Mac (--home-cgnat on)."
fi

# The service takes connections from phones, other Macs and lite members at
# home. With the application firewall on, an unsigned program gets none until
# it is listed; the firewall knows the program by its real path, not a link.
# It is listed only with the user's consent, kept in firewall.answer, and
# uninstall.sh takes the entry away.
fw=/usr/libexec/ApplicationFirewall/socketfilterfw
listed="/Library/Application Support/clipboardbridge/firewall"
answer=/etc/clipboardbridge/firewall.answer
if [ -x "$fw" ]; then
	# An installation from before the question listed the program without
	# one: that counts as a Yes, kept from now on, so that an update never
	# takes the listing away without an answer.
	earlier=
	if [ -f "$listed" ] && [ ! -f "$answer" ]; then
		earlier=yes
	fi
	if [ -f "$listed" ]; then
		"$fw" --remove "$(cat "$listed")" >/dev/null 2>&1 || true
		rm -f "$listed"
	fi
	fwstate=off
	if "$fw" --getglobalstate 2>/dev/null | grep -q enabled; then
		fwstate=on
	fi
	echo "Firewall: the macOS application firewall ($fwstate). Clipboard Bridge requires this rule:"
	echo "  1. Allow incoming connections to $service. Purpose: connections from the group's devices"
	echo "     on TCP $port and finding them on UDP 5353 (mDNS). The application firewall allows a"
	echo "     program on every port and from every address; Clipboard Bridge itself accepts only"
	echo "     the home network."
	yes=$firewall
	how=
	if [ "$yes" = express ]; then
		how=" (express installation)"
	elif [ "$yes" = ask ]; then
		yes=$(cat "$answer" 2>/dev/null || true)
		how=" (as answered before)"
		if [ -n "$earlier" ]; then
			yes=yes how=" (kept from an earlier installation)"
		fi
	fi
	if [ "$yes" != yes ] && [ "$yes" != no ] && [ "$yes" != express ]; then
		echo "With Yes, Clipboard Bridge adds this rule, keeps it current on every update and removes it on uninstall."
		printf 'Add this rule now? [y/N] '
		yes=
		how=
		if (: </dev/tty) 2>/dev/null; then
			reply=
			read -r reply </dev/tty || reply=
			case $reply in
			y | Y | yes | Yes | YES) yes=yes ;;
			*) yes=no ;;
			esac
		else
			echo
			echo "No terminal to answer on; taken as No."
		fi
	fi
	case $yes in
	no) echo no >"$answer" ;;
	yes | express) echo yes >"$answer" ;;
	esac
	if [ "$yes" = yes ] || [ "$yes" = express ]; then
		"$fw" --add "$service" >/dev/null
		"$fw" --unblockapp "$service" >/dev/null
		echo "$service" >"$listed"
		echo "Added the rule above$how. Clipboard Bridge manages it from now on."
	else
		echo "No firewall rule was added. Clipboard Bridge works only while the firewall allows the rule above."
		echo "To add it by hand, run:"
		echo "  sudo $fw --add \"$service\""
		echo "  sudo $fw --unblockapp \"$service\""
		echo "To let Clipboard Bridge add and manage it, run the installer again with --express."
	fi
fi

# uninstall.sh stays where get.sh's download does not: beside the program,
# as on Linux.
install -d -m 0755 /usr/local/share/clipboardbridge
install -m 0644 "$here/uninstall.sh" /usr/local/share/clipboardbridge/uninstall.sh

# restart DOMAIN LABEL PLIST stops the job if it runs and starts it again.
# bootout returns before launchd has let the job go, and a bootstrap in that
# moment fails with "5: Input/output error", so wait for it to be gone.
restart() {
	launchctl bootout "$1/$2" 2>/dev/null || true
	for _ in $(seq 50); do
		launchctl print "$1/$2" >/dev/null 2>&1 || break
		sleep 0.2
	done
	launchctl bootstrap "$1" "$3"
}

restart system "$daemon" "/Library/LaunchDaemons/$daemon.plist"
# answers waits up to 10 s until the service answers on its socket: in no
# group cbb status says so, which is an answer too. A command right after
# the installer then finds it running.
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
answers "$run" || true
# How this copy came, and automatic updates.
# shellcheck source=packaging/update.sh
. "$here/../update.sh"
update_setup "$run" "$bin" "$auto"
if [ -n "$user" ] && [ "$user" != root ]; then
	restart "gui/$(id -u "$user")" "$agent" "/Library/LaunchAgents/$agent.plist"
fi
if [ "$port" != 8764 ]; then
	echo "Clipboard Bridge uses TCP port $port instead of 8764. If a firewall on the network limits"
	echo "incoming connections, allow TCP $port from the home network. The iPhone shortcut works only"
	echo "with 8764; the Clipboard Bridge app takes any port."
fi
# An update of a device in a group keeps its group: no need to join.
if [ -f "/Library/Application Support/clipboardbridge/state/identity.json" ]; then
	echo "Clipboard Bridge is running on TCP port $port, in its group."
else
	echo "Clipboard Bridge is running on TCP port $port. Join a group: sudo cbb pair, and scan its QR code with the phone or type the code from cbb pair on the group's root or an admin; or start a group: sudo cbb new."
fi
