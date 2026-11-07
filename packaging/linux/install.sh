#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs cbb on a Linux machine with systemd:
#
#   sudo sh install.sh [--console] [--uinput] [--port N] [--home-cgnat on|off] [--auto-update on|off] [--express | --no-firewall] [--no-pair] path/to/cbb
#
# The full member's archive and the lite member's
# (cbb-lite-linux-*) both carry this script, each with its own systemd unit beside it; cbb version
# tells the two apart. It installs the binary to /usr/local/bin, the service
# user, the systemd unit, for the full member the desktop autostart entry and user unit,
# the tray app when the archive has it and the machine has GTK 4 and WebKitGTK
# 6.0 (with its autostart and menu entries), and the tmux configuration, adds the user
# who ran sudo to the cbb group, and starts or restarts the service.
# --console also starts tmux after a login on the text console and the
# console helper for remote paste there. --uinput, for the
# full member, adds the uinput helper, which presses the keys of a remote
# paste on desktops without another way (GNOME and KDE without the portal's
# dialog), and loads the uinput module at boot. --port moves
# the member port from 8764 to N, kept in /etc/cbb/cbb.env
# until the next --port; --port 8764 goes back. It finds the firewall, lists
# the rules cbb needs (mDNS and its port from the home network)
# and asks whether to add them (firewall.sh); the answer is kept for later
# runs. --express (CBB_FIREWALL=express) adds them without asking and says
# what it added, --no-firewall (CBB_FIREWALL=no) adds none and prints the
# commands that would. While it manages them, every run keeps them current,
# so an old port stays closed. --home-cgnat on (or CBB_HOME_CGNAT=1) counts
# 100.64.0.0/10, the carrier-grade NAT range, as the home network too, for a
# home network that uses it: the service (CBB_HOME_CGNAT=1 in the same file), the systemd
# unit's address limit and the firewall rules; --home-cgnat off goes back.
# The full member only. --auto-update on|off (or CBB_AUTO_UPDATE) answers
# whether the full member updates itself once a day to a signed release,
# which it asks otherwise and keeps (packaging/update.sh, cbb update -auto).
# The lite member, once running and in no group, starts pairing and shows
# its QR code at once (packaging/pair.sh); --no-pair (CBB_PAIR=no), for a
# scripted install, leaves that for later.
# uninstall.sh removes it all again. --rootless installs the full member for
# the user who runs it, without sudo (install-rootless.sh, D-79).
#
# On SteamOS, whose / is read-only and replaced by each system update, the
# binary and the shared files go to /opt/cbb instead, which
# SteamOS keeps in /home, and a keep list in /etc/atomic-update.conf.d names
# the files it writes in /etc, which SteamOS otherwise drops on an update.
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
# The firewall tools answer in the user's language; what this reads is English.
export LC_ALL=C

# --rootless installs for the user who runs it, without sudo.
for a in "$@"; do
	if [ "$a" = --rootless ]; then
		if [ ! -f "$(dirname "$0")/install-rootless.sh" ]; then
			echo "install.sh: this archive has no install-rootless.sh, so it cannot install without root" >&2
			exit 2
		fi
		exec sh "$(dirname "$0")/install-rootless.sh" "$@"
	fi
done

usage() {
	echo "usage: sudo sh install.sh [--console] [--uinput] [--port N] [--home-cgnat on|off] [--auto-update on|off] [--express | --no-firewall] [--no-pair] path/to/cbb" >&2
	echo "   or: sh install.sh --rootless [--port N] [--home-cgnat on|off] [--auto-update on|off] [--no-pair] path/to/cbb" >&2
	exit 2
}
console=no
uinput=no
port=
cgnat=${CBB_HOME_CGNAT:-}
firewall=${CBB_FIREWALL:-ask}
auto=
while [ $# -gt 1 ]; do
	case $1 in
	--console) console=yes ;;
	--uinput) uinput=yes ;;
	--express) firewall=express ;;
	--no-firewall) firewall=no ;;
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
if ! command -v systemctl >/dev/null 2>&1; then
	echo "install.sh: systemd is required" >&2
	exit 1
fi
# CBB_OS_RELEASE names another os-release file, for the tests.
steamos=no
if [ "$(sed -n 's/^ID=//p' "${CBB_OS_RELEASE:-/etc/os-release}" 2>/dev/null | tr -d '"')" = steamos ]; then
	steamos=yes
fi
if [ "$steamos" = yes ]; then
	cbb=/opt/cbb/bin/cbb
	share=/opt/cbb/share
	sysusers=/etc/sysusers.d/cbb.conf
else
	cbb=/usr/local/bin/cbb
	share=/usr/local/share/cbb
	sysusers=/usr/lib/sysusers.d/cbb.conf
fi
# place MODE FILE DEST installs FILE, a unit or a desktop entry, with the
# paths of this system.
place() {
	sed -e "s|/usr/local/bin/cbb|$cbb|g" -e "s|/usr/local/share/cbb|$share|g" "$2" >"$3.new"
	chmod "$1" "$3.new"
	mv "$3.new" "$3"
}
if ! "$bin" version >/dev/null 2>&1; then
	echo "install.sh: $bin does not run on this machine; is it built for $(uname -m)?" >&2
	exit 1
fi

# The full member and the lite member share the command, the paths and the
# service, but neither can use the other's keys: switching is a new device.
kind_of() {
	if "$1" version 2>/dev/null | grep -q 'lite member'; then echo lite; else echo full; fi
}
kind=$(kind_of "$bin")
if [ -x "$cbb" ] && [ "$(kind_of "$cbb")" != "$kind" ]; then
	echo "install.sh: the $(kind_of "$cbb") member is installed here, and the $kind member cannot use its keys;" >&2
	echo "remove it first: sudo sh $share/uninstall.sh --purge" >&2
	exit 1
fi
if [ "$kind" = lite ] && [ "$cgnat" = 1 ]; then
	echo "install.sh: --home-cgnat is for the full member" >&2
	exit 2
fi

# The account cbb gets the group's keys, the quick actions' polkit rights
# and the control socket. One that an earlier install made says "cbb
# service" (cbb.sysusers); another, a person's or another program's, is
# never taken over, nor a group cbb of others without that account.
if pw=$(getent passwd cbb); then
	if [ "$(printf '%s\n' "$pw" | cut -d: -f5)" != "cbb service" ]; then
		echo "install.sh: an account named cbb exists here and is not this service's (its comment is not \"cbb service\");" >&2
		echo "it would get the group's keys. Rename or remove it, then run install.sh again." >&2
		exit 1
	fi
elif gr=$(getent group cbb) && [ -n "$(printf '%s\n' "$gr" | cut -d: -f4)" ]; then
	echo "install.sh: a group named cbb exists here with members ($(printf '%s\n' "$gr" | cut -d: -f4)), and no service account;" >&2
	echo "they would reach the service. Rename or remove the group, then run install.sh again." >&2
	exit 1
fi

install -d -m 0755 "${cbb%/*}"
install -m 0755 "$bin" "$cbb"
install -d -m 0755 "${sysusers%/*}"
# SteamOS may drop /etc/group's changes with an update, so the sysusers
# file says who is in the group too: the user who ran sudo, and those it
# named before. systemd-sysusers adds them again after an update.
members=
if [ "$steamos" = yes ]; then
	members=$(sed -n 's/^m \([^ ]*\) cbb$/\1/p' "$sysusers" 2>/dev/null || true)
	if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		members="$members $SUDO_USER"
	fi
fi
{
	cat "$here/cbb.sysusers"
	# shellcheck disable=SC2086 # one name per word
	for m in $(printf '%s\n' $members | sort -u); do
		echo "m $m cbb"
	done
} >"$sysusers.new"
chmod 0644 "$sysusers.new"
mv "$sysusers.new" "$sysusers"
systemd-sysusers "$sysusers"
place 0644 "$here/cbb.service" /etc/systemd/system/cbb.service
# Desktop sessions start the connector with the session; the lite member has
# none.
# Desktops with graphical-session.target start it as a user unit, which the
# installer restarts after an update (below); others from the autostart entry.
# made records a path install.sh is about to create, which was not there,
# in $share/created, kept across runs: uninstall.sh removes it again once
# nothing else is in it.
install -d -m 0755 "$share"
made() {
	[ -e "$1" ] || grep -qsxF "$1" "$share/created" || echo "$1" >>"$share/created"
}
if [ "$kind" = full ]; then
	made /etc/xdg/autostart
	made /etc/systemd/user
	install -d -m 0755 /etc/xdg/autostart /etc/systemd/user
	place 0644 "$here/cbb-desktop.desktop" /etc/xdg/autostart/cbb-desktop.desktop
	place 0644 "$here/cbb-agent.service" /etc/systemd/user/cbb-agent.service
	systemctl --global enable cbb-agent.service >/dev/null 2>&1 || true
fi

# The tray app, when the archive has it (amd64 and arm64) and this machine
# has the GTK 4 and WebKitGTK 6.0 it runs on; a server without them keeps
# the service and the agent. It starts with each desktop session and is in
# the applications menu.
traybin=$(dirname "$bin")/cbb-desktop
if [ "$kind" = full ] && [ -f "$traybin" ]; then
	if ! command -v ldd >/dev/null 2>&1 || ldd "$traybin" 2>&1 | grep -q 'not found'; then
		echo "Not installed: the tray app, which needs GTK 4 and WebKitGTK 6.0 (Debian and Ubuntu:"
		echo "libgtk-4-1 libwebkitgtk-6.0-4; Fedora: gtk4 webkitgtk6.0). Install them and run this again to add it."
	else
		install -m 0755 "$traybin" "${cbb%/*}/cbb-desktop"
		install -d -m 0755 "$share"
		install -m 0644 "$here/cbb.png" "$share/cbb.png"
		made /etc/xdg/autostart
		install -d -m 0755 /etc/xdg/autostart
		place 0644 "$here/cbb-tray.desktop" /etc/xdg/autostart/cbb-tray.desktop
		# SteamOS replaces /usr with each update; its menu comes from the desktop.
		if [ "$steamos" = no ]; then
			made /usr/local/share/applications
			install -d -m 0755 /usr/local/share/applications
			place 0644 "$here/cbb.desktop" /usr/local/share/applications/cbb.desktop
		fi
	fi
fi

# tmux reads /etc/tmux.conf; source the cbb part from there once.
install -d -m 0755 "$share"
install -m 0644 "$here/../tmux/cbb.conf" "$share/tmux.conf"
line="source-file -q $share/tmux.conf"
if ! grep -qsF "$line" /etc/tmux.conf; then
	made /etc/tmux.conf
	echo "$line" >>/etc/tmux.conf
fi
if [ "$console" = yes ]; then
	install -m 0644 "$here/../tmux/cbb-console.sh" /etc/profile.d/cbb-console.sh
	place 0644 "$here/cbb-console.service" /etc/systemd/system/cbb-console.service
fi
if [ "$uinput" = yes ]; then
	if [ "$kind" != full ]; then
		echo "install.sh: --uinput is for the full member, which runs the desktop connector" >&2
		exit 2
	fi
	echo uinput >/etc/modules-load.d/cbb-uinput.conf
	modprobe uinput 2>/dev/null || echo "install.sh: could not load the uinput module now; it loads at the next boot" >&2
	place 0644 "$here/cbb-uinput.service" /etc/systemd/system/cbb-uinput.service
fi

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
	usermod -a -G cbb "$SUDO_USER"
	echo "Added $SUDO_USER to the cbb group; log in again to use cbb copy and paste."
fi

if [ "$steamos" = yes ]; then
	# Login shells find cbb in /opt; sudo does not, so the messages name
	# its whole path.
	install -d -m 0755 /etc/profile.d
	# shellcheck disable=SC2016 # expanded by the login shell
	echo 'case ":$PATH:" in *:/opt/cbb/bin:*) ;; *) PATH=$PATH:/opt/cbb/bin ;; esac' >/etc/profile.d/cbb-path.sh
	chmod 0644 /etc/profile.d/cbb-path.sh
	# What SteamOS keeps of /etc across an update: its own list (the units
	# in /etc/systemd/system and their links among them) and the drop-ins
	# in /etc/atomic-update.conf.d, this one among them.
	install -d -m 0755 /etc/atomic-update.conf.d
	cat >/etc/atomic-update.conf.d/cbb.conf.new <<'EOF'
# Written by cbb's install.sh: CBB's files in /etc,
# which SteamOS keeps across its updates. uninstall.sh removes it.
/etc/cbb/**
/etc/sysusers.d/cbb.conf
/etc/systemd/system/cbb.service.d/**
/etc/systemd/system/cbb-update.timer
/etc/systemd/user/cbb-agent.service
/etc/systemd/user/graphical-session.target.wants/cbb-agent.service
/etc/xdg/autostart/cbb-desktop.desktop
/etc/xdg/autostart/cbb-tray.desktop
/etc/profile.d/cbb-path.sh
/etc/profile.d/cbb-console.sh
/etc/modules-load.d/cbb-uinput.conf
/etc/polkit-1/rules.d/60-cbb.rules
/etc/firewalld/services/cbb.xml
/etc/tmux.conf
EOF
	chmod 0644 /etc/atomic-update.conf.d/cbb.conf.new
	mv /etc/atomic-update.conf.d/cbb.conf.new /etc/atomic-update.conf.d/cbb.conf
fi

# The settings: the ones given, else the ones kept from before, else the
# defaults (port 8764, 100.64.0.0/10 outside the home network).
env=/etc/cbb/cbb.env
install -d -m 0755 /etc/cbb
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
		echo "# Written by cbb's install.sh; change it with install.sh --port N and --home-cgnat on|off. A CBB_INTERFACES line is kept."
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
# The unit allows the home network's addresses only; a home network on
# 100.64.0.0/10 is added by a drop-in of its own, beside cbb global's.
cgnatconf=/etc/systemd/system/cbb.service.d/cgnat.conf
if [ "$cgnat" = 1 ]; then
	install -d -m 0755 "${cgnatconf%/*}"
	{
		echo "# Written by cbb's install.sh --home-cgnat on: 100.64.0.0/10 is the home network here."
		echo "[Service]"
		echo "IPAddressAllow=100.64.0.0/10"
	} >"$cgnatconf"
	chmod 0644 "$cgnatconf"
	echo "100.64.0.0/10 counts as the home network on this device (--home-cgnat on)."
else
	rm -f "$cgnatconf"
	rmdir "${cgnatconf%/*}" 2>/dev/null || true
fi

# A TPM keeps the member and admin keys (docs/guide/keys.md). The unit's
# sandbox hides the devices, so a drop-in lets the service open the kernel's
# resource manager, which the group tss may use. CBB_TPM=off in the
# environment file keeps new keys in the file.
tpmconf=/etc/systemd/system/cbb.service.d/tpm.conf
if [ "$kind" = full ] && [ -c /dev/tpmrm0 ] && getent group tss >/dev/null 2>&1; then
	install -d -m 0755 "${tpmconf%/*}"
	{
		echo "# Written by cbb's install.sh: the member and admin keys live in the TPM."
		echo "[Service]"
		echo "PrivateDevices=no"
		echo "DevicePolicy=closed"
		echo "DeviceAllow=/dev/tpmrm0 rw"
		echo "SupplementaryGroups=tss"
	} >"$tpmconf"
	chmod 0644 "$tpmconf"
	echo "New member and admin keys of this device go into its TPM."
else
	rm -f "$tpmconf"
	rmdir "${tpmconf%/*}" 2>/dev/null || true
fi

# A firewall drops what it does not allow, and cbb needs mDNS and its
# port from the other devices at home: firewall.sh adds them with the user's
# consent, after taking away what it opened before, so a changed port leaves
# nothing open behind it.
install -m 0644 "$here/firewall.sh" "$share/firewall.sh"
install -m 0644 "$here/uninstall.sh" "$share/uninstall.sh"
case $firewall in
ask | express | no) ;;
yes) firewall=ask ;; # what get.sh passed before --express
*)
	echo "install.sh: CBB_FIREWALL is ask, express or no, not $firewall" >&2
	exit 2
	;;
esac
sh "$share/firewall.sh" setup "$firewall" "$port"
if [ "$port" != 8764 ]; then
	echo "CBB uses TCP port $port instead of 8764. If a firewall on the network"
	echo "limits incoming connections, allow TCP $port from the home network."
fi

systemctl daemon-reload
systemctl enable cbb.service
# A binary that kept failing (an update that cbb update takes back) may have
# hit systemd's start limit, which a restart does not lift.
systemctl reset-failed cbb.service >/dev/null 2>&1 || true
systemctl restart cbb.service # also takes a new binary on a reinstall
if [ -f /etc/systemd/system/cbb-console.service ]; then
	systemctl enable cbb-console.service
	systemctl restart cbb-console.service
fi
if [ -f /etc/systemd/system/cbb-uinput.service ]; then
	systemctl enable cbb-uinput.service
	systemctl restart cbb-uinput.service || echo "install.sh: the uinput helper did not start; see journalctl -u cbb-uinput" >&2
fi
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
answers "$cbb" || true

# The agents running in desktop sessions still run the old binary: stop
# them, and start the user unit again in each session that has one, so the
# clipboard links again without logging out and in. A desktop without
# graphical-session.target starts the agent again at its next login.
if [ "$kind" = full ]; then
	if command -v pkill >/dev/null 2>&1; then
		pkill -x -f "$cbb agent" >/dev/null 2>&1 || true
	fi
	for dir in /run/user/*/systemd; do
		[ -d "$dir" ] || continue
		user=$(stat -c %U "$dir") || continue
		if systemctl --user -M "$user@" is-active -q graphical-session.target 2>/dev/null; then
			systemctl --user -M "$user@" daemon-reload >/dev/null 2>&1 || true
			systemctl --user -M "$user@" restart cbb-agent.service >/dev/null 2>&1 ||
				echo "install.sh: the desktop agent of $user did not start again; it starts at their next login" >&2
		fi
	done
fi
# A limit that cbb global wrote is brought in line with what the service
# asks for now, once it answers.
if [ "$kind" = full ] && [ -f /etc/systemd/system/cbb.service.d/away.conf ]; then
	if ! "$cbb" global allow; then
		echo "install.sh: cbb global allow failed; run sudo cbb global allow once the service runs." >&2
	fi
fi
# How this copy came, and automatic updates.
# shellcheck source=packaging/update.sh
. "$here/../update.sh"
update_setup "$cbb" "$bin" "$auto"
echo "CBB is running on TCP port $port. To remove it: sudo sh $share/uninstall.sh"
# sudo looks for commands in its own PATH, without /opt/cbb/bin.
run=cbb
if [ "$steamos" = yes ]; then
	run=$cbb
fi
if [ "$kind" = lite ]; then
	# shellcheck source=packaging/pair.sh
	. "$here/../pair.sh"
	if ! pair_now "$cbb" cbb; then
		echo "Next: see member/README.md; in short, sudo -u cbb $run pair here, and scan its QR code with the phone app."
	fi
else
	echo "Next: run sudo $run pair and scan its QR code with the CBB app on your phone; without the app, see docs/guide/without-app.md."
fi
