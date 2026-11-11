#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs cbb on FreeBSD, as root:
#
#   sh install.sh [--port N] [--home-cgnat on|off] [--auto-update on|off] [--express | --no-firewall] path/to/cbb
#
# It installs the binary to /usr/local/bin, makes the user and group
# cbb (pw), the rc.d script, which runs the service through
# daemon(8), and enables it in rc.conf, adds the user who ran sudo or doas
# to the group, and starts or restarts the service. The keys live in
# /var/db/cbb, the settings in /usr/local/etc/cbb;
# desktop sessions start the clipboard agent from XDG autostart.
# --port, --home-cgnat, --auto-update, --express and --no-firewall work as
# in the Linux installer; the firewall is pf or ipfw (firewall.sh). On OPNsense it also
# installs the plugin hook cbb.inc, which names the service's pf
# anchor in OPNsense's ruleset and shows the service in its pages; on
# pfSense, unsupported, it prints the rules and adds cbb.sh,
# since pfSense starts only rc.d scripts named so. uninstall.sh removes it
# all again.
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
# The messages in the user's language (packaging/l10n.sh), read before LC_ALL=C below.
cbb_l10n=$(cd "$(dirname "$0")" && pwd)/../l10n
# shellcheck source=packaging/l10n.sh
. "$cbb_l10n.sh"
export LC_ALL=C

usage() {
	echo "usage: sh install.sh [--port N] [--home-cgnat on|off] [--auto-update on|off] [--express | --no-firewall] path/to/cbb" >&2
	exit 2
}
port=
cgnat=${CBB_HOME_CGNAT:-}
firewall=${CBB_FIREWALL:-ask}
auto=
while [ $# -gt 1 ]; do
	case $1 in
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
case $firewall in
ask | express | no) ;;
yes) firewall=ask ;;
*)
	note install.sh "CBB_FIREWALL is ask, express or no, not %s" "$firewall"
	exit 2
	;;
esac
bin=$1
case $bin in
*/*) ;;
*) bin=./$bin ;;
esac
here=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
	note install.sh "run it as root (sudo or doas)"
	exit 1
fi
if [ "$(uname -s)" != FreeBSD ]; then
	note install.sh "this installer is for FreeBSD"
	exit 1
fi
if ! "$bin" version >/dev/null 2>&1; then
	note install.sh "%s does not run on this machine; is it built for %s?" "$bin" "$(uname -m)"
	exit 1
fi

# The account cbb gets the group's keys and the control socket. One that
# an earlier install made says "CBB"; another, a person's or another
# program's, is never taken over, nor a group cbb of others without it.
if pw=$(pw usershow cbb 2>/dev/null); then
	if [ "$(printf '%s\n' "$pw" | cut -d: -f8)" != CBB ]; then
		note install.sh "an account named cbb exists here and is not this service's (its comment is not \"CBB\"); it would get the group's keys. Rename or remove it, then run install.sh again."
		exit 1
	fi
elif gr=$(pw groupshow cbb 2>/dev/null) && [ -n "$(printf '%s\n' "$gr" | cut -d: -f4)" ]; then
	note install.sh "a group named cbb exists here with members, and no service account; they would reach the service. Rename or remove the group, then run install.sh again."
	exit 1
fi
if ! pw groupshow cbb >/dev/null 2>&1; then
	pw groupadd cbb
fi
if ! pw usershow cbb >/dev/null 2>&1; then
	pw useradd cbb -g cbb -d /nonexistent -s /usr/sbin/nologin -c "CBB"
fi
install -m 0755 "$bin" /usr/local/bin/cbb
if [ -f "$(dirname "$bin")/cbb-helper" ]; then
	install -m 0755 "$(dirname "$bin")/cbb-helper" /usr/local/bin/cbb-helper
fi
# The servers, which cbb forward and cbb relay run.
for server in cbb-forward cbb-relay; do
	if [ -f "$(dirname "$bin")/$server" ]; then
		install -m 0755 "$(dirname "$bin")/$server" "/usr/local/bin/$server"
	fi
done
install -d -m 0755 /usr/local/etc/rc.d /usr/local/share/cbb /usr/local/etc/cbb
install -m 0555 "$here/cbb" /usr/local/etc/rc.d/cbb
install -d -o cbb -g cbb -m 0700 /var/db/cbb

user=${SUDO_USER:-${DOAS_USER:-}}
if [ -n "$user" ] && [ "$user" != root ]; then
	pw groupmod cbb -m "$user"
	say "Added %s to the cbb group; log in again to use cbb copy and paste." "$user"
fi

env=/usr/local/etc/cbb/cbb.env
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

appliance=
if [ -f /usr/local/opnsense/version/core ]; then
	appliance=opnsense
	install -d -m 0755 /usr/local/etc/inc/plugins.inc.d
	install -m 0644 "$here/cbb.inc" /usr/local/etc/inc/plugins.inc.d/cbb.inc
elif grep -qi pfsense /etc/platform 2>/dev/null; then
	appliance=pfsense
	cat >/usr/local/etc/rc.d/cbb.sh <<'EOF'
#!/bin/sh
# Written by cbb's install.sh: pfSense starts only rc.d scripts named *.sh.
exec /usr/sbin/service cbb "one${1:-start}"
EOF
	chmod 0555 /usr/local/etc/rc.d/cbb.sh
fi
install -m 0644 "$here/firewall.sh" /usr/local/share/cbb/firewall.sh
install -m 0644 "$here/uninstall.sh" /usr/local/share/cbb/uninstall.sh
# uninstall.sh speaks the user's language too.
install -m 0644 "$here/../l10n.sh" /usr/local/share/cbb/l10n.sh
rm -rf /usr/local/share/cbb/l10n
cp -R "$here/../l10n" /usr/local/share/cbb/l10n
# Desktop sessions (KDE, GNOME, Xfce and others that read XDG autostart)
# start the clipboard agent, cbb agent, at login; a firewall has none.
if [ -z "$appliance" ]; then
	install -d -m 0755 /usr/local/etc/xdg/autostart
	install -m 0644 "$here/cbb-desktop.desktop" /usr/local/etc/xdg/autostart/cbb-desktop.desktop
fi
sh /usr/local/share/cbb/firewall.sh setup "$firewall" "$port"
if [ "$port" != 8764 ]; then
	say "CBB uses TCP port %s instead of 8764." "$port"
fi

sysrc -q cbb_enable=YES >/dev/null
service cbb restart >/dev/null 2>&1 || service cbb start

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
answers /usr/local/bin/cbb || true
# How this copy came, and automatic updates.
# shellcheck source=packaging/update.sh
. "$here/../update.sh"
update_setup /usr/local/bin/cbb "$bin" "$auto"
say "CBB is running on TCP port %s. To remove it: sh /usr/local/share/cbb/uninstall.sh" "$port"
case $appliance in
opnsense) say "OPNsense: it shows under System > Diagnostics > Services, and its rules follow every filter reload." ;;
pfsense) say "pfSense is not supported: an update of pfSense may remove CBB; run this installer again after one." ;;
esac
say "Next: run cbb pair as root and scan its QR code with the CBB app on your phone; without the app, see docs/guide/without-app.md."
