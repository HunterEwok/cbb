#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Opens and closes cbb's ports in FreeBSD's firewall, pf or ipfw:
#
#   sh firewall.sh setup ask|express|no PORT   # install.sh runs it
#   sh firewall.sh open PORT
#   sh firewall.sh close
#   sh firewall.sh reload                      # rc.d runs it at start
#   sh firewall.sh kind                        # the firewall it finds
#   sh firewall.sh commands PORT               # what to run by hand
#   sh firewall.sh hub-open PORT | hub-close   # cbb global hub runs them
#   sh firewall.sh hub-port | hub-commands PORT
#
# The same commands as packaging/linux/firewall.sh, run as root. setup
# lists the rules cbb needs and asks whether to add them,
# unless the answer is given or kept from before.
#
# pf: the rules live in the anchor "cbb", loaded from
# /usr/local/etc/cbb/pf.anchor. pf reads an anchor only where
# pf.conf names it, so with the user's consent open adds two marked lines at
# the end of /etc/pf.conf, and close removes exactly those lines; nothing
# else in pf.conf is touched. ipfw: rules added at run time in rule set 17,
# numbers 10500 and up, which close deletes as a whole; ipfw forgets them on
# a reboot, so the rc.d script runs reload. What open did is kept in
# /usr/local/etc/cbb/firewall, the hub's port in firewall.hub.
#
# OPNsense writes pf's whole ruleset at each filter reload, so pf.conf is
# not used there: the plugin hook cbb.inc names the anchor in
# OPNsense's ruleset, and the rules go into the anchor as above. pfSense
# gets the rules printed, to add in Firewall > Rules: it is unsupported.
set -eu
# The messages in the user's language (packaging/l10n.sh, beside this file
# where install.sh put it, or in the archive), read before LC_ALL=C below.
cbb_l10n=$(cd "$(dirname "$0")" && pwd)/l10n
[ -f "$cbb_l10n.sh" ] || cbb_l10n=${cbb_l10n%/l10n}/../l10n
# shellcheck source=packaging/l10n.sh
. "$cbb_l10n.sh"
export LC_ALL=C

etc=/usr/local/etc/cbb
state=$etc/firewall
hubstate=$etc/firewall.hub
answer=$etc/firewall.answer
anchorfile=$etc/pf.anchor
pfconf=${CBB_PF_CONF:-/etc/pf.conf}
mark='# cbb: the rules in its anchor; firewall.sh close removes these lines'
set17=17
first=10500

usage() {
	echo "usage: sh firewall.sh setup ask|express|no PORT | open PORT | close | reload | kind | commands PORT | hub-open PORT | hub-close | hub-port | hub-commands PORT" >&2
	exit 2
}

# appliance prints opnsense or pfsense on those firewalls, else nothing.
appliance() {
	if [ -f /usr/local/opnsense/version/core ]; then
		echo opnsense
	elif grep -qi pfsense /etc/platform 2>/dev/null; then
		echo pfsense
	fi
}

# kind prints the firewall that filters incoming packets here: opnsense or
# pfsense on those, else pf, ipfw or none. With both, pf.
kind() {
	a=$(appliance)
	if [ -n "$a" ]; then
		echo "$a"
	elif kldstat -q -m pf 2>/dev/null && pfctl -s info 2>/dev/null | grep -q '^Status: Enabled'; then
		echo pf
	elif kldstat -q -m ipfw 2>/dev/null && [ "$(sysctl -n net.inet.ip.fw.enable 2>/dev/null)" = 1 ]; then
		echo ipfw
	else
		echo none
	fi
}

# nets prints the home networks: the private IPv4 ranges, 100.64.0.0/10 when
# install.sh --home-cgnat on counts it as home, then link-local and
# unique-local IPv6.
nets() {
	echo 10.0.0.0/8
	echo 172.16.0.0/12
	echo 192.168.0.0/16
	if [ "$(sed -n 's/^CBB_HOME_CGNAT=//p' $etc/cbb.env 2>/dev/null | tail -n 1)" = 1 ]; then
		echo 100.64.0.0/10
	fi
	echo fe80::/10
	echo fc00::/7
}

rules() {
	from=$(nets | paste -sd, - | sed 's/,/, /g')
	say "  1. Allow incoming TCP %s from %s. Purpose: connections from the group's devices." "$1" "$from"
	say "  2. Allow incoming UDP 5353 from %s. Purpose: finding the group's devices (mDNS)." "$from"
}

# anchor writes the pf anchor: the home rules for PORT (none if empty) and
# the hub's port (none if empty).
anchor() {
	install -d -m 0755 $etc
	{
		echo "# Written by cbb's firewall.sh; it rewrites this file."
		echo "table <cbb_home> { $(nets | paste -sd' ' -) }"
		if [ -n "$1" ]; then
			echo "pass in quick proto tcp from <cbb_home> to port $1"
			echo "pass in quick proto udp from <cbb_home> to port 5353"
		fi
		if [ -n "$2" ]; then
			echo "pass in quick proto udp to port $2"
		fi
	} >"$anchorfile"
	chmod 0644 "$anchorfile"
	pfctl -a cbb -f "$anchorfile"
}

pf_lines() {
	echo "$mark"
	echo "anchor \"cbb\""
	echo "load anchor \"cbb\" from \"$anchorfile\""
}

# pf_hook adds the lines that make pf read the anchor, once; on OPNsense
# a filter reload runs the plugin hook, which names it.
pf_hook() {
	if [ "$(appliance)" = opnsense ]; then
		pfctl -s rules 2>/dev/null | grep -q 'anchor "cbb"' || configctl filter reload >/dev/null
		return
	fi
	if ! grep -qxF "$mark" "$pfconf" 2>/dev/null; then
		pf_lines >>"$pfconf"
		pfctl -f "$pfconf"
	fi
}

pf_unhook() {
	[ "$(appliance)" != opnsense ] || return 0
	[ -f "$pfconf" ] && grep -qxF "$mark" "$pfconf" || return 0
	tmp=$(mktemp)
	pf_lines >"$tmp.lines"
	grep -vxF -f "$tmp.lines" "$pfconf" >"$tmp" || true
	cat "$tmp" >"$pfconf"
	rm -f "$tmp" "$tmp.lines"
	pfctl -f "$pfconf" || true
}

ipfw_add() {
	n=$first
	for net in $(nets); do
		v=ip4
		case $net in *:*) v=ip6 ;; esac
		ipfw -q add $n set $set17 allow tcp from "$net" to me "$1" in $v
		n=$((n + 1))
		ipfw -q add $n set $set17 allow udp from "$net" to me 5353 in $v
		n=$((n + 1))
	done
}

ipfw_hub() {
	ipfw -q add $((first + 90)) set $set17 allow udp from any to me "$1" in
}

hub_port() {
	if [ -f "$hubstate" ]; then
		read -r _ p <"$hubstate" || true
		echo "${p:-}"
	fi
}

home_port() {
	if [ -f "$state" ]; then
		read -r _ p <"$state" || true
		echo "${p:-}"
	fi
}

# apply loads what the state files say into the firewall they name.
apply() {
	k=$(head -n 1 "$state" 2>/dev/null | cut -d' ' -f1)
	[ -n "$k" ] || k=$(head -n 1 "$hubstate" 2>/dev/null | cut -d' ' -f1)
	case $k in
	pf | opnsense)
		anchor "$(home_port)" "$(hub_port)"
		;;
	ipfw)
		ipfw -q delete set $set17 2>/dev/null || true
		if [ -n "$(home_port)" ]; then ipfw_add "$(home_port)"; fi
		if [ -n "$(hub_port)" ]; then ipfw_hub "$(hub_port)"; fi
		;;
	esac
}

close() {
	k=$(head -n 1 "$state" 2>/dev/null | cut -d' ' -f1)
	rm -f "$state"
	case $k in
	pf | ipfw | opnsense)
		apply_closed "$k"
		say "%s: removed the CBB rules." "$k"
		;;
	esac
}

# apply_closed takes away what is no longer kept for the firewall k.
apply_closed() {
	if [ -f "$hubstate" ]; then
		apply
		return
	fi
	case $1 in
	pf | opnsense)
		pfctl -a cbb -F rules 2>/dev/null || true
		rm -f "$anchorfile"
		pf_unhook
		;;
	ipfw) ipfw -q delete set $set17 2>/dev/null || true ;;
	esac
}

open() {
	close >/dev/null
	k=$(kind)
	case $k in
	pf | ipfw | opnsense) ;;
	*) return 1 ;;
	esac
	install -d -m 0755 $etc
	echo "$k $1" >"$state"
	[ "$k" = ipfw ] || pf_hook
	apply
}

hub_open() {
	hub_close >/dev/null
	k=$(kind)
	case $k in
	pf | ipfw | opnsense) ;;
	*) return 1 ;;
	esac
	install -d -m 0755 $etc
	echo "$k $1" >"$hubstate"
	[ "$k" = ipfw ] || pf_hook
	apply
}

hub_close() {
	[ -f "$hubstate" ] || return 0
	read -r k p <"$hubstate" || true
	rm -f "$hubstate"
	if [ -f "$state" ]; then
		apply
	else
		apply_closed "$k"
	fi
	say "Firewall: closed the hub's UDP port %s." "$p"
}

commands() {
	case $(kind) in
	opnsense | pfsense)
		say "  In Firewall > Rules, on each interface of the home network (LAN and the others):"
		say "    Pass, protocol TCP, source %s, destination This Firewall, port %s" "$(nets | paste -sd, - | sed 's/,/, /g')" "$1"
		say "    Pass, protocol UDP, the same sources, destination This Firewall, port 5353"
		;;
	pf)
		say "  Add to /etc/pf.conf, before the rules that block, and run pfctl -f /etc/pf.conf:"
		echo "    table <cbb_home> { $(nets | paste -sd' ' -) }"
		echo "    pass in quick proto tcp from <cbb_home> to port $1"
		echo "    pass in quick proto udp from <cbb_home> to port 5353"
		;;
	ipfw)
		for net in $(nets); do
			v=ip4
			case $net in *:*) v=ip6 ;; esac
			echo "  ipfw add allow tcp from $net to me $1 in $v"
			echo "  ipfw add allow udp from $net to me 5353 in $v"
		done
		say "  and the same lines in the script that firewall_script in rc.conf names, to keep them."
		;;
	esac
}

hub_commands() {
	case $(kind) in
	opnsense | pfsense) say "  In Firewall > Rules on WAN: Pass, protocol UDP, source any, destination WAN address, port %s" "$1" ;;
	pf) echo "  pass in quick proto udp to port $1   (in /etc/pf.conf, then pfctl -f /etc/pf.conf)" ;;
	ipfw) echo "  ipfw add allow udp from any to me $1 in" ;;
	esac
}

# ask reads yes or no from the terminal, no by default and without one.
ask() {
	t "%s [y/N]" "$1"
	printf ' '
	reply=
	if (: </dev/tty) 2>/dev/null; then
		read -r reply </dev/tty || reply=
	else
		echo
		say "No terminal to answer on; taken as No."
		return 2
	fi
	is_yes "$reply"
}

manual() {
	say "No firewall rules were added. CBB works only while the firewall allows the rules above. To add them by hand:"
	commands "$1"
}

setup() {
	mode=$1 port=$2
	k=$(kind)
	if [ "$k" = none ]; then
		close
		say "Firewall: no active firewall was found; no firewall rules are needed. If pf or ipfw is turned on later, run the installer again."
		return
	fi
	say "Firewall: %s (active). CBB requires these rules:" "$k"
	rules "$port"
	if [ "$k" = pfsense ]; then
		close
		say "CBB does not change pfSense's rules, and runs there unsupported. Add them by hand:"
		commands "$port"
		return
	fi
	install -d -m 0755 $etc
	kept=$(cat "$answer" 2>/dev/null || true)
	how=
	case $mode in
	express) yes=yes how=$(t " (express installation)") ;;
	no) yes=no ;;
	*)
		case $kept in
		yes | no) yes=$kept how=$(t " (as answered before)") ;;
		*)
			if [ "$k" = opnsense ]; then
				say "With Yes, CBB keeps these rules in its own pf anchor, which its plugin hook adds to OPNsense's ruleset; uninstalling removes both."
			elif [ "$k" = pf ]; then
				say "With Yes, CBB keeps these rules in its own pf anchor and adds the lines that load it at the end of %s; uninstalling removes both." "$pfconf"
			else
				say "With Yes, CBB adds these rules to ipfw's set %s at every start, and removes them on uninstall." "$set17"
			fi
			if ask "$(t "Add these rules now?")"; then
				yes=yes
			elif [ $? -eq 2 ]; then
				manual "$k" "$port"
				say "To let CBB add and manage them, run the installer again with --express."
				return
			else
				yes=no
			fi
			;;
		esac
		;;
	esac
	echo "$yes" >"$answer"
	chmod 0644 "$answer"
	if [ "$yes" = yes ]; then
		open "$port"
		say "Added the rules above%s. CBB manages them from now on." "$how"
	else
		close
		manual "$k" "$port"
		say "To let CBB add and manage them, run the installer again with --express."
	fi
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case $cmd in
kind)
	[ $# -eq 0 ] || usage
	kind
	exit
	;;
commands)
	[ $# -eq 1 ] || usage
	commands "$1"
	exit
	;;
hub-port)
	[ $# -eq 0 ] || usage
	hub_port
	exit
	;;
hub-commands)
	[ $# -eq 1 ] || usage
	hub_commands "$1"
	exit
	;;
esac
if [ "$(id -u)" -ne 0 ]; then
	note firewall.sh "run it as root"
	exit 1
fi
case $cmd in
setup)
	[ $# -eq 2 ] || usage
	case $1 in ask | express | no) ;; *) usage ;; esac
	setup "$@"
	;;
open)
	[ $# -eq 1 ] || usage
	open "$1" || note firewall.sh "neither pf nor ipfw is active; nothing was added."
	;;
close)
	[ $# -eq 0 ] || usage
	close
	;;
reload)
	[ $# -eq 0 ] || usage
	apply
	;;
hub-open)
	[ $# -eq 1 ] || usage
	hub_open "$1"
	;;
hub-close)
	[ $# -eq 0 ] || usage
	hub_close
	;;
*) usage ;;
esac
