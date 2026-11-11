#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Opens and closes cbb's ports in the firewall:
#
#   sudo sh firewall.sh setup ask|express|no PORT   # install.sh runs it
#   sudo sh firewall.sh open PORT...                 # e.g. 8764
#   sudo sh firewall.sh close
#   sh firewall.sh kind                              # the firewall it finds
#   sh firewall.sh commands PORT...                  # what to run by hand
#   sudo sh firewall.sh hub-open PORT | hub-close     # cbb global hub runs them
#   sh firewall.sh hub-port | hub-commands PORT
#
# setup finds the firewall, lists each rule cbb needs and asks
# whether to add them, unless the answer is given (express: yes, no: no)
# or kept from before in /etc/cbb/firewall.answer. Yes adds them
# and keeps them current on every run; no prints the commands that add them,
# and cbb works while the firewall allows them.
#
# open allows mDNS and the TCP ports from the home network only, when ufw or
# firewalld is active, and remembers in /etc/cbb/firewall what it
# added. A bare nftables or iptables setup that drops input gets the
# commands to run, since rules added at run time do not survive a restart
# and each system keeps them its own way. close removes exactly what open
# added and nothing else, so open first closes, and a changed port leaves
# no old rule behind. install.sh and uninstall.sh run it.
set -eu
# The messages in the user's language (packaging/l10n.sh, beside this file
# where install.sh put it, or in the archive), read before LC_ALL=C below.
cbb_l10n=$(cd "$(dirname "$0")" && pwd)/l10n
[ -f "$cbb_l10n.sh" ] || cbb_l10n=${cbb_l10n%/l10n}/../l10n
# shellcheck source=packaging/l10n.sh
. "$cbb_l10n.sh"
# The firewall tools answer in the user's language; what this reads is English.
export LC_ALL=C

state=/etc/cbb/firewall
hubstate=/etc/cbb/firewall.hub
answer=/etc/cbb/firewall.answer

usage() {
	echo "usage: sudo sh firewall.sh setup ask|express|no PORT | open PORT... | close | kind | commands PORT... | hub-open PORT | hub-close | hub-port | hub-commands PORT" >&2
	exit 2
}

# kind prints the firewall that filters incoming connections here: ufw,
# firewalld, fw4 (OpenWrt's, whose own installer is packaging/openwrt),
# nftables or iptables, or none. fw4 comes before nftables: it flushes rules
# added to its tables at run time.
kind() {
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
		echo ufw
	elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		echo firewalld
	elif [ -x /sbin/fw4 ]; then
		echo fw4
	elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'hook input.*policy drop'; then
		echo nftables
	elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP'; then
		echo iptables
	else
		echo none
	fi
}

# nets prints the home networks: the private IPv4 networks this machine is
# on, 100.64.0.0/10 when install.sh --home-cgnat on counts it as home, then
# link-local and unique-local IPv6. With the argument ufw, it leaves IPv6 out
# when ufw takes no IPv6 rules.
nets() {
	ip -o -f inet route show scope link 2>/dev/null | awk '
		$1 ~ /^10\./ || $1 ~ /^192\.168\./ || $1 ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ { print $1 }' | sort -u
	if [ "$(sed -n 's/^CBB_HOME_CGNAT=//p' /etc/cbb/cbb.env 2>/dev/null | tail -n 1)" = 1 ]; then
		echo 100.64.0.0/10
	fi
	# A kernel without IPv6 (ipv6.disable=1) has no IPv6 networks, and
	# ufw refuses rules for them, as it does with IPV6=no.
	if [ -d /proc/sys/net/ipv6 ] && ! { [ "${1-}" = ufw ] && ufw_no_ipv6; }; then
		echo fe80::/10
		echo fc00::/7
	fi
}

# ufw_no_ipv6 reports whether /etc/default/ufw sets IPV6=no, quoted or not.
ufw_no_ipv6() {
	grep -Eqi '^[[:space:]]*IPV6=["'\'']?no["'\'']?[[:space:]]*$' /etc/default/ufw 2>/dev/null
}

# rules prints the rules cbb needs for the firewall named first,
# one numbered line each.
rules() {
	from=$(nets "$1" | paste -sd, - | sed 's/,/, /g')
	shift
	n=1
	for p in "$@"; do
		say "  %s. Allow incoming TCP %s from %s. Purpose: connections from the group's devices." "$n" "$p" "$from"
		n=$((n + 1))
	done
	say "  %s. Allow incoming UDP 5353 from %s. Purpose: finding the group's devices (mDNS)." "$n" "$from"
}

# commands prints the commands that add the rules by hand for the firewall
# named first.
commands() {
	k=$1
	shift
	case $k in
	ufw)
		for net in $(nets ufw); do
			for p in "$@"; do
				echo "  sudo ufw allow proto tcp from $net to any port $p comment cbb"
			done
			echo "  sudo ufw allow proto udp from $net to any port 5353 comment 'cbb mDNS'"
		done
		;;
	firewalld)
		for net in $(nets); do
			family=ipv4
			case $net in *:*) family=ipv6 ;; esac
			for p in "$@"; do
				echo "  sudo firewall-cmd --permanent --add-rich-rule='rule family=$family source address=$net port port=$p protocol=tcp accept'"
			done
			echo "  sudo firewall-cmd --permanent --add-rich-rule='rule family=$family source address=$net service name=mdns accept'"
		done
		echo "  sudo firewall-cmd --reload"
		;;
	nftables)
		# The first input chain that drops, with its table and family.
		set -- "$(nft list ruleset 2>/dev/null | awk '
			$1 == "table" { family = $2; table = $3 }
			$1 == "chain" { chain = $2 }
			/hook input/ && /policy drop/ { print family, table, chain; exit }')" "$@"
		where=$1
		shift
		family=${where%% *}
		for net in $(nets); do
			match="ip saddr"
			case $net in *:*) match="ip6 saddr" ;; esac
			case "$family/$match" in
			ip/ip6*) continue ;;
			ip6/ip\ *) continue ;;
			esac
			for p in "$@"; do
				echo "  sudo nft insert rule $where $match $net tcp dport $p accept"
			done
			echo "  sudo nft insert rule $where $match $net udp dport 5353 accept"
		done
		;;
	fw4)
		for p in "$@"; do
			echo "  uci add firewall rule; uci set firewall.@rule[-1].name='cbb'; uci set firewall.@rule[-1].src=lan; uci set firewall.@rule[-1].proto=tcp; uci set firewall.@rule[-1].dest_port=$p; uci set firewall.@rule[-1].target=ACCEPT"
		done
		echo "  uci commit firewall && /etc/init.d/firewall reload"
		;;
	iptables)
		for net in $(nets); do
			tool=iptables
			case $net in *:*) tool=ip6tables ;; esac
			for p in "$@"; do
				echo "  sudo $tool -I INPUT -s $net -p tcp --dport $p -j ACCEPT"
			done
			echo "  sudo $tool -I INPUT -s $net -p udp --dport 5353 -j ACCEPT"
		done
		;;
	esac
}

# The firewall rules in /etc/cbb/firewall: "ufw", which tagged its
# rules with the comments cbb and "cbb mDNS", or "firewalld"
# followed by the rich rules it added, one "rule ..." per line. Without the
# file it looks for tagged ufw rules, which get.sh added before the file.
close() {
	added=ufw
	if [ -f "$state" ]; then
		added=$(head -n 1 "$state")
	fi
	case $added in
	ufw)
		if command -v ufw >/dev/null 2>&1; then
			# Delete from the last number down, since a deletion renumbers
			# the rules after it.
			ours=$(ufw status numbered 2>/dev/null |
				sed -n 's/^\[ *\([0-9][0-9]*\)\].*# cbb\( mDNS\)\{0,1\} *$/\1/p' | sort -rn)
			for n in $ours; do
				ufw --force delete "$n" >/dev/null
			done
			if [ -n "$ours" ]; then
				say "ufw: removed the CBB rules."
			fi
		fi
		;;
	firewalld)
		if command -v firewall-cmd >/dev/null 2>&1; then
			tail -n +2 "$state" | while read -r rule; do
				firewall-cmd --permanent --remove-rich-rule="$rule" >/dev/null 2>&1 || true
			done
			rm -f /etc/firewalld/services/cbb.xml
			firewall-cmd --reload >/dev/null 2>&1 || true
			say "firewalld: removed the CBB rules and service."
		fi
		;;
	esac
	rm -f "$state"
}

# firewalld_service writes the cbb service with the TCP ports.
firewalld_service() {
	{
		echo '<?xml version="1.0" encoding="utf-8"?>'
		echo '<!-- Written by cbb'"'"'s firewall.sh; removed with the rules. -->'
		echo '<service>'
		echo '  <short>cbb</short>'
		echo '  <description>CBB shared clipboard between the devices at home.</description>'
		for p in "$@"; do
			echo "  <port protocol=\"tcp\" port=\"$(echo "$p" | tr : -)\"/>"
		done
		echo '</service>'
	} >/etc/firewalld/services/cbb.xml
	chmod 0644 /etc/firewalld/services/cbb.xml
}

# open adds the rules to ufw or firewalld, and reports whether it did.
open() {
	close
	install -d -m 0755 /etc/cbb
	case $(kind) in
	ufw)
		echo ufw >"$state"
		for net in $(nets ufw); do
			ufw allow proto udp from "$net" to any port 5353 comment 'cbb mDNS' >/dev/null
			for p in "$@"; do
				ufw allow proto tcp from "$net" to any port "$p" comment cbb >/dev/null
			done
		done
		;;
	firewalld)
		echo firewalld >"$state"
		firewalld_service "$@"
		firewall-cmd --reload >/dev/null
		for net in $(nets); do
			family=ipv4
			case $net in *:*) family=ipv6 ;; esac
			for svc in cbb mdns; do
				rule="rule family=$family source address=$net service name=$svc accept"
				# A rule that was there before is not ours to remove.
				if ! firewall-cmd --permanent --query-rich-rule="$rule" >/dev/null 2>&1; then
					firewall-cmd --permanent --add-rich-rule="$rule" >/dev/null
					echo "$rule" >>"$state"
				fi
			done
		done
		firewall-cmd --reload >/dev/null
		;;
	*) return 1 ;;
	esac
}

# The hub's UDP port, which its clients reach from the internet: cbb global
# hub opens it with the user's consent and closes it when this device stops
# being a hub reached at its own address. /etc/cbb/firewall.hub
# holds the firewall and the port it opened; ufw's rule carries the comment
# "cbb hub", which close leaves alone.
hub_close() {
	[ -f "$hubstate" ] || return 0
	read -r added p <"$hubstate" || true
	case $added in
	ufw)
		ours=$(ufw status numbered 2>/dev/null |
			sed -n 's/^\[ *\([0-9][0-9]*\)\].*# cbb hub *$/\1/p' | sort -rn)
		for n in $ours; do
			ufw --force delete "$n" >/dev/null
		done
		;;
	firewalld)
		firewall-cmd --permanent --remove-port="$p/udp" >/dev/null 2>&1 || true
		firewall-cmd --reload >/dev/null 2>&1 || true
		;;
	esac
	rm -f "$hubstate"
	say "Firewall: closed the hub's UDP port %s." "$p"
}

hub_open() {
	hub_close >/dev/null
	install -d -m 0755 /etc/cbb
	case $(kind) in
	ufw)
		ufw allow proto udp to any port "$1" comment 'cbb hub' >/dev/null
		echo "ufw $1" >"$hubstate"
		;;
	firewalld)
		# A port that was open before is not ours to close.
		if ! firewall-cmd --permanent --query-port="$1/udp" >/dev/null 2>&1; then
			firewall-cmd --permanent --add-port="$1/udp" >/dev/null
			firewall-cmd --reload >/dev/null
			echo "firewalld $1" >"$hubstate"
		fi
		;;
	*) return 1 ;;
	esac
}

hub_commands() {
	case $(kind) in
	ufw) echo "  sudo ufw allow proto udp to any port $1 comment 'cbb hub'" ;;
	firewalld)
		echo "  sudo firewall-cmd --permanent --add-port=$1/udp"
		echo "  sudo firewall-cmd --reload"
		;;
	nftables)
		where=$(nft list ruleset 2>/dev/null | awk '
			$1 == "table" { family = $2; table = $3 }
			$1 == "chain" { chain = $2 }
			/hook input/ && /policy drop/ { print family, table, chain; exit }')
		echo "  sudo nft insert rule $where udp dport $1 accept"
		;;
	iptables)
		echo "  sudo iptables -I INPUT -p udp --dport $1 -j ACCEPT"
		echo "  sudo ip6tables -I INPUT -p udp --dport $1 -j ACCEPT"
		;;
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

# manual says what to run when cbb does not manage the rules.
manual() {
	k=$1
	shift
	say "No firewall rules were added. CBB works only while the firewall allows the rules above. To add them by hand, run:"
	commands "$k" "$@"
	case $k in
	nftables | iptables) say "Then make them permanent the way this system keeps its %s rules." "$k" ;;
	esac
}

# present says whether rules an earlier installation added are there: the
# state file, or ufw rules tagged by get.sh before the file existed.
present() {
	[ -s "$state" ] && return 0
	command -v ufw >/dev/null 2>&1 &&
		ufw status 2>/dev/null | grep -Eq '# cbb( mDNS)? *$'
}

setup() {
	mode=$1
	shift
	k=$(kind)
	if [ "$k" = none ]; then
		close
		say "Firewall: no active firewall was found; no firewall rules are needed. If a firewall is turned on later, run the installer again."
		return
	fi
	say "Firewall: %s (active). CBB requires these rules:" "$k"
	rules "$k" "$@"
	case $k in
	nftables | iptables | fw4)
		close
		say "cbb does not manage %s rules: rules added at run time do not survive a restart." "$k"
		manual "$k" "$@"
		return
		;;
	esac
	install -d -m 0755 /etc/cbb
	kept=$(cat "$answer" 2>/dev/null || true)
	how=
	case $mode in
	express) yes=yes how=$(t " (express installation)") ;;
	no) yes=no ;;
	*)
		case $kept in
		yes | no) yes=$kept how=$(t " (as answered before)") ;;
		*)
			# An installation from before the question added its rules
			# without one: they count as a Yes, kept from now on, so that an
			# update never removes rules without an answer.
			if present; then
				yes=yes how=$(t " (kept from an earlier installation)")
			else
				say "With Yes, CBB adds these rules, keeps them current on every update and removes them on uninstall."
				if ask "$(t "Add these rules now?")"; then
					yes=yes
				elif [ $? -eq 2 ]; then
					# Not an answer: nothing is added or removed, and the next run
					# with a terminal asks again.
					manual "$k" "$@"
					say "To let CBB add and manage them, run the installer again with --express."
					return
				else
					yes=no
				fi
			fi
			;;
		esac
		;;
	esac
	echo "$yes" >"$answer"
	chmod 0644 "$answer"
	if [ "$yes" = yes ]; then
		open "$@"
		say "Added the rules above%s. CBB manages them from now on." "$how"
	else
		close
		manual "$k" "$@"
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
	[ $# -ge 1 ] || usage
	commands "$(kind)" "$@"
	exit
	;;
hub-port)
	[ $# -eq 0 ] || usage
	if [ -f "$hubstate" ]; then
		read -r _ p <"$hubstate" || true
		echo "$p"
	fi
	exit
	;;
hub-commands)
	[ $# -eq 1 ] || usage
	hub_commands "$1"
	exit
	;;
esac
if [ "$(id -u)" -ne 0 ]; then
	note firewall.sh "run it with sudo"
	exit 1
fi
case $cmd in
setup)
	[ $# -eq 2 ] || usage
	case $1 in ask | express | no) ;; *) usage ;; esac
	setup "$@"
	;;
open)
	[ $# -ge 1 ] || usage
	open "$@" || note firewall.sh "no ufw or firewalld is active; nothing was added."
	;;
close)
	[ $# -eq 0 ] || usage
	close
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
