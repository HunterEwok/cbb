# shellcheck shell=sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Sourced by the install.sh of Linux and OpenWrt: the lite member starts
# pairing as soon as it is installed, since the small devices it runs on
# often have no keyboard and the user installs it to pair it at once. Its
# messages go through packaging/l10n.sh, which the installer sourced.

# pair_now CBB USER [ARGS] runs CBB pair ARGS, as USER when one is given,
# when the lite member it installed is in no group, so that its QR code
# shows right away. Joining still needs the code shown here: the phone
# scans it, or the code is typed. It returns 0 when the device joined or
# was in a group already (an update or a reinstall), and 1 when it did not
# pair: --no-pair (CBB_PAIR=no) for a scripted install, an output that is
# no terminal, a service that does not answer, or a pairing cancelled or
# timed out. The caller then says how to pair later.
pair_now() {
	pn_cbb=$1
	pn_user=$2
	shift 2
	[ "${CBB_PAIR:-}" != no ] || return 1
	[ -t 1 ] || return 1
	# In no group, cbb status shows an empty group line.
	pn_status=$("$pn_cbb" status 2>/dev/null) || return 1
	printf '%s\n' "$pn_status" | grep -q '^group *$' || return 0
	echo
	say "This device is in no group yet, so it starts pairing now (--no-pair skips this)."
	# Ctrl+C stops the pairing, not the installer: a trap, not an ignored
	# signal, which cbb pair would inherit.
	trap 'echo' INT
	if [ -n "$pn_user" ]; then
		# shellcheck disable=SC2016 # $0 and $@ are su's shell's
		in_locale su -s /bin/sh "$pn_user" -c '"$0" pair "$@"' "$pn_cbb" "$@" && pn_rc=0 || pn_rc=1
	else
		in_locale "$pn_cbb" pair "$@" && pn_rc=0 || pn_rc=1
	fi
	trap - INT
	return "$pn_rc"
}
