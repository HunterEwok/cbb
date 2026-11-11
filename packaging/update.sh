# shellcheck shell=sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Sourced by the install.sh of each system: how this copy was installed,
# and the question about automatic updates (docs/guide/install.md,
# "Updates"). Its messages go through packaging/l10n.sh, which the installer
# sourced.

# update_method BIN prints how the installer's program BIN came: brew for
# Homebrew's copy, else CBB_INSTALL_METHOD (package for the OpenWrt
# package), else get: get.sh or a release archive, which cbb update
# replaces by itself.
update_method() {
	case $1 in
	*/Cellar/* | */linuxbrew/* | */homebrew/* | */opt/cbb/bin/*) echo brew ;;
	*) echo "${CBB_INSTALL_METHOD:-get}" ;;
	esac
}

# update_setup CBB BIN [on|off] records with the installed CBB how BIN
# came and, for a copy that updates itself, sets automatic updates: as
# given, else as answered before, else it asks. An update (CBB_UPDATING,
# set by cbb update) asks nothing and writes the kept timer again.
update_setup() {
	upd_cbb=$1
	upd_method=$(update_method "$2")
	upd_auto=${3:-${CBB_AUTO_UPDATE:-}}
	# A rootless install (install-rootless.sh) changes its timer itself.
	upd_sudo='sudo '
	[ "${CBB_ROOTLESS:-}" != 1 ] || upd_sudo=
	if ! "$upd_cbb" update -installed-by "$upd_method"; then
		note install.sh "could not record how CBB was installed; cbb update takes it as get.sh"
	fi
	[ "$upd_method" = get ] || return 0
	case $upd_auto in
	on | off) ;;
	'') upd_auto=$("$upd_cbb" update -auto 2>/dev/null) || upd_auto= ;;
	*)
		note install.sh "automatic updates are on or off, not %s" "$upd_auto"
		return 2
		;;
	esac
	if [ "$upd_auto" != on ] && [ "$upd_auto" != off ]; then
		[ -z "${CBB_UPDATING:-}" ] || return 0
		say "CBB can check once a day for a release the project signed and install it; the check tells GitHub this device's address, as any download does."
		t "Update automatically? [y/N]"
		printf ' '
		if (: </dev/tty) 2>/dev/null; then
			upd_reply=
			read -r upd_reply </dev/tty || upd_reply=
			if is_yes "$upd_reply"; then upd_auto=on; else upd_auto=off; fi
		else
			# Not an answer: the next run with a terminal asks again.
			echo
			say "No terminal to answer on; not now. Later: %scbb update -auto on" "${upd_sudo}"
			return 0
		fi
	fi
	if ! "$upd_cbb" update -auto "$upd_auto"; then
		note install.sh "could not turn automatic updates %s; run %scbb update -auto %s" "$upd_auto" "${upd_sudo}" "$upd_auto"
	fi
}
