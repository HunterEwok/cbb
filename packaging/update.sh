# shellcheck shell=sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Sourced by the install.sh of each system: how this copy was installed,
# and the question about automatic updates (docs/guide/install.md,
# "Updates").

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
		echo "install.sh: could not record how CBB was installed; cbb update takes it as get.sh" >&2
	fi
	[ "$upd_method" = get ] || return 0
	case $upd_auto in
	on | off) ;;
	'') upd_auto=$("$upd_cbb" update -auto 2>/dev/null) || upd_auto= ;;
	*)
		echo "install.sh: automatic updates are on or off, not $upd_auto" >&2
		return 2
		;;
	esac
	if [ "$upd_auto" != on ] && [ "$upd_auto" != off ]; then
		[ -z "${CBB_UPDATING:-}" ] || return 0
		echo "CBB can check once a day for a release the project signed and install it;"
		echo "the check tells GitHub this device's address, as any download does."
		printf 'Update automatically? [y/N] '
		if (: </dev/tty) 2>/dev/null; then
			upd_reply=
			read -r upd_reply </dev/tty || upd_reply=
			case $upd_reply in
			y | Y | yes | Yes | YES) upd_auto=on ;;
			*) upd_auto=off ;;
			esac
		else
			# Not an answer: the next run with a terminal asks again.
			echo
			echo "No terminal to answer on; not now. Later: ${upd_sudo}cbb update -auto on"
			return 0
		fi
	fi
	if ! "$upd_cbb" update -auto "$upd_auto"; then
		echo "install.sh: could not turn automatic updates $upd_auto; run ${upd_sudo}cbb update -auto $upd_auto" >&2
	fi
}
