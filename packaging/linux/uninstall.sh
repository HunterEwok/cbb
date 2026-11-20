#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.sh installed:
#
#   sudo sh /usr/local/share/cbb/uninstall.sh [--purge]
#
# (on SteamOS /opt/cbb/share/uninstall.sh). A rootless install
# is removed by its own user, without sudo:
#
#   sh ~/.local/share/cbb/uninstall.sh [--purge]
#
# It stops the service and the desktop agents and removes the binary, the
# unit, the agent's user unit and autostart entry, the tmux and console
# configuration, the update timer and cbb update's folder, the settings in
# /etc/cbb, the quick actions' polkit rule and the firewall rules
# that install.sh added, and only those. The device's keys and
# group, in /var/lib/cbb, stay for a reinstall unless --purge; the
# cbb user and group stay too, since files may still belong to them,
# unless --purge.
set -eu

# A failure says so with its exit status; CBB_ERROR_DETAILS=1 shows every
# command as it runs, so that the output shows where and why it failed.
if [ "${CBB_ERROR_DETAILS:-}" = 1 ]; then
	set -x
fi
failed() {
	rc=$1
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ] && [ "${CBB_ERROR_DETAILS:-}" != 1 ]; then
		note uninstall.sh "failed (exit status %s). For every command it ran: CBB_ERROR_DETAILS=1, and run it again." "$rc"
	fi
}
trap 'failed $?' EXIT
# The messages in the user's language (packaging/l10n.sh, beside this file
# where install.sh put it, or in the archive), read before LC_ALL=C below.
cbb_l10n=$(cd "$(dirname "$0")" && pwd)/l10n
[ -f "$cbb_l10n.sh" ] || cbb_l10n=${cbb_l10n%/l10n}/../l10n
# shellcheck source=packaging/l10n.sh
. "$cbb_l10n.sh"
# The firewall tools answer in the user's language; what this reads is English.
export LC_ALL=C

purge=no
case ${1:-} in
'') ;;
--purge) purge=yes ;;
*)
	echo "usage: sudo sh uninstall.sh [--purge]" >&2
	exit 2
	;;
esac
# A rootless install (install.sh --rootless) is removed by its own user.
if [ "$(id -u)" -ne 0 ] && [ -n "${HOME:-}" ] && [ -e "$HOME/.local/bin/cbb" ]; then
	config=${XDG_CONFIG_HOME:-$HOME/.config}
	state=${XDG_STATE_HOME:-$HOME/.local/state}
	for u in cbb-update.timer cbb-agent.service cbb.service; do
		systemctl --user disable --now "$u" >/dev/null 2>&1 || true
	done
	rm -f "$config/systemd/user/cbb.service" "$config/systemd/user/cbb-agent.service" \
		"$config/systemd/user/cbb-update.service" "$config/systemd/user/cbb-update.timer" \
		"$config/autostart/cbb-desktop.desktop" "$HOME/.local/bin/cbb" "$HOME/.local/bin/cbb-helper"
	systemctl --user daemon-reload >/dev/null 2>&1 || true
	rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/cbb" "$config/cbb" "$state/cbb-update"
	if [ "$purge" = yes ]; then
		rm -rf "$state/cbb"
		say "CBB is removed, with this device's keys; it left its group."
	else
		say "CBB is removed. Its keys stay in %s/cbb for a reinstall; --purge removes them." "$state"
	fi
	exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
	note uninstall.sh "run it with sudo"
	exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
	systemctl disable --now cbb-console.service >/dev/null 2>&1 || true
	systemctl disable --now cbb-uinput.service >/dev/null 2>&1 || true
	systemctl disable --now cbb.service >/dev/null 2>&1 || true
	systemctl disable --now cbb-update.timer >/dev/null 2>&1 || true
fi
# The desktop agent runs in each user's session, from the user unit or the
# autostart entry; it stops here too, or it would keep the clipboard until
# the user logs out.
if command -v systemctl >/dev/null 2>&1; then
	systemctl --global disable cbb-agent.service >/dev/null 2>&1 || true
	for dir in /run/user/*/systemd; do
		[ -d "$dir" ] || continue
		user=$(stat -c %U "$dir") || continue
		systemctl --user -M "$user@" stop cbb-agent.service >/dev/null 2>&1 || true
	done
fi
# install.sh puts it in /usr/local, or on SteamOS in /opt/cbb.
cbb=/usr/local/bin/cbb
share=/usr/local/share/cbb
if [ -e /opt/cbb/bin/cbb ]; then
	cbb=/opt/cbb/bin/cbb
	share=/opt/cbb/share
fi
if command -v pkill >/dev/null 2>&1; then
	pkill -x -f "$cbb agent" >/dev/null 2>&1 || true
	pkill -x cbb-desktop >/dev/null 2>&1 || true
fi
if [ -f "$share/firewall.sh" ]; then
	sh "$share/firewall.sh" close
	sh "$share/firewall.sh" hub-close
fi
rm -f /etc/systemd/system/cbb.service.d/away.conf /etc/systemd/system/cbb.service.d/cgnat.conf \
	/etc/systemd/system/cbb.service.d/tpm.conf /etc/systemd/system/cbb.service.d/small.conf
rmdir /etc/systemd/system/cbb.service.d 2>/dev/null || true
rm -f /etc/systemd/system/cbb.service /etc/systemd/system/cbb-console.service \
	/etc/systemd/system/cbb-uinput.service /etc/modules-load.d/cbb-uinput.conf \
	/etc/systemd/system/cbb-update.service /etc/systemd/system/cbb-update.timer \
	/etc/xdg/autostart/cbb-desktop.desktop /etc/xdg/autostart/cbb-tray.desktop \
	/usr/local/share/applications/cbb.desktop /usr/local/bin/cbb-desktop /usr/local/bin/cbb-helper /usr/local/bin/cbb-forward /usr/local/bin/cbb-relay \
	/etc/systemd/user/cbb-agent.service \
	/etc/profile.d/cbb-console.sh /usr/lib/sysusers.d/cbb.conf /usr/local/bin/cbb \
	/etc/profile.d/cbb-path.sh /etc/sysusers.d/cbb.conf /etc/atomic-update.conf.d/cbb.conf \
	/etc/polkit-1/rules.d/60-cbb.rules /etc/polkit-1/localauthority/50-local.d/cbb.pkla \
	/usr/share/polkit-1/actions/tools.cbb.admin.policy
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
if [ -f /etc/tmux.conf ]; then
	line="source-file -q $share/tmux.conf"
	grep -vxF "$line" /etc/tmux.conf >/etc/tmux.conf.cbb || true
	cat /etc/tmux.conf.cbb >/etc/tmux.conf
	rm -f /etc/tmux.conf.cbb
fi
# What install.sh created (install.sh, made), once nothing else is in it:
# /etc/tmux.conf with only blank lines left, and empty folders.
if [ -f "$share/created" ]; then
	while read -r p; do
		case $p in
		/etc/tmux.conf) [ ! -f "$p" ] || grep -q '[^[:space:]]' "$p" || rm -f "$p" ;;
		/etc/* | /usr/local/share/applications) rmdir "$p" 2>/dev/null || true ;;
		esac
	done <"$share/created"
fi
# cbb update's folder: the answer about automatic updates, what it has
# seen and the previous programs.
rm -rf "$share" /etc/cbb /var/lib/cbb-update /opt/cbb /opt/cbb-update
if [ "$purge" = yes ]; then
	rm -rf /var/lib/cbb
	# Its files are gone, so the account goes too: a later one of the same
	# name gets nothing of this one's.
	if getent passwd cbb >/dev/null 2>&1 && command -v userdel >/dev/null 2>&1; then
		userdel cbb 2>/dev/null || true
	fi
	if getent group cbb >/dev/null 2>&1 && command -v groupdel >/dev/null 2>&1; then
		groupdel cbb 2>/dev/null || true
	fi
	say "CBB is removed, with this device's keys; it left its group."
else
	say "CBB is removed. Its keys stay in /var/lib/cbb for a reinstall; --purge removes them."
fi
