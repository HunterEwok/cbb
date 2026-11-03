#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.sh installed:
#
#   sudo sh /usr/local/share/clipboardbridge/uninstall.sh [--purge]
#
# (on SteamOS /opt/clipboardbridge/share/uninstall.sh). A rootless install
# is removed by its own user, without sudo:
#
#   sh ~/.local/share/clipboardbridge/uninstall.sh [--purge]
#
# It stops the service and the desktop agents and removes the binary, the
# unit, the agent's user unit and autostart entry, the tmux and console
# configuration, the update timer and cbb update's folder, the settings in
# /etc/clipboardbridge and the firewall rules
# that install.sh added, and only those. The device's keys and
# group, in /var/lib/clipboardbridge, stay for a reinstall unless --purge; the
# clipboardbridge user and group stay too, since files may still belong to them.
set -eu

# A failure says so with its exit status; CBB_ERROR_DETAILS=1 shows every
# command as it runs, so that the output shows where and why it failed.
if [ "${CBB_ERROR_DETAILS:-}" = 1 ]; then
	set -x
fi
failed() {
	rc=$1
	if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ] && [ "${CBB_ERROR_DETAILS:-}" != 1 ]; then
		echo "uninstall.sh: failed (exit status $rc). For every command it ran: CBB_ERROR_DETAILS=1, and run it again." >&2
	fi
}
trap 'failed $?' EXIT
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
	for u in clipboardbridge-update.timer clipboardbridge-agent.service clipboardbridge.service; do
		systemctl --user disable --now "$u" >/dev/null 2>&1 || true
	done
	rm -f "$config/systemd/user/clipboardbridge.service" "$config/systemd/user/clipboardbridge-agent.service" \
		"$config/systemd/user/clipboardbridge-update.service" "$config/systemd/user/clipboardbridge-update.timer" \
		"$config/autostart/clipboardbridge-desktop.desktop" "$HOME/.local/bin/cbb"
	systemctl --user daemon-reload >/dev/null 2>&1 || true
	rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/clipboardbridge" "$config/clipboardbridge" "$state/clipboardbridge-update"
	if [ "$purge" = yes ]; then
		rm -rf "$state/clipboardbridge"
		echo "CBB is removed, with this device's keys; it left its group."
	else
		echo "CBB is removed. Its keys stay in $state/clipboardbridge for a reinstall; --purge removes them."
	fi
	exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
	echo "uninstall.sh: run it with sudo" >&2
	exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
	systemctl disable --now clipboardbridge-console.service >/dev/null 2>&1 || true
	systemctl disable --now clipboardbridge-uinput.service >/dev/null 2>&1 || true
	systemctl disable --now clipboardbridge.service >/dev/null 2>&1 || true
	systemctl disable --now clipboardbridge-update.timer >/dev/null 2>&1 || true
fi
# The desktop agent runs in each user's session, from the user unit or the
# autostart entry; it stops here too, or it would keep the clipboard until
# the user logs out.
if command -v systemctl >/dev/null 2>&1; then
	systemctl --global disable clipboardbridge-agent.service >/dev/null 2>&1 || true
	for dir in /run/user/*/systemd; do
		[ -d "$dir" ] || continue
		user=$(stat -c %U "$dir") || continue
		systemctl --user -M "$user@" stop clipboardbridge-agent.service >/dev/null 2>&1 || true
	done
fi
# install.sh puts it in /usr/local, or on SteamOS in /opt/clipboardbridge.
cbb=/usr/local/bin/cbb
share=/usr/local/share/clipboardbridge
if [ -e /opt/clipboardbridge/bin/cbb ]; then
	cbb=/opt/clipboardbridge/bin/cbb
	share=/opt/clipboardbridge/share
fi
if command -v pkill >/dev/null 2>&1; then
	pkill -x -f "$cbb agent" >/dev/null 2>&1 || true
	pkill -x cbb-desktop >/dev/null 2>&1 || true
fi
if [ -f "$share/firewall.sh" ]; then
	sh "$share/firewall.sh" close
	sh "$share/firewall.sh" hub-close
fi
rm -f /etc/systemd/system/clipboardbridge.service.d/away.conf /etc/systemd/system/clipboardbridge.service.d/cgnat.conf \
	/etc/systemd/system/clipboardbridge.service.d/tpm.conf
rmdir /etc/systemd/system/clipboardbridge.service.d 2>/dev/null || true
rm -f /etc/systemd/system/clipboardbridge.service /etc/systemd/system/clipboardbridge-console.service \
	/etc/systemd/system/clipboardbridge-uinput.service /etc/modules-load.d/clipboardbridge-uinput.conf \
	/etc/systemd/system/clipboardbridge-update.service /etc/systemd/system/clipboardbridge-update.timer \
	/etc/xdg/autostart/clipboardbridge-desktop.desktop /etc/xdg/autostart/clipboardbridge-tray.desktop \
	/usr/local/share/applications/clipboardbridge.desktop /usr/local/bin/cbb-desktop \
	/etc/systemd/user/clipboardbridge-agent.service \
	/etc/profile.d/clipboardbridge-console.sh /usr/lib/sysusers.d/clipboardbridge.conf /usr/local/bin/cbb \
	/etc/profile.d/clipboardbridge-path.sh /etc/sysusers.d/clipboardbridge.conf /etc/atomic-update.conf.d/clipboardbridge.conf
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
if [ -f /etc/tmux.conf ]; then
	line="source-file -q $share/tmux.conf"
	grep -vxF "$line" /etc/tmux.conf >/etc/tmux.conf.clipboardbridge || true
	cat /etc/tmux.conf.clipboardbridge >/etc/tmux.conf
	rm -f /etc/tmux.conf.clipboardbridge
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
rm -rf "$share" /etc/clipboardbridge /var/lib/clipboardbridge-update /opt/clipboardbridge /opt/clipboardbridge-update
if [ "$purge" = yes ]; then
	rm -rf /var/lib/clipboardbridge
	echo "CBB is removed, with this device's keys; it left its group."
else
	echo "CBB is removed. Its keys stay in /var/lib/clipboardbridge for a reinstall; --purge removes them."
fi
