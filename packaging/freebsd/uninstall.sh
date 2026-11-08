#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.sh installed on FreeBSD, as root:
#
#   sh /usr/local/share/cbb/uninstall.sh [--purge]
#
# It stops the service and removes the binary, the rc.d script and its
# rc.conf line, the update's cron file and cbb update's folder, the settings
# in /usr/local/etc/cbb and the firewall rules that install.sh
# added, and only those. The device's keys
# and group, in /var/db/cbb, stay for a reinstall unless
# --purge; the cbb user and group stay too, since files may
# still belong to them.
set -eu

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
export LC_ALL=C

purge=no
case ${1:-} in
'') ;;
--purge) purge=yes ;;
*)
	echo "usage: sh uninstall.sh [--purge]" >&2
	exit 2
	;;
esac
if [ "$(id -u)" -ne 0 ]; then
	echo "uninstall.sh: run it as root (sudo or doas)" >&2
	exit 1
fi

if [ -x /usr/local/etc/rc.d/cbb ]; then
	service cbb onestop >/dev/null 2>&1 || true
fi
sysrc -q -x cbb_enable >/dev/null 2>&1 || true
share=/usr/local/share/cbb
if [ -f "$share/firewall.sh" ]; then
	sh "$share/firewall.sh" close
	sh "$share/firewall.sh" hub-close
fi
rm -f /usr/local/etc/rc.d/cbb /usr/local/etc/rc.d/cbb.sh /usr/local/bin/cbb /usr/local/bin/cbb-helper \
	/usr/local/etc/xdg/autostart/cbb-desktop.desktop /usr/local/etc/cron.d/cbb-update
rm -rf /var/db/cbb-update
# OPNsense: without the hook, the next filter reload drops the anchor.
if [ -f /usr/local/etc/inc/plugins.inc.d/cbb.inc ]; then
	rm -f /usr/local/etc/inc/plugins.inc.d/cbb.inc
	configctl filter reload >/dev/null 2>&1 || true
fi
rm -rf "$share" /usr/local/etc/cbb /var/run/cbb
if [ "$purge" = yes ]; then
	rm -rf /var/db/cbb
	echo "CBB is removed, with this device's keys; it left its group."
else
	echo "CBB is removed. Its keys stay in /var/db/cbb for a reinstall; --purge removes them."
fi
