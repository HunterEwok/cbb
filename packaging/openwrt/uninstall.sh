#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.sh installed on OpenWrt, as root:
#
#   sh /usr/share/clipboardbridge/uninstall.sh [--purge]
#
# It stops the service, whose firewall rules go with it, and removes the
# binary, the init script, the NTP hook, the capability file, the keep list,
# the settings in /etc/config/clipboardbridge, the update's cron line and
# cbb update's folder. The device's keys and
# group, in /etc/clipboardbridge, stay for a reinstall unless --purge; the
# clipboardbridge user and group stay too.
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
	echo "uninstall.sh: run it as root" >&2
	exit 1
fi

if [ -x /etc/init.d/clipboardbridge ]; then
	/etc/init.d/clipboardbridge stop || true
	/etc/init.d/clipboardbridge disable || true
fi
rm -f /etc/clipboardbridge/firewall.hub
/etc/init.d/firewall reload >/dev/null 2>&1 || true
rm -f /etc/init.d/clipboardbridge /etc/hotplug.d/ntp/50-clipboardbridge /lib/upgrade/keep.d/clipboardbridge \
	/etc/capabilities/clipboardbridge.json /etc/config/clipboardbridge /usr/bin/cbb /var/state/clipboardbridge.time
rm -rf /usr/share/clipboardbridge /var/run/clipboardbridge /etc/clipboardbridge-update /tmp/clipboardbridge-update
if grep -q '# clipboardbridge-update$' /etc/crontabs/root 2>/dev/null; then
	grep -v '# clipboardbridge-update$' /etc/crontabs/root >/etc/crontabs/root.new || true
	mv -f /etc/crontabs/root.new /etc/crontabs/root
	/etc/init.d/cron restart >/dev/null 2>&1 || true
fi
if [ "$purge" = yes ]; then
	rm -rf /etc/clipboardbridge
	echo "CBB is removed, with this device's keys; it left its group."
else
	echo "CBB is removed. Its keys stay in /etc/clipboardbridge for a reinstall; --purge removes them."
fi
