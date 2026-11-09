#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.sh installed on OpenWrt, as root:
#
#   sh /usr/share/cbb/uninstall.sh [--purge]
#
# It stops the service, whose firewall rules go with it, and removes the
# binary, the init script, the NTP hook, the capability file, the keep list,
# the settings in /etc/config/cbb, the update's cron line and
# cbb update's folder. The device's keys and
# group, in /etc/cbb, stay for a reinstall unless --purge; the
# cbb user and group stay too.
set -eu

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
# where install.sh put it, or in the archive).
cbb_l10n=$(cd "$(dirname "$0")" && pwd)/l10n
[ -f "$cbb_l10n.sh" ] || cbb_l10n=${cbb_l10n%/l10n}/../l10n
# shellcheck source=packaging/l10n.sh
. "$cbb_l10n.sh"

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
	note uninstall.sh "run it as root"
	exit 1
fi

if [ -x /etc/init.d/cbb ]; then
	/etc/init.d/cbb stop || true
	/etc/init.d/cbb disable || true
fi
# procd sends the service SIGTERM and returns before it has exited.
for _ in 1 2 3 4 5 6 7 8 9 10; do
	pgrep -x -f "/usr/bin/cbb service.*" >/dev/null 2>&1 || break
	sleep 1
done
rm -f /etc/cbb/firewall.hub
/etc/init.d/firewall reload >/dev/null 2>&1 || true
rm -f /etc/init.d/cbb /etc/hotplug.d/ntp/50-cbb /lib/upgrade/keep.d/cbb \
	/etc/capabilities/cbb.json /etc/config/cbb /usr/bin/cbb /var/state/cbb.time
rm -rf /usr/share/cbb /var/run/cbb /etc/cbb-update /tmp/cbb-update
if grep -q '# cbb-update$' /etc/crontabs/root 2>/dev/null; then
	grep -v '# cbb-update$' /etc/crontabs/root >/etc/crontabs/root.new || true
	mv -f /etc/crontabs/root.new /etc/crontabs/root
	/etc/init.d/cron restart >/dev/null 2>&1 || true
fi
if [ "$purge" = yes ]; then
	rm -rf /etc/cbb
	say "CBB is removed, with this device's keys; it left its group."
else
	say "CBB is removed. Its keys stay in /etc/cbb for a reinstall; --purge removes them."
fi
