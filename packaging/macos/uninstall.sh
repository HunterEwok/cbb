#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Removes what install.sh installed on a Mac:
#
#   sudo sh /usr/local/share/cbb/uninstall.sh [--purge]
#
# It stops the service and the pasteboard agent of every user and removes
# their plists, the service's entry in the application firewall, the binary
# in /usr/local/bin (but not Homebrew's link there: brew uninstall removes
# that), the update timer and cbb update's folder, the settings in
# /etc/cbb and the logs; after the installer package (pkg.sh), CBB.app in
# /Applications and the package's receipt too. The device's keys and group, in
# /Library/Application Support/cbb/state, stay for a reinstall
# unless --purge; the hidden _cbb user and group stay too, since
# files may still belong to them.
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
	echo "usage: sudo sh uninstall.sh [--purge]" >&2
	exit 2
	;;
esac
if [ "$(id -u)" -ne 0 ]; then
	note uninstall.sh "run it with sudo"
	exit 1
fi

daemon=tools.cbb
agent=tools.cbb.agent
launchctl bootout "system/$daemon" 2>/dev/null || true
launchctl bootout "system/$daemon.update" 2>/dev/null || true
# bootout returns while the service may still be exiting.
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
	launchctl print "system/$daemon" >/dev/null 2>&1 || break
	sleep 0.5
done
# The agent runs in each signed-in user's session.
for uid in $(ps -axo uid=,comm= | awk '$2 ~ /(^|\/)cbb$/ { print $1 }' | sort -u); do
	launchctl bootout "gui/$uid/$agent" 2>/dev/null || true
done
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
	launchctl bootout "gui/$(id -u "$SUDO_USER")/$agent" 2>/dev/null || true
fi
# The rights cbb confirm-setup wrote.
# (member/src/confirm.rs, system_rights: one right for each operation
# confirmed each time).
for right in tools.cbb.admin tools.cbb.admin.each \
	tools.cbb.admin.each.new tools.cbb.admin.each.leave tools.cbb.admin.each.take_over \
	tools.cbb.admin.each.recover tools.cbb.admin.each.hand_over tools.cbb.admin.each.key_level \
	tools.cbb.admin.each.takeover_delay tools.cbb.admin.each.make_admin tools.cbb.admin.each.pair \
	tools.cbb.admin.each.join tools.cbb.admin.each.invite tools.cbb.admin.each.away \
	tools.cbb.admin.each.hubs tools.cbb.admin.each.paste_receive tools.cbb.admin.each.keyboard \
	tools.cbb.admin.each.remote; do
	security authorizationdb remove "$right" >/dev/null 2>&1 || true
done
rm -f "/Library/LaunchDaemons/$daemon.plist" "/Library/LaunchDaemons/$daemon.update.plist" "/Library/LaunchAgents/$agent.plist"
rm -rf "/Library/Application Support/cbb-update" "/Library/Application Support/cbb-package"
if [ -f /usr/local/bin/cbb ] && [ ! -L /usr/local/bin/cbb ]; then
	rm -f /usr/local/bin/cbb
fi
for f in cbb-helper cbb-forward cbb-relay; do
	if [ -f "/usr/local/bin/$f" ] && [ ! -L "/usr/local/bin/$f" ]; then
		rm -f "/usr/local/bin/$f"
	fi
done
rm -rf /Library/Logs/cbb /usr/local/share/cbb /etc/cbb
# The app the package installed; one put there by hand or from source stays.
if pkgutil --pkg-info tools.cbb.pkg >/dev/null 2>&1; then
	pkill -x CBB 2>/dev/null || true
	rm -rf /Applications/CBB.app
	pkgutil --forget tools.cbb.pkg >/dev/null
fi
support="/Library/Application Support/cbb"
rm -rf "${support:?}/bin"
fw=/usr/libexec/ApplicationFirewall/socketfilterfw
if [ -f "$support/firewall" ]; then
	if [ -x "$fw" ]; then
		"$fw" --remove "$(cat "$support/firewall")" >/dev/null 2>&1 || true
	fi
	rm -f "$support/firewall"
fi
if [ "$purge" = yes ]; then
	rm -rf "$support"
	say "CBB is removed, with this Mac's keys; it left its group."
else
	rm -f "$support/control.sock" "$support/admin.sock"
	say "CBB is removed. Its keys stay in %s/state for a reinstall; --purge removes them." "$support"
fi
