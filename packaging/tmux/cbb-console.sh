# shellcheck shell=sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Start tmux after a login on the Linux text console, so that copy and paste
# reach the group there too. Installed to /etc/profile.d only on request.
if [ -z "${TMUX:-}" ] && [ "${TERM:-}" = "linux" ] && [ -t 0 ] && command -v tmux >/dev/null 2>&1; then
	case "$(tty)" in
	/dev/tty[0-9]*) tmux new-session -A -s "console-$(basename "$(tty)")" ;;
	esac
fi
