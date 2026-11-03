// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package steamos tells whether this program runs from the layout that
// packaging/linux/install.sh uses on SteamOS. Its / is read-only and
// replaced by each system update, so the binary and the shared files live
// in /opt/cbb, which SteamOS keeps in /home, instead of
// /usr/local.
package steamos

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const (
	// Dir holds the binary (bin/cbb) and the shared files (share).
	Dir = "/opt/cbb"
	// Bin is the installed binary.
	Bin = Dir + "/bin/cbb"
	// Share holds the installer's firewall.sh, uninstall.sh and tmux.conf.
	Share = Dir + "/share"
)

var is = sync.OnceValue(func() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return exe == Bin
})

// Is reports whether this program is the one install.sh put in /opt on
// SteamOS. It goes by the program's path rather than by the system, so a
// copy run from elsewhere keeps the usual paths.
func Is() bool { return is() }
