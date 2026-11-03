// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package control

// DefaultSocket is where the service listens on macOS: in a directory that
// only the _cbb group may enter.
const DefaultSocket = "/Library/Application Support/cbb/control.sock"

// Group is the group whose members may use the control socket.
const Group = "_cbb"

// permissionHint tells a user without access to the socket what to do.
const permissionHint = "add your user to the " + Group + " group and log in again"

// startHint tells a user whose service is not running how to start it.
const startHint = "start it with: sudo launchctl kickstart system/tools.cbb"

// adminSocketName is the admin socket's name next to the control socket.
const adminSocketName = "admin.sock"

// adminHint tells a user without access to the admin socket what to do.
const adminHint = "run it with sudo"
