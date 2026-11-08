// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import "time"

// The files and folders the service keeps in its state directory, which the
// tests look at, as the Rust cbb names them.
const (
	syncFile        = "sync.json"     // sync on or off (member/src/sync.rs)
	signedFile      = "signed.json"   // the records this device signed
	contentDir      = "content"       // the parts of images and files
	releaseFilesDir = "release-files" // the archives of the release held
)

// groupFiles are the files of the group that cbb leave deletes
// (member/src/leave.rs).
var groupFiles = []string{
	"identity.json", "credentials.json", "server-keys.json", "seal.json", signedFile, "tunnel.json",
	"entries.json", "networks.json", "attest-status.json", contentDir, "pastes.json", "actions-log.json",
	"mute.json", "before-0.6", "records.json",
}

// The remote paste targets as the Rust cbb names them (member/src/service.rs).
const (
	targetTmux    = "tmux"
	targetDesktop = "desktop"
)

// How long the tests wait for a join and for a connection; the second is
// the Rust cbb's own HANDSHAKE_TIMEOUT (member/src/node.rs).
const (
	joinTimeout      = 2 * time.Minute
	handshakeTimeout = 10 * time.Second
)

// restartAfter is how long the Rust cbb waits before it connects again
// after a mute or a restart (RESTART_AFTER in member/src/service.rs).
const restartAfter = 500 * time.Millisecond
