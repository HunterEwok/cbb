// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build unix

package main

import (
	"os"
	"time"
)

// watchParent ends the helper once cbb, its parent, is gone. The end of its
// input tells it so too, but not while a request holds it, such as one
// that waits for a TPM another program has: an orphan would keep the TPM
// and cbb's log open.
func watchParent() {
	parent := os.Getppid()
	go func() {
		for range time.Tick(time.Second) {
			if os.Getppid() != parent {
				os.Exit(1)
			}
		}
	}()
}
