// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !unix

package main

// watchParent does nothing where an orphan keeps its parent's process ID
// (Windows); the end of its input ends the helper there.
func watchParent() {}
