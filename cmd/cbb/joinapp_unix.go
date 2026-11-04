// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

import "syscall"

// noFollow makes opening the app's file fail on a symbolic link, and not
// wait on a pipe put in its place.
const noFollow = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
