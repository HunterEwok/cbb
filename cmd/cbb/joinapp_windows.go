// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

// noFollow is nothing on Windows, whose open has no such flag: the check
// that the opened file is the one Lstat saw stands for it.
const noFollow = 0
