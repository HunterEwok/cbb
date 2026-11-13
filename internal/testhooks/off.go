// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !testhooks && !benchtime

package testhooks

// Enabled: a release build reads no test hook.
const Enabled = false
