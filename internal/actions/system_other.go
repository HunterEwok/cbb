// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package actions

// Rights lists what the presets in on need on this system beyond what the
// signed-in user has: nothing here.
func Rights(on []string) []string { return nil }

// Grant gives the service the rights the presets in on need: nothing here.
func Grant(on []string) (string, error) { return "", nil }
