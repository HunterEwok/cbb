// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package testhooks reads the test hooks (build tag testhooks, which
// benchtime implies, never a release's): the end-to-end tests' variables
// that change whom cbb-helper trusts. They are read here only; a release
// build reads none of them, and cbb-helper version and the helper's first
// log line say when a build has them.
package testhooks

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// Vars are the variables only a build with the test hooks reads. Every
// other CBB_TEST_ variable a program reads is listed as ungated in this
// package's test, so that a new one is put on one side or the other.
var Vars = []string{"CBB_TEST_ATTEST_ROOTS", "CBB_TEST_TPM_ROOTS", "CBB_TEST_BLUEZ"}

// Getenv returns the test hook name, one of Vars; "" in a build without
// the test hooks, whatever the environment holds. The packages' own unit
// tests read them too: testing.Testing reports true only in a binary that
// go test built, which no shipped binary is.
func Getenv(name string) string {
	if !slices.Contains(Vars, name) {
		panic(name + " is not a test hook")
	}
	if !open(Enabled, testing.Testing()) {
		return ""
	}
	return os.Getenv(name)
}

// open reports whether the hooks are read: in a build with them, or in a
// binary go test built. A release helper is neither; tools/hookprobe asks
// one, in CI's hooks job, whether it still refuses what a hook would let
// through.
func open(enabled, underTest bool) bool { return enabled || underTest }

// Note is what cbb-helper version and its first log line say of the
// hooks: "" in a release build.
func Note() string {
	if !Enabled {
		return ""
	}
	var set []string
	for _, v := range Vars {
		if Getenv(v) != "" {
			set = append(set, v)
		}
	}
	if len(set) == 0 {
		return "test hooks build: reads the test variables; never install it"
	}
	return fmt.Sprintf("test hooks build: reads the test variables (%s set); never install it", strings.Join(set, ", "))
}
