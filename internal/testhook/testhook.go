// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package testhook reads the tests' hooks, the environment variables
// CBB_TEST_* (and CBB_TPM_SIMULATOR) with which the service's tests steer
// cbb-helper. Only a build for tests reads them: a test binary, or a program
// built with the tag testhooks, which a release never is (docs/maintainers/maintaining.md,
// "Test builds"); any other build does as it would without the variable.
package testhook

import (
	"os"
	"testing"
)

// Enabled reports whether this program reads the hooks.
func Enabled() bool { return tagged || testing.Testing() }

// Getenv is os.Getenv in a build for tests, else always "".
func Getenv(name string) string {
	v, _ := LookupEnv(name)
	return v
}

// LookupEnv is os.LookupEnv in a build for tests, else never set.
func LookupEnv(name string) (string, bool) {
	if !Enabled() {
		return "", false
	}
	return os.LookupEnv(name)
}

// Marker is the line a build with the tag testhooks carries and says, the
// same words as member/src/testbuild.rs's MARKER: the release workflow
// looks for it in every program it publishes (.github/hooks-marker.sh).
const Marker = "cbb-test-build-not-for-release"

// Note is what cbb-helper version and its first log line say of the
// hooks: "" in a release build.
func Note() string {
	if !tagged {
		return ""
	}
	return "a build for tests (" + Marker + "): it reads the test hooks; never install it"
}
