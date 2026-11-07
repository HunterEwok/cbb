// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build benchtime

package vless

import "os"

// In the bench's time-scaled build only (internal/benchtime), never in a
// release: the clients of XHTTP trust the CA in the PEM file
// CBB_TEST_XHTTP_CA too, for the bench's web server in front of a
// forwarder, whose certificate no public CA signs (docs/testbench-catalogue.md,
// W46). A file that is not there yet is skipped.
func init() {
	if file := os.Getenv("CBB_TEST_XHTTP_CA"); file != "" {
		if pem, err := os.ReadFile(file); err == nil {
			TrustForTests(pem)
		}
	}
}
