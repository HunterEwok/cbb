// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The program TestNotReadInAProgram builds: it prints the hook
// CBB_TEST_RESOLVE as it reads it.
package main

import (
	"fmt"

	"github.com/HunterEwok/cbb/internal/testhook"
)

func main() { fmt.Print(testhook.Getenv("CBB_TEST_RESOLVE")) }
