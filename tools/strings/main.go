// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command strings writes the apps' translations from their one source,
// apps/l10n/<language>.json (tools/strings/catalog): the String Catalogs,
// Android's strings.xml, the Aurora app's Qt files and the tray app's
// l10n. It also puts the source itself in order (sorted by ID, one string
// a line), so a new string may go anywhere in it.
//
//	go run ./tools/strings          rewrite the source and the generated files
//	go run ./tools/strings -check   fail if any of them is out of date
//
// tools/repocheck runs the same check.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/HunterEwok/cbb/tools/strings/catalog"
)

func main() {
	check := flag.Bool("check", false, "report the files that are out of date instead of writing them")
	flag.Parse()
	src, err := catalog.Load(os.ReadFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	files := src.Generate()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	stale := 0
	for _, n := range names {
		old, _ := os.ReadFile(n)
		if bytes.Equal(old, files[n]) {
			continue
		}
		if *check {
			fmt.Fprintf(os.Stderr, "%s is out of date: run go run ./tools/strings\n", n)
			stale++
			continue
		}
		if err := os.WriteFile(n, files[n], 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("wrote", n)
	}
	if stale > 0 {
		os.Exit(1)
	}
}
