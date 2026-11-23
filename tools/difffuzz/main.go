// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command difffuzz compares how the three implementations (Go, the
// Rust core and the Kotlin kit) read the bodies that come from the network.
//
//	go run ./tools/difffuzz gen -seed 1 -n 20000 -o corpus.jsonl
//	go run ./tools/difffuzz compare -corpus corpus.jsonl go=go-release.txt rust=rust.txt ...
//
// gen writes a corpus, one case to a line, made from the bodies of
// testdata/interop/strict-generated-*.json and strict-files.json, changed
// by a pseudo-random generator from the seed: the same seed gives the same
// corpus. compare
// reads the verdict files each implementation's test wrote for that corpus
// (its verdict test runs when CBB_VERDICTS names a corpus and writes to
// CBB_VERDICTS_OUT) and fails on any case they read differently, printing
// the case, so that it can become a vector of strict-generated-*.json. seeds
// writes the same bodies as the seed corpora of the cargo fuzz targets in
// core/fuzz.
//
// A case is a JSON object, {"kind": K, "body": base64}, with K one of
// manifest, keys, release, channel or attest-status.
//
// A verdict is one line per case, in the corpus's order:
//
//   - "refused" when the implementation refuses the body;
//   - "skip" when it does not read bodies of that kind;
//   - "taken" when it takes the body.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: difffuzz gen [-seed N] [-n N] [-o file]\n       difffuzz compare -corpus file impl=file[,file] ...\n       difffuzz seeds -o dir")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "gen":
		fs := flag.NewFlagSet("gen", flag.ExitOnError)
		seed := fs.Uint64("seed", 1, "the seed of the pseudo-random generator")
		n := fs.Int("n", 20000, "how many changed bodies")
		out := fs.String("o", "", "the corpus to write (default: standard output)")
		dir := fs.String("vectors", "testdata/interop", "the directory of the interop vectors")
		_ = fs.Parse(os.Args[2:])
		cases, err := generate(*dir, *seed, *n)
		if err != nil {
			fmt.Fprintln(os.Stderr, "difffuzz:", err)
			os.Exit(1)
		}
		if err := writeCorpus(*out, cases); err != nil {
			fmt.Fprintln(os.Stderr, "difffuzz:", err)
			os.Exit(1)
		}
	case "seeds":
		fs := flag.NewFlagSet("seeds", flag.ExitOnError)
		out := fs.String("o", "", "the directory to write the seeds to, one directory per cargo fuzz target")
		dir := fs.String("vectors", "testdata/interop", "the directory of the interop vectors")
		_ = fs.Parse(os.Args[2:])
		if *out == "" {
			usage()
		}
		if err := writeSeeds(*dir, *out); err != nil {
			fmt.Fprintln(os.Stderr, "difffuzz:", err)
			os.Exit(1)
		}
	case "compare":
		fs := flag.NewFlagSet("compare", flag.ExitOnError)
		corpus := fs.String("corpus", "", "the corpus the verdicts are for")
		max := fs.Int("max", 20, "how many differences to print")
		failures := fs.String("failures", "", "also write the cases read differently to this file, as a corpus")
		report := fs.String("report-only", "", "kinds, comma-separated, whose differences are printed but do not fail")
		_ = fs.Parse(os.Args[2:])
		if *corpus == "" || fs.NArg() < 2 {
			usage()
		}
		ok, err := compare(os.Stdout, *corpus, fs.Args(), *max, *failures, strings.Split(*report, ","))
		if err != nil {
			fmt.Fprintln(os.Stderr, "difffuzz:", err)
			os.Exit(1)
		}
		if !ok {
			os.Exit(1)
		}
	default:
		usage()
	}
}
