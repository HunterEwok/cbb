// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command difffuzz compares how the four implementations (Go, the lite
// member's Rust core, the Swift kit and the Kotlin kit) read the bodies that
// come from the network and the record sets they make of them.
//
//	go run ./tools/difffuzz gen -seed 1 -n 20000 -o corpus.jsonl
//	go run ./tools/difffuzz compare -corpus corpus.jsonl go=go-group.txt,go-release.txt rust=rust.txt ...
//
// gen writes a corpus, one case to a line, made from the bodies of
// testdata/interop/strict-generated-*.json and strict-files.json and the
// record sets of the other interop vectors, changed by a pseudo-random
// generator from the seed: the same seed gives the same corpus. compare
// reads the verdict files each implementation's test wrote for that corpus
// (its verdict test runs when CBB_VERDICTS names a corpus and writes to
// CBB_VERDICTS_OUT) and fails on any case they read differently, printing
// the case, so that it can become a vector of strict-generated-*.json. seeds
// writes the same bodies as the seed corpora of the cargo fuzz targets in
// core/fuzz.
//
// A case is a JSON object. A body case is {"kind": K, "body": base64},
// with K one of record, command, manifest, credential, keys, release,
// channel or attest-status. A set case is {"kind": "set", "ca": the group
// CA's DER, "records": [{"body", "sig", "chain"}], "keys": [key hashes]},
// all bytes in standard base64.
//
// A verdict is one line per case, in the corpus's order:
//
//   - "refused" when the implementation refuses the body;
//   - "skip" when it does not read bodies of that kind;
//   - "taken" and, for records, commands and credentials, the fields it
//     read, each " name=value", in the order of fields below;
//   - for a set, "set" and " taken=N" (how many records the set took),
//     " roots=" (SHA-256 of each root's DER), " devices=" (each device as
//     id:name:role:store:admin:admin key:frozen), " revoked=" and
//     " frozen=" (a 0 or 1 for each of the case's keys) and " digest=".
//
// A value is written as: a string as the hex of its UTF-8 bytes, an absent
// one as empty; an integer in decimal; a boolean as 0 or 1; bytes in hex; a
// list as its items joined by "."; a command's text as the hex SHA-256 of
// its UTF-8 bytes, to keep the lines short.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// The fields of a verdict, per kind; every implementation writes these.
var fields = map[string][]string{
	"record": {"type", "group", "signer", "seq", "prev", "time_ms", "device", "name", "role", "os", "store", "key", "admin", "powers",
		"commands", "holds_root", "keys", "root", "records"},
	"command":    {"type", "group", "by", "to", "id", "time_ms", "expires_ms", "mode", "enter", "kind", "text", "action"},
	"credential": {"type", "group", "version", "expires_ms", "tag", "key", "hubs", "admins", "members"},
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: difffuzz gen [-seed N] [-n N] [-sets N] [-o file]\n       difffuzz compare -corpus file impl=file[,file] ...\n       difffuzz seeds -o dir")
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
		sets := fs.Int("sets", 500, "how many record sets")
		out := fs.String("o", "", "the corpus to write (default: standard output)")
		dir := fs.String("vectors", "testdata/interop", "the directory of the interop vectors")
		_ = fs.Parse(os.Args[2:])
		cases, err := generate(*dir, *seed, *n, *sets)
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
