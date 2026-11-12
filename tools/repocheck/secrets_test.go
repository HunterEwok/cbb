// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"strings"
	"testing"
)

func TestReleaseSecrets(t *testing.T) {
	const flow = `name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    environment: release # the signing keys
    steps:
      - run: sign
        env:
          KEY: ${{ secrets.CBB_KEY }}
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: gh release upload
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  leak:
    runs-on: ubuntu-latest
    steps:
      - run: echo
        env:
          A: ${{ secrets.GITHUB_TOKEN }} ${{ secrets.CBB_TAP_KEY }}
  other-env:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - run: echo ${{ secrets.CBB_FEED_KEY }}
`
	got := checkReleaseSecrets(map[string][]byte{".github/workflows/release.yml": []byte(flow)})
	want := []string{
		".github/workflows/release.yml:21: the job leak reads secrets.CBB_TAP_KEY outside the environment release",
		".github/workflows/release.yml:27: the job other-env reads secrets.CBB_FEED_KEY outside the environment release",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// A secret above the jobs, in a top-level env, is no job's.
	top := "env:\n  A: ${{ secrets.X }}\njobs:\n  a:\n    steps: []\n"
	if got := checkReleaseSecrets(map[string][]byte{".github/workflows/published.yml": []byte(top)}); len(got) != 0 {
		t.Errorf("top-level env: %v", got)
	}
	if got := checkReleaseSecrets(map[string][]byte{"other.yml": []byte(flow)}); len(got) != 0 {
		t.Errorf("another workflow: %v", got)
	}
}

// The release workflows in the tree keep their secrets in the environment.
func TestReleaseSecretsInTheTree(t *testing.T) {
	files := map[string][]byte{}
	for _, name := range releaseWorkflows {
		b, err := os.ReadFile("../../" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "secrets.") {
			t.Fatalf("%s reads no secret", name)
		}
		files[name] = b
	}
	if got := checkReleaseSecrets(files); len(got) != 0 {
		t.Fatal(strings.Join(got, "\n"))
	}
}
