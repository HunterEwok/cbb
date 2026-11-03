// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTestNames(t *testing.T) {
	got := testNames(map[string][]byte{
		"a/x_test.go":   []byte("func TestA(t *testing.T) {}\nfunc FuzzB(f *testing.F) {}\nfunc helper() {}\n"),
		"b/x_test.go":   []byte("func TestA(t *testing.T) {}\n"),
		"lite/src/x.rs": []byte("#[test]\nfn one() {}\n#[test]\n#[ignore]\npub fn two() {}\nfn three() {}\n"),
		"k/Tests/T/X.swift": []byte("    func testOne() throws {\n    func helper() {\n    @Test func two() async {\n" +
			"    func testArgs(_ x: Int) {\n"),
		"kit/src/test/kotlin/X.kt": []byte("    @Test\n    fun one() {\n    fun helper() {\n    @Test fun `two words`() {\n"),
	})
	want := []string{"Go a TestA", "Go a FuzzB", "Go b TestA", "Rust one", "Rust two", "Swift testOne", "Swift two",
		"Kotlin one", "Kotlin `two words`"}
	if len(got) != len(want) {
		t.Errorf("%d tests, want %d: %v", len(got), len(want), got)
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("no %q in %v", w, got)
		}
	}
}

func TestTestsKept(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("init", "-q")
	os.MkdirAll(filepath.Join(repo, "p"), 0o755)
	os.WriteFile(filepath.Join(repo, "p/a_test.go"), []byte("func TestKept(t *testing.T) {}\nfunc TestGone(t *testing.T) {}\nfunc TestMoved(t *testing.T) {}\n"), 0o644)
	runGit("add", "-A")
	runGit("-c", "user.name=test", "-c", "user.email=test@example.org", "commit", "-q", "-m", "initial")
	t.Chdir(repo)
	now := map[string][]byte{
		"p/a_test.go": []byte("func TestKept(t *testing.T) {}\n"),
		"p/b_test.go": []byte("func TestMoved(t *testing.T) {}\n"),
	}
	problems, err := checkTestsKept("HEAD", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "TestGone") {
		t.Fatalf("%q", problems)
	}
}

// A Swift file is a test's under Tests and under an Xcode test target.
func TestSwiftTestFiles(t *testing.T) {
	for name, want := range map[string]bool{
		"apps/ios/CBBKit/Tests/CBBKitTests/A.swift": true,
		"apps/ios/CBBTests/A.swift":                 true,
		"apps/macos/CBBMacTests/A.swift":            true,
		"apps/ios/CBBUITests/A.swift":               true,
		"apps/ios/CBB/Tests.swift":                  false,
		"apps/ios/CBB/A.swift":                      false,
		"apps/ios/CBBTests/A.txt":                   false,
	} {
		if got := swiftTest(name); got != want {
			t.Errorf("swiftTest(%q) = %v, want %v", name, got, want)
		}
	}
}

// Each test's skips are counted: calls in its body, and attributes or
// annotations before it.
func TestTestSkips(t *testing.T) {
	got := testSkips(map[string][]byte{
		"a/x_test.go":   []byte("func TestA(t *testing.T) {\n\tt.Skip(\"x\")\n}\n\nfunc helper() {}\n\nfunc TestB(t *testing.T) {\n\tif x {\n\t\tt.Skipf(\"%d\", 1)\n\t}\n\tt.SkipNow()\n}\n"),
		"lite/src/x.rs": []byte("#[test]\nfn one() {}\n\n#[ignore]\n#[test]\nfn two() {}\n\n#[test]\n#[ignore = \"slow\"]\nfn three() {}\n"),
		"k/Tests/T/X.swift": []byte("    func testOne() throws {\n        throw XCTSkip(\"no\")\n    }\n" +
			"    func testTwo() throws {\n        try XCTSkipIf(true)\n    }\n    func testThree() {\n    }\n"),
		"kit/src/test/kotlin/X.kt": []byte("    @Ignore\n    @Test\n    fun one() {\n    }\n    @Test fun two() {\n        assumeTrue(false)\n    }\n    @Test fun three() {\n    }\n"),
	})
	for key, want := range map[string]int{"Go a TestA": 1, "Go a TestB": 2, "Rust one": 0, "Rust two": 1, "Rust three": 1,
		"Swift testOne": 1, "Swift testTwo": 1, "Swift testThree": 0, "Kotlin one": 1, "Kotlin two": 1, "Kotlin three": 0} {
		if got[key] != want {
			t.Errorf("%s: %d skips, want %d (all: %v)", key, got[key], want, got)
		}
	}
}

// A test that the base has and that now skips where it did not is
// reported; a new test may skip.
func TestTestsKeptRunning(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("init", "-q")
	os.MkdirAll(filepath.Join(repo, "p"), 0o755)
	os.WriteFile(filepath.Join(repo, "p/a_test.go"), []byte("func TestRuns(t *testing.T) {}\nfunc TestSkips(t *testing.T) {\n\tt.Skip()\n}\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "x.rs"), []byte("#[test]\nfn runs() {}\n"), 0o644)
	runGit("add", "-A")
	runGit("-c", "user.name=test", "-c", "user.email=test@example.org", "commit", "-q", "-m", "initial")
	t.Chdir(repo)
	now := map[string][]byte{
		"p/a_test.go": []byte("func TestRuns(t *testing.T) {\n\tt.Skip(\"later\")\n}\nfunc TestSkips(t *testing.T) {\n\tt.Skip()\n}\nfunc TestNew(t *testing.T) {\n\tt.Skip()\n}\n"),
		"x.rs":        []byte("#[test]\n#[ignore]\nfn runs() {}\n"),
	}
	problems, err := checkTestsKept("HEAD", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 || !strings.Contains(problems[0], "TestRuns skips") || !strings.Contains(problems[1], "runs skips") {
		t.Fatalf("%q", problems)
	}
}
