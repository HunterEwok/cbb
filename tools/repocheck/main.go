// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command repocheck enforces the repository rules that the Go tools do not
// check:
//
//   - every tracked text file is in English: no Cyrillic letters, except the
//     translations of the apps (String Catalogs, *.xcstrings, Android's
//     res/values-<language>/strings.xml, the tray app's
//     frontend/l10n/<language>.json, the Aurora app's
//     translations/cbb-<language>.ts, the website's site/l10n/<language>.json
//     and the Android app's store texts, fastlane/metadata/android/<locale>/
//     for a language other than English);
//   - every Go and Rust file, except generated Go code, starts with the
//     license header;
//   - code copied from other projects lives in a directory below a
//     third_party directory, with its LICENSE file next to it, and each of
//     its Go and Rust files keeps its own copyright notice instead of the
//     header;
//   - the documentation's links, names and command reference hold (docs.go);
//   - the Android apps' version is the last release in CHANGELOG.md
//     (version.go);
//   - no compiled program (ELF, Mach-O, PE) and no file over 1 MiB is
//     committed: build output belongs outside the repository, and a large
//     file stays in git's history for good;
//   - with -tests-since COMMIT, every test function of Go, Rust, Swift and
//     Kotlin that COMMIT has is still there, unless the change lists it in
//     removed-tests.txt with a decision (tests.go).
//
// Run it anywhere inside the repository:
//
//	go run ./tools/repocheck
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"unicode"
)

const spdxLine = "// SPDX-License-Identifier: AGPL-3.0-only"

var copyrightLine = regexp.MustCompile(`^// Copyright \(C\) \d{4}(-\d{4})? HunterEwok$`)

func main() {
	since := flag.String("tests-since", "", "also report the test functions that this commit has and the tree does not")
	flag.Parse()
	problems, checked, err := checkRepo(*since)
	if err != nil {
		fmt.Fprintln(os.Stderr, "repocheck:", err)
		os.Exit(1)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "repocheck: %d problem(s) in %d file(s) checked\n", len(problems), checked)
		os.Exit(1)
	}
}

// checkRepo checks the repository that contains the current directory and
// returns the problems and the number of files checked.
func checkRepo(testsSince string) (problems []string, checked int, err error) {
	top, err := git("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, 0, err
	}
	if err := os.Chdir(strings.TrimSpace(top)); err != nil {
		return nil, 0, err
	}
	// Tracked files and new files that are not ignored, so a local run also
	// checks files that are not committed yet.
	out, err := git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--deduplicate")
	if err != nil {
		return nil, 0, err
	}
	type file struct {
		name string
		data []byte
	}
	var files []file
	listed := make(map[string]bool)
	for _, name := range strings.Split(out, "\x00") {
		if name == "" {
			continue
		}
		data, ok, err := readEntry(name)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if ok {
			files = append(files, file{name, data})
			listed[name] = true
		}
	}
	contents := make(map[string][]byte, len(files))
	for _, f := range files {
		contents[f.name] = f.data
	}
	for _, f := range files {
		problems = append(problems, check(f.name, f.data, listed)...)
		problems = append(problems, checkDocs(f.name, f.data, contents)...)
		problems = append(problems, checkOldName(f.name, f.data)...)
	}
	problems = append(problems, checkCommands(contents)...)
	problems = append(problems, checkFlags(contents)...)
	problems = append(problems, checkPorts(contents)...)
	problems = append(problems, checkOps(contents)...)
	problems = append(problems, checkStyle(contents)...)
	problems = append(problems, checkEnv(contents)...)
	problems = append(problems, checkIndex(contents)...)
	problems = append(problems, checkPlanned(contents)...)
	problems = append(problems, checkAndroidVersion(contents)...)
	problems = append(problems, checkSpecVersions(contents)...)
	if testsSince != "" {
		lost, err := checkTestsKept(testsSince, contents)
		if err != nil {
			return nil, 0, err
		}
		problems = append(problems, lost...)
	}
	return problems, len(files), nil
}

// readEntry returns the content to check for one listed path: the file, or
// the target path of a symbolic link. It reports false for entries that have
// no content of their own: a deletion not committed yet, a submodule or a
// directory.
func readEntry(name string) ([]byte, bool, error) {
	fi, err := os.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(name)
		return []byte(target), err == nil, err
	case !fi.Mode().IsRegular():
		return nil, false, nil
	}
	data, err := os.ReadFile(name)
	return data, err == nil, err
}

// git runs a git command and returns its standard output.
func git(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// androidTranslation matches the strings of a language other than the
// default one in an Android project.
var androidTranslation = regexp.MustCompile(`(^|/)res/values-[a-z]{2,3}(-r[A-Z]{2})?/strings\.xml$`)

// desktopTranslation matches the texts of a language other than English
// in the tray app.
var desktopTranslation = regexp.MustCompile(`^apps/desktop/frontend/l10n/[a-z]{2,3}\.json$`)

// siteTranslation matches the texts of a language other than English on
// the website.
var siteTranslation = regexp.MustCompile(`^site/l10n/[a-z]{2,3}\.json$`)

// docTranslation matches a translated page of the guide on the website
// (site/docs/<language>/guide/), a translated picture of the documentation
// (docs/images/<language>/) and a language's texts for the pictures
// (tools/diagrams/l10n).
var docTranslation = regexp.MustCompile(`^(site/docs/[a-z]{2,3}/.+\.md|docs/images/[a-z]{2,3}/[^/]+\.svg|tools/diagrams/l10n/[a-z]{2,3}\.json)$`)

// silicaTranslation matches the texts of a language other than English in
// the app for Aurora OS and Sailfish OS (Qt's .ts files).
var silicaTranslation = regexp.MustCompile(`^apps/silica/translations/cbb-[a-z]{2,3}\.ts$`)

// storeTranslation matches the store texts of a locale in an Android
// project (F-Droid's fastlane layout); the first group is its language.
var storeTranslation = regexp.MustCompile(`(^|/)fastlane/metadata/android/([a-z]{2,3})(-[A-Za-z0-9]+)?/`)

// isTranslation reports whether a file holds the apps' translations, which
// are the one place for other languages.
func isTranslation(name string) bool {
	if m := storeTranslation.FindStringSubmatch(name); m != nil && m[2] != "en" {
		return true
	}
	return strings.HasSuffix(name, ".xcstrings") || androidTranslation.MatchString(name) || desktopTranslation.MatchString(name) || siteTranslation.MatchString(name) || docTranslation.MatchString(name) || silicaTranslation.MatchString(name)
}

// check returns the rule violations in one file; listed holds the paths of
// all files checked, which exist in the working tree.
func check(name string, data []byte, listed map[string]bool) []string {
	if kind := programKind(data); kind != "" {
		return []string{fmt.Sprintf("%s:1: a compiled program (%s); build output must not be committed, build into a directory outside the repository or one .gitignore lists", name, kind)}
	}
	if len(data) > maxFileSize {
		return []string{fmt.Sprintf("%s:1: %d bytes, over the limit of %d; large files stay in git's history for good", name, len(data), maxFileSize)}
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil // a binary file
	}
	var problems []string
	for i, line := range strings.Split(string(data), "\n") {
		if isTranslation(name) {
			break
		}
		if r, ok := firstCyrillic(line); ok {
			problems = append(problems, fmt.Sprintf("%s:%d: Cyrillic letter %q; the repository is in English only", name, i+1, r))
		}
	}
	if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".rs") {
		return problems
	}
	generated := strings.HasSuffix(name, ".go") && isGenerated(data)
	if dir := thirdPartyDir(name); dir != "" {
		if !listed[dir+"/LICENSE"] {
			problems = append(problems, fmt.Sprintf("%s:1: copied code without %s/LICENSE", name, dir))
		}
		if !generated && !strings.HasPrefix(string(data), "// Copyright ") {
			problems = append(problems, fmt.Sprintf("%s:1: copied code must keep its copyright notice on the first line", name))
		}
		return problems
	}
	if !generated && !hasHeader(data) {
		problems = append(problems, fmt.Sprintf("%s:1: missing license header; start the file with\n\t%s\n\t// Copyright (C) <year> HunterEwok", name, spdxLine))
	}
	return problems
}

// maxFileSize is the largest file the repository takes; the largest ones
// today are the app icons, under half of it.
const maxFileSize = 1 << 20

// programKind names the executable format that data starts with, or returns
// "" for any other file.
func programKind(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		return "ELF"
	case bytes.HasPrefix(data, []byte{0xcf, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(data, []byte{0xce, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(data, []byte{0xca, 0xfe, 0xba, 0xbe}) && len(data) >= 8 && data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] < 0x20:
		// Mach-O, 64 and 32 bits, and a universal binary, whose header
		// counts its architectures where a Java class has its version.
		return "Mach-O"
	case bytes.HasPrefix(data, []byte("MZ")) && len(data) >= 0x40 && isPE(data):
		return "PE"
	case bytes.HasPrefix(data, []byte("\x00asm\x01\x00\x00\x00")):
		// A WebAssembly module, such as the core's for wazero
		// (internal/core/cbb_core.wasm, built by wasm/build.sh).
		return "WebAssembly"
	}
	return ""
}

// isPE reports whether an MZ file carries a PE header where its DOS header
// points.
func isPE(data []byte) bool {
	off := int(data[0x3c]) | int(data[0x3d])<<8 | int(data[0x3e])<<16 | int(data[0x3f])<<24
	return off >= 0x40 && off+4 <= len(data) && string(data[off:off+4]) == "PE\x00\x00"
}

// thirdPartyDir returns the directory of the copied package that the file
// name belongs to: the directory right below a third_party directory, such
// as internal/third_party/cpace. It returns "" for the project's own files.
func thirdPartyDir(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if p == "third_party" && i+2 < len(parts) {
			return strings.Join(parts[:i+2], "/")
		}
	}
	return ""
}

func firstCyrillic(s string) (rune, bool) {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return r, true
		}
	}
	return 0, false
}

// isGenerated reports whether a Go file carries the generated-code marker
// before its package clause, as https://go.dev/s/generatedcode defines it.
func isGenerated(data []byte) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "", data, parser.PackageClauseOnly|parser.ParseComments)
	return err == nil && ast.IsGenerated(f)
}

func hasHeader(data []byte) bool {
	lines := strings.SplitN(string(data), "\n", 3)
	if len(lines) < 2 {
		return false
	}
	return strings.TrimSuffix(lines[0], "\r") == spdxLine &&
		copyrightLine.MatchString(strings.TrimSuffix(lines[1], "\r"))
}
