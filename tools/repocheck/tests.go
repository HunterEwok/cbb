// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// The test functions of each language, by the files they live in and how
// they are declared.
var testFuncs = []struct {
	lang  string
	file  func(name string) bool
	re    *regexp.Regexp
	byDir bool // Go names a test within its package, the others within the language
}{
	{"Go", func(n string) bool { return strings.HasSuffix(n, "_test.go") },
		regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark|Example)\w*)\(`), true},
	{"Rust", func(n string) bool { return strings.HasSuffix(n, ".rs") },
		regexp.MustCompile(`#\[test\]\s*(?:#\[[^\]]*\]\s*)*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)`), false},
	{"Swift", swiftTest,
		regexp.MustCompile(`(?m)^\s*(?:@Test(?:\([^)]*\))?\s+)?func\s+(test\w+|\w+)\s*\(\)\s*(?:async\s+)?(?:throws\s+)?\{`), false},
	{"Kotlin", func(n string) bool { return strings.HasSuffix(n, ".kt") && strings.Contains(n, "/src/test/") },
		regexp.MustCompile("@Test\\s+fun\\s+(`[^`]+`|\\w+)"), false},
}

// swiftTest tells whether a Swift file is a test's: under a folder named
// Tests, as in a package, or one whose name ends in Tests, as an Xcode
// project's test targets are.
func swiftTest(name string) bool {
	if !strings.HasSuffix(name, ".swift") {
		return false
	}
	dirs := strings.Split(path.Dir(name), "/")
	for _, d := range dirs {
		if strings.HasSuffix(d, "Tests") {
			return true
		}
	}
	return false
}

// The ways each language skips a test or leaves it out: the calls in its
// body, and the attributes or annotations before it.
var skipCalls = map[string]*regexp.Regexp{
	"Go":     regexp.MustCompile(`\.\s*Skip(?:f|Now)?\s*\(`),
	"Rust":   regexp.MustCompile(`#\[\s*ignore\b`),
	"Swift":  regexp.MustCompile(`\bXCTSkip(?:If|Unless)?\b|\.disabled\b`),
	"Kotlin": regexp.MustCompile(`@Ignore\b|@Disabled\b|\bassume(?:True|False|That|NotNull)\s*\(|\bAssume\.`),
}

// testSkips counts, for each test function of the files (keyed as
// testNames keys them), the skips in its attributes and its body: the
// text from the attribute lines before it to the next test or the end of
// the file.
func testSkips(files map[string][]byte) map[string]int {
	out := map[string]int{}
	for name, data := range files {
		for _, l := range testFuncs {
			if !l.file(name) {
				continue
			}
			ms := l.re.FindAllSubmatchIndex(data, -1)
			for i, m := range ms {
				fn := string(data[m[2]:m[3]])
				if l.lang == "Swift" && !strings.HasPrefix(fn, "test") && !strings.Contains(string(data[m[0]:m[1]]), "@Test") {
					continue
				}
				end := len(data)
				if i+1 < len(ms) {
					end = attrStart(data, ms[i+1][0])
				}
				start := attrStart(data, m[0])
				key := l.lang + " " + fn
				if l.byDir {
					key = l.lang + " " + path.Dir(name) + " " + fn
				}
				out[key] += len(skipCalls[l.lang].FindAll(data[start:max(start, end)], -1))
			}
		}
	}
	return out
}

// attrStart returns where the attribute or annotation lines just before
// the line of at begin: the lines that start with #[ or @.
func attrStart(data []byte, at int) int {
	start := strings.LastIndexByte(string(data[:at]), '\n') + 1
	for start > 0 {
		prev := strings.LastIndexByte(string(data[:start-1]), '\n') + 1
		line := strings.TrimSpace(string(data[prev : start-1]))
		if !strings.HasPrefix(line, "#[") && !strings.HasPrefix(line, "@") {
			break
		}
		start = prev
	}
	return start
}

// testNames returns the test functions in the files, as "language
// [directory] name" keys, with the file of each.
func testNames(files map[string][]byte) map[string]string {
	out := map[string]string{}
	for name, data := range files {
		for _, l := range testFuncs {
			if !l.file(name) {
				continue
			}
			for _, m := range l.re.FindAllSubmatch(data, -1) {
				fn := string(m[1])
				if l.lang == "Swift" && !strings.HasPrefix(fn, "test") && !strings.Contains(string(m[0]), "@Test") {
					continue
				}
				key := l.lang + " " + fn
				if l.byDir {
					key = l.lang + " " + path.Dir(name) + " " + fn
				}
				out[key] = name
			}
		}
	}
	return out
}

// checkTestsKept reports every test function that the commit base has and
// the files do not: a change keeps every test, and one that replaces a
// test keeps its name (CONTRIBUTING.md, "Tests").
func checkTestsKept(base string, files map[string][]byte) ([]string, error) {
	list, err := git("ls-tree", "-r", "-z", "--name-only", base)
	if err != nil {
		return nil, err
	}
	old := map[string][]byte{}
	for _, name := range strings.Split(list, "\x00") {
		matches := false
		for _, l := range testFuncs {
			matches = matches || (name != "" && l.file(name))
		}
		if !matches {
			continue
		}
		data, err := git("show", base+":"+name)
		if err != nil {
			return nil, err
		}
		old[name] = []byte(data)
	}
	had, have := testNames(old), testNames(files)
	skipped, skips := testSkips(old), testSkips(files)
	baseList, _ := git("show", base+":"+removedTestsFile)
	removed, problems := removedTests(files[removedTestsFile], []byte(baseList), files["docs/decisions.md"])
	for key, file := range have {
		f := strings.Fields(key)
		if removed[file+" "+f[len(f)-1]] {
			problems = append(problems, fmt.Sprintf("%s: the %s test %s is listed in %s but still there", file, f[0], f[len(f)-1], removedTestsFile))
		}
	}
	for key, file := range had {
		f := strings.Fields(key)
		if _, ok := have[key]; !ok {
			if removed[file+" "+f[len(f)-1]] {
				continue
			}
			problems = append(problems, fmt.Sprintf("%s: the %s test %s is gone; keep it, or keep its name for the test that replaces it", file, f[0], f[len(f)-1]))
		} else if skips[key] > skipped[key] {
			problems = append(problems, fmt.Sprintf("%s: the %s test %s skips where it did not; a change keeps every test running", have[key], f[0], f[len(f)-1]))
		}
	}
	sort.Strings(problems)
	return problems, nil
}

// removedTestsFile lists the tests a change removes together with what
// they test, by a decision of docs/decisions.md: one line each, "FILE TEST
// D-N: why", and # for a comment.
const removedTestsFile = "tools/repocheck/removed-tests.txt"

// removedTestLine is one line of removedTestsFile.
var removedTestLine = regexp.MustCompile(`^(\S+) (\S+) (D-[0-9]+): \S.*$`)

// removedTests returns the tests that list excuses, as "FILE TEST" keys,
// and what is wrong with it. A line excuses a test only when the change
// adds it (base, the list at the base commit, lacks it) and names a
// decision that docs/decisions.md (decisions) records, so an old line
// never lets a later change drop a test with the same name.
func removedTests(list, base, decisions []byte) (map[string]bool, []string) {
	old := map[string]bool{}
	for _, l := range strings.Split(string(base), "\n") {
		old[strings.TrimSpace(l)] = true
	}
	out := map[string]bool{}
	var problems []string
	for i, l := range strings.Split(string(list), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || old[l] {
			continue
		}
		m := removedTestLine.FindStringSubmatch(l)
		if m == nil {
			problems = append(problems, fmt.Sprintf("%s:%d: want \"FILE TEST D-N: why\"", removedTestsFile, i+1))
			continue
		}
		if !regexp.MustCompile(`(?m)^\| ` + m[3] + ` \|`).Match(decisions) {
			problems = append(problems, fmt.Sprintf("%s:%d: %s is no decision of docs/decisions.md", removedTestsFile, i+1, m[3]))
			continue
		}
		out[m[1]+" "+m[2]] = true
	}
	return out, problems
}
