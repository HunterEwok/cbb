// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	// protocolHeading matches a numbered section of docs/protocol.md and
	// the headings below it.
	protocolSection    = regexp.MustCompile(`^## (\d+)\. `)
	protocolSubheading = regexp.MustCompile(`^#{3,4} (.+)$`)
	// protocolRunIn matches a paragraph that starts with its own name in
	// bold, "**Two numbers.** Two different records ...", which is cited
	// as a heading too.
	protocolRunIn = regexp.MustCompile(`^(?:- )?\*\*([^*]+?)\.\*\*`)
	// protocolRef matches a reference to a section of docs/protocol.md
	// from another file, with the heading it names when it quotes one:
	// "protocol.md, section 10", "protocol.md, sections 9 and 10",
	// "protocol.md section 11, "Several hubs"". Comment markers at the
	// start of a line are folded away first, so a reference may wrap.
	protocolRef = regexp.MustCompile(`protocol\.md,? sections? (\d+)(?:(?:,| and|, and) (\d+))*(?:, "([^"]+)")?`)
	// protocolSelfRef matches the same inside docs/protocol.md, where a
	// reference names no file: "section 10, "Watches"".
	protocolSelfRef = regexp.MustCompile(`\b[Ss]ection (\d+), "([^"]+)"`)
	// lineFold matches a line break with the comment marker and the
	// indentation of the next line.
	lineFold = regexp.MustCompile(`[ \t]*\n[ \t]*(?://+!?|#+|\*|--|;+)?[ \t]*`)
)

// checkProtocolRefs reports a reference to a section of docs/protocol.md
// that the document does not have, or to a heading that its section does
// not have: the protocol is cited by section number from code and documents
// across the repository, and a renumbered section or a renamed heading would
// leave those references pointing at the wrong text.
func checkProtocolRefs(files map[string][]byte) []string {
	const name = "docs/protocol.md"
	data, ok := files[name]
	if !ok {
		return nil
	}
	headings := map[int]map[string]bool{}
	section := 0
	var sections, contents []string
	inContents := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") {
			inContents = line == "### Contents"
		} else if inContents && strings.HasPrefix(line, "- ") {
			contents = append(contents, line)
		}
		if m := protocolSection.FindStringSubmatch(line); m != nil {
			title := strings.TrimPrefix(line, "## ")
			sections = append(sections, fmt.Sprintf("- [%s](#%s)", title, slug(title)))
			section, _ = strconv.Atoi(m[1])
			headings[section] = map[string]bool{}
			continue
		}
		if m := protocolRunIn.FindStringSubmatch(line); m != nil && section > 0 {
			headings[section][m[1]] = true
			continue
		}
		if m := protocolSubheading.FindStringSubmatch(line); m != nil && section > 0 {
			h := strings.TrimSpace(m[1])
			headings[section][h] = true
			// "The joiner listens (for the phone)" is cited as "The joiner
			// listens" too.
			if i := strings.LastIndex(h, " ("); i > 0 && strings.HasSuffix(h, ")") {
				headings[section][h[:i]] = true
			}
		}
	}
	var problems []string
	if strings.Join(contents, "\n") != strings.Join(sections, "\n") {
		problems = append(problems, fmt.Sprintf("%s:1: the list under \"### Contents\" is not the numbered sections in order; it should be:\n%s", name, strings.Join(sections, "\n")))
	}
	report := func(file, text string, at int, msg string) {
		line := strings.Count(text[:at], "\n") + 1
		problems = append(problems, fmt.Sprintf("%s:%d: %s", file, line, msg))
	}
	check := func(file, text string, at int, numbers []string, heading string) {
		for _, n := range numbers {
			if n == "" {
				continue
			}
			s, _ := strconv.Atoi(n)
			if headings[s] == nil {
				report(file, text, at, fmt.Sprintf("refers to section %d of %s, which it does not have", s, name))
				return
			}
		}
		if heading == "" {
			return
		}
		s, _ := strconv.Atoi(numbers[len(numbers)-1])
		if !headings[s][heading] {
			report(file, text, at, fmt.Sprintf("refers to %q in section %d of %s, which has no such heading", heading, s, name))
		}
	}
	for _, file := range sortedKeys(files) {
		text := string(files[file])
		if file == "CHANGELOG.md" || !strings.Contains(text, "ection") {
			continue
		}
		// Fold wrapped lines but keep the offsets of line starts, so that
		// a problem names the line where its reference starts.
		folded, starts := foldLines(text)
		if file == name {
			for _, loc := range protocolSelfRef.FindAllStringSubmatchIndex(folded, -1) {
				check(file, text, starts[loc[0]], []string{folded[loc[2]:loc[3]]}, folded[loc[4]:loc[5]])
			}
			continue
		}
		for _, loc := range protocolRef.FindAllStringSubmatchIndex(folded, -1) {
			numbers := []string{folded[loc[2]:loc[3]]}
			if loc[4] >= 0 {
				numbers = append(numbers, folded[loc[4]:loc[5]])
			}
			heading := ""
			if loc[6] >= 0 {
				heading = folded[loc[6]:loc[7]]
			}
			check(file, text, starts[loc[0]], numbers, heading)
		}
	}
	return problems
}

// foldLines joins the lines of text as lineFold says and returns, for each
// byte of the result, the offset of the byte it came from in text.
func foldLines(text string) (string, []int) {
	var b strings.Builder
	offsets := make([]int, 0, len(text)+1)
	last := 0
	for _, loc := range lineFold.FindAllStringIndex(text, -1) {
		for i := last; i < loc[0]; i++ {
			offsets = append(offsets, i)
		}
		b.WriteString(text[last:loc[0]])
		b.WriteByte(' ')
		offsets = append(offsets, loc[0])
		last = loc[1]
	}
	for i := last; i < len(text); i++ {
		offsets = append(offsets, i)
	}
	b.WriteString(text[last:])
	offsets = append(offsets, len(text))
	return b.String(), offsets
}
