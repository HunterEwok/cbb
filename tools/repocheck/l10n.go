// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// installerTranslation matches the catalog of a language of the installers'
// messages (packaging/l10n.sh).
var installerTranslation = regexp.MustCompile(`^packaging/l10n/[a-z]{2,3}\.tsv$`)

// installerLanguages are the project's languages besides English, each of
// which has a catalog.
var installerLanguages = []string{"ar", "es", "he", "hi", "ru", "sw", "zh"}

// installerCall finds the texts the scripts hand packaging/l10n.sh: the
// first argument of say, sayerr, t, cbb_text and a script's fail, or the
// second one of note, quoted in double or single quotes.
var installerCall = regexp.MustCompile(`(?m)(?:^|[\s;|&(])(?:say|sayerr|t|cbb_text|fail|note [A-Za-z0-9_.-]+) ("(?:[^"\\]|\\.)*"|'[^']*')`)

// forwarded matches an argument that is one variable, which a function
// hands on rather than says ("$@", "$1", "$reply").
var forwarded = regexp.MustCompile(`^"\$(?:[@*0-9]|\{?[A-Za-z_][A-Za-z0-9_]*\}?)"$`)

// installerCallPS finds the texts the PowerShell scripts hand
// packaging/windows/l10n.ps1: the first argument of T, quoted.
var installerCallPS = regexp.MustCompile(`(?m)(?:^|[\s;(=])T (?:-Text )?('(?:[^']|'')*'|"(?:[^"` + "`" + `]|` + "`" + `.)*")`)

// installerDirective matches a printf directive in a text.
var installerDirective = regexp.MustCompile(`%.`)

// speaksThroughL10n reports whether a script's messages go through
// packaging/l10n.sh: it sources the file, or says that its caller did.
func speaksThroughL10n(name string, data []byte) bool {
	if !strings.HasPrefix(name, "packaging/") || name == "packaging/l10n-embed.sh" {
		return false
	}
	switch path.Ext(name) {
	case ".sh", "":
		return strings.Contains(string(data), "l10n.sh")
	case ".ps1":
		return strings.Contains(string(data), "l10n.ps1")
	}
	return false
}

// unquotePS returns the text of a PowerShell string in single or double
// quotes, and whether it is a constant.
func unquotePS(word string) (string, bool) {
	inner := word[1 : len(word)-1]
	if word[0] == '\'' {
		return strings.ReplaceAll(inner, "''", "'"), true
	}
	if strings.ContainsAny(inner, "$`") {
		return "", false
	}
	return inner, true
}

// unquoteShell returns the text of a shell word in double or single quotes,
// and whether it is a constant: no variable or command in it.
func unquoteShell(word string) (string, bool) {
	if word[0] == '\'' {
		return word[1 : len(word)-1], true
	}
	var b strings.Builder
	inner := word[1 : len(word)-1]
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case c == '\\' && i+1 < len(inner) && strings.IndexByte("\"\\$`", inner[i+1]) >= 0:
			i++
			b.WriteByte(inner[i])
		case c == '$' || c == '`':
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// directives returns the number of %s in a text, or an error for another
// directive.
func directives(text string) (int, error) {
	n := 0
	for _, d := range installerDirective.FindAllString(text, -1) {
		switch d {
		case "%s":
			n++
		case "%%":
		default:
			return 0, fmt.Errorf("the directive %s; a text takes only %%s and %%%%", d)
		}
	}
	if strings.HasSuffix(strings.ReplaceAll(text, "%%", ""), "%") {
		return 0, fmt.Errorf("a lone %% at the end")
	}
	return n, nil
}

// checkInstallerL10n checks the installers' messages against their
// catalogs: every text the scripts hand packaging/l10n.sh is a constant
// printf format with only %s, and every catalog translates each of them, and
// nothing else, with as many %s.
func checkInstallerL10n(contents map[string][]byte) []string {
	var problems []string
	texts := map[string]string{} // text -> where it is first used
	for name, data := range contents {
		if !speaksThroughL10n(name, data) {
			continue
		}
		call, unquote := installerCall, unquoteShell
		if strings.HasSuffix(name, ".ps1") {
			call, unquote = installerCallPS, unquotePS
		}
		for _, m := range call.FindAllSubmatchIndex(data, -1) {
			if forwarded.Match(data[m[2]:m[3]]) {
				continue
			}
			line := 1 + strings.Count(string(data[:m[2]]), "\n")
			text, ok := unquote(string(data[m[2]:m[3]]))
			where := fmt.Sprintf("%s:%d", name, line)
			switch {
			case !ok:
				problems = append(problems, where+": a translated text names a variable or a command; give it as an argument for a %s")
				continue
			case strings.ContainsAny(text, "\\\t\n"):
				problems = append(problems, where+": a translated text with a backslash, a tab or a newline, which a catalog line cannot hold")
				continue
			case text == "":
				continue
			}
			if _, err := directives(text); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", where, err))
				continue
			}
			if old, seen := texts[text]; !seen || where < old {
				texts[text] = where
			}
		}
	}
	var langs []string
	for name := range contents {
		if installerTranslation.MatchString(name) {
			langs = append(langs, strings.TrimSuffix(path.Base(name), ".tsv"))
		}
	}
	sort.Strings(langs)
	// A tree without installer texts or catalogs (a test's) needs none.
	if (len(langs) > 0 || len(texts) > 0) && !slices.Equal(langs, installerLanguages) {
		problems = append(problems, fmt.Sprintf("packaging/l10n: catalogs for %s, not for the project's languages %s", strings.Join(langs, " "), strings.Join(installerLanguages, " ")))
	}
	for _, lang := range langs {
		name := "packaging/l10n/" + lang + ".tsv"
		got := map[string]bool{}
		body := strings.TrimSuffix(string(contents[name]), "\n")
		for i, line := range strings.Split(body, "\n") {
			if body == "" {
				break
			}
			where := fmt.Sprintf("%s:%d", name, i+1)
			english, translated, ok := strings.Cut(line, "\t")
			if !ok || translated == "" || strings.Contains(translated, "\t") {
				problems = append(problems, where+": a line is the English text, one tab and its translation")
				continue
			}
			if got[english] {
				problems = append(problems, where+": the text is translated twice")
			}
			got[english] = true
			if _, used := texts[english]; !used {
				problems = append(problems, fmt.Sprintf("%s: no script says %q any more", where, english))
				continue
			}
			want, _ := directives(english)
			n, err := directives(translated)
			switch {
			case err != nil:
				problems = append(problems, fmt.Sprintf("%s: %v", where, err))
			case n != want:
				problems = append(problems, fmt.Sprintf("%s: %d %%s in the translation and %d in the English text", where, n, want))
			case strings.Contains(translated, "\\"):
				problems = append(problems, where+": a backslash in the translation")
			}
		}
		var missing []string
		for text := range texts {
			if !got[text] {
				missing = append(missing, texts[text]+": "+fmt.Sprintf("%q", text))
			}
		}
		sort.Strings(missing)
		for _, m := range missing {
			problems = append(problems, fmt.Sprintf("%s: no translation of the text at %s", name, m))
		}
	}
	return problems
}
