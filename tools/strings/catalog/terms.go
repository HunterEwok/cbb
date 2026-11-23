// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package catalog

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// TermsFile is the apps' termbase: for each concept the word every
// language uses for it, and the words it does not use.
const TermsFile = Dir + "/terms.json"

// ValeDir holds Vale's settings and styles for the apps' strings
// (docs/apps.md, "Words in the apps"); ValeDir/styles/<language>/Terms.yml
// is made from the termbase.
const ValeDir = "tools/strings/vale"

// Term is one concept of the termbase.
type Term struct {
	Concept string              `json:"concept"`
	Note    string              `json:"note,omitempty"`
	Langs   map[string]TermLang `json:"langs"`
}

// TermLang is how one language names a concept: Use, the word itself;
// Find, a pattern (Go's syntax, case ignored) that finds it in a text of
// that language; and Avoid, patterns (Vale's syntax, case ignored) of the
// words that are not used for it, but for the phrases in Except, where an
// avoided word means something else (Unix's root user).
type TermLang struct {
	Use    string   `json:"use"`
	Find   string   `json:"find,omitempty"`
	Avoid  []string `json:"avoid,omitempty"`
	Except []string `json:"except,omitempty"`
}

// Terms is the termbase.
type Terms []Term

// LoadTerms reads the termbase and checks its form.
func LoadTerms(read func(name string) ([]byte, error)) (Terms, error) {
	data, err := read(TermsFile)
	if err != nil {
		return nil, err
	}
	var file struct {
		Terms Terms `json:"terms"`
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("%s: %v", TermsFile, err)
	}
	var problems []string
	seen := map[string]bool{}
	for _, t := range file.Terms {
		if t.Concept == "" || seen[t.Concept] {
			problems = append(problems, fmt.Sprintf("%s: %q: a concept needs a name of its own", TermsFile, t.Concept))
		}
		seen[t.Concept] = true
		if _, ok := t.Langs["en"]; !ok {
			problems = append(problems, fmt.Sprintf("%s: %q: no English", TermsFile, t.Concept))
		}
		for l, tl := range t.Langs {
			if l != "en" && !isLanguage(l) {
				problems = append(problems, fmt.Sprintf("%s: %q: unknown language %q", TermsFile, t.Concept, l))
			}
			if tl.Use == "" {
				problems = append(problems, fmt.Sprintf("%s: %q: %s has no \"use\"", TermsFile, t.Concept, l))
			}
			if tl.Find != "" {
				if _, err := regexp.Compile(tl.Find); err != nil {
					problems = append(problems, fmt.Sprintf("%s: %q: %s: \"find\": %v", TermsFile, t.Concept, l, err))
				}
			}
			for _, a := range tl.Avoid {
				if a == "" || strings.ContainsAny(a, "\n") {
					problems = append(problems, fmt.Sprintf("%s: %q: %s: an empty \"avoid\"", TermsFile, t.Concept, l))
				}
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%s", strings.Join(problems, "\n"))
	}
	return file.Terms, nil
}

func isLanguage(l string) bool {
	for _, x := range Languages {
		if x == l {
			return true
		}
	}
	return false
}

// finder is a term's Find as Go matches it: case ignored, and not inside a
// longer word.
func finder(find string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(?:^|[^\pL\pN])(?:` + find + `)(?:$|[^\pL\pN])`)
}

// Generate returns the Vale rules made from the termbase, by path: one
// substitution rule for each language that avoids a word.
func (terms Terms) Generate() map[string][]byte {
	out := map[string][]byte{}
	for _, l := range append([]string{"en"}, Languages...) {
		var swaps, excepts []string
		for _, t := range terms {
			tl, ok := t.Langs[l]
			if !ok {
				continue
			}
			for _, a := range tl.Avoid {
				swaps = append(swaps, "  "+yamlQuote(a)+": "+yamlQuote(tl.Use)+"\n")
			}
			for _, e := range tl.Except {
				excepts = append(excepts, "  - "+yamlQuote(e)+"\n")
			}
		}
		if len(swaps) == 0 {
			continue
		}
		var b strings.Builder
		b.WriteString("# Made by go run ./tools/strings from " + TermsFile + ": edit that file, not this one.\n")
		b.WriteString("extends: substitution\n")
		b.WriteString("message: \"Use '%s' here, not '%s' (" + TermsFile + ").\"\n")
		b.WriteString("level: error\nignorecase: true\nnonword: true\nswap:\n")
		for _, s := range swaps {
			b.WriteString(s)
		}
		if len(excepts) > 0 {
			b.WriteString("exceptions:\n")
			for _, e := range excepts {
				b.WriteString(e)
			}
		}
		out[ValeDir+"/styles/"+l+"/Terms.yml"] = []byte(b.String())
	}
	return out
}

func yamlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// CheckTerms reports the translations that leave out the word for a
// concept the English names: where the English finds a concept, a language
// that has a Find for it must find it too.
func (terms Terms) CheckTerms(src Source) []string {
	var out []string
	for _, t := range terms {
		en := t.Langs["en"]
		if en.Find == "" {
			continue
		}
		enRe := finder(en.Find)
		for _, s := range src {
			if s.Fixed || !enRe.MatchString(s.EN) {
				continue
			}
			for _, l := range Languages {
				tl, ok := t.Langs[l]
				if !ok || tl.Find == "" {
					continue
				}
				if !finder(tl.Find).MatchString(s.Texts[l]) {
					out = append(out, fmt.Sprintf("%s/%s.json: %q: the English names the %s, so the text says %q (%s)", Dir, l, s.ID, t.Concept, tl.Use, TermsFile))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// variant is a directive, so that texts that differ only in their
// platform's directives (%@, %s, %1$s, %1) compare as one.
var variant = regexp.MustCompile(`%(?:[0-9]+\$)?(?:l{0,2}[a-z@]|[0-9]+)`)

// CheckSame reports the strings whose English is the same, but for the
// platform's directives, and whose translations differ: one English text has
// one translation. A string whose ID names its place in brackets is the
// way to give the same English another translation, and it must then differ
// from the plain string in some language.
func (src Source) CheckSame() []string {
	byEN := map[string][]String{}
	for _, s := range src {
		if !s.Fixed {
			k := variant.ReplaceAllString(s.EN, "%")
			byEN[k] = append(byEN[k], s)
		}
	}
	var out []string
	for _, group := range byEN {
		var plain []String
		var bracketed []String
		for _, s := range group {
			if s.ID == s.EN {
				plain = append(plain, s)
			} else {
				bracketed = append(bracketed, s)
			}
		}
		for _, l := range Languages {
			for _, s := range plain[min(1, len(plain)):] {
				a := variant.ReplaceAllString(plain[0].Texts[l], "%")
				b := variant.ReplaceAllString(s.Texts[l], "%")
				if a != b {
					out = append(out, fmt.Sprintf("%s/%s.json: %q and %q: one English text, two translations (%q, %q)", Dir, l, plain[0].ID, s.ID, plain[0].Texts[l], s.Texts[l]))
				}
			}
		}
		if len(plain) == 0 {
			continue
		}
		for _, s := range bracketed {
			differs := false
			for _, l := range Languages {
				if variant.ReplaceAllString(plain[0].Texts[l], "%") != variant.ReplaceAllString(s.Texts[l], "%") {
					differs = true
				}
			}
			if !differs {
				out = append(out, fmt.Sprintf("%s/en.json: %q: translated as %q is in every language: show %q there instead", Dir, s.ID, plain[0].ID, plain[0].ID))
			}
		}
	}
	sort.Strings(out)
	return out
}
