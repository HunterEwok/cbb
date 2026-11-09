// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

// The apps' translations in every language of the project (docs/apps.md,
// "Languages"; docs/testing.md, "The apps' languages, accessibility and
// screenshots"): each text of each app is translated into all eight
// languages, marked done, and its translation keeps the original's
// placeholders, so that no screen shows English in another language or
// drops a number. The UI tests check how the screens look in the eight.

// appLanguages are the project's languages besides English, as each kind of
// file names them.
var (
	catalogLanguages = []string{"ar", "es", "he", "hi", "ru", "sw", "zh-Hans"}
	androidLanguages = []string{"ar", "es", "hi", "iw", "ru", "sw", "zh"}
	jsonLanguages    = []string{"ar", "es", "he", "hi", "ru", "sw", "zh"}
)

// placeholder matches a printf placeholder of a String Catalog, Android's
// resources or the JSON files: %@, %lld, %d, %s, %1$@ and the others.
var placeholder = regexp.MustCompile(`%(\d+\$)?(ll|l)?[@dsuf]`)

// placeholders are the distinct placeholders of a text, numbered ones by
// their place: a translation may use one twice or once where the original
// does the other, but must use the same ones.
func placeholders(s string) []string {
	s = strings.ReplaceAll(s, "%%", "")
	seen := map[string]bool{}
	next := 1
	for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
		kind := m[0][len(m[0])-1:]
		if kind == "u" || kind == "d" {
			kind = "d"
		}
		if m[1] != "" {
			seen[m[1]+kind] = true
			continue
		}
		seen[fmt.Sprintf("%d$%s", next, kind)] = true
		next++
	}
	return slices.Sorted(maps.Keys(seen))
}

// checkAppTranslations checks the String Catalogs, the Android apps'
// strings.xml, and the tray app's and the command line's JSON.
func checkAppTranslations(contents map[string][]byte) []string {
	var problems []string
	for _, name := range slices.Sorted(maps.Keys(contents)) {
		switch {
		case strings.HasPrefix(name, "apps/") && strings.HasSuffix(name, ".xcstrings"):
			problems = append(problems, checkCatalog(name, contents[name])...)
		case androidDefaultStrings.MatchString(name):
			problems = append(problems, checkAndroidStrings(name, contents)...)
		}
	}
	for _, dir := range []string{"apps/desktop/frontend/l10n", "member/l10n"} {
		problems = append(problems, checkJSONTranslations(dir, contents)...)
	}
	return problems
}

// catalog is the part of a String Catalog the check reads.
type catalog struct {
	SourceLanguage string `json:"sourceLanguage"`
	Strings        map[string]struct {
		ShouldTranslate *bool                       `json:"shouldTranslate"`
		Localizations   map[string]catalogLocalized `json:"localizations"`
	} `json:"strings"`
}

type catalogLocalized struct {
	StringUnit *struct {
		State string `json:"state"`
		Value string `json:"value"`
	} `json:"stringUnit"`
	Variations map[string]map[string]catalogLocalized `json:"variations"`
}

// units are the texts of a localization: its own, or each of its
// variations' (plural, device).
func (l catalogLocalized) units(where string, out map[string]string, states map[string]string) {
	if l.StringUnit != nil {
		out[where] = l.StringUnit.Value
		states[where] = l.StringUnit.State
	}
	for kind, vs := range l.Variations {
		for v, sub := range vs {
			sub.units(where+"/"+kind+"="+v, out, states)
		}
	}
}

func checkCatalog(name string, data []byte) []string {
	var c catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return []string{fmt.Sprintf("%s: %v", name, err)}
	}
	var problems []string
	bad := func(format string, args ...any) {
		problems = append(problems, name+": "+fmt.Sprintf(format, args...))
	}
	for _, key := range slices.Sorted(maps.Keys(c.Strings)) {
		s := c.Strings[key]
		if (s.ShouldTranslate != nil && !*s.ShouldTranslate) || key == "" {
			continue
		}
		// The original: the source language's own text, else the key.
		original := key
		if src, ok := s.Localizations[c.SourceLanguage]; ok && src.StringUnit != nil {
			original = src.StringUnit.Value
		}
		want := placeholders(original)
		for _, lang := range catalogLanguages {
			l, ok := s.Localizations[lang]
			if !ok {
				bad("%q has no %s", short(key), lang)
				continue
			}
			texts, states := map[string]string{}, map[string]string{}
			l.units("", texts, states)
			if len(texts) == 0 {
				bad("%q has no %s text", short(key), lang)
			}
			for where, text := range texts {
				if states[where] != "translated" {
					bad("%q in %s%s is %q, not translated", short(key), lang, where, states[where])
				}
				if strings.TrimSpace(text) == "" {
					bad("%q in %s%s is empty", short(key), lang, where)
				}
				// A plural's variations may leave the number out ("one file").
				if got := placeholders(text); !slices.Equal(got, want) && !(strings.Contains(where, "plural=") && isSubset(got, want)) {
					bad("%q in %s%s has the placeholders %q, the original %q", short(key), lang, where, got, want)
				}
			}
		}
	}
	return problems
}

// androidDefaultStrings matches an Android module's English strings.
var androidDefaultStrings = regexp.MustCompile(`^apps/android/[a-z]+/src/main/res/values/strings\.xml$`)

// androidResources is the part of a strings.xml the check reads.
type androidResources struct {
	Strings []struct {
		Name         string `xml:"name,attr"`
		Translatable string `xml:"translatable,attr"`
		Text         string `xml:",chardata"`
	} `xml:"string"`
	Plurals []struct {
		Name  string `xml:"name,attr"`
		Items []struct {
			Quantity string `xml:"quantity,attr"`
			Text     string `xml:",chardata"`
		} `xml:"item"`
	} `xml:"plurals"`
}

// texts are a strings.xml's translatable texts by name, a plural's by its
// name and quantity.
func (r androidResources) texts() map[string]string {
	out := map[string]string{}
	for _, s := range r.Strings {
		if s.Translatable != "false" {
			out[s.Name] = s.Text
		}
	}
	for _, p := range r.Plurals {
		for _, it := range p.Items {
			out[p.Name+"/"+it.Quantity] = it.Text
		}
	}
	return out
}

func checkAndroidStrings(name string, contents map[string][]byte) []string {
	var en androidResources
	if err := xml.Unmarshal(contents[name], &en); err != nil {
		return []string{fmt.Sprintf("%s: %v", name, err)}
	}
	original := en.texts()
	var problems []string
	res := path.Dir(path.Dir(name))
	for _, lang := range androidLanguages {
		file := path.Join(res, "values-"+lang, "strings.xml")
		data, ok := contents[file]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: no translation into %s (%s)", name, lang, file))
			continue
		}
		var tr androidResources
		if err := xml.Unmarshal(data, &tr); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		got := tr.texts()
		for _, key := range slices.Sorted(maps.Keys(original)) {
			plural := strings.Contains(key, "/")
			text, ok := got[key]
			if !ok {
				// Languages differ in their plural forms: a plural needs its "other", not each quantity.
				if !plural || strings.HasSuffix(key, "/other") {
					problems = append(problems, fmt.Sprintf("%s: %s is not translated", file, key))
				}
				continue
			}
			want, have := placeholders(original[key]), placeholders(text)
			if !slices.Equal(have, want) && !(plural && isSubset(have, want)) {
				problems = append(problems, fmt.Sprintf("%s: %s has the placeholders %q, the original %q", file, key, have, want))
			}
		}
	}
	return problems
}

// checkJSONTranslations checks a folder of <language>.json files keyed by
// the English text: every language has every text the others have, none
// empty, with the original's placeholders.
func checkJSONTranslations(dir string, contents map[string][]byte) []string {
	if !slices.ContainsFunc(slices.Collect(maps.Keys(contents)), func(n string) bool { return strings.HasPrefix(n, dir+"/") }) {
		return nil
	}
	files := map[string]map[string]string{}
	var problems []string
	for _, lang := range jsonLanguages {
		file := path.Join(dir, lang+".json")
		data, ok := contents[file]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: no translation into %s", dir, lang))
			continue
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		files[file] = m
	}
	keys := map[string]bool{}
	for _, m := range files {
		for k := range m {
			keys[k] = true
		}
	}
	for _, file := range slices.Sorted(maps.Keys(files)) {
		m := files[file]
		for _, key := range slices.Sorted(maps.Keys(keys)) {
			text, ok := m[key]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s: %q is not translated", file, short(key)))
			case strings.TrimSpace(text) == "":
				problems = append(problems, fmt.Sprintf("%s: %q is empty", file, short(key)))
			case !slices.Equal(placeholders(text), placeholders(key)):
				problems = append(problems, fmt.Sprintf("%s: %q has the placeholders %q, the original %q", file, short(key), placeholders(text), placeholders(key)))
			}
		}
	}
	return problems
}

func isSubset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// short is the start of a long text, for a message.
func short(s string) string {
	if r := []rune(s); len(r) > 50 {
		return string(r[:50]) + "…"
	}
	return s
}
