// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"io/fs"
	"log"
	"slices"
	"strings"
)

// translations returns the window's and the tray's texts in a language,
// keyed by their English: frontend/l10n/<language>.json, which the window
// reads too. English needs none.
func translations(lang string) map[string]string {
	tr := map[string]string{}
	if lang == "en" {
		return tr
	}
	data, err := assets.ReadFile("frontend/l10n/" + lang + ".json")
	if err != nil {
		return tr
	}
	if err := json.Unmarshal(data, &tr); err != nil {
		log.Printf("l10n %s: %v", lang, err)
	}
	return tr
}

// languages are the codes of the languages the app speaks: English and
// those with a file in frontend/l10n, in the order of their codes.
func languages() []string {
	out := []string{"en"}
	files, _ := fs.Glob(assets, "frontend/l10n/*.json")
	for _, f := range files {
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(f, "frontend/l10n/"), ".json"))
	}
	slices.Sort(out)
	return out
}

// pickLang is the language the user picked when the app speaks it, else
// the system's.
func pickLang(set string) string {
	if set != "" && slices.Contains(languages(), set) {
		return set
	}
	return language()
}

// pickLanguage takes the first of the user's languages that the app
// speaks, as "ru" from "ru_RU.UTF-8" or "ru-RU", "zh" from "zh-Hans-CN";
// English otherwise.
func pickLanguage(prefs []string) string {
	have := languages()
	for _, p := range prefs {
		p = strings.ToLower(p)
		if p == "" || p == "c" || p == "posix" {
			continue
		}
		code, _, _ := strings.Cut(strings.NewReplacer("_", "-", ".", "-").Replace(p), "-")
		if slices.Contains(have, code) {
			return code
		}
	}
	return "en"
}
