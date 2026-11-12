// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestPlaceholders(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"%d of %d online", []string{"1$d", "2$d"}},
		{"%lld files from %@", []string{"1$d", "2$@"}},
		{"%2$s needs %1$s, take %2$s", []string{"1$s", "2$s"}},
		{"100%% sure", nil},
	} {
		if got := placeholders(c.in); !slices.Equal(got, c.want) {
			t.Errorf("placeholders(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// catalogWith is a String Catalog of one key, its translation into each
// of the project's languages given by tr.
func catalogWith(key string, tr func(lang string) string) []byte {
	var locs []string
	for _, l := range catalogLanguages {
		if v := tr(l); v != "" {
			locs = append(locs, fmt.Sprintf(`%q: {"stringUnit": {"state": "translated", "value": %q}}`, l, v))
		}
	}
	return fmt.Appendf(nil, `{"sourceLanguage": "en", "strings": {%q: {"localizations": {%s}}, "CBB": {"shouldTranslate": false}}}`, key, strings.Join(locs, ","))
}

func TestCheckAppTranslations(t *testing.T) {
	good := map[string][]byte{"apps/ios/CBB/Localizable.xcstrings": catalogWith("%lld of %lld online", func(l string) string { return l + " %lld / %lld" })}
	for _, l := range jsonLanguages {
		good["apps/desktop/frontend/l10n/"+l+".json"] = fmt.Appendf(nil, `{"%%d of %%d online": "%s %%d/%%d"}`, l)
		good["member/l10n/"+l+".json"] = []byte(`{}`)
	}
	good["apps/android/app/src/main/res/values/strings.xml"] = []byte(`<resources><string name="a">%1$s needs %2$s</string><string name="x" translatable="false">CBB</string><plurals name="n"><item quantity="one">one file</item><item quantity="other">%d files</item></plurals></resources>`)
	for _, l := range androidLanguages {
		good["apps/android/app/src/main/res/values-"+l+"/strings.xml"] = []byte(`<resources><string name="a">%2$s: %1$s</string><plurals name="n"><item quantity="other">%d</item></plurals></resources>`)
	}
	if p := checkAppTranslations(good); len(p) > 0 {
		t.Fatalf("good translations: %q", p)
	}

	bad := func(name string, data []byte, want string) {
		t.Helper()
		files := map[string][]byte{}
		for k, v := range good {
			files[k] = v
		}
		if data == nil {
			delete(files, name)
		} else {
			files[name] = data
		}
		p := checkAppTranslations(files)
		if !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, want) }) {
			t.Errorf("%s: want a problem with %q, got %q", name, want, p)
		}
	}
	bad("apps/ios/CBB/Localizable.xcstrings", catalogWith("%lld of %lld online", func(l string) string {
		if l == "sw" {
			return ""
		}
		return "%lld / %lld"
	}), "has no sw")
	bad("apps/ios/CBB/Localizable.xcstrings", catalogWith("%lld of %lld online", func(l string) string { return "%lld" }), "placeholders")
	bad("apps/ios/CBB/Localizable.xcstrings", []byte(`{"sourceLanguage": "en", "strings": {"Hi": {"localizations": {"ar": {"stringUnit": {"state": "needs_review", "value": "x"}}}}}}`), "not translated")
	bad("apps/desktop/frontend/l10n/he.json", []byte(`{}`), "is not translated")
	bad("apps/desktop/frontend/l10n/hi.json", []byte(`{"%d of %d online": "%d"}`), "placeholders")
	bad("member/l10n/zh.json", nil, "no translation into zh")
	bad("apps/android/app/src/main/res/values-iw/strings.xml", nil, "no translation into iw")
	bad("apps/android/app/src/main/res/values-ar/strings.xml", []byte(`<resources><plurals name="n"><item quantity="other">%d</item></plurals></resources>`), "a is not translated")
	bad("apps/android/app/src/main/res/values-ru/strings.xml", []byte(`<resources><string name="a">%1$s</string><plurals name="n"><item quantity="other">%d</item></plurals></resources>`), "placeholders")
}
