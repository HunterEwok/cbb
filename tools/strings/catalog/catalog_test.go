// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package catalog

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// files makes a source of en.json and the same translation, the English
// text with the language in front, in every language.
func files(en string, tr map[string]string) map[string][]byte {
	m := map[string][]byte{Dir + "/en.json": []byte(en)}
	for _, l := range Languages {
		t := map[string]string{}
		for id, s := range tr {
			t[id] = l + ": " + s
		}
		b, _ := json.Marshal(t)
		m[Dir+"/"+l+".json"] = b
	}
	return m
}

func reader(m map[string][]byte) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		if b, ok := m[name]; ok {
			return b, nil
		}
		return nil, fmt.Errorf("%s: %w", name, fs.ErrNotExist)
	}
}

func TestGenerate(t *testing.T) {
	en := `{
  "Don't paste": {"in": ["android:no_paste", "aurora:Main", "harmony:no_paste", "ios", "tray"]},
  "CBB": {"in": ["android:app_name", "harmony:app_name", "ios"], "translate": false},
  "Open %@ & %@": {"in": ["mac"]},
  "Open camera": {"en": "Scan the code", "in": ["ios-plist:NSCameraUsageDescription"]}
}`
	src, err := Load(reader(files(en, map[string]string{
		"Don't paste":  "Don't paste",
		"Open %@ & %@": "Open %2$@ & %1$@",
		"Open camera":  "Scan the code",
	})))
	if err != nil {
		t.Fatal(err)
	}
	out := src.Generate()
	for name, want := range map[string][]string{
		"apps/android/app/src/main/res/values/strings.xml": {
			`<string name="app_name" translatable="false">CBB</string>`,
			`<string name="no_paste">Don\'t paste</string>`,
		},
		"apps/android/app/src/main/res/values-iw/strings.xml": {`<string name="no_paste">he: Don\'t paste</string>`},
		"apps/silica/translations/cbb-ru.ts": {
			`<TS version="2.1" language="ru_RU">`,
			"<context>\n    <name>Main</name>\n    <message>\n        <source>Don't paste</source>\n        <translation>ru: Don't paste</translation>",
		},
		"apps/ios/CBB/Resources/Localizable.xcstrings": {
			"\"CBB\": {\n      \"shouldTranslate\": false\n    }",
			"\"zh-Hans\": {\n          \"stringUnit\": {\n            \"state\": \"translated\",\n            \"value\": \"zh: Don't paste\"",
		},
		"apps/ios/CBB/Resources/InfoPlist.xcstrings":        {`"NSCameraUsageDescription": {`, `"value": "ar: Scan the code"`},
		"apps/macos/CBBMac/Resources/Localizable.xcstrings": {`"Open %@ & %@": {`, `"value": "es: Open %2$@ & %1$@"`},
		"apps/desktop/frontend/l10n/sw.json":                {"{\n  \"Don't paste\": \"sw: Don't paste\"\n}\n"},
		"apps/harmony/entry/src/main/resources/base/element/string.json": {
			"{\n  \"string\": [\n    {\"name\": \"app_name\", \"value\": \"CBB\"},\n    {\"name\": \"no_paste\", \"value\": \"Don't paste\"}\n  ]\n}\n",
		},
		"apps/harmony/entry/src/main/resources/zh_CN/element/string.json": {`{"name": "no_paste", "value": "zh: Don't paste"}`},
	} {
		for _, w := range want {
			if !strings.Contains(string(out[name]), w) {
				t.Errorf("%s lacks %q:\n%s", name, w, out[name])
			}
		}
	}
	if strings.Contains(string(out["apps/android/app/src/main/res/values-ru/strings.xml"]), "app_name") || strings.Contains(string(out["apps/harmony/entry/src/main/resources/ru/element/string.json"]), "app_name") {
		t.Error("a name that stays as it is went into a language's strings")
	}
	// The source comes back in order, one string a line.
	wantEN := `{
  "CBB": {"in": ["android:app_name", "harmony:app_name", "ios"], "translate": false},
  "Don't paste": {"in": ["android:no_paste", "aurora:Main", "harmony:no_paste", "ios", "tray"]},
  "Open %@ & %@": {"in": ["mac"]},
  "Open camera": {"en": "Scan the code", "in": ["ios-plist:NSCameraUsageDescription"]}
}
`
	if got := string(out[Dir+"/en.json"]); got != wantEN {
		t.Errorf("en.json:\n%s\nwant\n%s", got, wantEN)
	}
	// Generating what was generated changes nothing.
	again, err := Load(reader(out))
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range again.Generate() {
		if string(b) != string(out[name]) {
			t.Errorf("%s changed when generated again", name)
		}
	}
}

func TestLoadProblems(t *testing.T) {
	for _, c := range []struct {
		name, en string
		tr       map[string]string
		want     string
	}{
		{"unknown place", `{"A": {"in": ["web"]}}`, map[string]string{"A": "A"}, `unknown place "web"`},
		{"no name", `{"A": {"in": ["android"]}}`, map[string]string{"A": "A"}, "needs a resource name"},
		{"no HarmonyOS name", `{"A": {"in": ["harmony:A"]}}`, map[string]string{"A": "A"}, "needs a resource name"},
		{"shown nowhere", `{"A": {"in": []}}`, map[string]string{"A": "A"}, "shown nowhere"},
		{"taken twice", `{"A": {"in": ["android:a"]}, "B": {"in": ["android:a"]}}`, map[string]string{"A": "A", "B": "B"}, "with the same key"},
		{"untranslated", `{"A": {"in": ["tray"]}, "B": {"in": ["tray"]}}`, map[string]string{"A": "A"}, `no translation of "B"`},
		{"fixed translated", `{"A": {"in": ["ios"], "translate": false}}`, map[string]string{"A": "A"}, "is not translated"},
		{"unknown ID", `{"A": {"in": ["tray"]}}`, map[string]string{"A": "A", "Z": "Z"}, `"Z" is in no app`},
		{"directives", `{"%d of %d": {"in": ["tray"]}}`, map[string]string{"%d of %d": "%d"}, "the directives"},
	} {
		_, err := Load(reader(files(c.en, c.tr)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestEscapes(t *testing.T) {
	if got, want := androidText(`@me "it's" a\b & <c>`+"\n?"), `\@me \"it\'s\" a\\b &amp; &lt;c>\n?`; got != want {
		t.Errorf("androidText = %s, want %s", got, want)
	}
	if got, want := quote("a\"b\\c\né\x01"), `"a\"b\\c\né\u0001"`; got != want {
		t.Errorf("quote = %s, want %s", got, want)
	}
	if got := directives("%2$@ then %1$@ and %2$@"); strings.Join(got, ",") != "1 @,2 @" {
		t.Errorf("directives = %v", got)
	}
}
