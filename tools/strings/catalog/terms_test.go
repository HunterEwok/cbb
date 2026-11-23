// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package catalog

import (
	"strings"
	"testing"
)

const testTerms = `{"terms": [
  {"concept": "main device", "langs": {
    "en": {"use": "main device", "find": "main devices?", "avoid": ["\\broot\\b"], "except": ["without root"]},
    "es": {"use": "dispositivo principal", "find": "dispositivos? principal(?:es)?", "avoid": ["\\braíz\\b"]}}}
]}`

func TestTerms(t *testing.T) {
	terms, err := LoadTerms(reader(map[string][]byte{TermsFile: []byte(testTerms)}))
	if err != nil {
		t.Fatal(err)
	}
	rules := terms.Generate()
	es := string(rules[ValeDir+"/styles/es/Terms.yml"])
	for _, w := range []string{"extends: substitution\n", "  '\\braíz\\b': 'dispositivo principal'\n", "level: error\n"} {
		if !strings.Contains(es, w) {
			t.Errorf("es's rule lacks %q:\n%s", w, es)
		}
	}
	if en := string(rules[ValeDir+"/styles/en/Terms.yml"]); !strings.Contains(en, "exceptions:\n  - 'without root'\n") {
		t.Errorf("en's rule lacks the exception:\n%s", en)
	}
	if _, ok := rules[ValeDir+"/styles/zh/Terms.yml"]; ok {
		t.Error("a rule for a language the termbase does not name")
	}

	en := `{
  "The main device decides.": {"in": ["tray"]},
  "The main device knows. [ios]": {"en": "The main device knows.", "in": ["ios"]},
  "The main device knows.": {"in": ["tray"]},
  "Main devices": {"in": ["tray"]},
  "A domain device": {"in": ["tray"]}
}`
	src, err := Load(reader(files(en, map[string]string{
		"The main device decides.":     "Decide el dispositivo principal.",
		"The main device knows. [ios]": "Lo sabe el dispositivo principal.",
		"The main device knows.":       "Lo sabe el dispositivo principal.",
		"Main devices":                 "Raíces",
		"A domain device":              "Un dispositivo del dominio",
	})))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(terms.CheckTerms(src), "\n")
	if !strings.Contains(got, `"Main devices": the English names the main device, so the text says "dispositivo principal"`) {
		t.Errorf("a translation without the term passed:\n%s", got)
	}
	if strings.Contains(got, "decides") || strings.Contains(got, "domain") {
		t.Errorf("a term found where it is, or inside another word:\n%s", got)
	}
	same := strings.Join(src.CheckSame(), "\n")
	if !strings.Contains(same, `"The main device knows. [ios]": translated as "The main device knows." is in every language`) {
		t.Errorf("a variant translated as its plain string passed:\n%s", same)
	}
}

func TestCheckSame(t *testing.T) {
	en := `{
  "%1 left.": {"in": ["aurora:A"]},
  "%@ left.": {"in": ["ios"]},
  "%s left.": {"in": ["tray"]}
}`
	m := files(en, map[string]string{"%1 left.": "%1 left.", "%@ left.": "%@ left.", "%s left.": "%s left."})
	m[Dir+"/es.json"] = []byte(`{"%1 left.": "%1 se fue.", "%@ left.": "%@ se fue.", "%s left.": "%s salió."}`)
	src, err := Load(reader(m))
	if err != nil {
		t.Fatal(err)
	}
	got := src.CheckSame()
	if len(got) != 1 || !strings.Contains(got[0], "apps/l10n/es.json") || !strings.Contains(got[0], "one English text, two translations") {
		t.Errorf("CheckSame = %q", got)
	}
}

func TestLoadTermsProblems(t *testing.T) {
	for _, c := range []struct{ name, file, want string }{
		{"no English", `{"terms": [{"concept": "a", "langs": {"es": {"use": "b"}}}]}`, "no English"},
		{"unknown language", `{"terms": [{"concept": "a", "langs": {"en": {"use": "a"}, "xx": {"use": "b"}}}]}`, `unknown language "xx"`},
		{"no use", `{"terms": [{"concept": "a", "langs": {"en": {"find": "a"}}}]}`, `has no "use"`},
		{"bad find", `{"terms": [{"concept": "a", "langs": {"en": {"use": "a", "find": "("}}}]}`, `"find"`},
		{"twice", `{"terms": [{"concept": "a", "langs": {"en": {"use": "a"}}}, {"concept": "a", "langs": {"en": {"use": "a"}}}]}`, "a name of its own"},
		{"unknown field", `{"terms": [{"concept": "a", "langs": {"en": {"use": "a", "avoids": ["b"]}}}]}`, "unknown field"},
	} {
		_, err := LoadTerms(reader(map[string][]byte{TermsFile: []byte(c.file)}))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
