// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package catalog turns the apps' strings, apps/l10n/<language>.json, into
// the files each app's platform reads: the String Catalogs of the iPhone,
// Watch and Mac apps, the Android app's and the watch's res/values*/strings.xml,
// the Aurora app's Qt translations and the tray app's frontend/l10n.
//
// apps/l10n/en.json lists every string once: its ID (the English text, or the
// text with the first place in brackets where the same English needs another
// translation), "en" when the English differs from the ID, "in", the places
// that show it, and "translate": false for a name that stays as it is. Each
// other language's file holds the translation of every string under its ID.
// A place is one of
//
//	ios, ios-share, ios-push, ios-watch, ios-widgets, ios-shortcuts, mac   the String Catalogs, keyed by the English
//	ios-plist:KEY                                                          the iPhone app's InfoPlist catalog, keyed by KEY
//	tray                                                                   the tray app, keyed by the English
//	aurora:CONTEXT                                                         the Aurora app's Qt context, keyed by the English
//	android:NAME, wear:NAME                                                the Android app's and the watch's resource NAME
//
// Every text is plain: Generate escapes it for Android's resources and the
// XML of Qt's files.
package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// Dir holds the strings, one file for each language.
const Dir = "apps/l10n"

// Languages are the languages besides English, in the order of the files.
var Languages = []string{"ar", "es", "he", "hi", "ru", "sw", "zh"}

// Entry is one string of en.json.
type Entry struct {
	EN        string   `json:"en,omitempty"`
	In        []string `json:"in"`
	Translate *bool    `json:"translate,omitempty"`
}

// String is a string with its ID and its texts.
type String struct {
	ID      string
	EN      string
	In      []string
	Fixed   bool              // "translate": false
	Texts   map[string]string // by language, without English
	Comment string
}

// Source is the strings of every language, sorted by ID.
type Source []String

// catalogs are the String Catalogs by place.
var catalogs = map[string]string{
	"ios":           "apps/ios/CBB/Resources/Localizable.xcstrings",
	"ios-shortcuts": "apps/ios/CBB/Resources/AppShortcuts.xcstrings",
	"ios-plist":     "apps/ios/CBB/Resources/InfoPlist.xcstrings",
	"ios-share":     "apps/ios/ShareExtension/Localizable.xcstrings",
	"ios-push":      "apps/ios/NotificationService/Localizable.xcstrings",
	"ios-watch":     "apps/ios/Watch/Localizable.xcstrings",
	"ios-widgets":   "apps/ios/Widgets/Localizable.xcstrings",
	"mac":           "apps/macos/CBBMac/Resources/Localizable.xcstrings",
}

// androidRes are the resource folders of the Android projects by place.
var androidRes = map[string]string{
	"android": "apps/android/app/src/main/res",
	"wear":    "apps/android/wear/src/main/res",
}

// Each platform's names for the languages.
var (
	xcLang      = map[string]string{"zh": "zh-Hans"}
	androidLang = map[string]string{"he": "iw"}
	qtLang      = map[string]string{"es": "es_ES", "he": "he_IL", "hi": "hi_IN", "ru": "ru_RU", "zh": "zh_CN"}
)

func lang(m map[string]string, l string) string {
	if v, ok := m[l]; ok {
		return v
	}
	return l
}

// androidName is a resource name.
var androidName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// place splits a place into its kind and key, and checks it.
func place(p string) (kind, key string, err error) {
	kind, key, _ = strings.Cut(p, ":")
	switch kind {
	case "ios", "ios-shortcuts", "ios-share", "ios-push", "ios-watch", "ios-widgets", "mac", "tray":
		if key != "" {
			return "", "", fmt.Errorf("place %q takes no key", p)
		}
	case "ios-plist", "aurora":
		if key == "" {
			return "", "", fmt.Errorf("place %q needs a key after the colon", p)
		}
	case "android", "wear":
		if !androidName.MatchString(key) {
			return "", "", fmt.Errorf("place %q needs a resource name after the colon", p)
		}
	default:
		return "", "", fmt.Errorf("unknown place %q", p)
	}
	return kind, key, nil
}

// directive matches a format directive of the platforms: printf's (%s,
// %1$s, %lld, %@, %d) and Qt's (%1).
var directive = regexp.MustCompile(`%(?:%|([0-9]+)\$(l{0,2}[a-z@])|(l{0,2}[a-z@])|([0-9]+))`)

// directives returns the arguments a text takes, each once, as its
// position and its kind: a translation may reorder them (%2$@ before
// %1$@), and may use one twice or once.
func directives(s string) []string {
	var out []string
	next := 0
	for _, m := range directive.FindAllStringSubmatch(s, -1) {
		switch {
		case m[2] != "":
			out = append(out, m[1]+" "+m[2])
		case m[3] != "":
			next++
			out = append(out, fmt.Sprint(next)+" "+m[3])
		case m[4] != "":
			out = append(out, m[4]+" qt")
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// Load reads the strings through read and checks them: every place known
// and taken once, every translated string translated into every language
// with the same format directives, no translation of an unknown ID.
func Load(read func(name string) ([]byte, error)) (Source, error) {
	data, err := read(Dir + "/en.json")
	if err != nil {
		return nil, err
	}
	var en map[string]Entry
	if err := json.Unmarshal(data, &en); err != nil {
		return nil, fmt.Errorf("%s/en.json: %v", Dir, err)
	}
	texts := map[string]map[string]string{}
	for _, l := range Languages {
		data, err := read(Dir + "/" + l + ".json")
		if err != nil {
			return nil, err
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("%s/%s.json: %v", Dir, l, err)
		}
		texts[l] = m
	}
	var src Source
	var problems []string
	taken := map[string]string{} // place and key -> ID
	for id, e := range en {
		s := String{ID: id, EN: e.EN, In: e.In, Fixed: e.Translate != nil && !*e.Translate, Texts: map[string]string{}}
		if s.EN == "" {
			s.EN = id
		}
		if e.Translate != nil && *e.Translate {
			problems = append(problems, fmt.Sprintf("%q: \"translate\": true is the default; leave it out", id))
		}
		if len(s.In) == 0 {
			problems = append(problems, fmt.Sprintf("%q: shown nowhere (no \"in\")", id))
		}
		for _, p := range s.In {
			kind, key, err := place(p)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%q: %v", id, err))
				continue
			}
			if key == "" || kind == "aurora" {
				key += "\x00" + s.EN
			}
			if other, ok := taken[kind+"\x00"+key]; ok {
				problems = append(problems, fmt.Sprintf("%q and %q: both in %s with the same key", other, id, p))
			}
			taken[kind+"\x00"+key] = id
		}
		for _, l := range Languages {
			t, ok := texts[l][id]
			switch {
			case s.Fixed && ok:
				problems = append(problems, fmt.Sprintf("%s/%s.json: %q is not translated (\"translate\": false)", Dir, l, id))
			case !s.Fixed && !ok:
				problems = append(problems, fmt.Sprintf("%s/%s.json: no translation of %q", Dir, l, id))
			case ok:
				if !slices.Equal(directives(t), directives(s.EN)) {
					problems = append(problems, fmt.Sprintf("%s/%s.json: %q: the directives %v, the English has %v", Dir, l, id, directives(t), directives(s.EN)))
				}
				s.Texts[l] = t
			}
		}
		src = append(src, s)
	}
	for _, l := range Languages {
		for id := range texts[l] {
			if _, ok := en[id]; !ok {
				problems = append(problems, fmt.Sprintf("%s/%s.json: %q is in no app (not in en.json)", Dir, l, id))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%s", strings.Join(problems, "\n"))
	}
	sort.Slice(src, func(i, j int) bool { return src[i].ID < src[j].ID })
	return src, nil
}

// Generate returns the source in its canonical form and every file made
// from it, by path.
func (src Source) Generate() map[string][]byte {
	out := map[string][]byte{}
	out[Dir+"/en.json"] = src.enJSON()
	for _, l := range Languages {
		m := ordered{}
		for _, s := range src {
			if !s.Fixed {
				m = append(m, [2]string{s.ID, s.Texts[l]})
			}
		}
		out[Dir+"/"+l+".json"] = m.json()
	}
	for kind, file := range catalogs {
		out[file] = src.xcstrings(kind)
	}
	for _, l := range Languages {
		out["apps/desktop/frontend/l10n/"+l+".json"] = src.tray(l)
		out["apps/silica/translations/cbb-"+l+".ts"] = src.qt(l)
	}
	for kind, res := range androidRes {
		out[res+"/values/strings.xml"] = src.android(kind, "")
		for _, l := range Languages {
			out[res+"/values-"+lang(androidLang, l)+"/strings.xml"] = src.android(kind, l)
		}
	}
	return out
}

// at returns the strings shown in places of kind, each with its key,
// sorted by key.
func (src Source) at(kind string) []keyed {
	var out []keyed
	for _, s := range src {
		for _, p := range s.In {
			k, key, _ := place(p)
			if k != kind {
				continue
			}
			out = append(out, keyed{key: key, s: s})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].key != out[j].key {
			return out[i].key < out[j].key
		}
		return out[i].s.EN < out[j].s.EN
	})
	return out
}

type keyed struct {
	key string
	s   String
}

// enJSON writes en.json: one string a line.
func (src Source) enJSON() []byte {
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, s := range src {
		b.WriteString("  " + quote(s.ID) + ": {")
		if s.EN != s.ID {
			b.WriteString(`"en": ` + quote(s.EN) + ", ")
		}
		b.WriteString(`"in": [`)
		for j, p := range s.In {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(quote(p))
		}
		b.WriteString("]")
		if s.Fixed {
			b.WriteString(`, "translate": false`)
		}
		b.WriteString("}")
		if i < len(src)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// ordered is a JSON object of strings in a given order.
type ordered [][2]string

// json writes it with two spaces of indent, each pair on a line.
func (o ordered) json() []byte {
	if len(o) == 0 {
		return []byte("{}\n")
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, kv := range o {
		b.WriteString("  " + quote(kv[0]) + ": " + quote(kv[1]))
		if i < len(o)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// xcstrings writes a String Catalog.
func (src Source) xcstrings(kind string) []byte {
	var b bytes.Buffer
	b.WriteString("{\n  \"sourceLanguage\": \"en\",\n  \"strings\": {\n")
	strs := src.at(kind)
	for i, k := range strs {
		key := k.key
		if key == "" {
			key = k.s.EN
		}
		b.WriteString("    " + quote(key) + ": {\n")
		if k.s.Fixed {
			b.WriteString("      \"shouldTranslate\": false\n")
		} else {
			b.WriteString("      \"localizations\": {\n")
			ls := slices.Clone(Languages)
			sort.Slice(ls, func(i, j int) bool { return lang(xcLang, ls[i]) < lang(xcLang, ls[j]) })
			for j, l := range ls {
				b.WriteString("        " + quote(lang(xcLang, l)) + ": {\n")
				b.WriteString("          \"stringUnit\": {\n")
				b.WriteString("            \"state\": \"translated\",\n")
				b.WriteString("            \"value\": " + quote(k.s.Texts[l]) + "\n")
				b.WriteString("          }\n        }")
				if j < len(ls)-1 {
					b.WriteString(",")
				}
				b.WriteString("\n")
			}
			b.WriteString("      }\n")
		}
		b.WriteString("    }")
		if i < len(strs)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  },\n  \"version\": \"1.0\"\n}\n")
	return b.Bytes()
}

// tray writes the tray app's texts of a language, keyed by the English.
func (src Source) tray(l string) []byte {
	var o ordered
	for _, k := range src.at("tray") {
		o = append(o, [2]string{k.s.EN, k.s.Texts[l]})
	}
	return o.json()
}

// generated is the note at the top of a generated file that takes comments.
const generated = "Generated by tools/strings from apps/l10n: edit those and run go run ./tools/strings."

// The license lines of the generated XML files, which reuse should not take
// for this file's own.
// REUSE-IgnoreStart
const (
	xmlLicense   = "<!-- SPDX-License-Identifier: AGPL-3.0-only -->\n"
	xmlCopyright = "<!-- Copyright (C) 2026 HunterEwok -->\n"
)

// REUSE-IgnoreEnd

// qt writes the Aurora app's translations of a language.
func (src Source) qt(l string) []byte {
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!DOCTYPE TS>\n")
	b.WriteString(xmlLicense + xmlCopyright)
	b.WriteString("<!-- " + generated + " -->\n")
	b.WriteString("<TS version=\"2.1\" language=\"" + lang(qtLang, l) + "\">\n")
	strs := src.at("aurora")
	for i, k := range strs {
		if i == 0 || strs[i-1].key != k.key {
			b.WriteString("<context>\n    <name>" + xmlText(k.key) + "</name>\n")
		}
		b.WriteString("    <message>\n        <source>" + xmlText(k.s.EN) + "</source>\n")
		b.WriteString("        <translation>" + xmlText(k.s.Texts[l]) + "</translation>\n    </message>\n")
		if i == len(strs)-1 || strs[i+1].key != k.key {
			b.WriteString("</context>\n")
		}
	}
	b.WriteString("</TS>\n")
	return b.Bytes()
}

// android writes an Android project's strings: English ("") with the names
// that stay as they are, or a language's translations.
func (src Source) android(kind, l string) []byte {
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" + xmlLicense)
	b.WriteString("<!-- " + generated + " -->\n<resources>\n")
	for _, k := range src.at(kind) {
		switch {
		case l == "" && k.s.Fixed:
			b.WriteString("    <string name=\"" + k.key + "\" translatable=\"false\">" + androidText(k.s.EN) + "</string>\n")
		case l == "":
			b.WriteString("    <string name=\"" + k.key + "\">" + androidText(k.s.EN) + "</string>\n")
		case !k.s.Fixed:
			b.WriteString("    <string name=\"" + k.key + "\">" + androidText(k.s.Texts[l]) + "</string>\n")
		}
	}
	b.WriteString("</resources>\n")
	return b.Bytes()
}

// xmlText escapes a text for an XML element.
func xmlText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// androidText escapes a text for an Android string resource.
func androidText(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '@', '?':
			if i == 0 {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// quote writes a JSON string as Python's json.dumps(ensure_ascii=False)
// does, which the String Catalogs and the tray's files have been written
// with: other characters than the quote, the backslash and the controls
// as they are.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		s = s[n:]
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
