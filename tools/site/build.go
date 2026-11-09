// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	stdhtml "html"
	"html/template"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// pages are the site's pages, each site/templates/<page>.html inside
// layout.html.
var pages = []string{"index", "download", "privacy", "terms", "code-signing"}

// errorPages are the pages nginx shows for an error, in the visitor's
// language (site/deploy/nginx.conf); search engines and the sitemap leave
// them out.
var errorPages = []string{"404", "50x"}

// siteURL is where the site is published, for the links that must be
// absolute: canonical, hreflang, Open Graph, the sitemap.
const siteURL = "https://cbb.tools"

// faq are the questions on the home page, in English, also given to search
// engines as a FAQPage. An answer is plain text: no links.
var faq = []struct{ Q, A string }{
	{"Is it free?", "Yes. Copy Beyond Borders is free software: no price, no subscription, no ads."},
	{"Can anyone else read what I copy?", "No. Every copy is encrypted end to end on the device that makes it, for your own devices alone. Whatever passes it on, a base or a server, cannot read it."},
	{"Do I need a computer?", "No. A group of phones only works too. A computer that is often on keeps sync away from home going at any time."},
	{"Does it work away from home?", "Yes. Turn on Everywhere, and your devices reach each other through the group's base, a computer of yours or a phone while its app is open, or through a backup server that cannot read your copies. It works on hotel, office and campus Wi-Fi too."},
	{"Why does the iPhone need a gesture?", "iOS does not let apps read the clipboard in the background. You send a copy with the Action button or a double tap on the back of the phone."},
	{"Are my passwords synced?", "What password managers mark as secret is not synced automatically."},
	{"Where is the iPhone app?", "It comes with TestFlight, which is not open yet."},
	{"Does it work on hotel or office Wi-Fi?", "Yes. Away from home it also works on strict networks, such as hotel, office and campus Wi-Fi, which let few apps through."},
	{"Does it need the internet?", "No. At home your devices need only your own network, with or without the internet."},
	{"What if I lose my phone?", "Remove it from the group on another device you trust. If the lost phone made the group, another phone of yours that you trust becomes the group's owner."},
	{"Who makes it?", "One developer, HunterEwok, in the United Kingdom. There is no company, no investors and no ads, and Copy Beyond Borders will always be free and open source."},
	{"How is it different from Universal Clipboard or KDE Connect?", "Universal Clipboard joins only Apple devices near each other, signed in to one Apple Account. KDE Connect works on one local network. Copy Beyond Borders joins iPhone, Android, Aurora, Windows, Mac and Linux, at home and away, with no account."},
}

// Language is one language of the site.
type Language struct {
	Code string // the directory and the code in links: "en", "zh"
	Name string // its own name, for the language menu
	Tag  string // the html lang attribute: "zh-Hans"
	RTL  bool   // written right to left
	// texts maps each English text to its translation; nil for English.
	texts map[string]string
}

// Meta keys of a translation file: they describe the language and are not
// texts of a page.
const (
	metaName = "@name" // the language's own name
	metaTag  = "@lang" // its html lang attribute, when not its code
	metaDir  = "@dir"  // "rtl" for a language written right to left
)

// english is the language the pages are written in.
var english = Language{Code: "en", Name: "English", Tag: "en"}

// loadLanguages returns English and every language of site/l10n, in the
// order of their own names: the Latin ones alphabetically, then each other
// script together, as the menu lists them.
func loadLanguages(root string) ([]Language, error) {
	langs := []Language{english}
	files, err := filepath.Glob(filepath.Join(root, "l10n", "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var texts map[string]string
		if err := json.Unmarshal(data, &texts); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		code := strings.TrimSuffix(filepath.Base(f), ".json")
		l := Language{Code: code, Name: texts[metaName], Tag: texts[metaTag], RTL: texts[metaDir] == "rtl", texts: texts}
		if l.Name == "" {
			return nil, fmt.Errorf("%s: no %q", f, metaName)
		}
		if l.Tag == "" {
			l.Tag = code
		}
		langs = append(langs, l)
	}
	slices.SortFunc(langs, func(a, b Language) int { return strings.Compare(a.Name, b.Name) })
	return langs, nil
}

// page is what a page's template sees.
type page struct {
	Lang  Language
	Langs []Language
	Page  string   // the page's file name, "download.html"
	Path  string   // its path in links: "download.html", "" for the home page
	Error bool     // an error page, or a page standing in for a missing translation: not to be indexed
	Doc   *docView // the documentation's pages
	Release
}

// Release is the latest release, from CHANGELOG.md.
type Release struct {
	Version string // "0.5.0"
	Date    string // "2026-10-26"
}

// releaseHeading is a release's heading in CHANGELOG.md.
var releaseHeading = regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})\r?$`)

// latestRelease reads the first release of the changelog next to site/.
func latestRelease(root string) (Release, error) {
	data, err := os.ReadFile(filepath.Join(root, "..", "CHANGELOG.md"))
	if err != nil {
		return Release{}, err
	}
	m := releaseHeading.FindSubmatch(data)
	if m == nil {
		return Release{}, errors.New("CHANGELOG.md: no release")
	}
	return Release{Version: string(m[1]), Date: string(m[2])}, nil
}

// assets maps the files of site/static that pages link by name to the
// names they are published under: each carries a hash of its contents, so
// browsers may keep it for good and still get each new version.
func assets(root string) (map[string]string, map[string][]byte, error) {
	names, out := map[string]string{}, map[string][]byte{}
	for _, file := range []string{"style.css", "theme.js", "site.js"} {
		data, err := os.ReadFile(filepath.Join(root, "static", file))
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(data)
		ext := filepath.Ext(file)
		name := "static/" + strings.TrimSuffix(file, ext) + "." + hex.EncodeToString(sum[:4]) + ext
		names[file] = "/" + name
		out[name] = data
	}
	return names, out, nil
}

// URL returns the absolute address of this page in lang.
func (p page) URL(lang Language) string {
	return siteURL + "/" + lang.Code + "/" + p.Path
}

// pagePath returns the path of a page in links.
func pagePath(name string) string {
	if name == "index" {
		return ""
	}
	return name + ".html"
}

// translator turns the pages' English texts into one language and records
// what it was asked for and what it lacked.
type translator struct {
	lang    Language
	used    map[string]bool
	missing map[string]bool
	warn    []string // what is out of date or not translated yet, not an error
}

// placeholder is where a text takes an argument: a link, a command.
var placeholder = regexp.MustCompile(`%s`)

// t translates text and puts args into its placeholders, in order. The
// text is escaped; an argument is escaped too unless it is already HTML,
// such as what link and code return.
func (tr *translator) t(text string, args ...any) (template.HTML, error) {
	out := tr.raw(text)
	n := len(placeholder.FindAllStringIndex(out, -1))
	if n != len(args) {
		return "", fmt.Errorf("%s: %q has %d placeholders for %d arguments", tr.lang.Code, out, n, len(args))
	}
	i := 0
	escaped := placeholder.ReplaceAllStringFunc(template.HTMLEscapeString(out), func(string) string {
		i++
		return html(args[i-1])
	})
	return template.HTML(escaped), nil
}

// raw returns the translation of text as it is, and records it as used,
// or as missing when the language lacks it and the English stands in.
func (tr *translator) raw(text string) string {
	tr.used[text] = true
	if tr.lang.texts == nil {
		return text
	}
	if s, ok := tr.lang.texts[text]; ok && s != "" {
		return s
	}
	tr.missing[text] = true
	return text
}

// html returns v as HTML: as it is when it is HTML already, escaped
// otherwise.
func html(v any) string {
	if h, ok := v.(template.HTML); ok {
		return string(h)
	}
	return template.HTMLEscapeString(fmt.Sprint(v))
}

// funcs are the functions the pages use besides t.
var funcs = template.FuncMap{
	"t":    func(string, ...any) template.HTML { return "" }, // replaced per language
	"list": func(v ...any) []any { return v },
	"code": func(s string) template.HTML {
		return template.HTML(`<code dir="ltr">` + template.HTMLEscapeString(s) + "</code>")
	},
	"link":      link,
	"hasPrefix": strings.HasPrefix,
	"dict": func(kv ...any) (map[string]any, error) {
		if len(kv)%2 != 0 {
			return nil, errors.New("dict: odd number of arguments")
		}
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[fmt.Sprint(kv[i])] = plain(kv[i+1])
		}
		return m, nil
	},
	// jsonld writes v as the JSON of a <script type="application/ld+json">;
	// json.Marshal escapes <, > and &, so it cannot close the element.
	"jsonld": func(v any) (template.JS, error) {
		b, err := json.Marshal(v)
		return template.JS(b), err
	},
	// fit is the class that sizes a label to its place on a drawing: a
	// long name is written smaller, so it stays on the drawing in every
	// language.
	"fit": func(v any) string {
		switch n := utf8.RuneCountInString(fmt.Sprint(plain(v))); {
		case n > 10:
			return "longer"
		case n > 9:
			return "long"
		}
		return ""
	},
}

// link returns a link to href that reads text.
func link(href string, text any) template.HTML {
	return template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + html(text) + `</a>`)
}

// plain returns v as plain text when it is translated HTML without markup,
// for JSON-LD; anything else stays as it is.
func plain(v any) any {
	if h, ok := v.(template.HTML); ok {
		return stdhtml.UnescapeString(string(h))
	}
	return v
}

// soonLine is one language's line of soon.html, the page everyone sees
// while the site is closed.
type soonLine struct {
	Lang              Language
	Coming, Meanwhile template.HTML
}

// qa is a question of the FAQ in one language.
type qa struct{ Q, A template.HTML }

// faqIn translates the FAQ.
func faqIn(tr *translator) ([]qa, error) {
	var out []qa
	for _, f := range faq {
		q, err := tr.t(f.Q)
		if err != nil {
			return nil, err
		}
		a, err := tr.t(f.A)
		if err != nil {
			return nil, err
		}
		out = append(out, qa{q, a})
	}
	return out, nil
}

// faqLD is the FAQ as a schema.org FAQPage.
func faqLD(items []qa) map[string]any {
	var qs []any
	for _, it := range items {
		qs = append(qs, map[string]any{
			"@type":          "Question",
			"name":           plain(it.Q),
			"acceptedAnswer": map[string]any{"@type": "Answer", "text": plain(it.A)},
		})
	}
	return map[string]any{"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": qs}
}

// render renders every page in every language and returns them by path
// below the output directory, with the translators to check.
func render(root string) (map[string][]byte, []*translator, error) {
	langs, err := loadLanguages(root)
	if err != nil {
		return nil, nil, err
	}
	release, err := latestRelease(root)
	if err != nil {
		return nil, nil, err
	}
	names, out, err := assets(root)
	if err != nil {
		return nil, nil, err
	}
	asset := template.FuncMap{"asset": func(name string) (string, error) {
		if n, ok := names[name]; ok {
			return n, nil
		}
		return "", fmt.Errorf("asset %q: not hashed", name)
	}}
	ds, err := loadDocs(root)
	if err != nil {
		return nil, nil, err
	}
	// docLangs are the languages each page of the documentation is in, in
	// the order of the pages.
	docLangs := map[string][]Language{}
	var trs []*translator
	var soon []soonLine
	for _, lang := range langs {
		tr := &translator{lang: lang, used: map[string]bool{}, missing: map[string]bool{}}
		trs = append(trs, tr)
		items, err := faqIn(tr)
		if err != nil {
			return nil, nil, err
		}
		perLang := template.FuncMap{
			"t":     tr.t,
			"faq":   func() []qa { return items },
			"faqld": func() map[string]any { return faqLD(items) },
		}
		line := soonLine{Lang: lang}
		if line.Coming, err = tr.t("The website opens soon."); err != nil {
			return nil, nil, err
		}
		if line.Meanwhile, err = tr.t("Meanwhile, Copy Beyond Borders is on %s.", link("https://github.com/HunterEwok/cbb", "GitHub")); err != nil {
			return nil, nil, err
		}
		soon = append(soon, line)
		parse := func(name string) (*template.Template, error) {
			// chalk.html holds the line drawings, written by site/chalk.js.
			return template.New("layout.html").Funcs(funcs).Funcs(perLang).Funcs(asset).ParseFiles(
				filepath.Join(root, "templates", "layout.html"),
				filepath.Join(root, "templates", "chalk.html"),
				filepath.Join(root, "templates", name+".html"))
		}
		for _, name := range append(slices.Clone(pages), errorPages...) {
			tmpl, err := parse(name)
			if err != nil {
				return nil, nil, err
			}
			var b bytes.Buffer
			p := page{Lang: lang, Langs: langs, Page: name + ".html", Path: pagePath(name), Error: slices.Contains(errorPages, name), Release: release}
			if err := tmpl.Execute(&b, p); err != nil {
				return nil, nil, fmt.Errorf("%s/%s.html: %w", lang.Code, name, err)
			}
			out[lang.Code+"/"+name+".html"] = b.Bytes()
		}
		docTmpl, err := parse("doc")
		if err != nil {
			return nil, nil, err
		}
		outs, err := ds.pages(lang, tr, func(path string, d docView, translated bool) ([]byte, error) {
			var b bytes.Buffer
			p := page{Lang: lang, Langs: langs, Page: path, Path: path, Doc: &d, Error: !translated, Release: release}
			err := docTmpl.Execute(&b, p)
			return b.Bytes(), err
		})
		if err != nil {
			return nil, nil, err
		}
		for _, o := range outs {
			file := o.Path
			if strings.HasSuffix(file, "/") {
				file += "index.html"
			}
			out[lang.Code+"/"+file] = o.HTML
			if o.Translated {
				docLangs[o.Path] = append(docLangs[o.Path], lang)
			}
		}
	}
	// Without the language chooser, "/" falls back to English.
	out["index.html"] = []byte(`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=en/"><title>Copy Beyond Borders</title><a href="en/">Copy Beyond Borders</a>` + "\n")
	tmpl, err := template.New("soon.html").Funcs(asset).ParseFiles(filepath.Join(root, "templates", "soon.html"))
	if err != nil {
		return nil, nil, err
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, soon); err != nil {
		return nil, nil, fmt.Errorf("soon.html: %w", err)
	}
	out["soon.html"] = b.Bytes()
	for name, data := range ds.images {
		out["docs/images/"+name] = data
	}
	var entries []docEntry
	for _, f := range ds.files {
		entries = append(entries, docEntry{Path: docPath(f), Langs: docLangs[docPath(f)]})
	}
	out["sitemap.xml"] = sitemap(langs, entries)
	out[".well-known/security.txt"] = securityTxt(release)
	if out["site.webmanifest"], err = manifest(); err != nil {
		return nil, nil, err
	}
	out["robots.txt"] = []byte("User-agent: *\n" +
		"# \"/\" only redirects; \"/?lang=\" sets a cookie.\n" +
		"Disallow: /?\n" +
		"Sitemap: " + siteURL + "/sitemap.xml\n")
	return out, trs, nil
}

// securityTxt tells security researchers where to report (RFC 9116). It
// expires a year after the latest release, so a site nobody keeps up says
// so.
func securityTxt(r Release) []byte {
	released, err := time.Parse(time.DateOnly, r.Date)
	if err != nil {
		released = time.Now()
	}
	return []byte("Contact: https://github.com/HunterEwok/cbb/security/advisories/new\n" +
		"Policy: https://github.com/HunterEwok/cbb/blob/main/SECURITY.md\n" +
		"Preferred-Languages: en, ru\n" +
		"Canonical: " + siteURL + "/.well-known/security.txt\n" +
		"Expires: " + released.AddDate(1, 0, 0).Format(time.RFC3339) + "\n")
}

// manifest describes the site to a phone that keeps it on its home screen.
func manifest() ([]byte, error) {
	return json.MarshalIndent(map[string]any{
		"name":             "Copy Beyond Borders",
		"short_name":       "CBB",
		"start_url":        "/",
		"display":          "browser",
		"theme_color":      "#0A7A3E",
		"background_color": "#E8EFEF",
		"icons": []map[string]string{
			{"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
			{"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"},
		},
	}, "", "  ")
}

// compressible are the files build also writes gzipped, for nginx's
// gzip_static.
var compressible = []string{".html", ".css", ".js", ".xml", ".txt", ".webmanifest"}

// gzipped returns data compressed as well as gzip can, with no name or time
// in its header, so a build is the same each time.
func gzipped(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w, err := gzip.NewWriterLevel(&b, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// docEntry is a page of the documentation and the languages it is in.
type docEntry struct {
	Path  string
	Langs []Language
}

// sitemap lists every page in every language, each with its translations
// (hreflang), for search engines. A page of the documentation is listed in
// the languages it is translated into.
func sitemap(langs []Language, docs []docEntry) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">` + "\n")
	list := func(path string, in []Language) {
		p := page{Path: path}
		for _, l := range in {
			fmt.Fprintf(&b, "<url><loc>%s</loc>", p.URL(l))
			for _, alt := range in {
				fmt.Fprintf(&b, `<xhtml:link rel="alternate" hreflang="%s" href="%s"/>`, alt.Tag, p.URL(alt))
			}
			b.WriteString("</url>\n")
		}
	}
	for _, name := range pages {
		list(pagePath(name), langs)
	}
	for _, d := range docs {
		list(d.Path, d.Langs)
	}
	b.WriteString("</urlset>\n")
	return b.Bytes()
}

// check renders the site and reports every missing, unused or broken
// translation. What is only out of date, a documentation page not
// translated yet or following an older original, is printed to warn, and
// counts as a problem when strict is set.
func check(root string, strict bool, warn io.Writer) error {
	_, trs, err := render(root)
	if err != nil {
		return err
	}
	used := trs[0].used // English asks for every text
	var problems []string
	for _, tr := range trs[1:] {
		for _, w := range tr.warn {
			if strict {
				problems = append(problems, w)
			} else {
				fmt.Fprintln(warn, "warning:", w)
			}
		}
		for _, text := range sortedKeys(tr.missing) {
			problems = append(problems, fmt.Sprintf("l10n/%s.json: no translation of %q", tr.lang.Code, text))
		}
		for _, text := range sortedKeys(tr.lang.texts) {
			if !used[text] && !strings.HasPrefix(text, "@") {
				problems = append(problems, fmt.Sprintf("l10n/%s.json: %q is on no page", tr.lang.Code, text))
			}
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

// build writes the site to dir: the pages and site/static.
func build(root, dir string) error {
	if err := check(root, false, io.Discard); err != nil {
		return err
	}
	files, _, err := render(root)
	if err != nil {
		return err
	}
	static := filepath.Join(root, "static")
	err = filepath.WalkDir(static, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(static, p)
		files["static/"+filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(files) {
		if slices.Contains(compressible, filepath.Ext(name)) {
			gz, err := gzipped(files[name])
			if err != nil {
				return err
			}
			files[name+".gz"] = gz
		}
	}
	for _, name := range sortedKeys(files) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, files[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
