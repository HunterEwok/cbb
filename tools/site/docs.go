// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
)

// The documentation on the site, at /<language>/docs/: the index
// (docs/README.md) and the pages for users (docs/guide), in every language
// of the site, inside the site's own layout. Every other page of the
// documentation is English only and stays on GitHub; the index links to it
// there, and says so.
//
// The English pages are the Markdown files of docs/. A translation of a
// guide page is site/docs/<language>/guide/<page>.md: the same Markdown,
// text translated, with every link, picture and code block as it is in the
// original, and the same headings in the same order. The headings keep the
// original's anchors in every language, so a link to a section reads the
// same in all of them, and the links of a translation are the original's.
// A page not translated yet shows in English, with a note. The index is the
// English docs/README.md read line by line through site/l10n/<language>.json:
// each heading, paragraph, name and description is a text there.
//
// A translation says which version of its original it follows with a line
// `<!-- source: HASH -->`; when the original changes, the line goes stale
// and `site check` says so (`-strict` fails on it, `site docs-sync` renews
// the lines once the translations are brought up to date).

// repoURL is where a file of the repository is shown on GitHub.
const repoURL = "https://github.com/HunterEwok/cbb/blob/main/"

// indexFile is the documentation's index; guideDir holds the pages for users.
const (
	indexFile = "docs/README.md"
	guideDir  = "docs/guide/"
)

// docPath returns the path of an English documentation file's page below a
// language's directory: "docs/" for the index.
func docPath(file string) string {
	if file == indexFile {
		return "docs/"
	}
	return strings.TrimSuffix(file, ".md") + ".html"
}

// docView is what doc.html sees.
type docView struct {
	Title       string
	Description string
	Body        template.HTML
	Crumb       template.HTML // the way back to the index
	Notice      template.HTML // the page is not translated, or its translation is old
	Footer      template.HTML // where the page is kept
}

// docSet is the documentation read from the repository.
type docSet struct {
	root    string
	files   []string          // the index, then the guide pages
	english map[string][]byte // each file's content
	guides  map[string]bool
	images  map[string][]byte // below docs/images
}

// loadDocs reads the English documentation and its pictures.
func loadDocs(root string) (*docSet, error) {
	repo := filepath.Join(root, "..")
	ds := &docSet{root: root, files: []string{indexFile}, english: map[string][]byte{}, guides: map[string]bool{}, images: map[string][]byte{}}
	names, err := filepath.Glob(filepath.Join(repo, "docs", "guide", "*.md"))
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	for _, n := range names {
		file := guideDir + filepath.Base(n)
		ds.files = append(ds.files, file)
		ds.guides[file] = true
	}
	for _, f := range ds.files {
		data, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(f)))
		if err != nil {
			return nil, err
		}
		ds.english[f] = lf(data)
	}
	images := filepath.Join(repo, "docs", "images")
	err = filepath.WalkDir(images, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(images, p)
		ds.images[filepath.ToSlash(rel)], err = os.ReadFile(p)
		return err
	})
	return ds, err
}

// translation returns a language's translation of a guide page, or nil.
func (ds *docSet) translation(lang, file string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(ds.root, "docs", lang, filepath.FromSlash(strings.TrimPrefix(file, "docs/"))))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return lf(data), err
}

// lf turns the line ends of a Markdown file into LF: a Windows checkout may
// have Git's CR LF in them, which must change neither the hash of a page
// nor the lines the index is read by.
func lf(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

// sourceMark is the line of a translation that names the version of the
// original it follows.
var sourceMark = regexp.MustCompile(`(?m)^<!-- source: ([0-9a-f]{12}) -->\r?\n?`)

// contentHash identifies a version of an original.
func contentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:6])
}

// syncDocs sets the source line of every translation to the original's
// present version, for when the translations have been brought up to date.
func syncDocs(root string) error {
	ds, err := loadDocs(root)
	if err != nil {
		return err
	}
	dirs, err := filepath.Glob(filepath.Join(root, "docs", "*"))
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		lang := filepath.Base(dir)
		for _, file := range ds.files[1:] {
			data, err := ds.translation(lang, file)
			if err != nil || data == nil {
				if err != nil {
					return err
				}
				continue
			}
			mark := "<!-- source: " + contentHash(ds.english[file]) + " -->\n"
			var out []byte
			if loc := sourceMark.FindIndex(data); loc != nil {
				out = append(append(slices.Clone(data[:loc[0]]), mark...), data[loc[1]:]...)
			} else {
				first, rest, _ := bytes.Cut(data, []byte("\n"))
				out = append(append(append(slices.Clone(first), '\n'), mark...), rest...)
			}
			if !bytes.Equal(out, data) {
				p := filepath.Join(root, "docs", lang, filepath.FromSlash(strings.TrimPrefix(file, "docs/")))
				if err := os.WriteFile(p, out, 0o644); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// githubIDs gives the headings the anchors GitHub gives them: lower case,
// spaces as hyphens, other punctuation dropped, -1, -2 for a repeat.
type githubIDs struct{ seen map[string]int }

func (g *githubIDs) Generate(value []byte, _ ast.NodeKind) []byte {
	var b strings.Builder
	for _, r := range strings.ToLower(string(value)) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	id := b.String()
	if n := g.seen[id]; n > 0 {
		g.seen[id]++
		id = fmt.Sprintf("%s-%d", id, n)
	} else {
		g.seen[id] = 1
	}
	return []byte(id)
}

func (g *githubIDs) Put(value []byte) { g.seen[string(value)]++ }

// ordinalIDs gives a translation's headings the anchors of the original's,
// in order.
type ordinalIDs struct {
	ids  []string
	next int
}

func (o *ordinalIDs) Generate([]byte, ast.NodeKind) []byte {
	o.next++
	if o.next > len(o.ids) { // a heading too many: shapeProblems says so
		return fmt.Appendf(nil, "section-%d", o.next)
	}
	return []byte(o.ids[o.next-1])
}

func (o *ordinalIDs) Put([]byte) {}

// markdown renders the documentation: GitHub's tables, strikethrough and
// autolinks, no raw HTML, and no alignment attributes, which the site's
// Content-Security-Policy would block as inline styles.
var markdown = goldmark.New(
	goldmark.WithExtensions(
		extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignNone)),
		extension.Strikethrough,
		extension.Linkify,
	),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
)

// docInfo is a parsed page: what the site reads from it, and what a
// translation must keep.
type docInfo struct {
	src           []byte
	root          ast.Node
	title, desc   string
	levels        []int
	ids           []string
	codes         int
	links, images []string // the destinations as written
}

func parseDoc(src []byte, ids parser.IDs) *docInfo {
	ctx := parser.NewContext(parser.WithIDs(ids))
	d := &docInfo{src: src}
	d.root = markdown.Parser().Parse(text.NewReader(src), parser.WithContext(ctx))
	_ = ast.Walk(d.root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Heading:
			d.levels = append(d.levels, n.Level)
			if id, ok := n.AttributeString("id"); ok {
				if b, ok := id.([]byte); ok {
					d.ids = append(d.ids, string(b))
				}
			}
			if n.Level == 1 && d.title == "" {
				d.title = plainText(n, src)
			}
		case *ast.Paragraph:
			if d.desc == "" && d.title != "" {
				d.desc = describe(plainText(n, src))
			}
		case *ast.FencedCodeBlock, *ast.CodeBlock:
			d.codes++
		case *ast.Link:
			d.links = append(d.links, string(n.Destination))
		case *ast.Image:
			d.images = append(d.images, string(n.Destination))
		}
		return ast.WalkContinue, nil
	})
	return d
}

// shapeProblems lists what a translation changed that it must keep: the
// headings, the code blocks, the links and the pictures.
func (d *docInfo) shapeProblems(en *docInfo) []string {
	var p []string
	if !slices.Equal(d.levels, en.levels) {
		p = append(p, fmt.Sprintf("%d headings (levels %v), the original has %d (levels %v)", len(d.levels), d.levels, len(en.levels), en.levels))
	}
	if d.codes != en.codes {
		p = append(p, fmt.Sprintf("%d code blocks, the original has %d", d.codes, en.codes))
	}
	for _, c := range []struct {
		what         string
		have, wanted []string
	}{{"links", d.links, en.links}, {"pictures", d.images, en.images}} {
		a, b := slices.Sorted(slices.Values(c.have)), slices.Sorted(slices.Values(c.wanted))
		if !slices.Equal(a, b) {
			p = append(p, fmt.Sprintf("the %s differ from the original's: has %q, wants %q", c.what, a, b))
		}
	}
	return p
}

// linker turns the destination of a link in an English file into its
// address on the site or on GitHub, for one language.
type linker struct {
	lang string
	ds   *docSet
}

// rewrite returns the address for dest; an address with a scheme or an
// anchor alone stays.
func (l linker) rewrite(file, dest string) string {
	if dest == "" || strings.HasPrefix(dest, "#") || strings.Contains(dest, ":") {
		return dest
	}
	target, frag, _ := strings.Cut(dest, "#")
	if frag != "" {
		frag = "#" + frag
	}
	target = path.Join(path.Dir(file), target)
	if target == indexFile || l.ds.guides[target] {
		return "/" + l.lang + "/" + docPath(target) + frag
	}
	if rest, ok := strings.CutPrefix(target, "docs/images/"); ok {
		if _, ok := l.ds.images[l.lang+"/"+rest]; ok {
			return "/docs/images/" + l.lang + "/" + rest
		}
		return "/docs/images/" + rest
	}
	return repoURL + target + frag
}

// body rewrites the links of a parsed page and renders it.
func (l linker) body(d *docInfo, file string) (template.HTML, error) {
	err := ast.Walk(d.root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Link:
			n.Destination = []byte(l.rewrite(file, string(n.Destination)))
		case *ast.Image:
			n.Destination = []byte(l.rewrite(file, string(n.Destination)))
		}
		return ast.WalkContinue, nil
	})
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := markdown.Renderer().Render(&b, d.src, d.root); err != nil {
		return "", err
	}
	return template.HTML(l.boards(b.String())), nil
}

// A picture of the documentation on its own line, as goldmark renders it.
var pictureLine = regexp.MustCompile(`<p><img src="/docs/images/([^"]+\.svg)" alt="[^"]*"></p>`)

var (
	svgStyle  = regexp.MustCompile(`(?s)<style>.*?</style>\n?`)
	svgSize   = regexp.MustCompile(`^(<svg [^>]*?) width="\d+" height="\d+"`)
	svgLead   = regexp.MustCompile(`^<!--.*?-->\n`)
	svgShape  = regexp.MustCompile(`<path\b`)
	tableOpen = regexp.MustCompile(`<table\b[^>]*>`)
)

// boards puts each picture of a page, which is an SVG drawn for GitHub, on a
// drawing sheet of the site: inline, with the sheet's corner marks, where the
// stylesheet (.diagram) draws it in the site's lines in place of its own
// colours. The file stays as it is, so GitHub shows it as before.
func (l linker) boards(html string) string {
	html = tableOpen.ReplaceAllString(html, `<div class="tablewrap"><table>`)
	html = strings.ReplaceAll(html, "</table>", "</table></div>")
	return pictureLine.ReplaceAllStringFunc(html, func(m string) string {
		name := pictureLine.FindStringSubmatch(m)[1]
		data, ok := l.ds.images[name]
		if !ok {
			return m
		}
		svg := svgLead.ReplaceAllString(string(lf(data)), "")
		svg = svgStyle.ReplaceAllString(svg, "")
		svg = svgSize.ReplaceAllString(svg, "$1")
		svg = svgShape.ReplaceAllString(svg, "<path pathLength=\"1\"")
		return `<div class="frame diagram"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i><div class="surface">` +
			strings.TrimSpace(svg) + `</div></div>`
	})
}

// plainText returns the text of n without its markup.
func plainText(n ast.Node, src []byte) string {
	var b strings.Builder
	_ = ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch c := c.(type) {
		case *ast.Text:
			b.Write(c.Segment.Value(src))
			if c.SoftLineBreak() || c.HardLineBreak() {
				b.WriteByte(' ')
			}
		case *ast.String:
			b.Write(c.Value)
		}
		return ast.WalkContinue, nil
	})
	return b.String()
}

// describe cuts a page's first paragraph to a description for search
// engines: at most 160 characters, ending at a word.
func describe(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 160 {
		s = string(r[:157])
		if i := strings.LastIndex(s, " "); i > 0 {
			s = s[:i]
		}
		s += "…"
	}
	return s
}

// cellLink is the first cell of an index row: a link.
var cellLink = regexp.MustCompile(`^\[(.+)\]\((.+)\)$`)

// translateIndex reads the English index line by line and returns it in
// the translator's language: every heading, paragraph, link text and cell
// is a text of the translation file. A section without a guide page gets
// the note that its pages are English and on GitHub.
func translateIndex(src []byte, tr *translator) string {
	lines := strings.Split(strings.TrimRight(string(src), "\n"), "\n")
	note := tr.raw("These pages are in English only, and open on GitHub.")
	var out, para []string
	noteDue := false
	flush := func() {
		if len(para) == 0 {
			return
		}
		out = append(out, tr.raw(strings.Join(para, " ")))
		para = nil
		if noteDue {
			noteDue = false
			if tr.lang.texts != nil {
				out = append(out, "", note)
			}
		}
	}
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "<!--"):
			out = append(out, line)
		case line == "":
			flush()
			out = append(out, "")
		case strings.HasPrefix(line, "#"):
			flush()
			hashes, title, _ := strings.Cut(line, " ")
			out = append(out, hashes+" "+tr.raw(title))
			if hashes == "##" {
				noteDue = true
				for _, next := range lines[i+1:] {
					if strings.HasPrefix(next, "## ") {
						break
					}
					if strings.Contains(next, "](guide/") {
						noteDue = false
					}
				}
			}
		case strings.HasPrefix(line, "|"):
			flush()
			out = append(out, translateRow(line, tr))
		default:
			para = append(para, line)
		}
	}
	flush()
	return strings.Join(out, "\n") + "\n"
}

// translateRow translates a row of an index table.
func translateRow(line string, tr *translator) string {
	if strings.Trim(line, "|-: ") == "" {
		return line
	}
	cells := strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "| "), " |"), " | ")
	for i, c := range cells {
		if m := cellLink.FindStringSubmatch(c); m != nil {
			cells[i] = "[" + tr.raw(m[1]) + "](" + m[2] + ")"
		} else {
			cells[i] = tr.raw(c)
		}
	}
	return "| " + strings.Join(cells, " | ") + " |"
}

// docOut is a rendered page of the documentation.
type docOut struct {
	Path       string // below the language's directory: "docs/guide/keys.html"
	HTML       []byte
	Translated bool // in this language, not English standing in
}

// pages renders the documentation in one language; page turns a docView
// into the finished page at a path, and is told whether the page is in the
// language (and so to be indexed) or English standing in for it.
func (ds *docSet) pages(lang Language, tr *translator, page func(path string, d docView, translated bool) ([]byte, error)) ([]docOut, error) {
	lk := linker{lang: lang.Code, ds: ds}
	var outs []docOut
	var askErr error
	t := func(text string, args ...any) template.HTML {
		h, err := tr.t(text, args...)
		if err != nil && askErr == nil {
			askErr = err
		}
		return h
	}
	for _, file := range ds.files {
		rel := strings.TrimPrefix(file, "docs/")
		en := parseDoc(ds.english[file], &githubIDs{seen: map[string]int{}})
		info, translated, stale := en, lang.Code == "en", false
		if file == indexFile {
			info = parseDoc([]byte(translateIndex(ds.english[file], tr)), &githubIDs{seen: map[string]int{}})
			translated = true
		} else if !translated {
			data, err := ds.translation(lang.Code, file)
			if err != nil {
				return nil, err
			}
			if data == nil {
				tr.warn = append(tr.warn, fmt.Sprintf("site/docs/%s/%s: not translated; the English page stands in", lang.Code, rel))
			} else {
				info = parseDoc(data, &ordinalIDs{ids: en.ids})
				if p := info.shapeProblems(en); len(p) > 0 {
					return nil, fmt.Errorf("site/docs/%s/%s: %s", lang.Code, rel, strings.Join(p, "; "))
				}
				translated = true
				if m := sourceMark.FindSubmatch(data); m == nil || string(m[1]) != contentHash(ds.english[file]) {
					stale = true
					tr.warn = append(tr.warn, fmt.Sprintf("site/docs/%s/%s: follows an older %s; bring it up to date, then run site docs-sync", lang.Code, rel, file))
				}
			}
		}
		if info.title == "" {
			return nil, fmt.Errorf("%s: no title (# heading)", file)
		}
		body, err := lk.body(info, file)
		if err != nil {
			return nil, err
		}
		d := docView{Title: info.title, Description: info.desc, Body: body}
		if file != indexFile {
			d.Crumb = link("/"+lang.Code+"/docs/", t("All documentation"))
		}
		// Every text is asked for on every page, so that English, which
		// shows none of the notes, still counts them as used.
		original := link(repoURL+file, t("the English original"))
		kept := t("This page is kept on %s, where changes to it are made.", link(repoURL+file, "GitHub"))
		from := t("This page is translated from %s on GitHub, where changes to it are made.", original)
		missing := t("This page is not translated into your language yet; here it is in English.")
		old := t("The English original has changed since this page was translated; see %s for the newest text.", original)
		switch {
		case file == indexFile:
		case lang.Code == "en":
			d.Footer = kept
		case !translated:
			d.Notice, d.Footer = missing, kept
		default:
			d.Footer = from
			if stale {
				d.Notice = old
			}
		}
		if askErr != nil {
			return nil, askErr
		}
		pp := docPath(file)
		html, err := page(pp, d, translated)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", lang.Code, pp, err)
		}
		outs = append(outs, docOut{Path: pp, HTML: html, Translated: translated})
	}
	return outs, nil
}
