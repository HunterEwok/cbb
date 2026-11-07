// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// The documentation rules:
//
//   - a relative link in a Markdown file names a file or directory of the
//     repository, and its #anchor, if any, a heading of that file;
//   - the project's old names do not come back, in any file (oldName);
//   - every command of cbb, the full and the lite member, is in docs/reference/cli.md,
//     the lite member's in its section;
//   - every subcommand of the full member that has flags of its own, and each
//     of those flags, is in docs/reference/cli.md, the flags in a line that
//     names the command;
//   - every port the code listens on by default is in the ports table of
//     docs/reference/devices.md;
//   - every environment variable that the code, the installers or the units
//     read (CBB_*) is in docs/reference/config.md;
//   - every page below docs/ is reached from docs/README.md, the index;
//   - no page outside the changelog calls something "planned for" a version
//     that is released already (the newest version in CHANGELOG.md);
//   - every operation of the control socket (internal/control's Op
//     constants) is named in section 8 of docs/protocol.md or has a row of
//     its own in a table of the protocol, as section 10's do, and every
//     field of its header (internal/control's Header) is named in section 8;
//   - the pages for users and administrators (docs/guide, docs/admin and the
//     READMEs) do not tell the reader something is easy ("simply", "easy",
//     "easily", "obviously", "of course").

var (
	mdLink    = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	mdHeading = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*\s*$`)
	// oldName matches the project's old names in every spelling, written
	// in pieces so that this file does not hold them either.
	oldName   = regexp.MustCompile(`(?i)clip(?:` + `board)?[ _.-]?` + `bridge`)
	goCommand = regexp.MustCompile(`(?m)^\s*case "([a-z]+)"`)
	rsCommand = regexp.MustCompile(`(?m)^\s*"([a-z]+)" => cmd_`)
	// envQuoted is a variable's name as a string in Go, Rust, Swift and
	// Kotlin; envShell is one that a shell script, a systemd unit or
	// PowerShell reads.
	envQuoted = regexp.MustCompile(`"(CBB_[A-Z0-9_]+)"`)
	envShell  = regexp.MustCompile(`(?:\$\{?|\$env:|Environment=)(CBB_[A-Z0-9_]+)`)
	mdPageRef = regexp.MustCompile(`\]\(([^)#\s]+\.md)(?:#[^)]*)?\)`)
	// flagSet starts a command's flags in cmd/cbb; goFlag is one flag of it.
	flagSet = regexp.MustCompile(`flag\.NewFlagSet\("([a-z][a-z -]*)"`)
	goFlag  = regexp.MustCompile(`\b\w+\.(?:String|Bool|Int|Int64|Uint|Duration|Float64|Func|BoolFunc)\("([A-Za-z][\w-]*)"|\b\w+\.(?:StringVar|BoolVar|IntVar|Int64Var|UintVar|DurationVar|Var|TextVar)\([^,()]+, "([A-Za-z][\w-]*)"`)
	// goPort and rsPort are a port constant, listenPort a default listen
	// address of a flag.
	goPort     = regexp.MustCompile(`(?m)^\s*(?:const\s+)?\w*Port\s*=\s*(\d{2,5})\s*$`)
	rsPort     = regexp.MustCompile(`const \w*PORT: u16 = (\d{2,5});`)
	listenPort = regexp.MustCompile(`\.String\("[\w-]*listen", "[\w.]*:(\d{2,5})"`)
	plannedFor = regexp.MustCompile(`(?i)\bplanned for (\d+)\.(\d+)\b`)
	// easyWord is a word that tells the reader something is easy; notProse
	// what a line holds besides prose: code, a link's target, a URL, a quote.
	easyWord = regexp.MustCompile(`(?i)\b(simply|easy|easily|obviously|of course)\b`)
	notProse = regexp.MustCompile("`[^`]*`|\\]\\([^)]*\\)|<[^>]*>|https?://\\S+|\"[^\"]*\"")
)

// notEnv are the CBB_ names in the code that are not environment variables.
var notEnv = map[string]bool{
	"CBB_SELECTION": true, // the X11 property the desktop connector reads a selection into
}

// configRef is the reference page of the environment variables.
const configRef = "docs/reference/config.md"

// checkDocs checks the rules above in one file; files maps every checked
// path to its content.
// checkOldName reports each line of a file that holds one of the
// project's old names: the project is Copy Beyond Borders (CBB), and its
// command and every technical name are cbb, in code, docs and the
// changelog alike.
func checkOldName(name string, data []byte) []string {
	var problems []string
	for i, line := range strings.Split(string(data), "\n") {
		if oldName.MatchString(line) {
			problems = append(problems, fmt.Sprintf("%s:%d: an old name; the project is Copy Beyond Borders (CBB) and every technical name cbb", name, i+1))
		}
	}
	return problems
}

func checkDocs(name string, data []byte, files map[string][]byte) []string {
	// A translated page keeps the links of its English original, which
	// the website resolves from the original's place; tools/site checks
	// that it does.
	if !strings.HasSuffix(name, ".md") || docTranslation.MatchString(name) {
		return nil
	}
	var problems []string
	inCode := false
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCode = !inCode
			continue
		}
		if inCode {
			continue
		}
		for _, m := range mdLink.FindAllStringSubmatch(line, -1) {
			if p := checkLink(name, m[1], files); p != "" {
				problems = append(problems, fmt.Sprintf("%s:%d: %s", name, i+1, p))
			}
		}
	}
	return problems
}

// checkLink returns what is wrong with one link target in the file name, or
// "" when it is fine or not a relative link.
func checkLink(name, target string, files map[string][]byte) string {
	if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
		return ""
	}
	file, anchor, _ := strings.Cut(target, "#")
	if file == "" {
		file = name
	} else {
		file = path.Clean(path.Join(path.Dir(name), file))
	}
	data, ok := files[file]
	if !ok {
		if !isDir(file, files) {
			return fmt.Sprintf("link to %s, which is not in the repository", target)
		}
		return ""
	}
	if anchor == "" || !strings.HasSuffix(file, ".md") {
		return ""
	}
	if !anchors(data)[anchor] {
		return fmt.Sprintf("link to %s: %s has no heading for #%s", target, file, anchor)
	}
	return ""
}

// isDir reports whether some checked file lies below dir.
func isDir(dir string, files map[string][]byte) bool {
	for f := range files {
		if strings.HasPrefix(f, dir+"/") {
			return true
		}
	}
	return false
}

// anchors returns the anchors GitHub makes for the headings of a Markdown
// file: lower case, spaces as hyphens, punctuation dropped, and -1, -2 for
// repeated headings.
func anchors(data []byte) map[string]bool {
	seen := make(map[string]int)
	out := make(map[string]bool)
	inCode := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCode = !inCode
			continue
		}
		m := mdHeading.FindStringSubmatch(line)
		if inCode || m == nil {
			continue
		}
		a := slug(m[1])
		if n := seen[a]; n > 0 {
			out[fmt.Sprintf("%s-%d", a, n)] = true
		} else {
			out[a] = true
		}
		seen[a]++
	}
	return out
}

// slug turns a heading into its GitHub anchor.
func slug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// liteSection is the heading of the lite member's commands in docs/reference/cli.md.
const liteSection = "## The lite member"

// checkCommands reports the commands of cbb that docs/reference/cli.md does not name:
// the full member's anywhere, the lite member's in its section.
func checkCommands(files map[string][]byte) []string {
	ref, ok := files["docs/reference/cli.md"]
	if !ok {
		return nil
	}
	var problems []string
	lite := ""
	if _, after, ok := strings.Cut(string(ref), "\n"+liteSection+"\n"); ok {
		lite, _, _ = strings.Cut(after, "\n## ")
	}
	for _, c := range []struct {
		source, doc string
		re          *regexp.Regexp
	}{
		{"cmd/cbb/main.go", string(ref), goCommand},
		{"member/src/lib.rs", lite, rsCommand},
	} {
		src, ok := files[c.source]
		if !ok {
			continue
		}
		for _, m := range c.re.FindAllStringSubmatch(string(src), -1) {
			if !strings.Contains(c.doc, "`cbb "+m[1]) {
				problems = append(problems, fmt.Sprintf("docs/reference/cli.md:1: the command cbb %s (%s) is not described", m[1], c.source))
			}
		}
	}
	return problems
}

// sortedKeys returns the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// envFile reports how a file names environment variables: as strings in
// code, or as a shell script, a systemd unit or PowerShell reads them; nil
// for other files.
func envFile(name string) *regexp.Regexp {
	switch path.Ext(name) {
	case ".go", ".rs", ".swift", ".kt":
		return envQuoted
	case ".sh", ".ps1", ".service":
		return envShell
	}
	return nil
}

// envVars returns the CBB_ environment variables that the files read, each
// with the first file that reads it.
func envVars(files map[string][]byte) map[string]string {
	vars := make(map[string]string)
	for _, name := range sortedKeys(files) {
		re := envFile(name)
		// repocheck's own tests name variables that do not exist.
		if re == nil || thirdPartyDir(name) != "" || strings.HasPrefix(name, "tools/repocheck/") {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(string(files[name]), -1) {
			if _, ok := vars[m[1]]; !ok && !notEnv[m[1]] {
				vars[m[1]] = name
			}
		}
	}
	return vars
}

// checkEnv reports the environment variables that docs/reference/config.md
// does not describe.
func checkEnv(files map[string][]byte) []string {
	ref, ok := files[configRef]
	if !ok {
		return nil
	}
	vars := envVars(files)
	var problems []string
	for _, v := range sortedKeys(vars) {
		if !strings.Contains(string(ref), "`"+v+"`") {
			problems = append(problems, fmt.Sprintf("%s:1: the environment variable %s (%s) is not described", configRef, v, vars[v]))
		}
	}
	return problems
}

// checkIndex reports the pages below docs/ that docs/README.md does not
// reach: by a link of its own, or by a link of the index page of a
// directory it links to, such as docs/decisions/README.md.
func checkIndex(files map[string][]byte) []string {
	if _, ok := files["docs/README.md"]; !ok {
		return nil
	}
	reached := map[string]bool{"docs/README.md": true}
	queue := []string{"docs/README.md"}
	for len(queue) > 0 {
		from := queue[0]
		queue = queue[1:]
		for _, m := range mdPageRef.FindAllStringSubmatch(string(files[from]), -1) {
			to := path.Clean(path.Join(path.Dir(from), m[1]))
			if reached[to] || !strings.HasPrefix(to, "docs/") {
				continue
			}
			reached[to] = true
			if path.Base(to) == "README.md" {
				queue = append(queue, to)
			}
		}
	}
	var problems []string
	for _, name := range sortedKeys(files) {
		if strings.HasPrefix(name, "docs/") && strings.HasSuffix(name, ".md") && !reached[name] {
			problems = append(problems, fmt.Sprintf("%s:1: not reached from docs/README.md, the index", name))
		}
	}
	return problems
}

// newestRelease returns the major and minor version of the newest release
// in CHANGELOG.md, or false when it names none.
func newestRelease(files map[string][]byte) (major, minor int, ok bool) {
	m := released.FindSubmatch(files["CHANGELOG.md"])
	if m == nil {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(string(m[1]))
	minor, _ = strconv.Atoi(string(m[2]))
	return major, minor, true
}

// checkPlanned reports the Markdown lines that call something planned for a
// version that is out already: it is built, moved to a later version, or
// dropped, and the line should say which.
func checkPlanned(files map[string][]byte) []string {
	major, minor, ok := newestRelease(files)
	if !ok {
		return nil
	}
	var problems []string
	for _, name := range sortedKeys(files) {
		if !strings.HasSuffix(name, ".md") || name == "CHANGELOG.md" {
			continue
		}
		for i, line := range strings.Split(string(files[name]), "\n") {
			for _, m := range plannedFor.FindAllStringSubmatch(line, -1) {
				ma, _ := strconv.Atoi(m[1])
				mi, _ := strconv.Atoi(m[2])
				if ma < major || ma == major && mi <= minor {
					problems = append(problems, fmt.Sprintf("%s:%d: %q, but %d.%d is released; say whether it is built, moved or dropped", name, i+1, m[0], ma, mi))
				}
			}
		}
	}
	return problems
}

// cliRef is the reference page of the commands.
const cliRef = "docs/reference/cli.md"

// checkFlags reports the subcommands of the full member with flags of their
// own that docs/reference/cli.md does not name, and the flags it does not
// name in a line about their command.
func checkFlags(files map[string][]byte) []string {
	ref, ok := files[cliRef]
	if !ok {
		return nil
	}
	lines := strings.Split(string(ref), "\n")
	var problems []string
	for _, name := range sortedKeys(files) {
		if !strings.HasPrefix(name, "cmd/cbb/") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src := string(files[name])
		sets := flagSet.FindAllStringSubmatchIndex(src, -1)
		for i, m := range sets {
			cmd := src[m[2]:m[3]]
			// A command's flags end at the next command's or at the next function.
			end := len(src)
			if i+1 < len(sets) {
				end = sets[i+1][0]
			}
			body := src[m[1]:end]
			if k := strings.Index(body, "\nfunc "); k >= 0 {
				body = body[:k]
			}
			if !strings.Contains(string(ref), "`cbb "+cmd) {
				problems = append(problems, fmt.Sprintf("%s:1: the command cbb %s (%s) is not described", cliRef, cmd, name))
				continue
			}
			first, _, _ := strings.Cut(cmd, " ")
			var about []string
			for _, l := range lines {
				if strings.Contains(l, "`cbb "+first) {
					about = append(about, l)
				}
			}
			for _, f := range goFlag.FindAllStringSubmatch(body, -1) {
				flag := f[1] + f[2]
				if !anyContains(about, "-"+flag) {
					problems = append(problems, fmt.Sprintf("%s:1: the flag -%s of cbb %s (%s) is not described", cliRef, flag, cmd, name))
				}
			}
		}
	}
	return problems
}

// anyContains reports whether any of lines contains s.
func anyContains(lines []string, s string) bool {
	for _, l := range lines {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// devicesRef is the reference page with the ports table.
const devicesRef = "docs/reference/devices.md"

// checkPorts reports the ports that the code listens on by default and the
// ports table of docs/reference/devices.md does not name.
func checkPorts(files map[string][]byte) []string {
	ref, ok := files[devicesRef]
	if !ok {
		return nil
	}
	_, table, _ := strings.Cut(string(ref), "\n## Ports\n")
	table, _, _ = strings.Cut(table, "\n## ")
	ports := make(map[string]string)
	for _, name := range sortedKeys(files) {
		var res []*regexp.Regexp
		switch {
		case thirdPartyDir(name) != "" || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "tools/"):
			continue
		case strings.HasSuffix(name, ".go"):
			res = []*regexp.Regexp{goPort, listenPort}
		case strings.HasSuffix(name, ".rs"):
			res = []*regexp.Regexp{rsPort}
		}
		for _, re := range res {
			for _, m := range re.FindAllStringSubmatch(string(files[name]), -1) {
				if _, ok := ports[m[1]]; !ok {
					ports[m[1]] = name
				}
			}
		}
	}
	var problems []string
	for _, p := range sortedKeys(ports) {
		if !regexp.MustCompile(`\b` + p + `\b`).MatchString(table) {
			problems = append(problems, fmt.Sprintf("%s:1: the port %s (%s) is not in the ports table", devicesRef, p, ports[p]))
		}
	}
	return problems
}

// controlOp is an operation of the control socket in internal/control.
var controlOp = regexp.MustCompile(`(?m)^\tOp\w+\s+= "([a-z-]+)"`)

// checkOps reports the operations of the control socket that section 8 of
// docs/protocol.md, "Local control socket", does not name and no table row
// of the protocol starts with.
func checkOps(files map[string][]byte) []string {
	const src, ref = "internal/control/control.go", "docs/protocol.md"
	code, ok1 := files[src]
	doc, ok2 := files[ref]
	if !ok1 || !ok2 {
		return nil
	}
	section := string(doc)
	start := strings.Index(section, "\n## 8. ")
	if start < 0 {
		return []string{ref + ":1: section 8, the control socket, is missing"}
	}
	section = section[start+1:]
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	var problems []string
	for _, f := range headerFields(string(code)) {
		if !strings.Contains(section, "`"+f+"`") {
			problems = append(problems, fmt.Sprintf("%s:1: the control header field %s (%s) is not described in section 8", ref, f, src))
		}
	}
	for _, m := range controlOp.FindAllSubmatch(code, -1) {
		op := string(m[1])
		if !strings.Contains(section, "`"+op+"`") && !strings.Contains(string(doc), "\n| `"+op+"` |") {
			problems = append(problems, fmt.Sprintf("%s:1: the control operation %s (%s) is not described in section 8", ref, op, src))
		}
	}
	return problems
}

// styled reports whether a Markdown file is a page for users or
// administrators, which the style rules cover.
func styled(name string) bool {
	return strings.HasPrefix(name, "docs/guide/") || strings.HasPrefix(name, "docs/admin/") ||
		name == "README.md" || name == "member/README.md" || name == "esp32/README.md" ||
		name == "packaging/docker/README.md"
}

// checkStyle reports the lines of the pages for users and administrators
// that tell the reader something is easy, or name the product in lowercase
// outside code, links and quotes.
func checkStyle(files map[string][]byte) []string {
	var problems []string
	for _, name := range sortedKeys(files) {
		if !styled(name) {
			continue
		}
		// code is inside a fenced block, span inside a code span that
		// goes on from an earlier line.
		code, span := false, false
		for i, line := range strings.Split(string(files[name]), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				code = !code
				continue
			}
			if code {
				continue
			}
			if span {
				line = "`" + line
			}
			if span = strings.Count(line, "`")%2 == 1; span {
				line += "`"
			}
			prose := notProse.ReplaceAllString(line, "")
			if m := easyWord.FindString(prose); m != "" {
				problems = append(problems, fmt.Sprintf("%s:%d: %q tells the reader it is easy; say what to do instead", name, i+1, m))
			}
		}
	}
	return problems
}

// jsonTag is a field's name in its JSON struct tag, headerStruct the start
// of internal/control's Header.
var (
	jsonTag      = regexp.MustCompile("`json:\"([a-z_]+)[,\"]")
	headerStruct = regexp.MustCompile(`(?m)^type Header struct \{`)
)

// headerFields returns the JSON names of the fields of internal/control's
// Header, the header of every message on the control socket.
func headerFields(code string) []string {
	loc := headerStruct.FindStringIndex(code)
	if loc == nil {
		return nil
	}
	body := code[loc[0]:]
	if end := strings.Index(body, "\n}"); end >= 0 {
		body = body[:end]
	}
	var fields []string
	for _, m := range jsonTag.FindAllStringSubmatch(body, -1) {
		fields = append(fields, m[1])
	}
	return fields
}
