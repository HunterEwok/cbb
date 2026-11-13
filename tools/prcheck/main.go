// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command prcheck checks what a pull request would put on main besides its
// tree: the people GitHub names as its authors, and the text of its squash
// commit.
//
// main takes a pull request squashed, with the pull request's title and
// description as the commit message, and GitHub adds a Co-authored-by line
// for every author and committer of the branch's commits and for every
// Co-authored-by line in them. An author with an unknown address shows on
// the repository's page as a contributor of its own and cannot be taken off
// without rewriting main, so every address must be one of allowedEmails.
// The title and description must not link to a conversation with an
// assistant or name a model; the description is what lands on main.
//
//	prcheck -base <sha> -head <sha>
//
// reads the title and description from PR_TITLE and PR_BODY, and the
// repository's squash setting from SQUASH_MESSAGE when it is set.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// allowedEmails are the addresses a commit of a pull request may carry as
// its author, committer or co-author: the owner's GitHub address, the
// assistant's, GitHub's own (merges made on the web) and Dependabot's.
var allowedEmails = map[string]bool{
	"88090358+HunterEwok@users.noreply.github.com":      true,
	"noreply@anthropic.com":                             true,
	"noreply@github.com":                                true,
	"49699333+dependabot[bot]@users.noreply.github.com": true,
}

// replaced are commits that were on main and were replaced there by a copy
// with a corrected message; branches that merged them before still hold
// them. Their authors are fine, only their messages carried what main must
// not, and the squash takes its message from the pull request.
var replaced = map[string]bool{
	"aebe559c06164af5eac5d304b2962013c8ab829b": true, // replaced by fefe810a52261be2a6392dc4ae17279f8dc1bd91
}

// assistantEmail is the assistant's address; its name must be plain "Claude".
const assistantEmail = "noreply@anthropic.com"

var (
	coAuthor = regexp.MustCompile(`(?im)^co-authored-by:\s*(.*?)\s*<([^>]*)>\s*$`)
	// A link to claude.ai other than its bare front page of Claude Code: a
	// conversation, a session, a project or its thread.
	conversationLink = regexp.MustCompile(`(?i)claude\.ai/(?:[^\s)\]>"'` + "`" + `]+)`)
	bareCodeLink     = regexp.MustCompile(`(?i)^code/?$`)
	sessionTrailer   = regexp.MustCompile(`(?im)^\s*claude-session:`)
	modelName        = regexp.MustCompile(`(?i)\b(?:claude[ -])?(?:opus|sonnet|haiku|fable)[ -]?\d`)
)

// commit is one commit of the pull request.
type commit struct {
	hash, authorName, authorEmail, committerName, committerEmail, message string
}

// checkCommit returns what is wrong with one commit's people.
func checkCommit(c commit) []string {
	var bad []string
	short := c.hash
	if len(short) > 9 {
		short = short[:9]
	}
	person := func(role, name, email string) {
		switch {
		case !allowedEmails[strings.ToLower(email)] && !allowedEmails[email]:
			bad = append(bad, fmt.Sprintf("%s: %s %q <%s> is not one of the allowed addresses; GitHub would list it as a contributor of its own", short, role, name, email))
		case email == assistantEmail && name != "Claude":
			bad = append(bad, fmt.Sprintf("%s: %s %q <%s>: the assistant's name is plain \"Claude\", without a model", short, role, name, email))
		}
	}
	person("author", c.authorName, c.authorEmail)
	person("committer", c.committerName, c.committerEmail)
	for _, m := range coAuthor.FindAllStringSubmatch(c.message, -1) {
		if !allowedEmails[m[2]] {
			bad = append(bad, fmt.Sprintf("%s: Co-authored-by %q <%s> is not one of the allowed addresses", short, m[1], m[2]))
		}
	}
	return bad
}

// checkText returns what is wrong with the title or description.
func checkText(what, text string) []string {
	var bad []string
	for _, m := range conversationLink.FindAllStringSubmatchIndex(text, -1) {
		path := strings.TrimRight(text[m[0]+len("claude.ai/"):m[1]], ".,;:")
		if bareCodeLink.MatchString(path) {
			continue
		}
		bad = append(bad, fmt.Sprintf("%s links to a conversation: claude.ai/%s", what, path))
	}
	if sessionTrailer.MatchString(text) {
		bad = append(bad, what+" has a Claude-Session line")
	}
	if m := modelName.FindString(text); m != "" {
		bad = append(bad, fmt.Sprintf("%s names a model: %q", what, m))
	}
	return bad
}

// checkSquash returns what is wrong with the repository's squash setting:
// anything but the pull request's title and description would put the
// branch's commit messages on main.
func checkSquash(setting string) []string {
	if setting == "" || setting == "PR_BODY" {
		return nil
	}
	return []string{fmt.Sprintf("the repository squashes with %s as the message; set Settings, General, Pull Requests, \"Allow squash merging\" to \"Pull request title and description\"", setting)}
}

// commits lists the commits of base..head, merges included.
func commits(base, head string) ([]commit, error) {
	out, err := exec.Command("git", "log", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x1e", base+".."+head).Output()
	if err != nil {
		return nil, fmt.Errorf("git log %s..%s: %w", base, head, err)
	}
	var list []commit
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, 0x1e); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for sc.Scan() {
		rec := strings.TrimLeft(sc.Text(), "\n")
		if rec == "" {
			continue
		}
		f := strings.SplitN(rec, "\x00", 6)
		if len(f) != 6 {
			return nil, fmt.Errorf("git log: unexpected record %q", rec)
		}
		list = append(list, commit{f[0], f[1], f[2], f[3], f[4], f[5]})
	}
	return list, sc.Err()
}

func main() {
	base := flag.String("base", "", "the pull request's base commit")
	head := flag.String("head", "HEAD", "the pull request's head commit")
	flag.Parse()
	if *base == "" {
		fmt.Fprintln(os.Stderr, "prcheck: -base is required")
		os.Exit(2)
	}
	list, err := commits(*base, *head)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prcheck:", err)
		os.Exit(2)
	}
	var bad []string
	for _, c := range list {
		if !replaced[c.hash] {
			bad = append(bad, checkCommit(c)...)
		}
	}
	bad = append(bad, checkText("the title", os.Getenv("PR_TITLE"))...)
	bad = append(bad, checkText("the description", os.Getenv("PR_BODY"))...)
	bad = append(bad, checkSquash(os.Getenv("SQUASH_MESSAGE"))...)
	for _, b := range bad {
		fmt.Println(b)
	}
	if len(bad) > 0 {
		os.Exit(1)
	}
	fmt.Printf("prcheck: %d commits, title and description are fine\n", len(list))
}
