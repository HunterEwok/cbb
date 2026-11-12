// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package refused is the list of groups that the operator of a public server
// refuses after an abuse report (docs/relay-budget.md, "Abuse reports"): the
// forwarder and the open relay read it, refuse a new registration of a
// group on it and drop the ones already registered. Every other group goes
// on as before; the list never limits who may use the server.
//
// The file has one group tag a line, 16 hex characters as cbb status shows
// them; a line may also name a period's tag as "period <tag>", for a group
// that registers with credentials. Blank lines and lines that begin with #
// are skipped, and so is anything after a tag on its line, such as the date
// of the report.
package refused

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxFile caps the file: a list of reports, never of everyone.
const maxFile = 1 << 20

// Message is what a refused device is told.
const Message = "this server's operator refuses this group under the server's terms; use another server or run your own"

// List is the list of refused groups, read from its file. A nil List
// refuses nothing.
type List struct {
	path string

	mu   sync.Mutex
	tags map[string]bool
	mod  time.Time
	size int64
}

// Load reads the list at path. A file that does not exist yet is an empty
// list, which Reload reads once it appears.
func Load(path string) (*List, error) {
	if path == "" {
		return nil, errors.New("refused: no file")
	}
	l := &List{path: path, tags: map[string]bool{}}
	if _, err := l.Reload(); err != nil {
		return nil, err
	}
	return l, nil
}

// Open reads the list a server's flag names: file, or refused-groups in
// the directory of the server's key file when file is "", or none, a nil
// List, when file is "none".
func Open(file, keyFile string) (*List, error) {
	switch file {
	case "none":
		return nil, nil
	case "":
		file = filepath.Join(filepath.Dir(keyFile), "refused-groups")
	}
	return Load(file)
}

// Refused tells whether the group or period tag is on the list.
func (l *List) Refused(tag string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tags[tag]
}

// Len is the number of tags on the list.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tags)
}

// Reload reads the file again when it changed, and tells whether the list
// did. A file that cannot be read or parsed keeps the list as it was: a
// typo in the file never lets a refused group back in.
func (l *List) Reload() (bool, error) {
	if l == nil {
		return false, nil
	}
	fi, err := os.Stat(l.path)
	if errors.Is(err, os.ErrNotExist) {
		l.mu.Lock()
		defer l.mu.Unlock()
		changed := len(l.tags) > 0
		l.tags, l.mod, l.size = map[string]bool{}, time.Time{}, 0
		return changed, nil
	}
	if err != nil {
		return false, fmt.Errorf("refused: %w", err)
	}
	l.mu.Lock()
	same := fi.ModTime().Equal(l.mod) && fi.Size() == l.size
	l.mu.Unlock()
	if same {
		return false, nil
	}
	if fi.Size() > maxFile {
		return false, fmt.Errorf("refused: %s is larger than %d bytes", l.path, maxFile)
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		return false, fmt.Errorf("refused: %w", err)
	}
	tags, err := Parse(b)
	if err != nil {
		return false, fmt.Errorf("refused: %s: %w", l.path, err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	changed := len(tags) != len(l.tags)
	for t := range tags {
		if !l.tags[t] {
			changed = true
		}
	}
	l.tags, l.mod, l.size = tags, fi.ModTime(), fi.Size()
	return changed, nil
}

// Parse reads the lines of a list.
func Parse(b []byte) (map[string]bool, error) {
	tags := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		tag := f[0]
		if tag == "period" {
			if len(f) < 2 || !isTag(f[1]) {
				return nil, fmt.Errorf("line %d: \"period\" without a tag of 16 hex characters", n)
			}
			tag = "period " + f[1]
		} else if !isTag(tag) {
			return nil, fmt.Errorf("line %d: %q is not a group tag of 16 hex characters", n, tag)
		}
		tags[tag] = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return tags, nil
}

func isTag(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}
