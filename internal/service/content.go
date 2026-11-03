// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/clip"
)

// The content of images and files (design.md, "Images and files",
// "Storage"): the service keeps the parts it holds whole as files named by
// their SHA-256 in a cache in its state directory, readable only by itself,
// and serves them to its peers. The cache keeps the current copy, deletes
// the parts of older ones 10 minutes after they are replaced and
// everything on restart, within twice the device's limit.

const (
	contentDir = "content"
	limitsFile = "limits"
	// contentKeep is how long the parts of a replaced copy stay.
	contentKeep = 10 * time.Minute
	// The limits of a copy (design.md, "Size limit").
	defaultMaxCopy     = 100 << 20
	defaultMaxCopyAway = 25 << 20
	minMaxCopy         = 1 << 20
)

// contentStore is the cache of the parts this member holds whole. It
// implements node.Content.
type contentStore struct {
	dir string
	now func() time.Time

	mu      sync.Mutex
	whole   map[[sha256.Size]byte]int64     // the parts held whole, by hash: their sizes
	current map[[sha256.Size]byte]bool      // the parts of the current copy, kept
	old     map[[sha256.Size]byte]time.Time // the parts of replaced copies: when they were replaced
	copies  map[[sha256.Size]byte]int64     // the size of the last copy each part was in
	// partials are the ".part" files that fetches left for a later one to
	// continue, and fetching the fetches writing one now.
	partials map[[sha256.Size]byte]leftPart
	fetching map[[sha256.Size]byte]int
}

// A leftPart is a ".part" file no fetch writes: its size, and when the
// last fetch left it.
type leftPart struct {
	size int64
	at   time.Time
}

// openContent empties the cache in dir and returns it.
func openContent(dir string, now func() time.Time) (*contentStore, error) {
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &contentStore{dir: dir, now: now, whole: map[[sha256.Size]byte]int64{}, current: map[[sha256.Size]byte]bool{}, old: map[[sha256.Size]byte]time.Time{}, copies: map[[sha256.Size]byte]int64{},
		partials: map[[sha256.Size]byte]leftPart{}, fetching: map[[sha256.Size]byte]int{}}, nil
}

func (c *contentStore) path(sum [sha256.Size]byte) string {
	return filepath.Join(c.dir, hex.EncodeToString(sum[:]))
}

// Open returns a part held whole; the caller closes it.
func (c *contentStore) Open(sum [sha256.Size]byte) (io.ReaderAt, int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	size, ok := c.whole[sum]
	if !ok {
		return nil, 0, false
	}
	f, err := os.Open(c.path(sum))
	if err != nil {
		return nil, 0, false
	}
	return f, size, true
}

// has reports whether the cache holds the part whole.
func (c *contentStore) has(sum [sha256.Size]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.whole[sum]
	return ok
}

// complete reports whether the cache holds every part of m.
func (c *contentStore) complete(m *clip.Manifest) bool {
	for _, p := range m.Parts {
		if !p.Dir && !c.has([sha256.Size]byte(p.SHA256)) {
			return false
		}
	}
	return true
}

// setCurrent makes m's parts the ones kept, and the parts of the copy
// before them old; limit is the device's limit, which the cache stays
// within twice of. m is nil when the current copy is a text.
func (c *contentStore) setCurrent(m *clip.Manifest, limit int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	next := map[[sha256.Size]byte]bool{}
	if m != nil {
		for _, p := range m.Parts {
			if !p.Dir {
				next[[sha256.Size]byte(p.SHA256)] = true
				c.copies[[sha256.Size]byte(p.SHA256)] = m.Size
			}
		}
	}
	for sum := range c.current {
		if !next[sum] {
			c.old[sum] = now
		}
	}
	for sum := range next {
		delete(c.old, sum)
	}
	c.current = next
	c.sweepLocked(now, limit)
}

// copySize returns the size of the last copy the part sum was in, or
// false when it is in none the cache knows.
func (c *contentStore) copySize(sum [sha256.Size]byte) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	size, ok := c.copies[sum]
	return size, ok
}

// sweep deletes the parts replaced longer ago than contentKeep.
func (c *contentStore) sweep(limit int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(c.now(), limit)
}

func (c *contentStore) sweepLocked(now time.Time, limit int64) {
	var total int64
	// What fetches left goes contentKeep after no copy needs it, and
	// oldest first past twice the limit; what a fetch writes stays.
	for sum, p := range c.partials {
		if c.fetching[sum] > 0 {
			continue
		}
		if !c.current[sum] && now.Sub(p.at) >= contentKeep {
			c.removePartLocked(sum)
			continue
		}
		total += p.size
	}
	for total > 2*limit {
		var oldest [sha256.Size]byte
		var at time.Time
		for sum, p := range c.partials {
			if c.fetching[sum] == 0 && (at.IsZero() || p.at.Before(at)) {
				oldest, at = sum, p.at
			}
		}
		if at.IsZero() {
			break
		}
		total -= c.partials[oldest].size
		c.removePartLocked(oldest)
	}
	for sum, size := range c.whole {
		total += size
		if _, ok := c.old[sum]; !ok && !c.current[sum] {
			c.old[sum] = now // a part of no copy, as one a fetch left
		}
	}
	for total > 2*limit || len(c.old) > 0 {
		// The oldest replaced part goes first; past twice the limit,
		// before its time.
		var oldest [sha256.Size]byte
		var at time.Time
		for sum, t := range c.old {
			if at.IsZero() || t.Before(at) {
				oldest, at = sum, t
			}
		}
		if at.IsZero() || total <= 2*limit && now.Sub(at) < contentKeep {
			break
		}
		total -= c.whole[oldest]
		c.removeLocked(oldest)
	}
}

func (c *contentStore) removeLocked(sum [sha256.Size]byte) {
	delete(c.old, sum)
	delete(c.whole, sum)
	delete(c.copies, sum)
	delete(c.partials, sum)
	os.Remove(c.path(sum))
	os.Remove(c.path(sum) + ".part")
}

func (c *contentStore) removePartLocked(sum [sha256.Size]byte) {
	delete(c.partials, sum)
	os.Remove(c.path(sum) + ".part")
}

// partial opens the file a part is fetched into, keeping what an earlier
// fetch left, and returns how much that is, with its hash so far. The
// caller calls fetchEnded when the fetch ends, and leave first when it
// ends without the whole part.
func (c *contentStore) partial(sum [sha256.Size]byte) (*os.File, int64, hashWriter, error) {
	c.mu.Lock()
	c.fetching[sum]++
	delete(c.partials, sum)
	c.mu.Unlock()
	h := sha256.New()
	f, err := os.OpenFile(c.path(sum)+".part", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, 0, nil, err
	}
	have, err := io.Copy(h, f)
	if err != nil {
		f.Close()
		return nil, 0, nil, err
	}
	return f, have, h, nil
}

// leave closes the ".part" of a fetch that ended without the whole part,
// for a later fetch to continue; the sweep counts it and ages it out.
func (c *contentStore) leave(f *os.File, sum [sha256.Size]byte) {
	var size int64
	if fi, err := f.Stat(); err == nil {
		size = fi.Size()
	}
	f.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := os.Stat(c.path(sum) + ".part"); err == nil {
		c.partials[sum] = leftPart{size: size, at: c.now()}
	}
}

// fetchEnded ends a fetch that partial began.
func (c *contentStore) fetchEnded(sum [sha256.Size]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fetching[sum]--; c.fetching[sum] <= 0 {
		delete(c.fetching, sum)
	}
}

// hashWriter is a running SHA-256.
type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}

// commit makes the file f, written whole, the part sum: a fetched
// ".part", or a copy's temporary file.
func (c *contentStore) commit(f *os.File, sum [sha256.Size]byte, size int64) error {
	name := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(name)
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Rename(name, c.path(sum)); err != nil {
		os.Remove(name)
		return err
	}
	c.whole[sum] = size
	return nil
}

// discard removes a part that did not match its hash.
func (c *contentStore) discard(f *os.File) {
	f.Close()
	os.Remove(f.Name())
}

// temp makes a temporary file for a part whose hash is not known yet.
func (c *contentStore) temp() (*os.File, error) {
	return os.CreateTemp(c.dir, "copy-*.part")
}

// mediaLimits are the device's limits of a copy, in bytes.
type mediaLimits struct {
	Home int64 `json:"max_copy"`
	Away int64 `json:"max_copy_away"`
}

func loadLimits(dir string) (mediaLimits, error) {
	l := mediaLimits{Home: defaultMaxCopy, Away: defaultMaxCopyAway}
	b, err := os.ReadFile(filepath.Join(dir, limitsFile))
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	var got mediaLimits
	if err := json.Unmarshal(b, &got); err != nil {
		return l, fmt.Errorf("%s: %w", limitsFile, err)
	}
	if err := got.check(); err != nil {
		return l, fmt.Errorf("%s: %w", limitsFile, err)
	}
	return got, nil
}

func (l mediaLimits) check() error {
	switch {
	case l.Home < minMaxCopy || l.Home > clip.MaxMedia:
		return fmt.Errorf("max-copy must be from %s to %s", SizeText(minMaxCopy), SizeText(clip.MaxMedia))
	case l.Away < minMaxCopy || l.Away > l.Home:
		return fmt.Errorf("max-copy-away must be from %s to max-copy, %s", SizeText(minMaxCopy), SizeText(l.Home))
	}
	return nil
}

func saveLimits(dir string, l mediaLimits) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, limitsFile), append(b, '\n'), 0o600)
}

// parseSize reads a size such as 100MiB, 100MB, 1GiB or 52428800 (bytes).
// MB and GB mean MiB and GiB, as most people mean them.
func parseSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	mul := int64(1)
	for _, u := range []struct {
		suffix string
		mul    int64
	}{{"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1}} {
		if rest, ok := strings.CutSuffix(t, u.suffix); ok {
			t, mul = strings.TrimSpace(rest), u.mul
			break
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n <= 0 || n > clip.MaxMedia/mul+1 {
		return 0, fmt.Errorf("%q is not a size such as 100MiB", s)
	}
	return n * mul, nil
}

// SizeText writes a size for people: 100 MiB, 1 GiB, 512 KiB, 12 bytes.
func SizeText(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GiB", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}
