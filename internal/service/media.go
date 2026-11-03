// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// Fetching images and files (design.md, "Manifest and chunks"): once the
// engine writes a media event, the service fetches every part it lacks,
// from the origin if it can, else from any peer that serves content,
// checks each against its hash and keeps it in the cache. A newer write
// stops the fetch. The watchers whose clipboard takes images or files get
// such a copy once it has arrived; the others get the copy's plain-text
// alternative.

const (
	// fetchFor bounds a fetch; a copy that has not arrived by then is
	// given up.
	fetchFor = 30 * time.Minute
	// fetchRetry is the pause before a part is asked for again, after no
	// peer gave it.
	fetchRetry = 2 * time.Second
)

// fetchRun is the fetch of one copy.
type fetchRun struct {
	m       *clip.Manifest
	origin  group.DeviceID
	cancel  context.CancelFunc
	done    chan struct{} // closed when the fetch ended; err says how
	err     error
	fetched atomic.Int64
	from    atomic.Pointer[string] // the name of the peer it fetches from now
}

// errTooLarge is a copy over this device's limit.
type errTooLarge struct {
	size, limit int64
	from        string
	away        bool
}

func (e *errTooLarge) Error() string {
	where := ""
	if e.away {
		where = " away from home"
	}
	return fmt.Sprintf("a %s copy from %s is over this device's limit of %s%s", SizeText(e.size), e.from, SizeText(e.limit), where)
}

// mediaWritten handles a write the engine decided on: for a media event
// it starts fetching the parts the cache lacks, and for a text it stops a
// fetch and lets the last copy's parts expire. It returns what the
// watchers get. s.mu is held.
func (s *Service) mediaWritten(w node.Write) (node.Write, bool) {
	if w.Kind != clip.Media || w.Media == nil {
		s.setMedia(nil, "", nil)
		return w, true
	}
	s.setMedia(w.Media, w.Origin, s.groupCtx)
	if w.Text == "" {
		return node.Write{}, false
	}
	return node.Write{Text: w.Text, Kind: clip.Text, Via: w.Via, Seq: w.Seq}, true
}

// setMedia makes m the current copy of the cache, stopping the fetch of an
// earlier one, and, with ctx, fetches what it lacks from the peers.
func (s *Service) setMedia(m *clip.Manifest, origin group.DeviceID, ctx context.Context) {
	if s.content == nil {
		return
	}
	s.mediaMu.Lock()
	defer s.mediaMu.Unlock()
	prev := s.fetch
	if prev != nil {
		if m != nil && prev.m == m {
			return
		}
		prev.cancel()
		s.fetch = nil
	}
	s.content.setCurrent(m, s.limits.Home)
	if m == nil || ctx == nil || s.content.complete(m) {
		return
	}
	s.fetchFailed = ""
	if m.Size > s.limits.Home {
		err := &errTooLarge{size: m.Size, limit: s.limits.Home, from: string(origin)}
		go func() {
			// Its name needs locks that the caller may hold.
			if name := s.deviceName(origin); name != "" {
				err.from = name
			}
			s.mediaMu.Lock()
			if s.fetch == nil {
				s.fetchFailed = err.Error()
			}
			s.mediaMu.Unlock()
			s.logf("cbb: not fetching a copy: %v", err)
		}()
		return
	}
	fctx, cancel := context.WithTimeout(ctx, fetchFor)
	run := &fetchRun{m: m, origin: origin, cancel: cancel, done: make(chan struct{})}
	s.fetch = run
	go func() {
		defer cancel()
		if prev != nil {
			<-prev.done // it may still write a part this one wants
		}
		err := s.fetchAll(fctx, run)
		s.mediaMu.Lock()
		run.err = err
		if err != nil && !errors.Is(err, context.Canceled) {
			s.fetchFailed = err.Error()
			s.logf("cbb: fetching a copy of %s: %v", SizeText(m.Size), err)
		} else if err == nil {
			s.logf("cbb: fetched a copy of %s", SizeText(m.Size))
		}
		s.mediaMu.Unlock()
		close(run.done)
		if !errors.Is(err, context.Canceled) {
			s.mediaArrived(m, err == nil)
		}
	}()
}

// fetchAll fetches the parts of run's copy that the cache lacks.
func (s *Service) fetchAll(ctx context.Context, run *fetchRun) error {
	for _, p := range run.m.Parts {
		if p.Dir || s.content.has([sha256.Size]byte(p.SHA256)) {
			run.fetched.Add(p.Size)
			continue
		}
		for {
			err := s.fetchPart(ctx, run, p)
			if err == nil {
				break
			}
			var large *errTooLarge
			switch {
			case errors.Is(ctx.Err(), context.DeadlineExceeded):
				return fmt.Errorf("it did not arrive within %s: %w", fetchFor, err)
			case ctx.Err() != nil:
				return ctx.Err()
			case errors.As(err, &large):
				return err
			}
			s.logf("cbb: fetching a part of %s: %v; trying again", SizeText(p.Size), err)
			select {
			case <-time.After(fetchRetry):
			case <-ctx.Done():
			}
		}
	}
	return nil
}

// fetchPart fetches one part from the first peer that gives it, the
// origin first, and keeps it in the cache if it matches its hash.
func (s *Service) fetchPart(ctx context.Context, run *fetchRun, p clip.Part) error {
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil {
		return s.errNoGroup()
	}
	peers := slices.DeleteFunc(nd.Peers(), func(q node.Peer) bool { return !q.Media })
	slices.SortStableFunc(peers, func(a, b node.Peer) int {
		switch {
		case a.ID == run.origin:
			return -1
		case b.ID == run.origin:
			return 1
		}
		return 0
	})
	if len(peers) == 0 {
		return errors.New("no member that serves images and files is connected")
	}
	away := s.awayAddr()
	s.mediaMu.Lock()
	limit := s.limits.Away
	s.mediaMu.Unlock()
	var last error
	for _, q := range peers {
		if away.IsValid() && q.Local == away && run.m.Size > limit {
			last = &errTooLarge{size: run.m.Size, limit: limit, from: q.Name, away: true}
			continue
		}
		name := q.Name
		run.from.Store(&name)
		err := s.fetchFrom(ctx, nd, q.ID, run, p)
		if err == nil || ctx.Err() != nil {
			return err
		}
		last = fmt.Errorf("from %s: %w", q.Name, err)
	}
	return last
}

// fetchFrom fetches one part from peer, continuing what an earlier fetch
// left.
func (s *Service) fetchFrom(ctx context.Context, nd *node.Node, peer group.DeviceID, run *fetchRun, p clip.Part) error {
	sum := [sha256.Size]byte(p.SHA256)
	f, have, h, err := s.content.partial(sum)
	defer s.content.fetchEnded(sum)
	if err != nil {
		return err
	}
	if have > p.Size {
		s.content.discard(f)
		return errors.New("the cache held more of the part than it has")
	}
	run.fetched.Add(have)
	err = nd.Fetch(ctx, peer, sum, p.Size, have, func(off int64, data []byte) error {
		if _, err := f.WriteAt(data, off); err != nil {
			return err
		}
		h.Write(data)
		run.fetched.Add(int64(len(data)))
		return nil
	})
	if err != nil {
		s.content.leave(f, sum)
		run.fetched.Add(-have)
		return err
	}
	if !bytes.Equal(h.Sum(nil), p.SHA256) {
		s.content.discard(f)
		run.fetched.Add(-p.Size)
		return errors.New("the part does not match its hash")
	}
	return s.content.commit(f, sum, p.Size)
}

// relayed takes an event this member passes on without writing it
// (node.Config.OnRelay). A hub that serves fetches a media event within
// its limit away from home, so that the members that reach only it can
// fetch it from its cache; a text, or a copy over the limit, lets the
// last copy's parts expire.
func (s *Service) relayed(w node.Write) {
	if !s.servingHub() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Only the group's current copy: an older event is passed on too.
	if e := s.eng; e == nil {
		return
	} else if cur, ok := e.Current(); !ok || cur.ID != w.ID {
		return
	}
	if w.Kind != clip.Media || w.Media == nil {
		s.setMedia(nil, "", nil)
		return
	}
	s.mediaMu.Lock()
	limit := s.limits.Away
	s.mediaMu.Unlock()
	ctx := s.groupCtx
	if w.Media.Size > limit {
		s.logf("cbb: not passing a copy of %s on to the members away from home: it is over this hub's limit of %s away from home", SizeText(w.Media.Size), SizeText(limit))
		ctx = nil
	}
	s.setMedia(w.Media, w.Origin, ctx)
}

// serves reports whether the member serves the part sum on a connection
// whose own address is local (node.Config.Serves): through the group's
// tunnel only the parts of copies within its limit away from home, so a
// hub's limit caps its whole star.
func (s *Service) serves(local netip.Addr, sum [sha256.Size]byte) bool {
	// The archives of a signed release go to members away from home too.
	if _, ok := s.heldAsset(sum); ok {
		return true
	}
	away := s.awayAddr()
	if !away.IsValid() || local != away || s.content == nil {
		return true
	}
	s.mediaMu.Lock()
	limit := s.limits.Away
	s.mediaMu.Unlock()
	size, ok := s.content.copySize(sum)
	return ok && size <= limit
}

// servingHub reports whether this device serves now as the group's hub.
func (s *Service) servingHub() bool {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	return s.tunnel != nil && s.tunnel.IsHub && s.tunServing
}

// awayAddr is this device's address in the group's tunnel: a peer reached
// on it is away from home. Invalid while sync away from home is off.
func (s *Service) awayAddr() (a netip.Addr) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if s.tunnel == nil || s.tunSelf == "" {
		return a
	}
	a, _ = tunnel.Addr(s.tunSelf)
	return a
}

// mediaStatus is images and files in cbb status.
func (s *Service) mediaStatus() *control.Media {
	s.mediaMu.Lock()
	defer s.mediaMu.Unlock()
	st := &control.Media{MaxCopy: s.limits.Home, MaxCopyAway: s.limits.Away, Failed: s.fetchFailed}
	if run := s.fetch; run != nil && run.err == nil && !closed(run.done) {
		st.Fetching, st.Fetched = run.m.Size, run.fetched.Load()
		if from := run.from.Load(); from != nil {
			st.From = *from
		}
	}
	return st
}

func closed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// setConfig sets one of the device's settings: max-copy or max-copy-away.
func (s *Service) setConfig(name, value string) error {
	n, err := parseSize(value)
	if err != nil {
		return err
	}
	s.mediaMu.Lock()
	defer s.mediaMu.Unlock()
	l := s.limits
	switch name {
	case "max-copy":
		l.Home = n
		if l.Away > n {
			l.Away = n
		}
	case "max-copy-away":
		l.Away = n
	default:
		return fmt.Errorf("there is no setting %q; the settings are max-copy and max-copy-away", name)
	}
	if err := l.check(); err != nil {
		return err
	}
	if err := saveLimits(s.cfg.StateDir, l); err != nil {
		return fmt.Errorf("saving the setting: %w", err)
	}
	s.limits = l
	s.logf("cbb: the largest copy is %s at home and %s away from home now", SizeText(l.Home), SizeText(l.Away))
	return nil
}

// copyMedia takes cbb copy FILE, or a watcher's copied image: the parts and
// their bytes come in part and data messages after the request, which
// carries the plain-text alternative. The parts go into the cache and the
// copy to the group.
func (s *Service) copyMedia(c net.Conn, r *control.Reader, m *control.Message) error {
	copied := m.Op == control.OpCopiedMedia
	if s.content == nil || s.engine() == nil {
		return s.errNoGroup()
	}
	if len(m.Payload) > clip.MaxAltText {
		return errors.New("the text that goes with the copy is larger than 256 KiB")
	}
	s.mediaMu.Lock()
	limit := s.limits.Home
	s.mediaMu.Unlock()
	man := &clip.Manifest{}
	for {
		pm, err := r.Read()
		if err != nil {
			return fmt.Errorf("reading the copy: %w", err)
		}
		if pm.Op != control.OpPart {
			return fmt.Errorf("expected a part, got %q", pm.Op)
		}
		if pm.Done {
			break
		}
		if pm.Part == nil || pm.Part.Size < 0 {
			return errors.New("a part without its description")
		}
		if len(man.Parts) == clip.MaxParts {
			return fmt.Errorf("a copy has at most %d files and folders", clip.MaxParts)
		}
		man.Size += pm.Part.Size
		if man.Size > limit {
			return fmt.Errorf("the copy is larger than this device's limit of %s; cbb config max-copy SIZE raises it, up to 1 GiB", SizeText(limit))
		}
		p := clip.Part{Type: pm.Part.Type, Path: pm.Part.Path, Dir: pm.Part.Dir, Size: pm.Part.Size}
		if !p.Dir {
			sum, err := s.receivePart(r, p.Size)
			if err != nil {
				return err
			}
			p.SHA256 = sum[:]
		}
		man.Parts = append(man.Parts, p)
	}
	if err := man.Validate(); err != nil {
		return err
	}
	s.setMedia(man, "", nil)
	if copied {
		return s.withNode(func(nd *node.Node) error {
			_, err := nd.CopiedMedia(man, string(m.Payload), clip.Copy)
			return err
		})
	}
	return s.withNode(func(nd *node.Node) error { return nd.SendMedia(man, string(m.Payload), clip.Copy) })
}

// receivePart reads size bytes of data messages into the cache.
func (s *Service) receivePart(r *control.Reader, size int64) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	f, err := s.content.temp()
	if err != nil {
		return sum, err
	}
	h := sha256.New()
	w := io.MultiWriter(f, h)
	for got := int64(0); got < size; {
		dm, err := r.Read()
		if err != nil || dm.Op != control.OpData || int64(len(dm.Payload)) > size-got || len(dm.Payload) == 0 {
			s.content.discard(f)
			return sum, errors.New("the bytes of a part did not come as said")
		}
		if _, err := w.Write(dm.Payload); err != nil {
			s.content.discard(f)
			return sum, err
		}
		got += int64(len(dm.Payload))
	}
	copy(sum[:], h.Sum(nil))
	return sum, s.content.commit(f, sum, size)
}

// pasteMedia answers cbb paste -o: the images or files of the member's own
// clipboard, or of the group's copy in a mode that keeps its clipboard to
// itself, once they have arrived; the plain-text alternative, then each
// part and its bytes.
func (s *Service) pasteMedia(ctx context.Context, c net.Conn) error {
	e := s.engine()
	if e == nil || s.content == nil {
		return s.errNoGroup()
	}
	var man *clip.Manifest
	var text string
	if e.Mode().Receives() {
		var ok bool
		if man, text, _, ok = e.LocalMedia(); !ok {
			return errors.New("the clipboard holds no images or files")
		}
	} else {
		ev, ok := e.Current()
		if !ok || ev.Media == nil {
			return errors.New("the group's copy is no images or files")
		}
		man, text = ev.Media, ev.Text
		s.setMedia(man, group.DeviceID(ev.Origin), s.groupContext())
	}
	if err := s.waitMedia(ctx, c, man); err != nil {
		return err
	}
	if err := reply(c, control.Header{Kind: control.KindMedia}, []byte(text)); err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for _, p := range man.Parts {
		if err := reply(c, control.Header{Part: &control.Part{Type: p.Type, Path: p.Path, Dir: p.Dir, Size: p.Size}}, nil); err != nil {
			return err
		}
		if p.Dir {
			continue
		}
		ra, size, ok := s.content.Open([sha256.Size]byte(p.SHA256))
		if !ok || size != p.Size {
			return errors.New("a part of the copy left the cache; copy it again")
		}
		err := sendPart(c, io.NewSectionReader(ra, 0, size), buf)
		ra.(io.Closer).Close()
		if err != nil {
			return err
		}
	}
	return reply(c, control.Header{Done: true}, nil)
}

func sendPart(c net.Conn, r io.Reader, buf []byte) error {
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			if werr := reply(c, control.Header{}, buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// waitMedia waits until the cache holds every part of man, while it is
// being fetched and the client waits.
func (s *Service) waitMedia(ctx context.Context, c net.Conn, man *clip.Manifest) error {
	left := gone(c)
	for !s.content.complete(man) {
		s.mediaMu.Lock()
		run, failed := s.fetch, s.fetchFailed
		s.mediaMu.Unlock()
		if run == nil || run.m != man {
			if failed != "" {
				return fmt.Errorf("the copy's images or files did not arrive: %s", failed)
			}
			return errors.New("the copy's images or files did not arrive")
		}
		select {
		case <-run.done:
			if run.err != nil {
				return fmt.Errorf("the copy's images or files did not arrive: %w", run.err)
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-left:
			return errors.New("the command stopped waiting")
		}
	}
	return nil
}

// gone returns a channel closed when the client closes its end of c.
func gone(c net.Conn) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		var b [1]byte
		c.Read(b[:])
		close(ch)
	}()
	return ch
}

// groupContext is the group's context, nil while in no group.
func (s *Service) groupContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.groupCtx
}

// nodeContent is what the node serves: the cache, unless it could not be
// made, and the archives of the held release.
func (s *Service) nodeContent() node.Content {
	if s.content == nil {
		return releaseContent{s}
	}
	return contents{s.content, releaseContent{s}}
}

// contentSweepEvery is how often the service deletes the parts of replaced
// copies once contentKeep has passed, so they go on time when no further
// copy comes to replace them (design.md, "Images and files", "Storage").
const contentSweepEvery = time.Minute

// sweepContent deletes the cache's old parts every contentSweepEvery until
// ctx ends.
func (s *Service) sweepContent(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mediaMu.Lock()
		limit := s.limits.Home
		s.mediaMu.Unlock()
		s.content.sweep(limit)
	}
}
