// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

// The content of images and files (docs/protocol.md, section 4, "Content"):
// a member that wants a part of a media event sends get, with the part's
// SHA-256 and a range, to a peer whose hello says it serves content, and
// the peer answers with binary chunk frames, or missing when it does not
// hold the part. Chunks go out only while no other message waits, and do
// not count against the queue limit, so events keep flowing during a
// large transfer.

const (
	// ChunkSize is the most bytes of a part one chunk carries.
	ChunkSize = 256 << 10
	// getWindow is the most bytes one get asks for; a fetch keeps at most
	// fetchAhead of them outstanding, asking for more as chunks arrive.
	getWindow  = 1 << 20
	fetchAhead = 4 << 20
	// chunkPad pads a chunk's frame to a multiple of it, so the network
	// learns less of the sizes of the parts.
	chunkPad = 16 << 10
	// chunkHead is the start of a chunk's frame: the part's SHA-256, the
	// offset and the length of the data.
	chunkHead = sha256.Size + 8 + 4
	// binaryFrame marks the length of a binary frame.
	binaryFrame = 1 << 31
	// maxChunkFrame bounds a chunk's frame, padding included.
	maxChunkFrame = (chunkHead + ChunkSize + chunkPad - 1) / chunkPad * chunkPad
	// chunkQueue is how many chunks a connection holds ready to write.
	chunkQueue = 8
	// maxGets bounds the gets a peer may have waiting on one connection.
	maxGets = 64
)

// fetchStall is how long a fetch waits for the next piece before it gives
// up, so that the caller asks again rather than waiting on gets the peer
// dropped. It is a variable for the tests.
var fetchStall = 15 * time.Second

// Content is the store of the images and files a member holds whole,
// which it serves to its peers.
type Content interface {
	// Open returns the part whose SHA-256 is sum and its size, or false
	// when this member does not hold all of it. The node closes the
	// reader when it is an io.Closer.
	Open(sum [sha256.Size]byte) (io.ReaderAt, int64, bool)
}

// release closes a reader that Content.Open returned.
func release(r io.ReaderAt) {
	if c, ok := r.(io.Closer); ok {
		c.Close()
	}
}

// Get asks for a range of a part, by its SHA-256; Length 0 cancels the
// sender's gets for that part.
type Get struct {
	SHA256 []byte `json:"sha256"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}

// chunk is a piece of a part, as a binary frame carries it.
type chunk struct {
	sum    [sha256.Size]byte
	offset int64
	data   []byte
}

// encodeChunk makes the frame of a chunk: the binary length, the part's
// SHA-256, the offset and the data's length, the data, and zeros up to a
// multiple of chunkPad.
func encodeChunk(ch chunk) []byte {
	body := chunkHead + len(ch.data)
	padded := (body + chunkPad - 1) / chunkPad * chunkPad
	f := make([]byte, 4+padded)
	binary.BigEndian.PutUint32(f, uint32(padded)|binaryFrame)
	copy(f[4:], ch.sum[:])
	binary.BigEndian.PutUint64(f[4+sha256.Size:], uint64(ch.offset))
	binary.BigEndian.PutUint32(f[4+sha256.Size+8:], uint32(len(ch.data)))
	copy(f[4+chunkHead:], ch.data)
	return f
}

// decodeChunk reads a chunk's frame body.
func decodeChunk(b []byte) (chunk, error) {
	if len(b) < chunkHead {
		return chunk{}, errors.New("node: a chunk is too short")
	}
	var ch chunk
	copy(ch.sum[:], b)
	ch.offset = int64(binary.BigEndian.Uint64(b[sha256.Size:]))
	// The length is compared as it was read: converted to int first, it goes
	// negative on a 32-bit build and slips past both checks.
	n := binary.BigEndian.Uint32(b[sha256.Size+8:])
	if ch.offset < 0 || n > ChunkSize || int64(n) > int64(len(b)-chunkHead) {
		return chunk{}, errors.New("node: a chunk's length is not valid")
	}
	ch.data = b[chunkHead : chunkHead+int(n)]
	return ch, nil
}

// ErrMissing is what Fetch returns when the peer does not hold the part.
var ErrMissing = errors.New("node: the peer does not have this content")

// serving is the gets a peer sent on one connection, which one goroutine
// answers in order.
type serving struct {
	mu      sync.Mutex
	gets    []served
	running bool
	// cancels counts the peer's cancels of each part queued or served, so
	// that a range queued before a cancel ends with its next chunk, while
	// one asked for after it goes on; current is the part being served.
	// A cancel of any other part changes nothing, so it is not counted.
	cancels map[[sha256.Size]byte]int
	current [sha256.Size]byte
}

// served is a get waiting to be served, with the part's cancels when it
// came.
type served struct {
	Get
	cancels int
}

// fetching is a fetch in progress on a connection: the chunks of its part
// go to ch, a missing closes missing, and done is closed once the fetch
// returned, so that a chunk still on its way never blocks the reader.
type fetching struct {
	ch      chan chunk
	missing chan struct{}
	done    chan struct{}
	once    sync.Once
}

// get serves a peer's get: it queues the range for the connection's server,
// or cancels the queued ranges of the part.
func (c *conn) get(g Get) {
	content := c.n.cfg.Content
	var sum [sha256.Size]byte
	if len(g.SHA256) != sha256.Size || g.Offset < 0 || g.Length < 0 || g.Length > getWindow {
		c.n.cfg.Logf("node: dropped a bad get from %s", c.id)
		return
	}
	copy(sum[:], g.SHA256)
	// Asked before the lock: it takes the service's.
	serves := g.Length == 0 || content != nil && c.serves(sum)
	s := &c.serving
	s.mu.Lock()
	defer s.mu.Unlock()
	if g.Length == 0 {
		kept := s.gets[:0]
		for _, q := range s.gets {
			if [sha256.Size]byte(q.SHA256) != sum {
				kept = append(kept, q)
			}
		}
		queued := len(kept) < len(s.gets)
		s.gets = kept
		if s.running && (queued || s.current == sum) {
			if s.cancels == nil {
				s.cancels = make(map[[sha256.Size]byte]int)
			}
			s.cancels[sum]++
		}
		return
	}
	if content == nil || !serves {
		c.enqueue(outgoing{missing: &g})
		return
	}
	r, size, ok := content.Open(sum)
	if ok {
		release(r)
	}
	if !ok || g.Offset >= size {
		c.enqueue(outgoing{missing: &g})
		return
	}
	if len(s.gets) >= maxGets {
		c.n.cfg.Logf("node: %s asks for too much at once; closing the connection", c.id)
		go c.close(false)
		return
	}
	s.gets = append(s.gets, served{Get: g, cancels: s.cancels[sum]})
	if !s.running {
		s.running = true
		go c.serve()
	}
}

// serves reports whether this member serves the part sum on this
// connection (Config.Serves).
func (c *conn) serves(sum [sha256.Size]byte) bool {
	if c.n.cfg.Serves == nil {
		return true
	}
	local, _ := netip.ParseAddrPort(c.tc.LocalAddr().String())
	return c.n.cfg.Serves(local.Addr().Unmap(), sum)
}

// serve reads the ranges the peer asked for, in order, and hands their
// chunks to the writer, until none is left or the connection ends.
func (c *conn) serve() {
	s := &c.serving
	for {
		s.mu.Lock()
		if len(s.gets) == 0 {
			s.running, s.cancels = false, nil
			s.mu.Unlock()
			return
		}
		g := s.gets[0]
		s.gets = s.gets[1:]
		s.current = [sha256.Size]byte(g.SHA256)
		s.mu.Unlock()
		sum := [sha256.Size]byte(g.SHA256)
		r, size, ok := c.n.cfg.Content.Open(sum)
		if !ok {
			c.enqueue(outgoing{missing: &g.Get})
			continue
		}
		more := c.serveRange(g, r, size)
		release(r)
		if !more {
			return
		}
	}
}

// serveRange hands the chunks of one get to the writer; it returns false
// when the connection ended.
func (c *conn) serveRange(g served, r io.ReaderAt, size int64) bool {
	sum := [sha256.Size]byte(g.SHA256)
	end := min(size, g.Offset+g.Length)
	for off := g.Offset; off < end && !c.cancelled(g); {
		n := min(ChunkSize, end-off)
		buf := make([]byte, n)
		if _, err := r.ReadAt(buf, off); err != nil && !(err == io.EOF && off+n == size) {
			c.n.cfg.Logf("node: reading content for %s: %v", c.id, err)
			c.enqueue(outgoing{missing: &g.Get})
			return true
		}
		select {
		case c.chunks <- chunk{sum: sum, offset: off, data: buf}:
		case <-c.done:
			return false
		}
		off += n
	}
	return true
}

// cancelled reports whether the peer cancelled its gets of the part since
// it asked for g.
func (c *conn) cancelled(g served) bool {
	c.serving.mu.Lock()
	defer c.serving.mu.Unlock()
	return c.serving.cancels[[sha256.Size]byte(g.SHA256)] != g.cancels
}

// Fetch fetches the part whose SHA-256 is sum and whose size is size from
// the connected peer, from offset on, and passes each piece to sink in
// order; it returns once the part is complete, the peer does not hold it
// (ErrMissing), the connection ends or ctx is done. It checks nothing of
// the content: the caller hashes what sink got. One fetch of a part runs
// on a connection at a time.
func (n *Node) Fetch(ctx context.Context, peer group.DeviceID, sum [sha256.Size]byte, size, offset int64, sink func(offset int64, data []byte) error) error {
	n.mu.Lock()
	c := n.conns[peer]
	n.mu.Unlock()
	if c == nil {
		return fmt.Errorf("node: %s is not connected", peer)
	}
	c.mu.Lock()
	media := c.peerMedia
	c.mu.Unlock()
	if !media {
		return fmt.Errorf("node: %s serves no content", peer)
	}
	f := &fetching{ch: make(chan chunk, chunkQueue), missing: make(chan struct{}), done: make(chan struct{})}
	c.fetchMu.Lock()
	if c.fetches[sum] != nil {
		c.fetchMu.Unlock()
		return errors.New("node: this part is already being fetched from that peer")
	}
	c.fetches[sum] = f
	c.fetchMu.Unlock()
	defer func() {
		c.fetchMu.Lock()
		delete(c.fetches, sum)
		c.fetchMu.Unlock()
		close(f.done)
	}()
	asked := offset // the end of the ranges asked for
	ask := func() {
		for asked < size && asked-offset < fetchAhead {
			l := min(getWindow, size-asked)
			c.enqueue(outgoing{get: &Get{SHA256: sum[:], Offset: asked, Length: l}})
			asked += l
		}
	}
	if size == 0 {
		return nil
	}
	ask()
	stall := time.NewTimer(fetchStall)
	defer stall.Stop()
	for offset < size {
		select {
		case ch := <-f.ch:
			if len(ch.data) == 0 || ch.offset+int64(len(ch.data)) > size {
				c.enqueue(outgoing{get: &Get{SHA256: sum[:]}})
				return fmt.Errorf("node: %s sent a chunk that is not valid", peer)
			}
			if ch.offset != offset {
				// Left from a fetch of the part cancelled before: the peer
				// serves gets in order, so the piece wanted comes later.
				// It is still a piece of the part, so the peer is not
				// stalled: on a slow link the leftovers alone can take
				// longer than fetchStall.
				stall.Reset(fetchStall)
				continue
			}
			if err := sink(offset, ch.data); err != nil {
				c.enqueue(outgoing{get: &Get{SHA256: sum[:]}})
				return err
			}
			offset += int64(len(ch.data))
			ask()
			stall.Reset(fetchStall)
		case <-f.missing:
			// The ranges asked for after the one missing may still be
			// served, as when the peer got the part meanwhile: they would
			// only cross the next fetch.
			c.enqueue(outgoing{get: &Get{SHA256: sum[:]}})
			return ErrMissing
		case <-stall.C:
			c.enqueue(outgoing{get: &Get{SHA256: sum[:]}})
			return fmt.Errorf("node: %s sent nothing of the part for %s", peer, fetchStall)
		case <-c.done:
			return fmt.Errorf("node: the connection to %s ended", peer)
		case <-ctx.Done():
			c.enqueue(outgoing{get: &Get{SHA256: sum[:]}})
			return ctx.Err()
		}
	}
	return nil
}

// received passes a chunk the peer sent to the fetch of its part; a chunk
// nobody waits for, as after a cancel, is dropped.
func (c *conn) received(ch chunk) {
	c.fetchMu.Lock()
	f := c.fetches[ch.sum]
	c.fetchMu.Unlock()
	if f == nil {
		return
	}
	select {
	case f.ch <- ch:
	case <-f.done:
	case <-c.done:
	}
}

// gotMissing ends the fetch of a part the peer does not hold.
func (c *conn) gotMissing(g Get) {
	if len(g.SHA256) != sha256.Size {
		return
	}
	c.fetchMu.Lock()
	f := c.fetches[[sha256.Size]byte(g.SHA256)]
	c.fetchMu.Unlock()
	if f != nil {
		f.once.Do(func() { close(f.missing) })
	}
}
