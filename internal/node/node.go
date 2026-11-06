// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package node runs a member's connections to the other members and joins
// them to the sync engine: it sends the hello when a connection starts,
// forwards each event the first time the engine sees it to every other
// connection, and passes the writes the engine decides on to the local
// clipboard.
//
// Each side sends a ping when it has sent nothing for PingEvery, and a
// connection is closed when the peer sends nothing for Timeout. A large
// frame gets more time, as if the link carried at least 16 KiB a second. An
// event that waits in a connection's queue is sent with that time added to
// its age.
package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/netguard"
	"github.com/HunterEwok/cbb/internal/seal"
	"github.com/HunterEwok/cbb/internal/uptime"
)

const (
	defaultPingEvery = 5 * time.Second
	defaultTimeout   = 15 * time.Second
	handshakeTimeout = 10 * time.Second
	rejoinWait       = 2 * time.Second // how long Rejoin waits for the old connections at most
	byeWait          = time.Second     // how long a closing connection may take to say goodbye
	queueLen         = 256
)

// Config configures a Node.
type Config struct {
	Identity *group.Identity
	Role     Role
	Name     string // this device's name, sent in the hello
	OS       string // this device's operating system (group.OSLinux...), sent in the hello
	// KeyStore is where this device's keys live (group.StoreFile or
	// group.StoreHardware or group.StoreRootless), sent in the hello; ""
	// sends group.StoreFile.
	KeyStore string
	// Actions, if set, lists this device's quick actions that are on,
	// sent in the hello.
	Actions func() []string
	// Evidence, if set, is sent to every peer after its hello: the
	// attestations of this device's keys.
	Evidence []Evidence
	// OnEvidence, if set, is called with the evidence a peer sent and
	// the certificate chain it presented. An error is logged.
	OnEvidence func(peer group.DeviceID, chain []*x509.Certificate, e Evidence) error
	// Device is this device's form, versions and MAC address, sent in the
	// hello for the others to show.
	Device group.DeviceInfo
	Engine *clip.Engine
	// Content, if set, holds the images and files this member serves;
	// the hello then says it serves content, and Fetch works with peers
	// that do.
	Content Content
	// Serves, if set, says whether this member serves the part sum on a
	// connection whose own address is local: a hub serves through its
	// tunnel only the copies within its limit away from home. The others
	// get a missing.
	Serves func(local netip.Addr, sum [sha256.Size]byte) bool

	// OnWrite puts a text into this member's own clipboard. Writes carry
	// growing sequence numbers; a write with a smaller one than the last
	// applied must be dropped. It is called from connection goroutines and
	// must not block for long.
	OnWrite func(Write)

	// OnRelay, if set, is called with a media event or a text this member
	// passes on to its peers without writing it to its own clipboard, as
	// a hub in a mode that keeps its clipboard to itself does; the hub
	// fetches the content to serve it to the members that reach only it.
	OnRelay func(Write)

	// OnPeers, if set, is called whenever the set of connected members, as
	// Peers reports it, may have changed. Calls may come from several
	// goroutines at once.
	OnPeers func()

	// OnCert, if set, is called with a renewed member certificate that a
	// peer sent for this member, and the admin CA that issued it when the
	// peer sent one; it checks it, keeps it and passes the new identity to
	// SetIdentity. An error is logged.
	OnCert func(der, issuer []byte) error

	// OnAdmin, if set, is called with the admin CA that a peer, the
	// group's root, sent for this member's admin key; it checks it, keeps
	// it and passes the new identity to SetIdentity. An error is logged.
	OnAdmin func(der []byte) error

	// OnCommand, if set, is called with a command that a peer sent; it
	// checks it, carries it out and returns the result to send back.
	// Without it every command is refused.
	OnCommand func(peer group.DeviceID, c group.Record) Result

	// Allow, if set, rejects peers, for example revoked devices. Recheck
	// asks it again for the running connections.
	Allow func(group.DeviceID, []*x509.Certificate) error

	// NoSecrets, if set, reports whether this member sends a peer no
	// secret: the peer then gets the mark of a secret event, never its text
	// (docs/protocol.md, section 10, "Stopping the exchange").
	NoSecrets func(group.DeviceID) bool

	// TakeCopy checks a sealed copy a peer sent against the group's
	// records and returns the engine's event of it: opened when it is
	// sealed to this member, Unread otherwise (docs/protocol.md, section 4,
	// "Opening"). A copy it refuses is dropped and logged; without it every
	// copy is.
	TakeCopy func(from group.DeviceID, s *clip.Sealed) (clip.Event, error)

	// Records, if set, keeps the group's signed records.
	Records RecordStore
	// Credentials, if set, keeps the group's server credentials, which go
	// to every peer after its hello.
	Credentials CredentialStore
	// Releases, if set, keeps the newest signed release, which goes to
	// every peer whose hello names an older one.
	Releases ReleaseStore
	// Entries, if set, keeps the newest signed list of the project's entry
	// points, which goes to every peer whose hello names an older one.
	Entries EntriesStore

	// SealKey, if set, is this member's public key for sealed messages
	// (internal/seal), which its hello offers so that the group's root or
	// an admin puts it in its device record (docs/protocol.md, section 15).
	SealKey []byte

	// TunnelKey, if set, is this member's WireGuard public key, which its
	// hello offers the group's hubs, with TunnelPSK, its own preshared key.
	TunnelKey []byte
	TunnelPSK []byte

	// OnTunnelKey, if set, is called with the tunnel key and preshared
	// key a peer's hello offered
	// and the certificate chain the peer presented. On a hub it admits the
	// key and returns the offers to send the peer: its own, then those of
	// the group's other hubs it passes on; on other members it returns
	// none.
	OnTunnelKey func(peer group.DeviceID, chain []*x509.Certificate, key, psk []byte) []TunnelOffer

	// HubShare, if set, returns what this member, a hub, shares with the
	// peer, a device that may be a hub too, after its hello; nil for
	// nothing. OnHubs, if set, is called with what a peer shared.
	HubShare func(peer group.DeviceID) *HubShare
	OnHubs   func(from group.DeviceID, chain []*x509.Certificate, h HubShare) error

	// OnTunnel, if set, is called with the offer a peer, the group's hub,
	// sent for this member's tunnel key, and the peer's verified chain; it
	// checks it and keeps it. An error is logged.
	OnTunnel func(from group.DeviceID, chain []*x509.Certificate, o TunnelOffer) error

	PingEvery time.Duration        // defaultPingEvery if zero
	Timeout   time.Duration        // defaultTimeout if zero
	Uptime    func() time.Duration // uptime.Now if nil
	Now       func() time.Time     // for certificate checks; time.Now if nil
	Logf      func(format string, args ...any)
}

// A RecordStore keeps the group's signed records (docs/protocol.md, section
// 10). Its methods are called from connection goroutines.
type RecordStore interface {
	// Digest returns the digest of the records, which the hello carries;
	// "" when there are none.
	Digest() string
	// All returns every record, for a peer whose digest differs.
	All() []group.Record
	// Add takes the records a peer sent and returns those that were new
	// and valid, which go on to the other peers.
	Add(from group.DeviceID, rs []group.Record) []group.Record
	// Settle is called with the records Add returned once they are queued
	// for the other peers, so that a device they revoke still gets them
	// before a Recheck closes its connection.
	Settle(fresh []group.Record)
}

// A CredentialStore keeps the group's server credentials
// (docs/protocol.md, section 18). Its methods are called from connection
// goroutines.
type CredentialStore interface {
	// All returns every credential, for a peer that sent its hello.
	All() []group.Credential
	// Add takes the credentials a peer sent and returns those that were
	// new and valid, which go on to the other peers.
	Add(from group.DeviceID, cs []group.Credential) []group.Credential
}

// A ReleaseStore keeps the newest signed release the group passes around
// (docs/protocol.md, section 16, "In the group"). Its methods are called
// from connection goroutines.
type ReleaseStore interface {
	// Current returns the release it holds and where it stands: the seq
	// of its keys.json, then that of its channel file, which a newer
	// keys.json starts again; nil and zero for none.
	Current() (*ReleaseSet, ReleaseOrder)
	// Add takes a release a peer sent and reports whether it checks out
	// and is newer than the one held, and so goes on to the other peers.
	Add(from group.DeviceID, r ReleaseSet) bool
}

// An EntriesStore keeps the newest signed list of the project's entry
// points the group passes around (docs/protocol.md, section 16, "Entry
// points"), as a ReleaseStore does; its order is the seq of its keys.json,
// then that of entries.json.
type EntriesStore interface {
	Current() (*EntriesSet, ReleaseOrder)
	Add(from group.DeviceID, e EntriesSet) bool
}

// Write is a text, or images or files, to put into the member's own
// clipboard.
type Write struct {
	Text string
	Kind clip.Kind
	Via  clip.Via
	Seq  uint64
	// Media, with Kind clip.Media, is the content to fetch first, with
	// the event's ID and origin; Text is its plain-text alternative.
	Media  *clip.Manifest
	ID     string
	Origin group.DeviceID
	// Blob is the sealed blob of the copy's images and files, which a
	// member fetches by its SHA-256 (docs/protocol.md, section 4, "The
	// blob"), and Key the copy's key that opens it, nil when this member
	// does not read the copy.
	Blob *clip.Blob
	Key  []byte
}

// write makes the Write of an event.
func write(ev *clip.Event, seq uint64) Write {
	w := Write{Text: ev.Text, Kind: ev.Kind, Via: ev.Via, Seq: seq, Media: ev.Media, ID: ev.ID, Origin: group.DeviceID(ev.Origin), Key: ev.Key}
	if ev.Sealed != nil {
		w.Blob = ev.Sealed.Blob
	}
	return w
}

// Peer is a connected member.
type Peer struct {
	ID   group.DeviceID
	Role Role
	Name string // from its hello; "" when it sent none or an invalid one
	OS   string // from its hello; "" when it sent none or an unknown one
	// Device is what its hello says about its device, its invalid fields
	// dropped.
	Device group.DeviceInfo
	Key    group.KeyHash
	// AdminKey is the admin key its hello offers, a SubjectPublicKeyInfo
	// in DER, as a member that is no admin yet or whose admin CA is from an
	// earlier root does; nil when it offers none.
	AdminKey []byte
	// Chain is the certificate chain its handshake verified, leaf first.
	Chain []*x509.Certificate
	// Mode is the sync mode its hello reports; "" when it reports none.
	Mode string
	// Muted tells that its hello says it is muted, until MutedUntil on
	// this member's clock, the zero time for until the mute is lifted.
	Muted      bool
	MutedUntil time.Time
	// KeyStore is where its hello says its keys live: group.StoreFile or
	// group.StoreHardware or group.StoreRootless; "" when it says none of
	// them.
	KeyStore string
	// Actions are the quick actions its hello says are on.
	Actions []string
	// Media tells that its hello says it serves content.
	Media bool
	// Seal is the public key for sealed messages its hello offers, of the
	// right size; nil when it offers none.
	Seal  []byte
	Since time.Duration // uptime when the connection started
	// Local is this end's address of the connection; invalid when it is
	// not an IP connection.
	Local netip.Addr
}

// A Node is a member's set of connections.
type Node struct {
	cfg       Config
	id        atomic.Pointer[group.Identity] // the current identity; renewal replaces it
	tunnelKey atomic.Pointer[[2][]byte]      // the key and preshared key the hello offers the hubs; nil for none

	rejoinMu sync.Mutex // one Rejoin at a time

	// synced is set once a member's hello carried this member's records
	// digest; recsAt is the uptime of the last records a member sent
	// (Synced).
	synced atomic.Bool
	recsAt atomic.Int64

	mu        sync.Mutex
	conns     map[group.DeviceID]*conn
	waiting   map[string]waiter  // the commands sent, by ID, until their result
	passed    map[string]passing // the commands passed on for other members, by ID
	closed    bool
	rejoining chan struct{} // closed when a Rejoin in progress is done; nil if none
	wg        sync.WaitGroup
}

// New returns a node.
func New(cfg Config) *Node {
	if cfg.PingEvery == 0 {
		cfg.PingEvery = defaultPingEvery
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Uptime == nil {
		cfg.Uptime = uptime.Now
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.OnWrite == nil {
		cfg.OnWrite = func(Write) {}
	}
	n := &Node{cfg: cfg, conns: make(map[group.DeviceID]*conn), waiting: make(map[string]waiter), passed: make(map[string]passing)}
	n.id.Store(cfg.Identity)
	n.SetTunnelKey(cfg.TunnelKey, cfg.TunnelPSK)
	return n
}

// SetTunnelKey replaces the tunnel key and preshared key that hellos offer
// the group's hubs; a nil key offers none. Connections made from now on
// carry them (see Reconnect).
func (n *Node) SetTunnelKey(key, psk []byte) {
	if len(key) == 0 {
		n.tunnelKey.Store(nil)
		return
	}
	n.tunnelKey.Store(&[2][]byte{bytes.Clone(key), bytes.Clone(psk)})
}

// Reconnect closes every connection, so that the members connect again
// and their hellos carry what changed, such as a new tunnel key.
func (n *Node) Reconnect() { n.closeAll() }

// identity returns the member's current identity.
func (n *Node) identity() *group.Identity { return n.id.Load() }

// SetIdentity replaces the member's identity with a renewed one, of the
// same device and group. New connections present its certificates; the
// running ones keep theirs.
func (n *Node) SetIdentity(id *group.Identity) { n.id.Store(id) }

func (n *Node) tlsOptions() group.TLSOptions {
	return group.TLSOptions{Allow: n.cfg.Allow, RecordsOnly: true, Now: n.cfg.Now}
}

// ServerTLS returns the TLS configuration for accepting member connections.
func (n *Node) ServerTLS() *tls.Config { return n.identity().ServerTLS(n.tlsOptions()) }

// Dial connects to the member peer at addr and runs the connection until it
// ends. Of two full members the one with the lower device ID dials, and the
// other only when that has not connected for a while (see Serve).
func (n *Node) Dial(ctx context.Context, peer group.DeviceID, addr string) error {
	d := net.Dialer{Timeout: handshakeTimeout, KeepAlive: -1, Control: netguard.Control}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return n.run(ctx, tls.Client(raw, n.identity().ClientTLS(peer, n.tlsOptions())), true)
}

// DialConn runs a member connection to peer over raw, a connection that is
// already open, such as one through the tunnel to the group's hub, until it
// ends.
func (n *Node) DialConn(ctx context.Context, peer group.DeviceID, raw net.Conn) error {
	return n.run(ctx, tls.Client(raw, n.identity().ClientTLS(peer, n.tlsOptions())), true)
}

// Serve runs a member connection that was accepted with ServerTLS, or with
// a configuration from it, until it ends. It closes the connection.
func (n *Node) Serve(ctx context.Context, tc *tls.Conn) error { return n.run(ctx, tc, false) }

// errOtherConn ends a connection when the one the lower device ID dialed is
// up between the same two members.
var errOtherConn = errors.New("node: the connection the lower device ID dialed is up")

// run runs a member connection until it ends; dialed says this member
// dialed it. A new connection to a peer replaces the old one, as a
// reconnect does, unless the old one was dialed by the member with the lower
// device ID and the new one was not: when both members dial at once, the
// two keep the same connection.
func (n *Node) run(ctx context.Context, tc *tls.Conn, dialed bool) error {
	// Close the socket itself at the end: the goodbye was said, and TLS's
	// own close message could wait for seconds on a peer that stopped
	// reading.
	defer tc.NetConn().Close()
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return err
	}
	cs := tc.ConnectionState()
	id, err := group.PeerID(cs)
	if err != nil {
		return err
	}
	if id == n.identity().ID {
		return errors.New("node: connected to itself")
	}
	chain := group.MemberChain(cs)
	if len(chain) == 0 {
		return errors.New("node: the peer's certificate was not verified")
	}
	if n.cfg.Allow != nil {
		if err := n.cfg.Allow(id, chain); errors.Is(err, group.ErrRecordsOnly) {
			return n.recordsOnly(ctx, tc, id, chain, err)
		}
	}
	c := &conn{n: n, id: id, tc: tc, lowerDialed: dialed == (n.identity().ID < id), peerCert: chain[0], peerChain: chain, out: make(chan outgoing, queueLen),
		chunks: make(chan chunk, chunkQueue), fetches: make(map[[sha256.Size]byte]*fetching),
		done: make(chan struct{}), finished: make(chan struct{}), since: n.cfg.Uptime()}
	defer close(c.finished)

	// A connection that arrives while a Rejoin closes the old ones waits
	// until the engine knows the member was away, so its hello counts.
	n.mu.Lock()
	for n.rejoining != nil {
		ch := n.rejoining
		n.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
		n.mu.Lock()
	}
	if n.closed {
		n.mu.Unlock()
		return errors.New("node: closed")
	}
	old := n.conns[id]
	if old != nil && old.lowerDialed && !c.lowerDialed && !old.ending() {
		n.mu.Unlock()
		return errOtherConn
	}
	n.conns[id] = c
	// The connection is in the forwarding set before the engine makes the
	// hello, so no event falls between the two.
	hello := n.cfg.Engine.Connected(string(id))
	c.enqueue(outgoing{hello: &hello})
	n.wg.Add(1)
	n.mu.Unlock()
	defer n.wg.Done()
	if old != nil {
		old.close(false) // a reconnect replaces the old connection
	}

	stop := context.AfterFunc(ctx, func() { c.close(false) })
	defer stop()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writer()
	}()
	err = c.reader()
	c.close(false)
	<-writerDone
	c.mu.Lock()
	bye := c.sayBye
	c.mu.Unlock()
	if bye {
		linger(tc.NetConn())
	}

	n.mu.Lock()
	if n.conns[id] == c {
		delete(n.conns, id)
	}
	n.mu.Unlock()
	n.cfg.Engine.Disconnected(string(id))
	n.peersChanged()
	return err
}

// linger ends a connection that said goodbye without losing what it sent:
// it shuts its sending side and reads what the peer still sends until the
// peer closes or byeWait passes. A socket closed with unread data resets
// the connection, and a reset makes the peer drop what it had received but
// not yet read, such as the result of a command that ended the connection.
func linger(raw net.Conn) {
	cw, ok := raw.(interface{ CloseWrite() error })
	if !ok || cw.CloseWrite() != nil {
		return
	}
	raw.SetReadDeadline(time.Now().Add(byeWait))
	io.Copy(io.Discard, raw)
}

// recordsQuiet is how long a records-only connection stays open after the
// last records came.
const recordsQuiet = 5 * time.Second

// recordsRecheck is how often a records-only connection asks again whether
// the records let the peer in, for records that came over another
// connection.
const recordsRecheck = 250 * time.Millisecond

// ErrLetIn ends a records-only connection once the records let the peer
// in: whoever dialed connects again at once, as a member.
var ErrLetIn = errors.New("node: the records let the peer in")

// recordsOnly runs a connection that carries records only
// (group.ErrRecordsOnly, why says which): with a root that an admin took
// the group over from, so that the old root, if it is still in use, learns
// of the takeover and its cancel reaches the group (docs/records-v2.md,
// "Handing the group over"), or with a member that no device record here
// names yet (group.ErrNotListed), so that the records reach whichever of
// the two lacks them. The connection ends with ErrLetIn once the records
// let the peer in, those it brought or those another member did, when it
// would connect anew as a member, or with nil when no records came for
// recordsQuiet. This member sends no clipboard, credentials or anything
// else on it, and takes nothing but records.
func (n *Node) recordsOnly(ctx context.Context, tc *tls.Conn, id group.DeviceID, chain []*x509.Certificate, why error) error {
	stop := context.AfterFunc(ctx, func() { tc.NetConn().Close() })
	defer stop()
	// Records from another member may let the peer in while this
	// connection waits: the check closes the socket, and the read below
	// ends.
	letIn := make(chan struct{})
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(recordsRecheck)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if n.cfg.Allow(id, chain) == nil {
					close(letIn)
					tc.NetConn().Close()
					return
				}
			}
		}
	}()
	admitted := func() error {
		n.cfg.Logf("node: the records let %s in; it connects again as a member", id)
		return ErrLetIn
	}
	st := n.cfg.Records
	write := func(m *message) error {
		f, err := frame(m)
		if err != nil {
			return err
		}
		tc.SetWriteDeadline(time.Now().Add(n.cfg.Timeout + transferTime(len(f))))
		_, err = tc.Write(f)
		return err
	}
	out := helloOut{Hello: clip.Hello{Wall: n.cfg.Now().UnixMilli()}, Name: n.cfg.Name, OS: n.cfg.OS}
	if st != nil {
		out.Records = st.Digest()
		if g, ok := st.(interface{ GroupCA() *x509.Certificate }); ok && errors.Is(why, group.ErrNotListed) && n.cfg.Role == Full {
			if ca := g.GroupCA(); ca != nil {
				out.GroupCA = ca.Raw
			}
		}
	}
	data, err := encode(out)
	if err != nil {
		return err
	}
	if err := write(&message{Type: typeHello, Role: n.cfg.Role, Hello: data}); err != nil {
		return err
	}
	n.cfg.Logf("node: %s: %v; exchanging records only", id, why)
	for first := true; ; first = false {
		tc.SetReadDeadline(time.Now().Add(recordsQuiet))
		m, err := readMessage(tc, n.cfg.Timeout)
		if err != nil {
			select {
			case <-letIn:
				return admitted()
			default:
			}
			if first {
				return err
			}
			return nil // quiet: the records are exchanged
		}
		switch {
		case first:
			if m.Type != typeHello {
				return fmt.Errorf("node: %s did not start with a hello", id)
			}
			_, extra, err := decodeHello(m.Hello)
			if err != nil {
				return fmt.Errorf("node: bad hello from %s: %w", id, err)
			}
			if st == nil {
				return nil
			}
			if mine := st.Digest(); mine == extra.Records {
				n.synced.Store(true)
			} else if mine != "" {
				for _, chunk := range chunkRecords(st.All()) {
					if err := write(&message{Type: typeRecs, Records: chunk}); err != nil {
						return err
					}
				}
			}
		case m.Type == typeRecs && st != nil && len(m.Records) > 0:
			n.recsAt.Store(int64(n.cfg.Uptime()))
			if fresh := st.Add(id, m.Records); len(fresh) > 0 {
				n.sendRecords(fresh, nil)
				st.Settle(fresh)
			}
			if n.cfg.Allow(id, chain) == nil {
				return admitted()
			}
		}
	}
}

// Copied passes a change that a clipboard watcher reported to the engine
// and sends the event, if any, to the connected members.
func (n *Node) Copied(text string, kind clip.Kind, via clip.Via) (bool, error) {
	ev, ok, err := n.cfg.Engine.Copied(text, kind, via)
	if err != nil || !ok {
		return false, err
	}
	n.forward(ev, nil)
	return true, nil
}

// Send makes an event from a deliberate action, sends it to the connected
// members and writes it to the member's own clipboard if needed.
func (n *Node) Send(text string, kind clip.Kind, via clip.Via) error {
	ev, res, err := n.cfg.Engine.Send(text, kind, via)
	if err != nil {
		return err
	}
	n.forward(ev, nil)
	if res.Write {
		n.cfg.OnWrite(write(&ev, res.Seq))
	}
	return nil
}

// SendMedia makes a media event from a deliberate action, whose content
// the caller put in Content first, as Send does a text.
func (n *Node) SendMedia(m *clip.Manifest, text string, via clip.Via) error {
	ev, res, err := n.cfg.Engine.SendMedia(m, text, via)
	if err != nil {
		return err
	}
	n.forward(ev, nil)
	if res.Write {
		n.cfg.OnWrite(write(&ev, res.Seq))
	}
	return nil
}

// CopiedMedia passes images or files that a clipboard watcher reported,
// whose content the caller put in Content first, as Copied does a text.
func (n *Node) CopiedMedia(m *clip.Manifest, text string, via clip.Via) (bool, error) {
	ev, ok, err := n.cfg.Engine.CopiedMedia(m, text, via)
	if err != nil || !ok {
		return false, err
	}
	n.forward(ev, nil)
	return true, nil
}

// Rejoin tells the engine that the member was away: the service started, or
// the machine woke up. First it closes every connection and waits, for at
// most two seconds, until they are gone; new connections wait meanwhile, so
// every hello after the absence counts.
func (n *Node) Rejoin() {
	n.rejoinMu.Lock()
	defer n.rejoinMu.Unlock()
	n.mu.Lock()
	done := make(chan struct{})
	n.rejoining = done
	n.mu.Unlock()

	t := time.NewTimer(rejoinWait)
	defer t.Stop()
wait:
	for _, c := range n.closeAll() {
		select {
		case <-c.finished:
		case <-t.C:
			break wait
		}
	}
	n.cfg.Engine.Rejoin()

	n.mu.Lock()
	n.rejoining = nil
	n.mu.Unlock()
	close(done)
}

// Close closes every connection, saying goodbye, refuses new ones, and
// returns when they are gone.
func (n *Node) Close() {
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	n.closeAll()
	n.wg.Wait()
}

// closeAll closes every connection with a goodbye and returns them.
func (n *Node) closeAll() []*conn {
	n.mu.Lock()
	conns := make([]*conn, 0, len(n.conns))
	for _, c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	for _, c := range conns {
		c.close(true)
	}
	return conns
}

// SayGoodbye closes the connections to the devices devs whose local
// address is local, as through a hub's tunnel, after sending what is queued
// for them and a goodbye.
func (n *Node) SayGoodbye(devs []group.DeviceID, local netip.Addr) {
	var conns []*conn
	n.mu.Lock()
	for id, c := range n.conns {
		if slices.Contains(devs, id) {
			conns = append(conns, c)
		}
	}
	n.mu.Unlock()
	for _, c := range conns {
		if a, err := netip.ParseAddrPort(c.tc.LocalAddr().String()); err == nil && a.Addr().Unmap() == local {
			c.close(true)
		}
	}
}

// Peers returns the connected members that sent their hello, sorted by
// device ID.
func (n *Node) Peers() []Peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Peer, 0, len(n.conns))
	for _, c := range n.conns {
		if role := c.role(); role != "" {
			c.mu.Lock()
			adminKey, device, mode, store, acts, media, sealKey := c.peerAdminKey, c.peerDevice, c.peerMode, c.peerKeyStore, c.peerActions, c.peerMedia, c.peerSeal
			muted, mutedUntil := c.peerMuted, c.peerMutedUntil
			c.mu.Unlock()
			local, _ := netip.ParseAddrPort(c.tc.LocalAddr().String())
			out = append(out, Peer{ID: c.id, Role: role, Name: c.name(), OS: c.os(), Device: device, Key: group.KeyHashOf(c.peerCert), Chain: c.peerChain, AdminKey: adminKey,
				Mode: mode, Muted: muted, MutedUntil: mutedUntil, KeyStore: store, Actions: acts, Media: media, Seal: sealKey, Since: c.since, Local: local.Addr().Unmap()})
		}
	}
	slices.SortFunc(out, func(a, b Peer) int { return strings.Compare(string(a.ID), string(b.ID)) })
	return out
}

// RenewPeers sends a renewed certificate to every connected member whose
// certificate is due for renewal, if this member is an admin.
// Peers are also checked when their hello arrives; this covers connections
// that last for months.
func (n *Node) RenewPeers() {
	n.mu.Lock()
	conns := make([]*conn, 0, len(n.conns))
	for _, c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	for _, c := range conns {
		if c.role() != "" {
			n.renewPeer(c)
		}
	}
}

// renewPeer sends the peer of c a renewed certificate if it is due, once
// per connection: the connection keeps the certificate of its handshake.
// An admin computer of a phone group renews only computers; the phones
// renew their own.
func (n *Node) renewPeer(c *conn) {
	id := n.identity()
	if role := c.role(); id.AdminCA != nil && role != Full {
		return
	}
	cert, issuer, err := id.RenewMember(c.peerCert, n.cfg.Now())
	if err != nil {
		n.cfg.Logf("node: renewing the certificate of %s: %v", c.id, err)
		return
	}
	if cert == nil {
		return
	}
	c.mu.Lock()
	sent := c.certSent
	c.certSent = true
	c.mu.Unlock()
	if !sent {
		n.cfg.Logf("node: sending %s a renewed certificate, valid until %s", c.id, cert.NotAfter.UTC().Format(time.DateOnly))
		c.enqueue(outgoing{cert: cert, issuer: issuer})
	}
}

// recordsSettle is how long after the last records a member sent this
// member counts as holding them all: a member sends all its records at
// once when the digests differ.
const recordsSettle = time.Second

// Synced reports whether this member holds the records of another member
// since it started: a member's hello carried the same digest, or a member
// sent its records and recordsSettle passed. A device brought back from a
// backup holds old records until then, and a record it signed before would
// take a seq it signed already (docs/protocol.md, section 10, "Two numbers").
func (n *Node) Synced() bool {
	if n.synced.Load() {
		return true
	}
	at := n.recsAt.Load()
	return at != 0 && n.cfg.Uptime()-time.Duration(at) >= recordsSettle
}

// offerRecords sends every record to the peer of c when its digest differs
// from this member's and this member has any.
func (n *Node) offerRecords(c *conn, digest string) {
	st := n.cfg.Records
	if st == nil {
		return
	}
	mine := st.Digest()
	if mine == digest {
		n.synced.Store(true)
	}
	if mine == "" || mine == digest {
		return
	}
	for _, chunk := range chunkRecords(st.All()) {
		c.enqueue(outgoing{records: chunk})
	}
}

// offerTunnel passes the tunnel key the peer of c offered to OnTunnelKey
// and sends the peer the offers it returns, then what this hub shares with
// the peer, if anything.
func (n *Node) offerTunnel(c *conn, key, psk []byte) {
	// A tunnel key comes with the sender's preshared key; one without it
	// is not offered.
	if n.cfg.OnTunnelKey != nil && len(key) > 0 && len(psk) == 32 {
		for _, o := range n.cfg.OnTunnelKey(c.id, c.peerChain, key, psk) {
			c.enqueue(outgoing{tunnel: &o})
		}
	}
	if n.cfg.HubShare != nil {
		if h := n.cfg.HubShare(c.id); h != nil {
			c.enqueue(outgoing{hubs: h})
		}
	}
}

// SendHubs sends each connected member what shareFor returns for it, such
// as a hub's share when it starts or stops serving.
func (n *Node) SendHubs(shareFor func(dev group.DeviceID) *HubShare) {
	for _, c := range n.helloed() {
		if h := shareFor(c.id); h != nil {
			c.enqueue(outgoing{hubs: h})
		}
	}
}

// SendTunnel sends each connected member an offer that offerFor returns for
// it, the old hub passing on the new hub's offer (docs/protocol.md, section
// 11, "Moving the hub"), and returns the members that got one.
func (n *Node) SendTunnel(offerFor func(dev group.DeviceID) *TunnelOffer) []group.DeviceID {
	var sent []group.DeviceID
	for _, c := range n.helloed() {
		if o := offerFor(c.id); o != nil {
			c.enqueue(outgoing{tunnel: o})
			sent = append(sent, c.id)
		}
	}
	return sent
}

// SendAdmin sends the connected member dev its admin CA, which makes it an
// admin. It reports whether dev is connected.
func (n *Node) SendAdmin(dev group.DeviceID, adminCA *x509.Certificate) bool {
	for _, c := range n.helloed() {
		if c.id == dev {
			c.enqueue(outgoing{admin: adminCA})
			return true
		}
	}
	return false
}

// SendCert sends the connected member dev a member certificate, and the
// admin CA that issued it, nil for the group CA, as RenewPeers does with
// one that is due. The member takes it only if it is a valid renewal of
// its own; the bench sends ones that are not. It reports whether dev is
// connected.
func (n *Node) SendCert(dev group.DeviceID, cert, issuer *x509.Certificate) bool {
	for _, c := range n.helloed() {
		if c.id == dev {
			c.enqueue(outgoing{cert: cert, issuer: issuer})
			return true
		}
	}
	return false
}

// SendEvent sends the connected member dev the event ev as it is, as a
// member passing on one it received; the bench sends one again to check
// that it is written once. It reports whether dev is connected.
func (n *Node) SendEvent(dev group.DeviceID, ev clip.Event) bool {
	for _, c := range n.helloed() {
		if c.id == dev {
			c.enqueue(outgoing{event: &ev})
			return true
		}
	}
	return false
}

// SendEvidence sends the connected member dev an evidence message, as the
// steps of a TPM's attestation (docs/protocol.md, section 17, "TPM
// evidence"). It reports whether dev is connected.
func (n *Node) SendEvidence(dev group.DeviceID, e Evidence) bool {
	for _, c := range n.helloed() {
		if c.id == dev {
			c.enqueue(outgoing{evid: &e})
			return true
		}
	}
	return false
}

// errNotConnected is SendCommand's error for a member that is not connected.
var errNotConnected = errors.New("the device is not connected to this one; it must be on and in reach")

// SendCommand sends the member dev a command signed for it and waits for
// its result until ctx ends. Connected to dev, it sends the command there;
// otherwise to the connected members in via, the group's hubs, and one
// connected to dev passes it on (docs/protocol.md, section 15). The other
// members never get it: a command's body, a paste's text among it, is
// signed but not encrypted.
func (n *Node) SendCommand(ctx context.Context, dev group.DeviceID, cmd group.Record, id string, via []group.DeviceID) (Result, error) {
	var to []*conn
	for _, h := range n.helloed() {
		if h.id == dev {
			to = []*conn{h}
			break
		}
		if slices.Contains(via, h.id) {
			to = append(to, h)
		}
	}
	if len(to) == 0 || to[0].id != dev && len(via) == 0 {
		return Result{}, errNotConnected
	}
	got := make(chan Result, 1)
	from := make(map[group.DeviceID]bool, len(to))
	for _, c := range to {
		from[c.id] = true
	}
	n.mu.Lock()
	n.waiting[id] = waiter{dev, from, got}
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.waiting, id)
		n.mu.Unlock()
	}()
	for _, c := range to {
		c.enqueue(outgoing{command: &cmd})
	}
	var closed <-chan struct{}
	if len(to) == 1 && to[0].id == dev {
		closed = to[0].done
	}
	select {
	case r := <-got:
		return r, nil
	case <-closed:
		return Result{}, errors.New("the connection to the device closed before it answered")
	case <-ctx.Done():
		if to[0].id != dev {
			return Result{}, errors.New("the device did not answer in time: it is not connected to this one, and no hub of the group connected to it passed the command on")
		}
		return Result{}, errors.New("the device did not answer in time")
	}
}

// passing is a command passed on to the member to for the peer from,
// waiting for its result until expires; from is nil once it came.
type passing struct {
	from    *conn
	to      group.DeviceID
	expires time.Time
}

// maxPassed bounds the commands a member passes on at a time.
const maxPassed = 4096

// pass passes a command for another member on, once, when that member is
// connected, and reports whether it did. The receiver checks the
// signature, so a member that passes a command can neither forge nor
// change it.
func (c *conn) pass(cmd *group.Record, id string, to group.DeviceID, expires time.Time) bool {
	n := c.n
	var dst *conn
	for _, h := range n.helloed() {
		if h.id == to {
			dst = h
		}
	}
	if dst == nil || dst == c || id == "" {
		return false
	}
	now := n.cfg.Now()
	if !expires.After(now) || expires.Sub(now) > group.CommandLifetime+group.CommandAhead {
		return false
	}
	n.mu.Lock()
	for k, p := range n.passed {
		if !p.expires.After(now) {
			delete(n.passed, k)
		}
	}
	_, seen := n.passed[id]
	if !seen && len(n.passed) < maxPassed {
		n.passed[id] = passing{from: c, to: to, expires: expires}
	}
	n.mu.Unlock()
	if seen {
		return true
	}
	dst.enqueue(outgoing{command: cmd})
	return true
}

// command answers a command a peer sent, or passes on one for another
// member.
func (c *conn) command(cmd *group.Record) {
	var b struct {
		ID        string         `json:"id"`
		To        group.DeviceID `json:"to"`
		ExpiresMS int64          `json:"expires_ms"`
	}
	json.Unmarshal(cmd.Body, &b)
	if self := c.n.identity(); self != nil && b.To != "" && b.To != self.ID {
		if !c.pass(cmd, b.ID, b.To, time.UnixMilli(b.ExpiresMS)) {
			c.n.cfg.Logf("node: a command from %s for %s, which is not connected here", c.id, b.To)
		}
		return
	}
	res := Result{Status: ResultRefused, Reason: "this device takes no commands"}
	if c.n.cfg.OnCommand != nil {
		res = c.n.cfg.OnCommand(c.id, *cmd)
	}
	if res.ID == "" {
		res.ID = b.ID
	}
	if self := c.n.identity(); self != nil {
		res.By = self.ID
	}
	c.enqueue(outgoing{result: &res})
}

// waiter is a command sent, waiting for its result from one of the
// members it went to.
type waiter struct {
	dev  group.DeviceID
	from map[group.DeviceID]bool
	got  chan Result
}

// MaxReason is the longest reason a result carries, in bytes.
const MaxReason = 256

// CleanReason makes a result's reason fit to show to a person, a terminal's
// user among them: invalid UTF-8 becomes U+FFFD, a control character
// (escape included) a space, and it is cut to MaxReason bytes at a character
// boundary. The member that answers is a peer, so the member that shows the
// reason cleans it.
func CleanReason(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if len(s) > MaxReason {
		s = s[:MaxReason]
		// The text was valid, so only a character cut in half is not: at
		// most 3 bytes go.
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// result passes a peer's result to the command sent to it that waits for it.
func (n *Node) result(from group.DeviceID, r *Result) {
	r.Reason = CleanReason(r.Reason)
	n.mu.Lock()
	w, ok := n.waiting[r.ID]
	p, passed := n.passed[r.ID]
	passed = passed && p.to == from && p.from != nil
	if passed {
		// Kept until it expires, so that the command is not passed on
		// again; the result goes back once.
		n.passed[r.ID] = passing{to: p.to, expires: p.expires}
	}
	n.mu.Unlock()
	// A member that the command went to so that it passes it on answers
	// only with the receiver's result; one that refuses the command for
	// itself is not the receiver.
	if ok && w.from[from] && (from == w.dev || r.By == w.dev) {
		select {
		case w.got <- *r:
		default:
		}
		return
	}
	if passed {
		p.from.enqueue(outgoing{result: r})
	}
}

// helloed returns the connections whose peer sent its hello.
func (n *Node) helloed() []*conn {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]*conn, 0, len(n.conns))
	for _, c := range n.conns {
		if c.role() != "" {
			out = append(out, c)
		}
	}
	return out
}

// SendRecords sends records to every connected member, for example a
// revocation made on this member.
func (n *Node) SendRecords(rs []group.Record) { n.sendRecords(rs, nil) }

// maxCredentials bounds the credentials of one message: all that a member
// keeps for a period.
const maxCredentials = group.MaxCredentials

// SendCredentials sends server credentials made on this member to the
// peers.
func (n *Node) SendCredentials(cs []group.Credential) { n.sendCredentials(cs, nil) }

// sendCredentials sends credentials to every connection that sent its
// hello, except the one they came from.
func (n *Node) sendCredentials(cs []group.Credential, from *conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.conns {
		if c != from && c.role() != "" {
			c.enqueue(outgoing{creds: cs})
		}
	}
}

// SendRelease sends a signed release this member took, from cbb update, to
// the peers.
func (n *Node) SendRelease(r *ReleaseSet) { n.sendRelease(r, nil) }

// sendRelease sends a release to every connection that sent its hello,
// except the one it came from.
func (n *Node) sendRelease(r *ReleaseSet, from *conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.conns {
		if c != from && takesRelease(c.role()) {
			c.enqueue(outgoing{release: r})
		}
	}
}

// SendEntries sends a signed list of entry points this member took, from
// cbb update, to the peers.
func (n *Node) SendEntries(e *EntriesSet) { n.sendEntries(e, nil) }

func (n *Node) sendEntries(e *EntriesSet, from *conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.conns {
		if c != from && takesEntries(c.role()) {
			c.enqueue(outgoing{entries: e})
		}
	}
}

// takesRelease reports whether a peer of the role gets the group's
// release: the computers and the lite members; the phones' apps update
// from their stores.
func takesRelease(r Role) bool { return r == Full || r == Lite }

// takesEntries reports whether a peer of the role gets the signed entry
// points: every member, the phones too, whose hubs register through them.
func takesEntries(r Role) bool { return r != "" }

// sendRecords sends records to every connection that sent its hello,
// except the one they came from.
func (n *Node) sendRecords(rs []group.Record, from *conn) {
	chunks := chunkRecords(rs)
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.conns {
		if c == from || c.role() == "" {
			continue
		}
		for _, chunk := range chunks {
			c.enqueue(outgoing{records: chunk})
		}
	}
}

// Recheck asks Allow again about every connection and closes those it now
// rejects, for example after a revocation. They get what is queued for them
// first, so a revoked device learns of the records that revoke it.
func (n *Node) Recheck() {
	if n.cfg.Allow == nil {
		return
	}
	n.mu.Lock()
	var drop []*conn
	for _, c := range n.conns {
		if err := n.cfg.Allow(c.id, c.peerChain); err != nil {
			n.cfg.Logf("node: closing the connection to %s: %v", c.id, err)
			drop = append(drop, c)
		}
	}
	n.mu.Unlock()
	for _, c := range drop {
		c.close(true)
	}
}

func (n *Node) peersChanged() {
	n.sendReach()
	if n.cfg.OnPeers != nil {
		n.cfg.OnPeers()
	}
}

// maxReach bounds the device IDs of a reach message.
const maxReach = 256

// sendReach tells each connected phone, when this member is a computer,
// the other members it is connected to now, whenever that changes for the
// phone (docs/protocol.md, section 4, "Reach"): away from home a phone
// connects only to a hub, which passes its commands on to the members
// behind it, so that the phone shows them as online.
func (n *Node) sendReach() {
	if n.cfg.Role != Full {
		return
	}
	n.mu.Lock()
	all := make([]group.DeviceID, 0, len(n.conns))
	var phones []*conn
	for id, c := range n.conns {
		switch c.role() {
		case "":
			continue
		case Phone:
			phones = append(phones, c)
		}
		all = append(all, id)
	}
	n.mu.Unlock()
	slices.Sort(all)
	for _, c := range phones {
		reach := make([]group.DeviceID, 0, len(all))
		for _, id := range all {
			if id != c.id && len(reach) < maxReach {
				reach = append(reach, id)
			}
		}
		c.mu.Lock()
		same := c.reachSent != nil && slices.Equal(*c.reachSent, reach)
		if !same {
			c.reachSent = &reach
		}
		c.mu.Unlock()
		if !same {
			c.enqueue(outgoing{reach: &reach})
		}
	}
}

// apply carries out what the engine decided about an event that came from
// a connection.
func (n *Node) apply(res clip.Result, from *conn) {
	if res.Forward == nil {
		return
	}
	n.forward(*res.Forward, from)
	if res.Write {
		n.cfg.OnWrite(write(res.Forward, res.Seq))
	} else if n.cfg.OnRelay != nil {
		n.cfg.OnRelay(write(res.Forward, res.Seq))
	}
}

// forward sends an event to every connection except the one it came from.
func (n *Node) forward(ev clip.Event, from *conn) {
	if ev.Sealed == nil {
		n.cfg.Logf("node: a copy that is not sealed is not sent")
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.conns {
		if c != from {
			e := ev
			c.enqueue(outgoing{event: &e})
		}
	}
}

// conn is one connection to a member.
type conn struct {
	n        *Node
	id       group.DeviceID
	tc       *tls.Conn
	peerCert *x509.Certificate // from the handshake
	// peerChain is the chain the handshake verified, leaf first and without
	// its root (group.MemberChain), for Recheck and the admin checks.
	peerChain []*x509.Certificate
	since     time.Duration
	out       chan outgoing
	// chunks are the chunks of content ready to write, which go out only
	// while out is empty; serving is the peer's gets, fetches the fetches
	// of this member that wait for chunks, by their part's SHA-256.
	chunks  chan chunk
	serving serving
	fetchMu sync.Mutex
	fetches map[[sha256.Size]byte]*fetching
	// lowerDialed says the member with the lower device ID dialed it.
	lowerDialed bool

	mu       sync.Mutex
	peerRole Role   // set by the peer's hello
	peerName string // set by the peer's hello
	peerOS   string // set by the peer's hello
	// peerDevice is what the peer's hello says about its device.
	peerDevice group.DeviceInfo
	// peerAdminKey is the admin key that the peer's hello names.
	peerAdminKey []byte
	peerMode     string // the sync mode its hello reports; "" when none or unknown
	// peerMuted and peerMutedUntil are the mute its hello reports.
	peerMuted      bool
	peerMutedUntil time.Time
	peerKeyStore   string   // where its hello says its keys live; "" when it says neither
	peerActions    []string // the quick actions its hello says are on
	peerMedia      bool     // its hello says it serves content
	peerSeal       []byte   // the key for sealed messages its hello offers
	// reachSent is the reach message last queued for the peer; nil
	// before the first.
	reachSent *[]group.DeviceID
	certSent  bool // a renewed certificate was queued for the peer
	sayBye    bool
	done      chan struct{} // closed to end the connection
	closed    bool
	finished  chan struct{} // closed when Serve has cleaned up
}

// outgoing is a queued message: a hello, an event, a renewed certificate,
// records, a tunnel offer or an admin CA.
type outgoing struct {
	hello   *clip.Hello
	event   *clip.Event
	cert    *x509.Certificate
	issuer  *x509.Certificate // the admin CA that issued cert; nil for the group CA
	records []group.Record
	creds   []group.Credential
	release *ReleaseSet
	entries *EntriesSet
	tunnel  *TunnelOffer
	admin   *x509.Certificate // an admin CA for the peer
	command *group.Record     // a command for the peer
	result  *Result           // the answer to the peer's command
	hubs    *HubShare         // what this hub shares with the peer
	evid    *Evidence         // an attestation of this member's key
	get     *Get              // asks the peer for content
	missing *Get              // tells the peer this member lacks what it asked for
	reach   *[]group.DeviceID // the other members this member is connected to
	queued  time.Duration
}

func (c *conn) role() Role {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerRole
}

func (c *conn) os() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerOS
}

func (c *conn) name() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerName
}

// enqueue queues a message without blocking. A peer that falls a whole
// queue behind is too slow, and its connection is closed; it gets the
// current event again in the hello of the next one.
func (c *conn) enqueue(o outgoing) {
	o.queued = c.n.cfg.Uptime()
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	select {
	case c.out <- o:
	default:
		c.n.cfg.Logf("node: %s is too slow; closing the connection", c.id)
		c.close(false)
	}
}

// close ends the connection. With bye, the writer first sends what is
// queued and a goodbye, within a second; without, at once. Either way a
// read or write that is blocked fails now rather than at its deadline.
// ending reports whether the connection is closing or closed.
func (c *conn) ending() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *conn) close(bye bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed, c.sayBye = true, bye
	close(c.done)
	now := time.Now()
	c.tc.SetReadDeadline(now)
	if bye {
		c.tc.SetWriteDeadline(now.Add(byeWait))
	} else {
		c.tc.SetWriteDeadline(now)
	}
}

// setDeadline sets a read or write deadline unless the connection is
// closing, whose own deadlines must not be pushed back.
func (c *conn) setDeadline(read bool, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if read {
		c.tc.SetReadDeadline(t)
	} else {
		c.tc.SetWriteDeadline(t)
	}
}

// Read and SetReadDeadline let readMessage use the connection.
func (c *conn) Read(p []byte) (int, error) { return c.tc.Read(p) }

// SetReadDeadline sets the read deadline, unless the connection is closing.
func (c *conn) SetReadDeadline(t time.Time) error {
	c.setDeadline(true, t)
	return nil
}

func (c *conn) closing() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// addAge adds d to an age in milliseconds without overflowing.
func addAge(age int64, d time.Duration) int64 {
	add := max(0, d).Milliseconds()
	if age > math.MaxInt64-add {
		return math.MaxInt64
	}
	return age + add
}

// message builds the frame of a queued message, with the time it waited
// added to an event's age.
func (c *conn) message(o outgoing) (*message, error) {
	switch {
	case o.hello != nil:
		h := *o.hello
		var current *clip.Sealed
		if h.Current != nil && h.Current.Sealed != nil {
			s := *h.Current.Sealed
			s.Age = addAge(h.Current.Age, c.n.cfg.Uptime()-o.queued)
			current = &s
		}
		h.Current = nil
		out := helloOut{Hello: h, Current: current, Name: c.n.cfg.Name, OS: c.n.cfg.OS, Mode: c.n.cfg.Engine.Mode().String(), KeyStore: c.n.cfg.KeyStore}
		if muted, left := c.n.cfg.Engine.MuteLeft(); muted {
			out.Muted, out.MutedFor = true, left.Milliseconds()
		}
		if out.KeyStore == "" {
			out.KeyStore = group.StoreFile
		}
		if c.n.cfg.Actions != nil {
			out.Actions = c.n.cfg.Actions()
		}
		if c.n.cfg.Content != nil {
			out.Features = []string{FeatureMedia}
		}
		if d := c.n.cfg.Device.Clean(); !d.IsZero() {
			out.Device = &d
		}
		id := c.n.identity()
		if id.AdminKey != nil && (id.AdminCA == nil || id.StaleAdminCA()) {
			spki, err := x509.MarshalPKIXPublicKey(group.PublicKey(id.AdminKey))
			if err != nil {
				return nil, err
			}
			out.AdminKey = spki
		}
		if c.n.cfg.Records != nil {
			out.Records = c.n.cfg.Records.Digest()
		}
		if st := c.n.cfg.Releases; st != nil {
			_, o := st.Current()
			out.ReleaseKeys, out.ReleaseSeq = o.Keys, o.Channel
		}
		if st := c.n.cfg.Entries; st != nil {
			_, o := st.Current()
			out.EntriesKeys, out.EntriesSeq = o.Keys, o.Channel
		}
		if k := c.n.tunnelKey.Load(); k != nil {
			out.TunnelKey, out.TunnelPSK = k[0], k[1]
		}
		out.Seal = c.n.cfg.SealKey
		data, err := encode(out)
		if err != nil {
			return nil, err
		}
		return &message{Type: typeHello, Role: c.n.cfg.Role, Hello: data}, nil
	case o.cert != nil:
		m := &message{Type: typeCert, Cert: o.cert.Raw}
		if o.issuer != nil {
			m.Issuer = o.issuer.Raw
		}
		return m, nil
	case o.records != nil:
		return &message{Type: typeRecs, Records: o.records}, nil
	case o.creds != nil:
		return &message{Type: typeCreds, Credentials: o.creds}, nil
	case o.release != nil:
		return &message{Type: typeRelease, Release: o.release}, nil
	case o.entries != nil:
		return &message{Type: typeEntries, Entries: o.entries}, nil
	case o.tunnel != nil:
		return &message{Type: typeTun, Tunnel: o.tunnel}, nil
	case o.admin != nil:
		return &message{Type: typeAdmin, AdminCA: o.admin.Raw}, nil
	case o.command != nil:
		return &message{Type: typeCommand, Command: o.command}, nil
	case o.result != nil:
		return &message{Type: typeResult, Result: o.result}, nil
	case o.hubs != nil:
		return &message{Type: typeHubs, Hubs: o.hubs}, nil
	case o.evid != nil:
		return &message{Type: typeEvid, Evidence: o.evid}, nil
	case o.get != nil:
		return &message{Type: typeGet, Get: o.get}, nil
	case o.missing != nil:
		return &message{Type: typeMissing, Get: o.missing}, nil
	case o.reach != nil:
		return &message{Type: typeReach, Reach: *o.reach}, nil
	default:
		ev := *o.event
		if ev.Sealed == nil {
			return nil, errors.New("a copy that is not sealed")
		}
		if ev.Kind == clip.Secret && !ev.Unread && c.n.cfg.NoSecrets != nil && c.n.cfg.NoSecrets(c.id) {
			ev = ev.Mark()
		}
		s := *ev.Sealed
		s.Age = addAge(ev.Age, c.n.cfg.Uptime()-o.queued)
		data, err := encode(s)
		if err != nil {
			return nil, err
		}
		return &message{Type: typeEvent, Event: data}, nil
	}
}

func (c *conn) writer() {
	ping := time.NewTimer(c.n.cfg.PingEvery)
	defer ping.Stop()
	put := func(f []byte, deadline bool) bool {
		if deadline {
			c.setDeadline(false, time.Now().Add(c.n.cfg.Timeout+transferTime(len(f))))
		}
		if _, err := c.tc.Write(f); err != nil {
			if !c.closing() {
				c.n.cfg.Logf("node: writing to %s: %v", c.id, err)
			}
			c.close(false)
			return false
		}
		ping.Reset(c.n.cfg.PingEvery)
		return true
	}
	writeFrame := func(f []byte) bool { return put(f, true) }
	write := func(m *message, deadline bool) bool {
		f, err := frame(m)
		if err != nil {
			c.n.cfg.Logf("node: to %s: %v", c.id, err)
			return true // drop this one message
		}
		return put(f, deadline)
	}
	send := func(o outgoing, deadline bool) bool {
		if o.result != nil && o.result.Written != nil {
			defer close(o.result.Written)
		}
		m, err := c.message(o)
		if err != nil {
			c.n.cfg.Logf("node: to %s: %v", c.id, err)
			return true
		}
		return write(m, deadline)
	}
	for {
		select {
		case <-c.done:
			c.mu.Lock()
			bye := c.sayBye
			c.mu.Unlock()
			if !bye {
				return
			}
			// Send what is still queued, then the goodbye, within the
			// second that close gave the writes.
			for {
				select {
				case o := <-c.out:
					if !send(o, false) {
						return
					}
					continue
				default:
				}
				break
			}
			write(&message{Type: typeBye}, false)
			return
		default:
		}
		// Content goes only while no other message waits.
		select {
		case o := <-c.out:
			if !send(o, true) {
				return
			}
			continue
		default:
		}
		select {
		case o := <-c.out:
			if !send(o, true) {
				return
			}
		case ch := <-c.chunks:
			if !writeFrame(encodeChunk(ch)) {
				return
			}
		case <-ping.C:
			if !write(&message{Type: typePing}, true) {
				return
			}
		case <-c.done:
		}
	}
}

// reader reads the peer's hello and then its events until the connection
// ends; a peer that says goodbye ends it without an error.
func (c *conn) reader() error {
	e := c.n.cfg.Engine
	timeout := c.n.cfg.Timeout
	for first := true; ; first = false {
		c.SetReadDeadline(time.Now().Add(timeout))
		m, err := readMessage(c, timeout)
		if c.closing() {
			return nil // closed on this side; nothing more counts
		}
		if err != nil {
			return err
		}
		if first {
			if m.Type != typeHello || !m.Role.known() {
				return fmt.Errorf("node: %s did not start with a hello", c.id)
			}
			h, extra, err := decodeHello(m.Hello)
			if err != nil {
				return fmt.Errorf("node: bad hello from %s: %w", c.id, err)
			}
			if extra.current != nil {
				if ev, ok := c.take(extra.current); ok {
					h.Current = &ev
				}
			}
			c.mu.Lock()
			c.peerRole = m.Role
			if group.ValidName(extra.Name) {
				c.peerName = extra.Name
			}
			if group.ValidOS(extra.OS) {
				c.peerOS = extra.OS
			}
			c.peerDevice = group.DeviceInfo{}
			if extra.Device != nil {
				c.peerDevice = extra.Device.Clean()
			}
			c.peerAdminKey = extra.AdminKey
			c.peerSeal = nil
			if len(extra.Seal) == seal.PublicKeySize {
				c.peerSeal = extra.Seal
			}
			c.peerKeyStore = ""
			if extra.KeyStore == group.StoreFile || extra.KeyStore == group.StoreHardware || extra.KeyStore == group.StoreRootless {
				c.peerKeyStore = extra.KeyStore
			}
			c.peerActions = nil
			for _, a := range extra.Actions {
				if group.ValidActionName(a) && len(c.peerActions) < maxPeerActions {
					c.peerActions = append(c.peerActions, a)
				}
			}
			c.peerMedia = slices.Contains(extra.Features[:min(len(extra.Features), maxFeatures)], FeatureMedia)
			c.peerMode = ""
			if _, err := clip.ParseMode(extra.Mode); err == nil {
				c.peerMode = extra.Mode
			}
			c.peerMuted, c.peerMutedUntil = extra.Muted, time.Time{}
			if extra.Muted && extra.MutedFor > 0 {
				c.peerMutedUntil = time.Now().Add(time.Duration(min(extra.MutedFor, maxMutedFor)) * time.Millisecond)
			}
			c.mu.Unlock()
			c.n.peersChanged()
			res, err := e.Reconcile(string(c.id), h)
			if err != nil {
				return fmt.Errorf("node: bad hello from %s: %w", c.id, err)
			}
			c.n.apply(res, c)
			c.n.renewPeer(c)
			c.n.offerRecords(c, extra.Records)
			if st := c.n.cfg.Credentials; st != nil {
				if all := st.All(); len(all) > 0 {
					c.enqueue(outgoing{creds: all})
				}
			}
			if st := c.n.cfg.Releases; st != nil {
				if r, o := st.Current(); r != nil && o.After(ReleaseOrder{extra.ReleaseKeys, extra.ReleaseSeq}) && takesRelease(c.role()) {
					c.enqueue(outgoing{release: r})
				}
			}
			if st := c.n.cfg.Entries; st != nil {
				if e, o := st.Current(); e != nil && o.After(ReleaseOrder{extra.EntriesKeys, extra.EntriesSeq}) && takesEntries(c.role()) {
					c.enqueue(outgoing{entries: e})
				}
			}
			c.n.offerTunnel(c, extra.TunnelKey, extra.TunnelPSK)
			for i := range c.n.cfg.Evidence {
				c.enqueue(outgoing{evid: &c.n.cfg.Evidence[i]})
			}
			continue
		}
		switch m.Type {
		case typeEvent:
			var s clip.Sealed
			if err := json.Unmarshal(m.Event, &s); err != nil {
				c.n.cfg.Logf("node: dropped an event from %s that does not decode", c.id)
				continue
			}
			ev, ok := c.take(&s)
			if !ok {
				continue
			}
			res, err := e.Received(ev)
			if err != nil {
				c.n.cfg.Logf("node: dropped a bad event from %s: %v", c.id, err)
				continue
			}
			c.n.apply(res, c)
		case typeCert:
			if c.n.cfg.OnCert == nil {
				continue
			}
			if err := c.n.cfg.OnCert(m.Cert, m.Issuer); err != nil {
				c.n.cfg.Logf("node: a renewed certificate from %s: %v", c.id, err)
			}
		case typeAdmin:
			if c.n.cfg.OnAdmin == nil {
				continue
			}
			if err := c.n.cfg.OnAdmin(m.AdminCA); err != nil {
				c.n.cfg.Logf("node: an admin CA from %s: %v", c.id, err)
			}
		case typeTun:
			if c.n.cfg.OnTunnel == nil || m.Tunnel == nil {
				continue
			}
			if err := c.n.cfg.OnTunnel(c.id, c.peerChain, *m.Tunnel); err != nil {
				c.n.cfg.Logf("node: a tunnel offer from %s: %v", c.id, err)
			}
		case typeHubs:
			if c.n.cfg.OnHubs == nil || m.Hubs == nil {
				continue
			}
			if err := c.n.cfg.OnHubs(c.id, c.peerChain, *m.Hubs); err != nil {
				c.n.cfg.Logf("node: what the hub %s shared: %v", c.id, err)
			}
		case typeEvid:
			if c.n.cfg.OnEvidence == nil || m.Evidence == nil {
				continue
			}
			if err := c.n.cfg.OnEvidence(c.id, c.peerChain, *m.Evidence); err != nil {
				c.n.cfg.Logf("node: the evidence from %s: %v", c.id, err)
			}
		case typeRecs:
			c.n.recsAt.Store(int64(c.n.cfg.Uptime()))
			if st := c.n.cfg.Records; st != nil && len(m.Records) > 0 {
				if fresh := st.Add(c.id, m.Records); len(fresh) > 0 {
					c.n.sendRecords(fresh, c)
					st.Settle(fresh)
				}
			}
		case typeCreds:
			if st := c.n.cfg.Credentials; st != nil && len(m.Credentials) > 0 && len(m.Credentials) <= maxCredentials {
				if fresh := st.Add(c.id, m.Credentials); len(fresh) > 0 {
					c.n.sendCredentials(fresh, c)
				}
			}
		case typeRelease:
			if st := c.n.cfg.Releases; st != nil && m.Release != nil && st.Add(c.id, *m.Release) {
				c.n.sendRelease(m.Release, c)
			}
		case typeEntries:
			if st := c.n.cfg.Entries; st != nil && m.Entries != nil && st.Add(c.id, *m.Entries) {
				c.n.sendEntries(m.Entries, c)
			}
		case typeCommand:
			if m.Command != nil {
				c.command(m.Command)
			}
		case typeResult:
			if m.Result != nil {
				c.n.result(c.id, m.Result)
			}
		case typeGet:
			if m.Get != nil {
				c.get(*m.Get)
			}
		case typeMissing:
			if m.Get != nil {
				c.gotMissing(*m.Get)
			}
		case typeChunk:
			c.received(*m.chunk)
		case typeBye:
			return nil
		}
		// A ping, or a message type from a newer version: nothing to do.
	}
}

// decodeHello decodes a hello, and returns the rest of it, the peer's
// records digest and name, as it came, with its current copy as it came
// in current. A current copy that does not decode, for example from a
// newer version, counts as none.
func decodeHello(raw json.RawMessage) (clip.Hello, helloBody, error) {
	var b helloBody
	if err := json.Unmarshal(raw, &b); err != nil || len(raw) == 0 {
		return clip.Hello{}, helloBody{}, errors.New("the hello does not decode")
	}
	h := clip.Hello{Wall: b.Wall}
	if len(b.Current) > 0 && string(b.Current) != "null" {
		var s clip.Sealed
		if json.Unmarshal(b.Current, &s) == nil {
			b.current = &s
		}
	}
	return h, b, nil
}

// take checks a sealed copy from the peer with TakeCopy and returns the
// engine's event of it; false, logged, when it is refused.
func (c *conn) take(s *clip.Sealed) (clip.Event, bool) {
	if c.n.cfg.TakeCopy == nil {
		c.n.cfg.Logf("node: dropped a copy from %s: this member checks no copies", c.id)
		return clip.Event{}, false
	}
	ev, err := c.n.cfg.TakeCopy(c.id, s)
	if err != nil {
		c.n.cfg.Logf("node: dropped a copy from %s: %v", c.id, err)
		return clip.Event{}, false
	}
	return ev, true
}

// maxPeerActions bounds the quick actions a peer's hello may list: the
// presets and its user's own.
const maxPeerActions = 64

// maxMutedFor bounds the mute a peer's hello reports, as a mute command
// does (group.MaxMute).
const maxMutedFor = int64(group.MaxMute / time.Millisecond)
