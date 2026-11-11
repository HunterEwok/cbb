// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/frame"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/netguard"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// Link is a member's relay: its address, the same for UDP and TCP, and the
// pin of its key, which the member checks before it sends anything. Also
// are more pins it accepts, as while the project's relay changes its key.
type Link struct {
	Endpoint netip.AddrPort
	Pin      string
	Also     []string
}

// same reports whether l and o name the same address and pins.
func (l Link) same(o Link) bool {
	return l.Endpoint == o.Endpoint && l.Pin == o.Pin && slices.Equal(l.Also, o.Also)
}

// MemberConfig configures a member's link to its relay.
type MemberConfig struct {
	Link Link
	Self string     // this device's ID
	Key  tunnel.Key // its WireGuard private key

	// Cert returns the member certificate with its chain to the group's
	// root; it is asked at each registration, so a renewed certificate is
	// taken.
	Cert func() tls.Certificate

	// Records, if set, returns the group's authority records
	// (group.Records.AuthorityRecords), which the relay keeps to refuse
	// the devices the group removed.
	Records func() []group.Record

	// Credentialed, if set, returns what the member registers with when
	// the period's members' credential lists it (docs/protocol.md,
	// section 18), in place of Cert and Records; false registers with
	// those.
	Credentialed func() (Credentialed, bool)

	// CredentialsChanged, if set, returns a channel that is closed when
	// the group's credentials change next, so that a registered member
	// looks at once whether it registers with other ones; it looks every
	// credentialCheck as well.
	CredentialsChanged func() <-chan struct{}

	// Want tells whether to connect to a device through the relay now:
	// false while it is connected already, for example on the home
	// network.
	Want func(peer string) bool

	// Dialed runs the member protocol, as the TLS client, over a
	// connection the relay joined to peer's; Called runs it as the TLS
	// server over one from a device the relay says is peer, which Called
	// must check. Both return when the connection ends.
	Dialed func(ctx context.Context, peer string, conn net.Conn) error
	Called func(ctx context.Context, peer string, conn net.Conn) error

	// Report, if set, hears how the link stands.
	Report func(Report)

	// Retry, if set, is asked after a registration failed with err for
	// the link to try next, as the project's relay's newest signed address
	// and keys; false keeps the link. A link with another address or other
	// pins is tried at once.
	Retry func(ctx context.Context, err error) (Link, bool)

	Logf    func(format string, args ...any)
	Verbose bool // also log WireGuard's own messages
}

// Credentialed is what a member registers with when the group's
// credentials list it: the relay then knows it by its pseudonym, and
// learns neither its device ID nor its group's roots, unless it serves a
// fixed list of groups.
type Credentialed struct {
	Cert  tls.Certificate    // the certificate of its server key (group.ServerCertificate)
	Self  string             // its pseudonym (group.Pseudonym)
	Creds []group.Credential // the period's hubs' and members' credentials
	// Period and Roots are the period credential and the group's roots,
	// the group CA first, for a relay that asks for them.
	Period group.Credential
	Roots  [][]byte
}

// Report is how a member's link to its relay stands.
type Report struct {
	Connected bool     // registered, with its tunnel and its watch
	Online    []string // the other devices of the group on the relay
	Through   int      // member connections through the relay now
	Err       error    // why it is not connected
}

// Backoff of the registration and of the dials.
const (
	minBackoff = time.Second
	maxBackoff = time.Minute
	// wantCheck is how often a dialer looks again whether it has to
	// connect, while the device is connected another way.
	wantCheck = 5 * time.Second
)

// Join keeps the member registered with its relay until ctx is done, and
// connects it through the relay to the other devices of its group there:
// the device with the lower ID dials, the other answers.
func Join(ctx context.Context, cfg MemberConfig) {
	if cfg.Report == nil {
		cfg.Report = func(Report) {}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	backoff := minBackoff
	for ctx.Err() == nil {
		start := time.Now()
		err := joinOnce(ctx, cfg)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errNewCredential) {
			cfg.Logf("cbb: sync away from home: the group's credentials changed; registering with the relay again")
			backoff = minBackoff
			continue
		}
		cfg.Report(Report{Err: err})
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		if cfg.Retry != nil {
			if l, ok := cfg.Retry(ctx, err); ok && !l.same(cfg.Link) {
				cfg.Logf("cbb: sync away from home: trying the relay at %v with the keys of its newest signed list", l.Endpoint)
				cfg.Link = l
				backoff = minBackoff
				continue
			}
			if ctx.Err() != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// session is one registration with its tunnel.
type session struct {
	cfg    MemberConfig
	client *tunnel.Client
	self   string // this device's name at the relay

	wg      sync.WaitGroup // the dialers and the answers
	mu      sync.Mutex
	online  []string
	dialers map[string]context.CancelFunc
	through int
	calls   int // the calls being answered
}

// errNewCredential ends a registration when what the member registers
// with changed, a new period or a members' credential that lists it now,
// so that it registers again at once.
var errNewCredential = errors.New("the group's credentials changed")

// credentialCheck is how often a registered member looks whether its
// credentials changed.
const credentialCheck = 5 * time.Second

// credentialKey names what the member registers with: its name and the
// IDs of its credentials, or nothing without them.
func credentialKey(c Credentialed, ok bool) string {
	if !ok {
		return ""
	}
	k := c.Self
	for _, cr := range c.Creds {
		id := cr.ID()
		k += " " + string(id[:])
	}
	return k
}

func joinOnce(ctx context.Context, cfg MemberConfig) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	live, was := cfg.Credentialed, ""
	if live != nil {
		// The registration is made with the credentials as they are now,
		// so that a change from here on ends it.
		c, ok := live()
		was = credentialKey(c, ok)
		cfg.Credentialed = func() (Credentialed, bool) { return c, ok }
		if ok {
			// With credentials the relay gets a fresh WireGuard key at each
			// registration, so the key links no two of them.
			if cfg.Key, err = tunnel.NewPrivateKey(); err != nil {
				return err
			}
		}
	}
	tc, w, self, err := register(ctx, cfg)
	if err != nil {
		return err
	}
	defer tc.Close()
	addr, err := netip.ParseAddr(w.Addr)
	if err != nil {
		return errors.New("the relay gave a bad tunnel address")
	}
	var relayKey, psk tunnel.Key
	if len(w.Key) != len(relayKey) || len(w.PSK) != len(psk) {
		return errors.New("the relay's keys are not 32 bytes")
	}
	copy(relayKey[:], w.Key)
	copy(psk[:], w.PSK)
	client, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: cfg.Key, PresharedKey: psk, Addr: addr,
		HubPublicKey: relayKey, HubAddr: Addr, Endpoint: cfg.Link.Endpoint, Logf: cfg.Logf, Verbose: cfg.Verbose})
	if err != nil {
		return err
	}
	defer client.Close()
	s := &session{cfg: cfg, client: client, self: self, dialers: map[string]context.CancelFunc{}}
	defer func() {
		cancel()
		s.wg.Wait()
	}()
	go func() {
		// The relay sends nothing more on the registration; reading tells
		// when it is gone.
		io.Copy(io.Discard, tc)
		cancel()
	}()
	var renew atomic.Bool
	if live != nil {
		go func() {
			t := time.NewTicker(credentialCheck)
			defer t.Stop()
			for {
				var changed <-chan struct{}
				if cfg.CredentialsChanged != nil {
					changed = cfg.CredentialsChanged()
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				case <-changed:
				}
				if credentialKey(live()) != was {
					renew.Store(true)
					cancel()
					return
				}
			}
		}()
	}
	defer func() {
		if renew.Load() {
			err = errNewCredential
		}
	}()

	dctx, dcancel := context.WithTimeout(ctx, setupTimeout)
	watch, err := client.Dial(dctx)
	dcancel()
	if err != nil {
		return fmt.Errorf("the relay's tunnel does not answer: %w", err)
	}
	defer watch.Close()
	stop := context.AfterFunc(ctx, func() { watch.Close() })
	defer stop()
	if err := writeLine(watch, request{Watch: true}, setupTimeout); err != nil {
		return fmt.Errorf("the relay's tunnel does not answer: %w", err)
	}
	defer s.stopDialers()
	notes := bufio.NewReaderSize(watch, 4<<10)
	for {
		var n note
		if err := frame.Read(notes, &n, maxLine); err != nil {
			if ctx.Err() != nil {
				return errors.New("the relay ended the registration")
			}
			return fmt.Errorf("the relay's watch ended: %w", err)
		}
		switch {
		case n.Online != nil:
			// The relay holds at most maxMembers devices of a group, and
			// names them by device ID or pseudonym; a relay that says
			// otherwise is not one to trust.
			if len(*n.Online) > maxMembers || slices.ContainsFunc(*n.Online, func(p string) bool { return !validName(p) }) {
				return errors.New("the relay's watch sent a list of devices that is not valid")
			}
			s.setOnline(ctx, *n.Online)
		case n.Call != "" && n.Ticket != "":
			if !validName(n.Call) || !validTicket(n.Ticket) || !s.takeCall() {
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.endCall()
				s.answer(ctx, n.Call, n.Ticket)
			}()
		}
	}
}

// takeCall counts a call being answered; false when there are as many
// as the relay keeps waiting for one device.
func (s *session) takeCall() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls >= maxCalls {
		return false
	}
	s.calls++
	return true
}

func (s *session) endCall() {
	s.mu.Lock()
	s.calls--
	s.mu.Unlock()
}

// validName reports whether s is a device's name at the relay: its device
// ID, 32 lowercase hex characters, or its pseudonym (group.Pseudonym).
func validName(s string) bool {
	if len(s) == 32 {
		return strings.Trim(s, "0123456789abcdef") == ""
	}
	_, ok := group.ParsePseudonym(s)
	return ok
}

// validTicket reports whether s is a call's ticket: 16 bytes in standard
// base64.
func validTicket(s string) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 16 && base64.StdEncoding.EncodeToString(b) == s
}

// register runs the registration's setup and returns its connection, which
// the member keeps open while it is registered, and the name the relay
// knows the member by.
func register(ctx context.Context, cfg MemberConfig) (*tls.Conn, welcome, string, error) {
	cred, withCreds := Credentialed{}, false
	if cfg.Credentialed != nil {
		cred, withCreds = cfg.Credentialed()
	}
	cert, self := cfg.Cert(), cfg.Self
	if withCreds {
		cert, self = cred.Cert, cred.Self
	}
	d := net.Dialer{Timeout: setupTimeout, KeepAlive: 30 * time.Second, Control: netguard.Control}
	raw, err := d.DialContext(ctx, "tcp", cfg.Link.Endpoint.String())
	if err != nil {
		return nil, welcome{}, "", fmt.Errorf("reaching the relay: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	fail := func(err error) (*tls.Conn, welcome, string, error) {
		stop()
		raw.Close()
		return nil, welcome{}, "", err
	}
	raw.SetDeadline(time.Now().Add(setupTimeout))
	tc := tls.Client(raw, forward.TLSVerifiedByPin(cert, Protocol, "relay", append([]string{cfg.Link.Pin}, cfg.Link.Also...)...))
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(fmt.Errorf("registering with the relay: %w", err))
	}
	cs := tc.ConnectionState()
	enc, dec := frame.NewEncoder(tc, 1<<20), frame.NewDecoder(io.LimitReader(tc, 1<<20), 1<<20)
	var ch challenge
	if err := dec.Decode(&ch); err != nil {
		return fail(fmt.Errorf("registering with the relay: %w", err))
	}
	priv, err := ecdh.X25519().NewPrivateKey(cfg.Key[:])
	if err != nil {
		return fail(err)
	}
	e, err := ecdh.X25519().NewPublicKey(ch.E)
	if err != nil {
		return fail(errors.New("registering with the relay: a bad challenge"))
	}
	shared, err := priv.ECDH(e)
	if err != nil {
		return fail(errors.New("registering with the relay: a bad challenge"))
	}
	p, err := proof(shared, cs)
	if err != nil {
		return fail(err)
	}
	c := claim{Key: priv.PublicKey().Bytes(), Proof: p}
	switch {
	case withCreds:
		c.Credentials = cred.Creds
		if ch.Roots {
			// A relay that serves a fixed list of groups knows them by
			// their roots.
			c.Credentials = append(slices.Clone(c.Credentials), cred.Period)
			c.Roots = cred.Roots
		}
	case cfg.Records != nil:
		c.Records = cfg.Records()
		if len(c.Records) > maxClaimRecords {
			c.Records = c.Records[:maxClaimRecords]
		}
	}
	if err := enc.Encode(c); err != nil {
		return fail(fmt.Errorf("registering with the relay: %w", err))
	}
	var w welcome
	if err := dec.Decode(&w); err != nil {
		return fail(fmt.Errorf("registering with the relay: %w", err))
	}
	if w.Error != "" {
		return fail(fmt.Errorf("the relay refused the registration: %s", w.Error))
	}
	raw.SetDeadline(time.Time{})
	// The registration lasts until ctx is done or the relay drops it.
	return tc, w, self, nil
}

func (s *session) report() {
	s.mu.Lock()
	r := Report{Connected: true, Online: slices.Clone(s.online), Through: s.through}
	s.mu.Unlock()
	s.cfg.Report(r)
}

// setOnline keeps a dialer for each device on the relay that this one
// dials: the ones with a higher name.
func (s *session) setOnline(ctx context.Context, online []string) {
	s.mu.Lock()
	s.online = online
	for p, stop := range s.dialers {
		if !slices.Contains(online, p) {
			stop()
			delete(s.dialers, p)
		}
	}
	for _, p := range online {
		if _, ok := s.dialers[p]; ok || strings.Compare(s.self, p) >= 0 {
			continue
		}
		pctx, stop := context.WithCancel(ctx)
		s.dialers[p] = stop
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dial(pctx, p)
		}()
	}
	s.mu.Unlock()
	s.report()
}

func (s *session) stopDialers() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, stop := range s.dialers {
		stop()
		delete(s.dialers, p)
	}
}

// dial connects to peer through the relay whenever it is not connected
// another way, until ctx is done.
func (s *session) dial(ctx context.Context, peer string) {
	backoff := minBackoff
	for ctx.Err() == nil {
		wait := wantCheck
		if s.cfg.Want(peer) {
			start := time.Now()
			err := s.dialOnce(ctx, peer)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				s.cfg.Logf("cbb: sync away from home: connecting to %s through the relay: %v", peer, err)
			}
			if time.Since(start) > maxBackoff {
				backoff = minBackoff
			}
			wait, backoff = backoff, min(2*backoff, maxBackoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (s *session) dialOnce(ctx context.Context, peer string) error {
	c, err := s.open(ctx, request{Dial: peer})
	if err != nil {
		return err
	}
	return s.run(ctx, peer, c, s.cfg.Dialed)
}

// answer takes a call from peer and runs the member protocol on it.
func (s *session) answer(ctx context.Context, peer, ticket string) {
	c, err := s.open(ctx, request{Answer: ticket})
	if err != nil {
		if ctx.Err() == nil {
			s.cfg.Logf("cbb: sync away from home: answering %s through the relay: %v", peer, err)
		}
		return
	}
	if err := s.run(ctx, peer, c, s.cfg.Called); err != nil && ctx.Err() == nil {
		s.cfg.Logf("cbb: sync away from home: connection from %s through the relay: %v", peer, err)
	}
}

// open opens a connection to the relay's member port, sends req and waits
// until the relay joined it.
func (s *session) open(ctx context.Context, req request) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, setupTimeout)
	c, err := s.client.Dial(dctx)
	cancel()
	if err != nil {
		return nil, err
	}
	if err := ask(ctx, c, req); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// ask sends req on c and waits until the relay joined it, or until ctx is
// done. A registration that ends waits for its dials and answers before it
// closes its tunnel and registers again (joinOnce), and the relay that
// dropped it sends nothing more on c: a wait to the timeout would keep the
// device off the relay for that long.
func ask(ctx context.Context, c net.Conn, req request) error {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	var n note
	err := writeLine(c, req, setupTimeout)
	if err == nil {
		err = readLine(c, &n, callTimeout+setupTimeout)
	}
	if !stop() {
		return ctx.Err()
	}
	switch {
	case err != nil:
		return err
	case !n.OK:
		if n.Error == "" {
			n.Error = "no answer"
		}
		return fmt.Errorf("the relay: %s", n.Error)
	}
	return nil
}

// run runs a member connection the relay joined, counting it.
func (s *session) run(ctx context.Context, peer string, c net.Conn, f func(context.Context, string, net.Conn) error) error {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	s.mu.Lock()
	s.through++
	s.mu.Unlock()
	s.report()
	err := f(ctx, peer, c)
	c.Close()
	s.mu.Lock()
	s.through--
	s.mu.Unlock()
	s.report()
	return err
}
