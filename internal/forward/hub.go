// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/HunterEwok/cbb/internal/frame"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/netguard"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
)

// Link is a hub's forwarder: its address, the same for UDP and TCP, and the
// pin of its key, which the hub checks before it sends anything.
type Link struct {
	Endpoint netip.AddrPort
	Pin      string
	// Also are other pins the forwarder's key may have: the project's
	// forwarder while its key changes.
	Also []string
}

// Pin returns the pin of a forwarder's certificate: the fingerprint of its
// key, in the one form of docs/protocol.md (Conventions, "Fingerprints"),
// SHA-256 over its SubjectPublicKeyInfo in standard base64.
func Pin(cert *x509.Certificate) string { return group.KeyHashOf(cert).String() }

// CheckPin tells whether s looks like a pin.
func CheckPin(s string) error {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != sha256.Size || base64.StdEncoding.EncodeToString(b) != s {
		return fmt.Errorf("%q is not a forwarder's key; cbb forward prints it, 44 characters of base64", s)
	}
	return nil
}

// HubConfig configures a hub's registration.
type HubConfig struct {
	Link Link
	Key  [32]byte // the hub's WireGuard private key
	// Obfuscation is the group's AmneziaWG settings, nil for plain
	// WireGuard; the forwarder needs them to read the group's packets.
	Obfuscation *tunnel.Obfuscation
	// VLESSID is the group's VLESS user ID, for a hub whose clients come
	// over VLESS; empty without.
	VLESSID string
	// VLESS, if set with VLESSID, returns the ways the hub reaches the
	// forwarder over VLESS when its TCP port does not answer, tried in
	// order: the settings it learned from an earlier registration, or the
	// project's forwarder's from its signed entry points or built in. The
	// registration then goes inside VLESS with vless.RegistrationID, and
	// the hub's own packets with VLESSID (docs/protocol.md, section 13,
	// "VLESS").
	VLESS func() []tunnel.VLESS
	// Cert returns the hub's member certificate with its chain to the
	// group's root; it is asked at each registration, so a renewed
	// certificate is taken.
	// Authority returns the key of the group's root or of this hub's admin
	// CA, that admin CA (nil for a root), and the group's authority records
	// (group.Records.AuthorityRecords): only the root or an admin may
	// register its group, and the forwarder learns from the records whom
	// the group removed. A hub whose root or admin key cannot sign without
	// the user, a phone's, returns a nil key: the records then show the
	// forwarder that its member key is the root's or an admin's.
	Authority func() (key crypto.Signer, admin *x509.Certificate, records []group.Record)
	Cert      func() tls.Certificate
	// Credentials, if set, returns the chain of the group's hubs'
	// credentials that lists this hub (docs/protocol.md, section 18), and
	// HubCert the hub's certificate for it, which names no device. A nil
	// chain registers with Cert and Authority instead.
	Credentials func() []group.Credential
	HubCert     func() (tls.Certificate, error)

	// Send sends a packet from the hub's WireGuard port, so that the
	// forwarder learns where that port is reached.
	Send func(to netip.AddrPort, p []byte) error

	// Report, if set, hears how the registration stands.
	Report func(Report)

	// Allowed, if set, says which addresses the hub may dial to reach the
	// forwarder; the service passes netguard.Allowed. Without it, only
	// Link.Endpoint's, as for a phone, whose app keeps no list of the
	// group's servers.
	Allowed func(netip.Addr) bool
}

// control is the Control of the dialer that reaches the forwarder: it
// refuses, before any packet leaves, an address that cfg.Allowed refuses.
func (cfg HubConfig) control() func(network, address string, _ syscall.RawConn) error {
	allowed := cfg.Allowed
	if allowed == nil {
		to := cfg.Link.Endpoint.Addr().Unmap()
		allowed = func(a netip.Addr) bool { return a.Unmap() == to }
	}
	return func(network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !allowed(ap.Addr()) {
			return fmt.Errorf("%s: %w", address, netguard.ErrOutside)
		}
		return nil
	}
}

// Report is how a hub's registration stands.
type Report struct {
	Registered bool
	Seen       netip.AddrPort // where the forwarder reaches the hub's WireGuard port
	VLESS      *tunnel.VLESS  // how the hub's clients reach the forwarder over VLESS
	OverVLESS  bool           // the hub itself reaches the forwarder over VLESS
	Err        error          // why the hub is not registered
}

// Hellos go every helloEvery, which keeps the NAT mapping of the hub's port
// open, and every second until the forwarder saw one.
const (
	helloEvery = 15 * time.Second
	helloFirst = time.Second
	minBackoff = time.Second
	maxBackoff = time.Minute
)

// errNewCredential ends a registration when the group's hubs' credential
// changed, so that the hub registers again at once with the new one, and
// the forwarder refuses the old one from then on.
var errNewCredential = errors.New("the group's hubs' credential changed")

// Register keeps the hub registered with its forwarder until ctx is done,
// registering again whenever the connection breaks.
func Register(ctx context.Context, cfg HubConfig) {
	report := cfg.Report
	if report == nil {
		report = func(Report) {}
	}
	backoff := minBackoff
	for ctx.Err() == nil {
		start := time.Now()
		err := registerOnce(ctx, cfg, report)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errNewCredential) {
			backoff = minBackoff
			continue
		}
		report(Report{Err: err})
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// TLSVerifiedByPin builds the TLS of a registration with a server known only
// by the pin of its key, a forwarder or a relay (what, in the errors): the
// server has no name and a self-signed certificate, so crypto/tls cannot
// check it, and VerifyConnection checks its key against the pin instead. (The
// name, like the pairing's clientTLSVerifiedByFingerprint, tells CodeQL that
// InsecureSkipVerify is checked here.)
func TLSVerifiedByPin(cert tls.Certificate, protocol, what string, pins ...string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{protocol},
		// The server has no name; the pin names it. Without a name the
		// hello carries no server name either.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || !slices.Contains(pins, Pin(cs.PeerCertificates[0])) {
				return fmt.Errorf("the %s's key is not the one given for it", what)
			}
			if cs.NegotiatedProtocol != protocol {
				return fmt.Errorf("the %s does not speak the registration protocol", what)
			}
			return nil
		},
	}
}

func registerOnce(ctx context.Context, cfg HubConfig, report func(Report)) error {
	var creds []group.Credential
	if cfg.Credentials != nil && cfg.HubCert != nil {
		creds = cfg.Credentials()
	}
	var cert tls.Certificate
	if creds != nil {
		var err error
		if cert, err = cfg.HubCert(); err != nil {
			return fmt.Errorf("the hub's certificate: %w", err)
		}
	} else {
		cert = cfg.Cert()
	}
	tlsCfg := TLSVerifiedByPin(cert, Protocol, "forwarder", append([]string{cfg.Link.Pin}, cfg.Link.Also...)...)
	handshake := func(raw net.Conn) (*tls.Conn, error) {
		raw.SetDeadline(time.Now().Add(setupTimeout))
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("registering with the forwarder: %w", err)
		}
		return tc, nil
	}
	d := net.Dialer{Timeout: setupTimeout, KeepAlive: 30 * time.Second, Control: cfg.control()}
	raw, err := d.DialContext(ctx, "tcp", cfg.Link.Endpoint.String())
	var tc *tls.Conn
	var over *tunnel.VLESS // the way in over VLESS the registration took
	if err == nil {
		if tc, err = handshake(raw); err != nil {
			raw.Close()
			return err
		}
	} else {
		var ways []tunnel.VLESS
		if cfg.VLESS != nil && cfg.VLESSID != "" {
			ways = cfg.VLESS()
		}
		if len(ways) == 0 {
			return fmt.Errorf("reaching the forwarder: %w", err)
		}
		// Each way in until one gets through to the registration.
		direct := err
		for i := range ways {
			way, verr := vless.DialRegistration(ways[i])
			if verr != nil {
				err = verr
				continue
			}
			lo := net.Dialer{Timeout: setupTimeout}
			if raw, verr = lo.DialContext(ctx, "tcp", way.Addr().String()); verr != nil {
				way.Close()
				err = verr
				continue
			}
			if tc, verr = handshake(raw); verr != nil {
				raw.Close()
				way.Close()
				err = verr
				continue
			}
			defer way.Close()
			over = &ways[i]
			break
		}
		if over == nil {
			return fmt.Errorf("reaching the forwarder: %w; over VLESS: %w", direct, err)
		}
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	cs := tc.ConnectionState()
	enc, dec := frame.NewEncoder(tc, 1<<20), frame.NewDecoder(io.LimitReader(tc, 1<<20), 1<<20)
	var ch challenge
	if err := dec.Decode(&ch); err != nil {
		return fmt.Errorf("registering with the forwarder: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(cfg.Key[:])
	if err != nil {
		return err
	}
	e, err := ecdh.X25519().NewPublicKey(ch.E)
	if err != nil {
		return errors.New("registering with the forwarder: a bad challenge")
	}
	shared, err := priv.ECDH(e)
	if err != nil {
		return errors.New("registering with the forwarder: a bad challenge")
	}
	p, err := proof(shared, cs)
	if err != nil {
		return err
	}
	c := claim{Key: priv.PublicKey().Bytes(), Proof: p, Obfuscation: cfg.Obfuscation, VLESS: cfg.VLESSID, Credentials: creds}
	if creds == nil && cfg.Authority != nil {
		key, admin, records := cfg.Authority()
		if key != nil {
			if c.AdminSig, err = SignAdmin(key, cs, c.Key); err != nil {
				return err
			}
			if admin != nil {
				c.Admin = admin.Raw
			}
		}
		if len(records) > maxClaimRecords {
			records = records[:maxClaimRecords]
		}
		c.Records = records
	}
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("registering with the forwarder: %w", err)
	}
	var a answer
	if err := dec.Decode(&a); err != nil {
		return fmt.Errorf("registering with the forwarder: %w", err)
	}
	if a.Error != "" {
		return fmt.Errorf("the forwarder refused the registration: %s", a.Error)
	}
	if len(a.Mask) != 32 {
		return errors.New("registering with the forwarder: no key for the hellos' mask")
	}
	mask := [32]byte(a.Mask)
	var vl *tunnel.VLESS
	if cfg.VLESSID != "" {
		if a.VLESS == nil {
			return errors.New("registering with the forwarder: it gave no VLESS settings")
		}
		vl = &tunnel.VLESS{Transport: a.VLESS.Transport, Endpoint: netip.AddrPortFrom(cfg.Link.Endpoint.Addr(), a.VLESS.Port),
			PublicKey: a.VLESS.PublicKey, ShortID: a.VLESS.ShortID, ServerName: a.VLESS.ServerName, Path: a.VLESS.Path, ID: cfg.VLESSID}
		if err := vl.Check(); err != nil {
			return fmt.Errorf("registering with the forwarder: its VLESS settings: %w", err)
		}
	}
	raw.SetDeadline(time.Time{})
	// Over VLESS the hub's own packets go there too, with the group's user
	// ID, which the forwarder lets in now: from the hub's WireGuard port to
	// a local port that leads to the forwarder's UDP port.
	helloTo := cfg.Link.Endpoint
	if over != nil {
		v := *over
		if vl != nil {
			v = *vl
		}
		v.ID = cfg.VLESSID
		c, err := vless.Dial(v)
		if err != nil {
			return fmt.Errorf("the hub's packets over VLESS: %w", err)
		}
		defer c.Close()
		helloTo = c.Addr()
	}
	report(Report{Registered: true, VLESS: vl, OverVLESS: over != nil})
	var key [32]byte
	hk, err := cs.ExportKeyingMaterial(helloLabel, nil, 32)
	if err != nil {
		return err
	}
	copy(key[:], hk)

	answers := make(chan answer)
	failed := make(chan error, 1)
	go func() {
		for {
			var a answer
			if err := dec.Decode(&a); err != nil {
				failed <- err
				return
			}
			select {
			case answers <- a:
			case <-ctx.Done():
				return
			}
		}
	}()
	var counter uint64
	seen := netip.AddrPort{}
	every := helloFirst
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failed:
			return fmt.Errorf("the connection to the forwarder broke: %w", err)
		case a := <-answers:
			if ep, err := netip.ParseAddrPort(a.Seen); err == nil && ep != seen {
				seen, every = ep, helloEvery
				report(Report{Registered: true, Seen: seen, VLESS: vl, OverVLESS: over != nil})
			}
		case <-t.C:
			if creds != nil {
				if now := cfg.Credentials(); len(now) > 0 && now[len(now)-1].ID() != creds[len(creds)-1].ID() {
					return errNewCredential
				}
			}
			counter = max(counter+1, uint64(time.Now().UnixNano()))
			// A hello that cannot go out now goes with the next one.
			_ = cfg.Send(helloTo, hello(&mask, &key, a.ID, counter))
			t.Reset(every)
		}
	}
}
