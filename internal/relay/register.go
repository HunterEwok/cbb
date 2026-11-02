// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/frame"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// maxChain is the most certificates a member may present: its member
// certificate, its admin CA and the group's roots; and maxRoots the roots
// it may show with its credentials.
const (
	maxChain = 8
	maxRoots = 8
)

// maxClaim bounds a claim, which carries the group's authority records,
// and maxClaimRecords the records in it, whose signatures the relay checks.
const (
	maxClaim        = 1 << 20
	maxClaimRecords = 1024
)

// rootOf returns the root among certs that names the group tag.
func rootOf(certs []*x509.Certificate, tag string) *x509.Certificate {
	for _, c := range certs[1:] {
		if c.IsCA && c.CheckSignatureFrom(c) == nil && group.Tag(c) == tag {
			return c
		}
	}
	return nil
}

// serverTLS is the registrations' TLS: TLS 1.3, the relay's own
// certificate, and a member certificate whose chain the relay checks
// itself against the groups it serves.
func (r *Relay) serverTLS() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{r.cfg.Keys.Cert},
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{Protocol},
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != Protocol {
				return errors.New("relay: the device does not speak the registration protocol")
			}
			_, _, _, err := r.groupOf(cs.PeerCertificates, time.Now())
			return err
		},
	}
}

// groupOf checks that the certificates a device presented are a member
// certificate with its chain to the root of a group the relay serves, and
// returns that group's tag and the device's ID; or a server certificate
// alone, which names neither, for a device that registers with the
// group's credentials (cred). A root that the device presents counts only
// if the relay serves its group.
func (r *Relay) groupOf(certs []*x509.Certificate, now time.Time) (tag, device string, cred bool, err error) {
	if len(certs) == 0 || len(certs) > maxChain {
		return "", "", false, errors.New("relay: the device presented no member certificate chain")
	}
	id, err := group.DeviceOf(certs[0])
	if err != nil {
		if len(certs) == 1 && !certs[0].IsCA {
			return "", "", true, nil
		}
		return "", "", false, fmt.Errorf("relay: %w", err)
	}
	inter := x509.NewCertPool()
	var roots []*x509.Certificate
	for _, c := range certs[1:] {
		if c.IsCA && c.CheckSignatureFrom(c) == nil {
			if r.cfg.Open || r.allowed[group.Tag(c)] {
				roots = append(roots, c)
			}
		} else {
			inter.AddCert(c)
		}
	}
	for _, root := range roots {
		pool := x509.NewCertPool()
		pool.AddCert(root)
		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots: pool, Intermediates: inter, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err == nil {
			return group.Tag(root), string(id), false, nil
		}
	}
	return "", "", false, errors.New("relay: the device is not of a group this relay serves")
}

// credentialTag is the name under which the relay keeps a group that
// registered with the period's tag: apart from the tags of group CAs.
func credentialTag(tag string) string { return "period " + tag }

// credentialed checks a device that registers with credentials: the
// period's hubs' and members' credentials (group.CheckPresented), which
// list the key of its server certificate among the members; and on a
// relay that serves a fixed list of groups, the period credential, signed
// by one of the roots the device shows, which must be the root of a group
// the relay serves.
func (r *Relay) credentialed(leaf *x509.Certificate, c claim, now time.Time) (*group.Presented, error) {
	p, err := group.CheckPresented(c.Credentials, now)
	switch {
	case err != nil && strings.Contains(err.Error(), "expired"):
		return nil, errors.New("the group's credentials expired; the group's root starts a new period")
	case err != nil:
		return nil, errors.New("the group's credentials do not verify")
	case p.Members == nil:
		return nil, errors.New("the device sent no members' credential")
	case !slices.Contains(p.Members.Members, group.KeyHashOf(leaf)):
		return nil, errors.New("the group's members' credential does not list this device")
	}
	if r.cfg.Open {
		return p, nil
	}
	if p.Period == nil || len(c.Roots) > maxRoots {
		return nil, errors.New("the device showed no root of its group")
	}
	for _, der := range c.Roots {
		root, err := x509.ParseCertificate(der)
		if err != nil || !root.IsCA || root.CheckSignatureFrom(root) != nil || !bytes.Equal(root.RawSubjectPublicKeyInfo, p.PeriodRoot) {
			continue
		}
		if r.allowed[group.Tag(root)] {
			return p, nil
		}
	}
	return nil, errors.New("the device is not of a group this relay serves")
}

// A period is what the relay holds, in memory, of a group that registered
// with credentials: the period key it first saw for the period's tag, the
// newest versions of its credentials, and the members the newest members'
// credential lists.
type period struct {
	signer           group.KeyHash
	hubs, membersVer uint64
	members          []group.KeyHash
}

// checkPeriodLocked checks the credentials p against what the relay holds
// for their period: they are of the key that registered it first, and no
// older than the ones it saw. It changes nothing; takePeriodLocked does.
func (r *Relay) checkPeriodLocked(tag string, p *group.Presented) error {
	cur := r.periods[tag]
	switch {
	case cur == nil:
	case cur.signer != p.Signer:
		return errors.New("another key registered this group's period first")
	case p.Hubs.Version < cur.hubs || p.Members.Version < cur.membersVer:
		return errors.New("the group's credentials are older than ones this relay saw")
	}
	return nil
}

// leavingLocked tells the devices of the period tag that the credentials p
// would leave out when taken.
func (r *Relay) leavingLocked(tag string, p *group.Presented) func(*member) bool {
	if cur := r.periods[tag]; cur != nil && cur.members != nil && p.Members.Version <= cur.membersVer {
		return nil
	}
	return func(o *member) bool { return !slices.Contains(p.Members.Members, o.leaf) }
}

// takePeriodLocked takes the credentials p, which checkPeriodLocked let
// through, for their period; the devices a newer members' credential no
// longer lists go.
func (r *Relay) takePeriodLocked(tag string, p *group.Presented) {
	cur := r.periods[tag]
	if cur == nil {
		cur = &period{signer: p.Signer}
		r.periods[tag] = cur
	}
	cur.hubs = p.Hubs.Version
	if p.Members.Version > cur.membersVer || cur.members == nil {
		cur.membersVer, cur.members = p.Members.Version, p.Members.Members
		for _, o := range r.groups[tag] {
			if !slices.Contains(cur.members, o.leaf) {
				r.dropLocked(o)
			}
		}
	}
}

// acceptRegistrations takes the members' TLS connections.
func (r *Relay) acceptRegistrations() {
	for {
		conn, err := r.tcp.Accept()
		if err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			r.logf("cbb relay: accepting registrations: %v", err)
			return
		}
		from := addrOf(conn)
		if !r.takeSlot(from) {
			conn.Close()
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.serveRegistration(conn, from)
		}()
	}
}

// serveRegistration registers one device and holds its registration while
// the connection lasts.
func (r *Relay) serveRegistration(raw net.Conn, from netip.Addr) {
	m, err := r.register(raw, from)
	r.freeSlot(from)
	if err != nil {
		raw.Close()
		return
	}
	// The device sends nothing more; reading tells when it goes.
	io.Copy(io.Discard, m.conn)
	r.mu.Lock()
	r.dropLocked(m)
	r.mu.Unlock()
}

// register runs a registration's setup: TLS with the device's member
// certificate, then the proof that it holds its WireGuard key, bound to
// this TLS session, as with the forwarder.
func (r *Relay) register(raw net.Conn, from netip.Addr) (*member, error) {
	raw.SetDeadline(time.Now().Add(r.setupWait))
	tc := tls.Server(raw, r.tlsCfg)
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	cs := tc.ConnectionState()
	tag, device, cred, err := r.groupOf(cs.PeerCertificates, time.Now())
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	enc, dec := frame.NewEncoder(tc, maxClaim), frame.NewDecoder(io.LimitReader(tc, maxClaim), maxClaim)
	if err := enc.Encode(challenge{E: eph.PublicKey().Bytes(), Roots: cred && !r.cfg.Open}); err != nil {
		return nil, err
	}
	var c claim
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	refuse := func(msg string) (*member, error) {
		enc.Encode(welcome{Error: msg})
		return nil, errors.New(msg)
	}
	if len(c.Key) != 32 {
		return refuse("the WireGuard key is not 32 bytes")
	}
	pub, err := ecdh.X25519().NewPublicKey(c.Key)
	if err != nil {
		return refuse("the WireGuard key is not an X25519 key")
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return refuse("the WireGuard key is not an X25519 key")
	}
	want, err := proof(shared, cs)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(want, c.Proof) {
		return refuse("the device does not hold that WireGuard key")
	}
	if len(c.Records) > maxClaimRecords {
		return refuse("too many records")
	}
	leaf := group.KeyHashOf(cs.PeerCertificates[0])
	var recs *recordSet
	var fresh bool
	var pr *group.Presented
	// The group's registrations that check records take turns, until this
	// one has added its device.
	unlockTag := func() {}
	defer func() { unlockTag() }()
	psk, err := tunnel.NewPresharedKey()
	if err != nil {
		return nil, err
	}
	m := &member{leaf: leaf, chain: cs.PeerCertificates, psk: psk, conn: tc, raw: raw, streams: map[net.Conn]bool{}, from: addrOf(raw)}
	copy(m.key[:], c.Key)
	if cred {
		if pr, err = r.credentialed(cs.PeerCertificates[0], c, time.Now()); err != nil {
			return refuse(err.Error())
		}
		m.tag, m.device = credentialTag(pr.Tag), group.Pseudonym(leaf)
	} else {
		m.tag, m.device = tag, device
		// A registration the relay would refuse anyway sends it no records
		// to keep.
		r.mu.Lock()
		err := r.admitLocked(m, nil)
		r.mu.Unlock()
		if err != nil {
			return refuse(err.Error())
		}
		// The relay keeps the group's records once verified, and checks only
		// the ones a claim brings that it does not have; the group's other
		// registrations wait meanwhile.
		unlockTag = r.lockTag(tag)
		if recs, fresh, err = r.checkRecords(tag, rootOf(cs.PeerCertificates, tag), from, c.Records); err != nil {
			r.forgetRecords(tag)
			return refuse(err.Error())
		}
		r.mu.Lock()
		if recs != nil && fresh {
			// The devices the new records remove go now, whatever becomes
			// of this registration: the records stay with the group's
			// devices.
			for _, o := range r.groups[tag] {
				if refusedHere(recs.set, o.chain) != nil {
					r.dropLocked(o)
				}
			}
		}
		r.mu.Unlock()
		// A group the relay holds no verified record of is one it knows
		// nothing about: only records it holds can refuse a device.
		if recs != nil && recs.set.Len() > 0 {
			if err := refusedHere(recs.set, cs.PeerCertificates); err != nil {
				r.forgetRecords(tag)
				return refuse(strings.TrimPrefix(err.Error(), "group: "))
			}
		}
	}
	r.mu.Lock()
	select {
	case <-r.done:
		r.mu.Unlock()
		return refuse("the relay is stopping")
	default:
	}
	// What was checked before the records may have changed meanwhile.
	var refusal error
	var leaving func(*member) bool
	if pr != nil {
		refusal, leaving = r.checkPeriodLocked(m.tag, pr), r.leavingLocked(m.tag, pr)
	}
	if refusal == nil {
		refusal = r.admitLocked(m, leaving)
	}
	if refusal != nil {
		r.mu.Unlock()
		if recs != nil {
			r.forgetRecords(m.tag)
		}
		return refuse(refusal.Error())
	}
	if err := r.addLocked(m); err != nil {
		r.mu.Unlock()
		if recs != nil {
			r.forgetRecords(m.tag)
		}
		return nil, err
	}
	if pr != nil {
		r.takePeriodLocked(m.tag, pr)
	}
	r.mu.Unlock()
	unlockTag()
	unlockTag = func() {}
	relayKey := r.cfg.Keys.WireGuard.Public()
	if err := enc.Encode(welcome{Key: relayKey[:], PSK: psk[:], Addr: m.addr.String()}); err != nil {
		r.mu.Lock()
		r.dropLocked(m)
		r.mu.Unlock()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return m, nil
}

// proof is what a device sends to prove it holds its WireGuard key: an
// HMAC, under the X25519 secret of its key and the relay's ephemeral one,
// of a key from this TLS session, so it proves nothing on another
// connection.
func proof(shared []byte, cs tls.ConnectionState) ([]byte, error) {
	k, err := cs.ExportKeyingMaterial(proofLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, shared)
	m.Write(k)
	return m.Sum(nil), nil
}

// refusedHere is why the relay refuses a device of a group: what the
// records refuse, except a stop of the exchange (group.ErrStopped), under
// which the group's devices still exchange records through the relay.
func refusedHere(set *group.Records, chain []*x509.Certificate) error {
	if err := set.Refused(chain); err != nil && !errors.Is(err, group.ErrStopped) {
		return err
	}
	return nil
}
