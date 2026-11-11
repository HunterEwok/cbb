// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/frame"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
)

// Protocol is the ALPN protocol of a hub's registration.
const Protocol = "cbb-forward/2"

// The labels of the keys the registration takes from TLS: the one the hub
// proves its WireGuard key under, and the one its hellos carry a MAC of.
const (
	proofLabel = "cbb forwarder key"
	helloLabel = "cbb forwarder hello"
	// adminLabel is the key the hub's root or admin CA signs, with the
	// hub's WireGuard key, to show the hub may register its group.
	adminLabel = "cbb forwarder admin"
)

// maxClaim bounds a claim, which carries the group's authority records,
// and maxClaimRecords the records in it, whose signatures the forwarder
// checks.
const (
	maxClaim        = 1 << 20
	maxClaimRecords = 1024
)

// setupTimeout bounds a registration from the TCP connection to the
// forwarder's answer.
const setupTimeout = 15 * time.Second

// maxChain is the most certificates a hub may present: its member
// certificate, its admin CA and the group's roots.
const maxChain = 8

// The registration's messages, one JSON object a line (docs/protocol.md,
// section 13).
type (
	challenge struct {
		E []byte `json:"e"` // the forwarder's ephemeral X25519 key
	}
	claim struct {
		Key   []byte `json:"key"`   // the hub's WireGuard public key
		Proof []byte `json:"proof"` // HMAC-SHA256(X25519(hub key, e), the TLS proof key)
		// Obfuscation is the group's AmneziaWG settings, without which the
		// forwarder cannot read an obfuscated group's packets.
		Obfuscation *tunnel.Obfuscation `json:"obfuscation,omitempty"`
		// VLESS is the group's VLESS user ID, for a hub whose clients come
		// over VLESS.
		VLESS string `json:"vless,omitempty"`
		// Admin is the admin CA that signed AdminSig, or empty when a root
		// of the group did; AdminSig signs SHA-256 of the TLS admin key and
		// the WireGuard key (adminMessage). Only the root or an admin may
		// register its group.
		Admin    []byte `json:"admin,omitempty"`
		AdminSig []byte `json:"admin_sig"`
		// Records are the group's authority records
		// (group.Records.AuthorityRecords), so that the forwarder refuses
		// a removed or frozen hub; a hub with a credential sends none.
		Records []group.Record `json:"records,omitempty"`
		// Credentials are the period's hubs' credential
		// (docs/protocol.md, section 18), in place of the records, the
		// admin and its signature.
		Credentials []group.Credential `json:"credentials,omitempty"`
	}
	answer struct {
		ID    uint64       `json:"id,omitempty"`    // the registration, for the hellos
		Mask  []byte       `json:"mask,omitempty"`  // the key of the hellos' mask
		VLESS *vlessAnswer `json:"vless,omitempty"` // how clients reach the forwarder over VLESS
		Error string       `json:"error,omitempty"` // why the forwarder refused it
		Seen  string       `json:"seen,omitempty"`  // where the hub's WireGuard port is reached
	}
	vlessAnswer struct {
		Transport  string `json:"transport"`   // "xhttp"
		Port       uint16 `json:"port"`        // the web server's TCP port, at the forwarder's address
		ServerName string `json:"server_name"` // the site the handshakes name
		Path       string `json:"path"`        // the path the web server passes
	}
)

// serverTLS is the forwarder's TLS: TLS 1.3, its own certificate, and a
// client certificate whose chain the forwarder checks itself, since it
// knows no group beforehand.
func (f *Forwarder) serverTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{Protocol},
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != Protocol {
				return errors.New("forward: the hub does not speak the registration protocol")
			}
			_, err := groupOf(cs.PeerCertificates, time.Now())
			return err
		},
	}
}

// presented is what a hub's TLS certificates say: whether it registers
// with its member certificate and the group's records, and then its
// group's tag, or with a credential (docs/protocol.md, section 18), whose
// tag the credential gives.
type presented struct {
	tag    string
	member bool
	root   *x509.Certificate // with a member certificate: the root its chain verified to
}

// groupOf checks the certificates a hub presented. A hub that registers
// with a credential presents one certificate of its server key, which
// names neither a device nor a group; one that registers with records
// presents its member certificate with its chain to a root of the group,
// the self-signed CA among them, which names the group. Any group may
// register, but only its hubs can register it.
func groupOf(certs []*x509.Certificate, now time.Time) (presented, error) {
	if len(certs) == 0 || len(certs) > maxChain {
		return presented{}, errors.New("forward: the hub presented no certificate")
	}
	if _, err := group.DeviceOf(certs[0]); err != nil {
		if len(certs) != 1 || certs[0].IsCA {
			return presented{}, errors.New("forward: the hub presented neither a member certificate nor a server certificate")
		}
		return presented{}, nil
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range certs[1:] {
		if c.IsCA && c.CheckSignatureFrom(c) == nil {
			roots.AddCert(c)
		} else {
			inter.AddCert(c)
		}
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return presented{}, fmt.Errorf("forward: the hub's certificate: %w", err)
	}
	c := chains[0]
	root := c[len(c)-1]
	return presented{tag: group.Tag(root), member: true, root: root}, nil
}

// acceptRegistrations takes the hubs' TLS connections.
func (f *Forwarder) acceptRegistrations() {
	for {
		conn, err := f.tcp.Accept()
		if err != nil {
			select {
			case <-f.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			f.logf("cbb forward: accepting registrations: %v", err)
			return
		}
		var from netip.Addr
		if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			from = ta.AddrPort().Addr().Unmap()
		}
		f.mu.Lock()
		busy := f.setting >= f.limits.Connections || !f.from.Take(from, 1)
		if !busy {
			f.setting++
		}
		f.mu.Unlock()
		if busy {
			conn.Close()
			continue
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer func() {
				f.mu.Lock()
				f.from.Remove(from, 1)
				f.mu.Unlock()
			}()
			f.serveRegistration(conn, false)
		}()
	}
}

// groupPath returns the group's own part of the XHTTP path: the same for
// the group at each registration and after a restart, so that its clients'
// offers stay good, and known to nobody without the forwarder's key.
func (f *Forwarder) groupPath(tag string) string {
	m := hmac.New(sha256.New, f.pathKey[:])
	m.Write([]byte("cbb group path\x00" + tag))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

// registrationOverVLESS takes a hub's registration that came over VLESS,
// from a hub that reaches the forwarder in no other way. from is the
// client's own address as the VLESS server knows it (vless.ServerConfig's
// Register): it pays as a hub that registers directly does, from the same
// setup slots and the same caps (docs/relay-budget.md, "The forwarder").
// When the address is not known (a loopback address, from a web server in
// front that does not name it), the registrations are bounded together
// instead, and their setups take at most an eighth of the setup slots, so
// that they never keep out a hub that registers directly. Limits.OverVLESS
// bounds all of them.
func (f *Forwarder) registrationOverVLESS(conn net.Conn, from netip.Addr) {
	known := from.IsValid() && !from.IsLoopback() && !from.IsUnspecified()
	f.mu.Lock()
	limit := f.limits.OverVLESS
	if limit == 0 {
		limit = DefaultLimits.OverVLESS
	}
	busy := f.setting >= f.limits.Connections || f.overVLESS >= limit
	if !busy {
		if known {
			busy = !f.from.Take(from, 1)
		} else {
			busy = f.vlessSet >= max(1, f.limits.Connections/8)
		}
	}
	select {
	case <-f.done:
		if !busy && known {
			f.from.Remove(from, 1)
		}
		busy = true
	default:
	}
	if !busy {
		f.setting++
		f.overVLESS++
		if !known {
			f.vlessSet++
		}
		f.wg.Add(1)
	}
	f.mu.Unlock()
	if busy {
		conn.Close()
		return
	}
	defer f.wg.Done()
	defer func() {
		f.mu.Lock()
		f.overVLESS--
		if known {
			f.from.Remove(from, 1)
		}
		f.mu.Unlock()
	}()
	f.serveRegistration(conn, !known)
}

// serveRegistration registers one hub and holds its registration while the
// connection lasts; unknown is a registration over VLESS from an address
// not known, counted in vlessSet while it is set up.
func (f *Forwarder) serveRegistration(raw net.Conn, unknown bool) {
	r, err := f.register(raw)
	f.mu.Lock()
	f.setting--
	if unknown {
		f.vlessSet--
	}
	f.mu.Unlock()
	if err != nil {
		raw.Close()
		return
	}
	defer func() {
		f.mu.Lock()
		f.dropRegLocked(r)
		f.mu.Unlock()
		f.memory.left(r.tag)
	}()
	enc := frame.NewEncoder(r.conn, maxClaim)
	gone := make(chan struct{})
	go func() {
		// The hub sends nothing more; reading tells when it goes.
		_, _ = io.Copy(io.Discard, r.conn)
		close(gone)
	}()
	for {
		select {
		case <-gone:
			return
		case <-f.done:
			return
		case ep := <-r.seen:
			r.conn.SetWriteDeadline(time.Now().Add(setupTimeout))
			if enc.Encode(answer{Seen: ep.String()}) != nil {
				return
			}
		}
	}
}

// register runs a registration's setup: TLS with the hub's member
// certificate, then the proof that the hub holds its WireGuard key, bound
// to this TLS session.
func (f *Forwarder) register(raw net.Conn) (*reg, error) {
	raw.SetDeadline(time.Now().Add(setupTimeout))
	tc := tls.Server(raw, f.tlsCfg)
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	cs := tc.ConnectionState()
	p, err := groupOf(cs.PeerCertificates, time.Now())
	if err != nil {
		return nil, err
	}
	tag := p.tag
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	enc, dec := frame.NewEncoder(tc, maxClaim), frame.NewDecoder(io.LimitReader(tc, maxClaim), maxClaim)
	if err := enc.Encode(challenge{E: eph.PublicKey().Bytes()}); err != nil {
		return nil, err
	}
	var c claim
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	refuse := func(msg string) (*reg, error) {
		enc.Encode(answer{Error: msg})
		return nil, errors.New(msg)
	}
	if len(c.Records) > maxClaimRecords {
		return refuse("too many records")
	}
	if len(c.Credentials) > 3 {
		return refuse("too many credentials")
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
		return refuse("the hub does not hold that WireGuard key")
	}
	if c.Obfuscation != nil {
		if err := c.Obfuscation.Check(); err != nil {
			return refuse("the obfuscation settings are not usable")
		}
	}
	if c.VLESS != "" && f.vless == nil {
		// A hub asks for VLESS by default; without it here, the hub is
		// registered for UDP alone, and the answer carries no VLESS.
		c.VLESS = ""
	}
	if c.VLESS != "" {
		if err := tunnel.CheckVLESSID(c.VLESS); err != nil || c.VLESS == vless.RegistrationID {
			return refuse("the VLESS user ID is not usable")
		}
	}
	var cred *group.Presented
	var adminMsg []byte
	if p.member {
		if adminMsg, err = adminMessage(cs, c.Key); err != nil {
			return nil, err
		}
	} else {
		if cred, err = credentialed(cs.PeerCertificates[0], c.Credentials, time.Now()); err != nil {
			return refuse(err.Error())
		}
		if err := f.versions.check(cred, remoteAddr(raw)); err != nil {
			return refuse(err.Error())
		}
		// A period's tag is the group's own choice: it never meets a tag
		// from a group CA.
		tag = credentialTag(cred.Tag)
	}
	r := &reg{tag: tag, obf: c.Obfuscation, vlessID: c.VLESS, seen: make(chan netip.AddrPort, 1), clients: map[netip.AddrPort]int{}, conn: tc, raw: raw}
	copy(r.key[:], c.Key)
	r.mac1 = mac1Key(r.key)
	hk, err := cs.ExportKeyingMaterial(helloLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	copy(r.helloKey[:], hk)
	var idb [8]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	r.id = binary.BigEndian.Uint64(idb[:])
	now := time.Now()
	r.packets, r.bytes = *newBucket(f.limits.PacketRate, now), *newBucket(f.limits.ByteRate, now)

	f.mu.Lock()
	old := f.regs[tag]
	f.mu.Unlock()
	var records []group.Record
	if p.member {
		// The records are checked outside the lock: their signatures take
		// time.
		if records, err = authority(cs.PeerCertificates[0], p.root, c, adminMsg, f.memory.records(tag)); err != nil {
			return refuse(err.Error())
		}
		if !fits(records) {
			return refuse("the group's authority records are too large for this forwarder")
		}
		if err := f.memory.room(tag, remoteAddr(raw), records); err != nil {
			return refuse(err.Error())
		}
	}
	var vlessAns *vlessAnswer
	if v := f.vlessCfg; r.vlessID != "" {
		// The group's packets come under a path of its own, the same at
		// each registration: v.XHTTP.Path, which every build may carry,
		// takes only registrations.
		r.vlessPath = f.groupPath(tag)
		vlessAns = &vlessAnswer{Transport: tunnel.TransportXHTTP, Port: v.XHTTP.Port, ServerName: v.XHTTP.Host, Path: v.XHTTP.Path + "/" + r.vlessPath}
	}
	f.mu.Lock()
	if o := f.regs[tag]; o != old {
		// Another registration of the group came meanwhile; this one
		// holds the records of the one it checked against only.
		f.mu.Unlock()
		return refuse("the group registered meanwhile; try again")
	}
	for _, o := range f.regs {
		if o.key == r.key && o.tag != tag {
			f.mu.Unlock()
			return refuse("another group registered that WireGuard key")
		}
	}
	if old == nil && len(f.regs) >= f.limits.Groups {
		f.mu.Unlock()
		return refuse("the forwarder is full")
	}
	if o := f.byVLESS[r.vlessID]; r.vlessID != "" && o != nil && o.tag != tag {
		f.mu.Unlock()
		return refuse("another group registered that VLESS user ID")
	}
	// The user ID is let in before the group's earlier registration goes,
	// so a refusal leaves that one as it was; the same user ID passes from
	// it to this one.
	if r.vlessID != "" && (old == nil || old.vlessID != r.vlessID) {
		if err := f.vless.AddUser(r.vlessID); err != nil {
			f.mu.Unlock()
			return refuse("the VLESS user ID is not usable")
		}
	}
	if old != nil {
		// The group's hub registers again, or another hub took over.
		if old.vlessID == r.vlessID {
			old.vlessID = ""
		}
		f.dropRegLocked(old)
	}
	if r.vlessPath != "" {
		if err := f.vless.AddPath(r.vlessPath); err != nil {
			r.vlessPath = ""
		}
	}
	a := answer{ID: r.id, Mask: f.mask[:]}
	if r.vlessID != "" {
		f.byVLESS[r.vlessID] = r
		a.VLESS = vlessAns
	}
	f.regs[tag], f.byID[r.id] = r, r
	if r.obf != nil {
		f.byInit[initSize(r.obf)] = append(f.byInit[initSize(r.obf)], r)
	}
	f.mu.Unlock()
	if p.member {
		f.memory.keep(tag, remoteAddr(raw), records)
	} else if err := f.versions.keep(cred, remoteAddr(raw)); errors.Is(err, errTableFull) {
		// Another registration took the room meanwhile.
		f.mu.Lock()
		f.dropRegLocked(r)
		f.mu.Unlock()
		return refuse(err.Error())
	} else if err != nil {
		f.logf("forward: keeping the state: %v", err)
	}
	if err := enc.Encode(a); err != nil {
		f.mu.Lock()
		f.dropRegLocked(r)
		f.mu.Unlock()
		f.memory.left(tag)
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return r, nil
}

// remoteAddr is the address a connection came from, the zero address if it
// has none.
func remoteAddr(c net.Conn) netip.Addr {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// credentialed checks a hub that registers with a credential: the
// period's hubs' credential (group.CheckPresented), which has not expired
// and lists the key of the hub's certificate among the hubs.
func credentialed(leaf *x509.Certificate, cs []group.Credential, now time.Time) (*group.Presented, error) {
	if len(cs) != 1 {
		return nil, errors.New("the hub sent no hubs' credential")
	}
	p, err := group.CheckPresented(cs, now)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, errors.New("the group's hubs' credential expired; the group's root starts a new period")
		}
		return nil, errors.New("the group's hubs' credential does not verify")
	}
	if !slices.Contains(p.Hubs.Hubs, group.KeyHashOf(leaf)) {
		return nil, errors.New("the group's hubs' credential does not list this hub")
	}
	return p, nil
}

// credentialTag is the name under which the forwarder keeps a group that
// registered with the period's tag: apart from the tags of group CAs.
func credentialTag(tag string) string { return "period " + tag }

// adminMessage is what the hub's root or admin CA signs: SHA-256 of a key
// from this TLS session and the hub's WireGuard key, so the signature
// proves nothing on another connection or for another key.
func adminMessage(cs tls.ConnectionState, wgKey []byte) ([]byte, error) {
	k, err := cs.ExportKeyingMaterial(adminLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append(k, wgKey...))
	return sum[:], nil
}

// SignAdmin signs a registration's admin message with the key of the
// group's root or of an admin CA.
func SignAdmin(key crypto.Signer, cs tls.ConnectionState, wgKey []byte) ([]byte, error) {
	msg, err := adminMessage(cs, wgKey)
	if err != nil {
		return nil, err
	}
	return key.Sign(rand.Reader, msg, crypto.SHA256)
}

// authority checks that a root or an admin of the hub's group signed the
// registration, and that neither it nor the hub was removed or frozen, by
// the records the hub sent and those the group's last registration left
// (known). It returns the records to keep for the group: the forwarder
// keeps them in memory while the group stays registered, so a removed admin
// that registers next cannot leave them out. It knows the group only by its
// group CA, the root the hub's member certificate verified to, whose tag
// names the group.
func authority(leaf, groupCA *x509.Certificate, c claim, msg []byte, known []group.Record) ([]group.Record, error) {
	if groupCA == nil {
		return nil, errors.New("the hub presented no root")
	}
	recs := group.NewRecords(groupCA)
	recs.AddAll(known)
	recs.AddAll(c.Records)
	path := append([]*x509.Certificate{groupCA}, recs.Roots()...)
	var admin *x509.Certificate
	if len(c.Admin) != 0 {
		ca, err := x509.ParseCertificate(c.Admin)
		if err != nil {
			return nil, errors.New("the admin CA cannot be read")
		}
		for _, root := range path {
			if group.CheckAdminCA(ca, root) == nil {
				admin = ca
				break
			}
		}
	}
	var signer *x509.Certificate
	for _, cand := range path {
		if admin != nil {
			cand = admin
		}
		if pub, ok := cand.PublicKey.(*ecdsa.PublicKey); ok && ecdsa.VerifyASN1(pub, msg, c.AdminSig) {
			signer = cand
			break
		}
		if admin != nil {
			break
		}
	}
	if signer == nil && memberOfAuthority(recs, leaf) {
		signer = leaf
	}
	if signer == nil {
		return nil, errors.New("only the group's root or an admin may register it, and this hub is neither")
	}
	s, l := group.KeyHashOf(signer), group.KeyHashOf(leaf)
	if recs.Revoked(s) || recs.Revoked(l) {
		return nil, errors.New("the hub was removed from its group")
	}
	if recs.Frozen(s) || recs.Frozen(l) {
		return nil, errors.New("the hub is a frozen admin of its group")
	}
	return recs.AuthorityRecords(), nil
}

// memberOfAuthority reports whether the records make the device of leaf,
// with leaf's key, the group's root or an admin: a phone hub, whose root or
// admin key signs only after Face ID, registers with its member key alone
// (docs/protocol.md, section 13).
func memberOfAuthority(recs *group.Records, leaf *x509.Certificate) bool {
	dev, err := group.DeviceOf(leaf)
	if err != nil {
		return false
	}
	k := group.KeyHashOf(leaf)
	if root, key := recs.RootMember(); root == dev && key == k {
		return true
	}
	for _, d := range recs.Devices() {
		if d.ID == dev && d.Key == k && d.Admin && !d.Frozen {
			return true
		}
	}
	return false
}

// proof is what a hub sends to prove it holds its WireGuard key: an HMAC,
// under the X25519 secret of its key and the forwarder's ephemeral one, of
// a key from this TLS session, so it proves nothing on another connection.
func proof(shared []byte, cs tls.ConnectionState) ([]byte, error) {
	k, err := cs.ExportKeyingMaterial(proofLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, shared)
	m.Write(k)
	return m.Sum(nil), nil
}
