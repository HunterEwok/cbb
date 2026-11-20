// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/HunterEwok/cbb/internal/blind"
	"github.com/HunterEwok/cbb/internal/refused"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
)

// Protocol is the ALPN protocol of a hub's registration: the forwarder
// speaks the one of 0.6 alone (D-106).
const Protocol = "cbb-forward/3"

// The labels of the keys the registration takes from TLS: the one the hub
// proves its WireGuard key under, and the one its hellos carry a MAC of.
const (
	proofLabel = "cbb forwarder key"
	helloLabel = "cbb forwarder hello"
)

// maxSetup bounds what the forwarder reads from a hub in all, frames and
// their lengths together.
const maxSetup = 1 << 20

// setupTimeout bounds a registration from the TCP connection to the
// forwarder's answer.
const setupTimeout = 15 * time.Second

// serverTLS is the forwarder's TLS: TLS 1.3, its own certificate, and the
// hub's certificate of its server key alone, which the forwarder checks
// itself, since it knows no group beforehand.
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
			_, err := serverKeyOf(cs.PeerCertificates)
			return err
		},
	}
}

// serverKeyOf is the hash of the server key of the one certificate a hub
// presents, which names neither a device nor a group: how the hubs'
// credential lists it.
func serverKeyOf(certs []*x509.Certificate) ([32]byte, error) {
	if len(certs) != 1 || certs[0].IsCA {
		return [32]byte{}, errors.New("forward: the hub must show the certificate of its server key alone")
	}
	pub, err := blind.PublicKeyOf(certs[0])
	if err != nil {
		return [32]byte{}, errors.New("forward: the hub's certificate holds no P-256 key")
	}
	return blind.KeyHash(blind.AlgES256, pub), nil
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
	}()
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
			if _, err := r.conn.Write(msgSeen(ep)); err != nil {
				return
			}
		}
	}
}

// register runs a registration's setup: TLS with the certificate of the
// hub's server key, then the hub's registration: the proof that it holds
// its WireGuard key, bound to this TLS session, and its group's hubs'
// credential that lists the server key.
func (f *Forwarder) register(raw net.Conn) (*reg, error) {
	raw.SetDeadline(time.Now().Add(setupTimeout))
	tc := tls.Server(raw, f.tlsCfg)
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	cs := tc.ConnectionState()
	leaf, err := serverKeyOf(cs.PeerCertificates)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if _, err := tc.Write(msgChallenge(eph.PublicKey().Bytes())); err != nil {
		return nil, err
	}
	refuse := func(msg string) (*reg, error) {
		tc.Write(msgError(msg))
		return nil, errors.New(msg)
	}
	t, m, _, err := blind.ReadFrame(io.LimitReader(tc, maxSetup), maxSetup)
	if err != nil {
		return refuse("the registration breaks the format: " + err.Error())
	}
	c, err := readRegister(t, m)
	if err != nil {
		return refuse("the registration breaks the format: " + err.Error())
	}
	pub, err := ecdh.X25519().NewPublicKey(c.Key[:])
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
	if !hmac.Equal(want, c.Proof[:]) {
		return refuse("the hub does not hold that WireGuard key")
	}
	if c.BadObfuscation {
		return refuse("the obfuscation settings are not usable")
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
	cred, err := credentialed(leaf, c.Credentials, time.Now())
	if err != nil {
		return refuse(err.Error())
	}
	if err := f.versions.check(cred, remoteAddr(raw)); err != nil {
		return refuse(err.Error())
	}
	tag := credentialTag(cred.tag)
	if f.refused.Refused(tag) {
		return refuse(refused.Message)
	}
	r := &reg{tag: tag, obf: c.Obfuscation, vlessID: c.VLESS, seen: make(chan netip.AddrPort, 1), clients: map[netip.AddrPort]int{}, conn: tc, raw: raw}
	r.key = c.Key
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
	// The registration's ID is 1 to 2^63 - 1, as the format takes it.
	r.id = binary.BigEndian.Uint64(idb[:])>>1 | 1
	now := time.Now()
	r.packets, r.bytes = *newBucket(f.limits.PacketRate, now), *newBucket(f.limits.ByteRate, now)

	f.mu.Lock()
	old := f.regs[tag]
	f.mu.Unlock()
	var w *way
	if v := f.vlessCfg; r.vlessID != "" {
		// The group's packets come under a path of its own, made from its
		// user ID: v.XHTTP.Path, which every build may carry, takes only
		// registrations.
		r.vlessPath = tunnel.GroupPath(r.vlessID)
		user, _ := hex.DecodeString(stripDashes(r.vlessID))
		w = &way{User: [16]byte(user), Port: v.XHTTP.Port, Host: v.XHTTP.Host, Path: v.XHTTP.Path + "/" + r.vlessPath}
	}
	f.mu.Lock()
	// The list may have changed since it was asked: reloadRefused changes
	// it before it takes f.mu, so this registration is either refused
	// here or dropped by it.
	if f.refused.Refused(tag) {
		f.mu.Unlock()
		return refuse(refused.Message)
	}
	if o := f.regs[tag]; o != old {
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
	if r.vlessID != "" {
		f.byVLESS[r.vlessID] = r
	} else {
		w = nil
	}
	f.regs[tag], f.byID[r.id] = r, r
	if r.obf != nil {
		f.byInit[initSize(r.obf)] = append(f.byInit[initSize(r.obf)], r)
	}
	f.mu.Unlock()
	if err := f.versions.keep(cred, remoteAddr(raw)); errors.Is(err, errTableFull) {
		// Another registration took the room meanwhile.
		f.mu.Lock()
		f.dropRegLocked(r)
		f.mu.Unlock()
		return refuse(err.Error())
	} else if err != nil {
		f.logf("forward: keeping the state: %v", err)
	}
	if _, err := tc.Write(msgRegistered(r.id, f.mask[:], w)); err != nil {
		f.mu.Lock()
		f.dropRegLocked(r)
		f.mu.Unlock()
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

// shown is what the forwarder keeps of a hub's credential: the period's
// tag in hex, the hash of the period key that signed it, its version and
// its expiry.
type shown struct {
	tag       string
	signer    [32]byte
	version   uint64
	expiresMs int64
}

// credentialed checks a hub's credentials (docs/protocol.md, section 18,
// "What a server checks"): the hubs' credential alone, which has not
// expired and lists the hub's server key leaf among the hubs.
func credentialed(leaf [32]byte, envs [][]byte, now time.Time) (*shown, error) {
	if len(envs) != 1 {
		return nil, errors.New("the hub must show its hubs' credential alone")
	}
	c, err := blind.ReadCredential(envs[0])
	if err != nil || c.Kind != blind.TypeHubs {
		return nil, errors.New("the group's hubs' credential does not verify")
	}
	if !c.Live(uint64(now.UnixMilli())) {
		return nil, errors.New("the group's hubs' credential expired; the group's root starts a new period")
	}
	if !c.Lists(leaf) {
		return nil, errors.New("the group's hubs' credential does not list this hub")
	}
	exp := int64(min(c.ExpiresMs, 1<<62))
	return &shown{tag: hex.EncodeToString(c.Group[:]), signer: c.SignerHash(), version: c.Version, expiresMs: exp}, nil
}

// credentialTag is the name under which the forwarder keeps a group: its
// period's tag, as the list of refused groups names it.
func credentialTag(tag string) string { return "period " + tag }

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
