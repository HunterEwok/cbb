// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/HunterEwok/cbb/internal/benchtime"
)

// MemberProtocol is the ALPN protocol of connections between members.
const MemberProtocol = "cbb/2"

// TLSOptions adjust the TLS configuration of member connections.
type TLSOptions struct {
	// Allow, if set, is called with the peer's device ID and the
	// certificates it presented (leaf first) once they are verified; an
	// error rejects the peer, for example a revoked device.
	Allow func(DeviceID, []*x509.Certificate) error

	// RecordsOnly lets a peer through for which Allow returns
	// ErrRecordsOnly; the caller then exchanges records with it and
	// nothing else.
	RecordsOnly bool

	// Now returns the current time; time.Now if nil.
	Now func() time.Time
}

func (o TLSOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return benchtime.Now()
}

// ServerTLS returns the TLS configuration for accepting connections from
// members: TLS 1.3 only, and a client certificate from the group CA is
// required.
func (id *Identity) ServerTLS(opt TLSOptions) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.memberTLSCert()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    id.groupPool(),
		NextProtos:   []string{MemberProtocol},
		Time:         id.verifyClock(opt),
		// Member connections last; without resumption every connection
		// checks the full chain.
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := id.checkPeer(cs, opt)
			return err
		},
	}
}

// ClientTLS returns the TLS configuration for connecting to the member
// peer, whose device ID came from discovery: TLS 1.3 only, and the server
// must present the member certificate of that device from the group CA.
func (id *Identity) ClientTLS(peer DeviceID, opt TLSOptions) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.memberTLSCert()},
		RootCAs:      id.groupPool(),
		ServerName:   peer.HostName(),
		NextProtos:   []string{MemberProtocol},
		Time:         id.verifyClock(opt),
		VerifyConnection: func(cs tls.ConnectionState) error {
			got, err := id.checkPeer(cs, opt)
			if err == nil && got != peer {
				err = fmt.Errorf("group: reached %s instead of %s", got, peer)
			}
			return err
		},
	}
}

// PhoneTLS returns the TLS configuration for the iPhone port, with the
// cbb.local certificate. It returns nil on a device without one.
func (id *Identity) PhoneTLS() *tls.Config {
	cert := id.PhoneCertificate()
	if cert == nil {
		return nil
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
	}
}

// PhoneCertificate returns the cbb.local certificate with its CA, for
// the iPhone port, or nil on a device without one.
func (id *Identity) PhoneCertificate() *tls.Certificate {
	if id.Phone == nil {
		return nil
	}
	cert := id.tlsCert(id.Phone)
	cert.Certificate = append(cert.Certificate, id.PhoneCA.Cert.Raw)
	return &cert
}

// PeerID returns the device ID of the member at the other end of a
// connection that completed its handshake with ServerTLS or ClientTLS.
func PeerID(cs tls.ConnectionState) (DeviceID, error) {
	if len(cs.PeerCertificates) == 0 {
		return "", errors.New("group: the peer sent no certificate")
	}
	return DeviceOf(cs.PeerCertificates[0])
}

// MemberChain returns the peer's certificates that crypto/tls verified to a
// root of the group, leaf first, without the root: the leaf and, when an
// admin CA issued it, that admin CA. Certificates the peer presented but
// the verification did not use are left out, so callers never mistake one
// of them for the leaf's issuer. It returns nil for a connection that was
// not verified.
func MemberChain(cs tls.ConnectionState) []*x509.Certificate {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) < 2 {
		return nil
	}
	c := cs.VerifiedChains[0]
	return c[:len(c)-1]
}

// checkPeer runs after crypto/tls verified the peer's certificate chain to
// the group CA: it checks the protocol and the device ID and asks Allow.
func (id *Identity) checkPeer(cs tls.ConnectionState, opt TLSOptions) (DeviceID, error) {
	if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != MemberProtocol {
		return "", errors.New("group: the peer does not speak the member protocol")
	}
	peer, err := PeerID(cs)
	if err != nil {
		return "", err
	}
	if opt.Allow != nil {
		if err := opt.Allow(peer, MemberChain(cs)); err != nil && !(opt.RecordsOnly && errors.Is(err, ErrRecordsOnly)) {
			return "", err
		}
	}
	return peer, nil
}

// memberTLSCert is the member certificate for member connections, with its
// admin CA when one issued it, so that the peer can build the chain to the
// group CA.
//
// On the admin that took the group over it is the certificate from before
// the takeover (PrevCert) while that lasts: a member that missed the
// takeover knows only the old root, and takes the root record over a
// connection it can verify; the others take it too, since the takeover
// keeps the admin CA that issued it (docs/protocol.md, section 10). It
// stops before the certificate is due for renewal, so that no admin renews
// the root's certificate from its admin CA.
func (id *Identity) memberTLSCert() tls.Certificate {
	leaf, issuer := id.Cert, id.Issuer
	if id.PrevCert != nil && benchtime.Now().Before(id.PrevCert.NotAfter.Add(-memberRenewBefore)) && SameKey(id.Key, id.PrevCert.PublicKey) {
		leaf, issuer = id.PrevCert, id.PrevIssuer
	}
	cert := id.tlsCert(leaf)
	if issuer != nil {
		cert.Certificate = append(cert.Certificate, issuer.Raw)
	}
	return cert
}

// ForwarderCertificate returns the member certificate with its admin CA,
// if any, and the group's roots: a hub registers with it on its forwarder,
// which knows no group beforehand and checks the whole chain.
func (id *Identity) ForwarderCertificate() tls.Certificate {
	cert := id.memberTLSCert()
	for _, root := range id.Trusted() {
		cert.Certificate = append(cert.Certificate, root.Raw)
	}
	return cert
}

func (id *Identity) tlsCert(leaf *x509.Certificate) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: id.Key, Leaf: leaf}
}

func (id *Identity) groupPool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, root := range id.Trusted() {
		pool.AddCert(root)
	}
	return pool
}

// verifyClock returns the clock crypto/tls checks member certificates
// with; see verifyTime.
func (id *Identity) verifyClock(opt TLSOptions) func() time.Time {
	ca := id.Root()
	return func() time.Time { return verifyTime(ca, opt.now()) }
}

// ServerCertificateName is the subject of the certificate a device
// registers with on a server when it has the group's credentials: it names
// no device and no group.
const ServerCertificateName = "cbb server"

// ServerCertificate returns the certificate a device registers with on a
// forwarder or a relay when it has the group's credentials
// (docs/protocol.md, section 18): one of its server key, signed by that
// key, that names neither a device nor a group.
func ServerCertificate(key crypto.Signer) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: ServerCertificateName},
		NotBefore:    time.Unix(0, 0).UTC(),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
