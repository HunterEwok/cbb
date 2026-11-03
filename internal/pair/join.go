// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/third_party/cpace"
)

// A Joiner is a device that joins a group: its new device ID and key.
type Joiner struct {
	ID   group.DeviceID
	Key  crypto.Signer // a P-256 key, in a file or a TPM
	Info Info

	// Member is the device ID of the member that admitted this device,
	// once a join succeeded.
	Member group.DeviceID
	// Records are the records that lead to the group's roots, as the
	// Welcome gave them, set before the identity is saved: the new device
	// keeps them with its records, so the roots it trusts are those the
	// records name.
	Records []group.Record
	// ClaimTimes are when the set first held each claim of Records, the
	// admitting member's times where they are earlier (Welcome.ClaimTimes).
	ClaimTimes []group.ClaimTime

	certOnce sync.Once
	certDER  []byte // the self-signed certificate for Key, made once
	certErr  error
}

// NewJoiner returns a joiner with a new device ID and key.
func NewJoiner(info Info) (*Joiner, error) {
	if err := info.check(); err != nil {
		return nil, err
	}
	key, err := group.NewDeviceKey()
	if err != nil {
		return nil, err
	}
	return &Joiner{ID: group.NewDeviceID(), Key: key, Info: info}, nil
}

// cert returns the joiner's self-signed certificate for its key, the same
// on every call: it is what the QR code's fingerprint names.
func (j *Joiner) cert() ([]byte, error) {
	j.certOnce.Do(func() {
		tmpl := &x509.Certificate{
			Subject:   pkix.Name{CommonName: string(j.ID)},
			NotBefore: time.Unix(0, 0),
			NotAfter:  time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		}
		j.certDER, j.certErr = x509.CreateCertificate(rand.Reader, tmpl, tmpl, group.PublicKey(j.Key), j.Key)
	})
	return j.certDER, j.certErr
}

// tlsConfigVerifiedByCPace returns the joiner's TLS configuration, for
// either end of the connection. The joiner cannot check the member's
// certificate during the handshake, since it does not know the group CA
// yet: the CPace exchange, bound to this TLS session and to the member's
// certificate, authenticates the member, and the joiner checks the
// certificate against the group CA it receives.
func (j *Joiner) tlsConfigVerifiedByCPace() (*tls.Config, error) {
	der, err := j.cert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: j.Key}},
		InsecureSkipVerify:     true,
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{Protocol},
		SessionTicketsDisabled: true,
	}, nil
}

// Fingerprint returns the fingerprint of the joiner's certificate that a
// member dialing the joiner checks: SHA-256 over the DER, in base64url
// without padding.
func (j *Joiner) Fingerprint() (string, error) {
	der, err := j.cert()
	if err != nil {
		return "", err
	}
	return CertFingerprint(der), nil
}

// CertFingerprint returns the fingerprint of a certificate's key, the one
// form of docs/protocol.md (Conventions, "Fingerprints"): SHA-256 over its
// SubjectPublicKeyInfo in standard base64, as a record's key hash. It is
// "" for bytes that are no certificate.
func CertFingerprint(der []byte) string {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	return group.KeyHashOf(c).String()
}

// Join runs the joining side of a pairing over conn, a connection the
// joiner dialed to the member's port, with the code the user typed. It
// checks what the member sends, builds the device's new identity, calls
// save with it, and tells the member whether that worked.
func (j *Joiner) Join(ctx context.Context, conn net.Conn, code string, save func(*group.Identity) error) (*group.Identity, error) {
	cfg, err := j.tlsConfigVerifiedByCPace()
	if err != nil {
		conn.Close()
		return nil, err
	}
	code, err = NormalizeCode(code)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return j.join(ctx, tls.Client(conn, cfg), []byte(code), 0, false, save)
}

// JoinSecret runs the joining side of a pairing like Join, with the secret
// of a remote invitation in place of a typed code. The member then asks
// its admin to confirm the device before it admits it, so the joiner waits
// up to wait longer than for a code.
func (j *Joiner) JoinSecret(ctx context.Context, conn net.Conn, secret []byte, wait time.Duration, save func(*group.Identity) error) (*group.Identity, error) {
	cfg, err := j.tlsConfigVerifiedByCPace()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if len(secret) < MinSecret {
		conn.Close()
		return nil, errors.New("pair: the invitation's secret is too short")
	}
	return j.join(ctx, tls.Client(conn, cfg), secret, wait, false, save)
}

// Accept runs the joining side of a pairing over conn, a connection that a
// member dialed to the joiner, which listens and showed its address and
// Fingerprint in the QR code. The member, which dialed, confirms the key
// first, so the joiner reveals nothing to a device that does not know the
// code: a failed attempt is never Spent, and the joiner may take another.
func (j *Joiner) Accept(ctx context.Context, conn net.Conn, code string, save func(*group.Identity) error) (*group.Identity, error) {
	cfg, err := j.tlsConfigVerifiedByCPace()
	if err != nil {
		conn.Close()
		return nil, err
	}
	code, err = NormalizeCode(code)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return j.join(ctx, tls.Server(conn, cfg), []byte(code), 0, true, save)
}

// join runs the exchange with the password: the code, or an invitation's
// secret. With memberFirst the member confirms the key before the joiner
// does; wait is the time the member may take to confirm the device.
func (j *Joiner) join(ctx context.Context, tc *tls.Conn, password []byte, wait time.Duration, memberFirst bool, save func(*group.Identity) error) (*group.Identity, error) {
	defer tc.Close()
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout+wait)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { tc.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	cs := tc.ConnectionState()
	if cs.NegotiatedProtocol != Protocol || len(cs.PeerCertificates) == 0 {
		return nil, errors.New("pair: the device does not offer pairing")
	}
	memberCert := cs.PeerCertificates[0]
	own, err := j.cert()
	if err != nil {
		return nil, err
	}
	ci, sid, err := binding(cs, memberCert.Raw, own)
	if err != nil {
		return nil, err
	}
	return j.exchange(tc, password, ci, sid, memberCert, memberFirst, save)
}

// exchange runs the frames of the exchange over rw, bound to a channel by ci
// and sid, with the member whose certificate is memberCert.
func (j *Joiner) exchange(tc io.ReadWriter, password []byte, ci, sid []byte, memberCert *x509.Certificate, memberFirst bool, save func(*group.Identity) error) (*group.Identity, error) {
	ad, err := json.Marshal(j.Info)
	if err != nil {
		return nil, err
	}
	st, msg, err := cpace.Start(&cpace.Config{Role: cpace.Initiator, Password: password, ChannelID: ci, SessionID: sid, AD: ad})
	if err != nil {
		return nil, err
	}
	if err := writeFrame(tc, &frame{Msg: msg, AD: ad}); err != nil {
		return nil, err
	}
	reply, err := readFrame(tc)
	if err != nil {
		return nil, err
	}
	if reply.Error != "" {
		return nil, errorOf(reply.Error)
	}
	if _, err := st.Finish(reply.Msg, reply.AD); err != nil {
		return nil, err
	}
	var member memberAD
	if err := json.Unmarshal(reply.AD, &member); err != nil {
		return nil, err
	}
	// spent marks an error after the joiner's tag went out, from which on
	// the other side can check a guess of the code; when the member
	// confirmed first, it already proved that it knows the code.
	spent := func(err error) error { return &spentError{err} }
	if memberFirst {
		if err := st.Verify(reply.Tag); err != nil {
			writeFrame(tc, &frame{Error: codeOf(ErrWrongCode)})
			return nil, ErrWrongCode
		}
		spent = func(err error) error { return err }
	}
	if err := writeFrame(tc, &frame{Tag: st.Tag()}); err != nil {
		return nil, spent(err)
	}
	final, err := readFrame(tc)
	if err != nil {
		return nil, spent(err)
	}
	if final.Error != "" {
		return nil, spent(errorOf(final.Error))
	}
	if !memberFirst && st.Verify(final.Tag) != nil || final.Welcome == nil {
		return nil, spent(errors.New("pair: the other device did not prove that it knows the code"))
	}
	id, err := j.identity(final.Welcome, memberCert, member)
	if err == nil {
		err = save(id)
	}
	if err != nil {
		writeFrame(tc, &frame{Error: "refused"})
		return nil, spent(err)
	}
	// The identity is stored, and the member admitted the device when it
	// sent the welcome, whether or not it hears this.
	writeFrame(tc, &frame{OK: true})
	j.Member, _ = group.DeviceOf(memberCert)
	return id, nil
}

// identity checks what the member sent and builds the new identity.
func (j *Joiner) identity(w *Welcome, memberCert *x509.Certificate, member memberAD) (*group.Identity, error) {
	var err error
	id := &group.Identity{ID: j.ID, Key: j.Key}
	if id.Cert, err = x509.ParseCertificate(w.Cert); err != nil {
		return nil, err
	}
	if id.GroupCA.Cert, err = x509.ParseCertificate(w.GroupCA); err != nil {
		return nil, err
	}
	if group.Tag(id.GroupCA.Cert) != member.Group {
		return nil, errors.New("pair: the member sent another group CA than it announced")
	}
	// The roots are only those the records lead to: an admin could
	// otherwise name a root of its own, and every certificate from it
	// would pass here for good, whatever the group's root removes.
	recs := group.NewRecords(id.GroupCA.Cert)
	recs.AddAll(w.Records)
	recs.TakeClaimTimes(w.ClaimTimes)
	id.Roots = recs.Roots()
	if len(id.Roots) != len(w.Roots) {
		return nil, errors.New("pair: the member's roots are not the ones the group's records lead to")
	}
	for i, root := range id.Roots {
		if !bytes.Equal(root.Raw, w.Roots[i]) {
			return nil, errors.New("pair: the member's roots are not the ones the group's records lead to")
		}
	}
	j.Records, j.ClaimTimes = recs.All(), recs.ClaimTimes()
	// An admin phone issues with its admin CA, under one of the group's
	// roots.
	issuers := id.Trusted()
	if w.Issuer != nil {
		if id.Issuer, err = x509.ParseCertificate(w.Issuer); err != nil {
			return nil, err
		}
		err = errors.New("not under a root of the group")
		for _, root := range issuers {
			if err = group.CheckAdminCA(id.Issuer, root); err == nil {
				break
			}
		}
		if err != nil {
			return nil, &CauseError{Msg: "pair: the member's admin CA is not from the group", Err: err}
		}
		issuers = append([]*x509.Certificate{id.Issuer}, issuers...)
	}
	// The member's own certificate is from that CA, or from a root (an
	// admin phone whose root renewed its certificate), and names the
	// device it announced.
	err = errors.New("no issuer")
	for _, issuer := range issuers {
		if err = memberCert.CheckSignatureFrom(issuer); err == nil {
			break
		}
	}
	if err != nil {
		return nil, &CauseError{Msg: "pair: the member's certificate is not from the group", Err: err}
	}
	if dev, err := group.DeviceOf(memberCert); err != nil || dev != member.Device {
		return nil, errors.New("pair: the member's certificate does not name the member")
	}
	if err := id.Check(); err != nil {
		return nil, err
	}
	return id, nil
}
