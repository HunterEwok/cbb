// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/third_party/cpace"
	"github.com/HunterEwok/cbb/internal/uptime"
)

// Options adjust a pairing window. The zero value uses the system clocks.
type Options struct {
	// Records, when set, returns the records that lead to the admin's
	// roots (group.Records.PathRecords), for the Welcome; a group that was
	// handed over needs them, or the new device refuses the Welcome.
	Records func() []group.Record
	// ClaimTimes, when set, returns when the admin first held each claim
	// of the records (group.Records.ClaimTimes), for the Welcome.
	ClaimTimes func() []group.ClaimTime
	// Taken, when set, reports whether a device ID is in the group already:
	// a device record names it or a member with it is connected. Such a
	// joiner is refused before the exchange, since a device picks its own
	// ID and a second key under one ID would be a member that removing the
	// device leaves behind.
	Taken func(group.DeviceID) bool

	// Secret, when set, is the password in place of a six-digit code: the
	// secret of a remote invitation, at least MinSecret bytes.
	Secret []byte
	// Lifetime is how long the window stays open; Lifetime if zero.
	Lifetime time.Duration
	// Confirm, when set, is asked whether to admit a device that proved it
	// knows the code, before its certificate is made; an error refuses it,
	// and the attempt counts as failed. It may wait up to ConfirmWait for
	// the admin's answer, and should stop when ctx ends.
	Confirm     func(ctx context.Context, r Request) error
	ConfirmWait time.Duration
	// Admins lets the window make a phone that offers an admin key an
	// admin (cbb pair -admin), on the group's root only; any other window
	// refuses such a phone, so that the code alone never makes an admin.
	Admins bool
	// KnownKey, when set, reports whether the records name a key hash
	// already: a device's key, an admin key or the recovery key. Such an
	// admin key is refused, so that admitting a phone never gives a key
	// that the group knows powers it did not have.
	KnownKey func(group.KeyHash) bool

	Now       func() time.Time                        // for the certificates; time.Now if nil
	Uptime    func() time.Duration                    // for the window's lifetime; uptime.Now if nil
	AfterFunc func(time.Duration, func()) func() bool // the expiry timer, returning its Stop; time.AfterFunc if nil
}

// A Window is an open pairing window on an admin: a member that holds the
// CA keys, or a computer that the root phone made an admin.
type Window struct {
	admin   *group.Identity
	code    []byte // the password: the six digits, or a secret
	records func() []group.Record
	claims  func() []group.ClaimTime
	taken   func(group.DeviceID) bool
	confirm func(context.Context, Request) error
	wait    time.Duration // how long confirm may take
	admins  bool          // makes a phone that offers an admin key an admin
	known   func(group.KeyHash) bool
	now     func() time.Time
	uptime  func() time.Duration

	mu        sync.Mutex
	expires   time.Duration // on the uptime clock
	busy      bool          // an attempt is running
	committed bool          // the running attempt is sending the welcome
	cancel    context.CancelFunc
	failures  int
	idle      map[string]int // attempts by address that ended before they counted
	err       error          // why the window closed; nil while open
	result    *Result
	done      chan struct{}
	stopTimer func() bool
}

// Request is a device that proved it knows the code, for the admin to
// confirm.
type Request struct {
	Device group.DeviceID
	Info   Info
	// Fingerprint is the fingerprint of the device's key, as
	// Joiner.Fingerprint shows it on the device.
	Fingerprint string
}

// Result is a device the window admitted.
type Result struct {
	Device group.DeviceID
	Info   Info
	Cert   *x509.Certificate
	// AdminCA is the admin CA the root issued a phone for its admin key;
	// nil for any other device.
	AdminCA *x509.Certificate
	// Confirmed reports whether the device said that it stored its
	// identity. When it did not, it may still hold the certificate, and,
	// for a Linux member, the CA keys.
	Confirmed bool
}

// Open opens a pairing window for the code.
func Open(admin *group.Identity, code string, opt Options) (*Window, error) {
	if ca, _ := admin.Signer(); ca == nil {
		return nil, errors.New("pair: only an admin can admit devices: the computer that created the group, or a member its root made an admin")
	}
	if opt.Admins && !admin.IsRoot() {
		return nil, ErrPhoneNeedsRoot
	}
	switch {
	case opt.Secret != nil && len(opt.Secret) < MinSecret:
		return nil, errors.New("pair: the secret is too short")
	case opt.Secret != nil:
		code = string(opt.Secret)
	default:
		var err error
		if code, err = NormalizeCode(code); err != nil {
			return nil, err
		}
	}
	lifetime := opt.Lifetime
	if lifetime <= 0 {
		lifetime = Lifetime
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Uptime == nil {
		opt.Uptime = uptime.Now
	}
	if opt.AfterFunc == nil {
		opt.AfterFunc = func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }
	}
	w := &Window{admin: admin, code: []byte(code), records: opt.Records, claims: opt.ClaimTimes, taken: opt.Taken, confirm: opt.Confirm, wait: opt.ConfirmWait, admins: opt.Admins, known: opt.KnownKey,
		now: opt.Now, uptime: opt.Uptime, expires: opt.Uptime() + lifetime, done: make(chan struct{})}
	stop := opt.AfterFunc(lifetime, w.expire)
	w.mu.Lock()
	w.stopTimer = stop
	w.mu.Unlock()
	return w, nil
}

// Code returns the window's code, normalized to six digits; for a window
// with a secret, the secret.
func (w *Window) Code() string { return string(w.code) }

// Done is closed when the window closes.
func (w *Window) Done() <-chan struct{} { return w.done }

// Result returns the outcome once the window has closed: the device it
// admitted, or why it closed without one.
func (w *Window) Result() (*Result, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.result != nil {
		return w.result, nil
	}
	return nil, w.err
}

// Close closes the window. A running attempt fails at once, unless it has
// already started sending the welcome; then the device is admitted.
func (w *Window) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.committed {
		return // succeed closes the window
	}
	w.closeLocked(ErrClosed)
	if w.cancel != nil {
		w.cancel()
	}
}

// expire closes the window when its time is up. A running attempt may
// still finish; the window closes when it ends.
func (w *Window) expire() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.busy {
		w.closeLocked(ErrExpired)
	}
}

func (w *Window) closeLocked(err error) {
	if w.err != nil || w.result != nil {
		return
	}
	w.err = err
	if w.stopTimer != nil {
		w.stopTimer()
	}
	close(w.done)
}

// acquire starts an attempt from addr ("" for one the member dialed), or
// reports why the window takes none.
func (w *Window) acquire(cancel context.CancelFunc, addr string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.busy && w.uptime() >= w.expires {
		w.closeLocked(ErrExpired)
	}
	switch {
	case w.result != nil:
		return ErrClosed
	case w.err != nil:
		return w.err
	case w.busy, addr != "" && w.idle[addr] >= maxIdle:
		return ErrBusy
	}
	w.busy, w.cancel = true, cancel
	return nil
}

// commit marks the running attempt as admitted, just before the welcome
// goes out, unless the window was closed meanwhile.
func (w *Window) commit() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	w.committed = true
	return nil
}

// release ends an attempt from addr that admitted no device; failed
// reports whether it counts. One that does not count still counts against
// its address, so that one device cannot keep the window busy.
func (w *Window) release(failed bool, addr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.busy, w.cancel = false, nil
	if !failed && addr != "" {
		if w.idle == nil {
			w.idle = map[string]int{}
		}
		if len(w.idle) < 1024 {
			w.idle[addr]++
		}
	}
	if failed {
		w.failures++
		if w.failures >= MaxFailures {
			w.closeLocked(ErrTooMany)
		}
	}
	if w.uptime() >= w.expires {
		w.closeLocked(ErrExpired)
	}
}

// succeed records the admitted device and closes the window.
func (w *Window) succeed(r *Result) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.busy, w.committed, w.cancel = false, false, nil
	w.result = r
	if w.stopTimer != nil {
		w.stopTimer()
	}
	close(w.done)
}

// ServerTLS returns the TLS configuration for connections to this window.
// It presents the certificate the window binds the exchange to: the admin's
// identity when the window opened, which a renewal while it is open (an
// admin's new admin CA, a renewed member certificate) does not change, or
// every joiner would fail as with a wrong code.
func (w *Window) ServerTLS() *tls.Config { return ServerTLS(w.admin) }

// ServerTLS returns the TLS configuration for pairing connections: the
// member's own certificate, and any client certificate, which the exchange
// authenticates.
func ServerTLS(admin *group.Identity) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{{Certificate: [][]byte{admin.Cert.Raw}, PrivateKey: admin.Key, Leaf: admin.Cert}},
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{Protocol},
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != Protocol {
				return errors.New("pair: the client does not speak the pairing protocol")
			}
			id, err := joinerID(cs)
			if err == nil && id == admin.ID {
				err = errors.New("pair: the joining device has this member's own device ID")
			}
			return err
		},
	}
}

// ClientTLS returns the TLS configuration for dialing a joiner that listens:
// the member's own certificate, and the joiner's self-signed certificate,
// which must have the fingerprint fp from the joiner's QR code.
func ClientTLS(admin *group.Identity, fp string) *tls.Config {
	return clientTLSVerifiedByFingerprint(admin, fp)
}

// clientTLSVerifiedByFingerprint builds ClientTLS: crypto/tls cannot check a
// self-signed certificate against a fingerprint, so VerifyConnection does.
func clientTLSVerifiedByFingerprint(admin *group.Identity, fp string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{{Certificate: [][]byte{admin.Cert.Raw}, PrivateKey: admin.Key, Leaf: admin.Cert}},
		InsecureSkipVerify: true, // checked below against the fingerprint
		NextProtos:         []string{Protocol},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != Protocol {
				return errors.New("pair: the device does not offer pairing")
			}
			if len(cs.PeerCertificates) != 1 || group.KeyHashOf(cs.PeerCertificates[0]).String() != fp {
				return errors.New("pair: the device is not the one in the QR code")
			}
			id, err := joinerID(cs)
			if err == nil && id == admin.ID {
				err = errors.New("pair: the joining device has this member's own device ID")
			}
			return err
		},
	}
}

// joinerID returns the device ID of the joiner's self-signed certificate.
func joinerID(cs tls.ConnectionState) (group.DeviceID, error) {
	if len(cs.PeerCertificates) != 1 {
		return "", errors.New("pair: the joining device must send exactly one certificate")
	}
	c := cs.PeerCertificates[0]
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return "", errors.New("pair: the joining device's key is not a P-256 key")
	}
	return group.ParseDeviceID(c.Subject.CommonName)
}

// Refuse answers a pairing connection, whose TLS handshake used ServerTLS,
// with err, such as ErrClosed when no window is open, and closes it. The
// joiner sees err instead of a broken handshake.
func Refuse(ctx context.Context, conn *tls.Conn, err error) {
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, refuseTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	// Read the joiner's first message before answering, as Serve does.
	readFrame(conn)
	writeFrame(conn, &frame{Error: codeOf(err)})
}

// Serve runs the member's side of one pairing connection, whose TLS
// handshake used ServerTLS. It returns the error of this attempt; Result
// reports the outcome of the window.
func (w *Window) Serve(ctx context.Context, conn *tls.Conn) error {
	return w.attempt(ctx, conn, false)
}

// Dial runs the member's side of a pairing with a joiner that listens:
// conn is a connection the member dialed to the address in the joiner's QR
// code, and fp the fingerprint in it. The member, which dialed, confirms the
// key first; the joiner tells it whether that was right.
func (w *Window) Dial(ctx context.Context, conn net.Conn, fp string) error {
	return w.attempt(ctx, tls.Client(conn, ClientTLS(w.admin, fp)), true)
}

// attempt runs one attempt; with dialed, the member confirms first.
func (w *Window) attempt(ctx context.Context, conn *tls.Conn, dialed bool) error {
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout+w.wait)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	addr := ""
	if !dialed {
		addr = hostOf(conn.RemoteAddr())
	}
	if err := w.acquire(cancel, addr); err != nil {
		// Read the joiner's first message before answering, so the answer
		// does not arrive while the joiner is still writing.
		readFrame(conn)
		writeFrame(conn, &frame{Error: codeOf(err)})
		return err
	}
	res, started, err := w.serve(ctx, conn, dialed)
	if res != nil {
		w.succeed(res)
		if !res.Confirmed {
			return fmt.Errorf("pair: %s got its certificate but did not confirm that it stored it: %w", res.Device, err)
		}
		return nil
	}
	if ctx.Err() != nil && errors.Is(context.Cause(ctx), context.Canceled) {
		err = ErrClosed // Close ended the attempt
	}
	if errors.Is(err, ErrClosed) {
		addr = "" // not the joiner's doing
	}
	w.release(started, addr)
	writeFrame(conn, &frame{Error: codeOf(err)})
	return err
}

// hostOf returns the IP address of a connection's remote end, or "" when it
// has none.
func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return ""
	}
	return host
}

// serve runs the exchange. It returns a result once the welcome went out,
// with the error of the last step if the device did not confirm; started
// reports whether the joiner got the member's CPace message, after which a
// failure counts. With memberFirst the member sends its confirmation tag
// with its CPace message, and the joiner answers with its own tag or an
// error.
func (w *Window) serve(ctx context.Context, conn *tls.Conn, memberFirst bool) (res *Result, started bool, err error) {
	cs := conn.ConnectionState()
	joiner, err := joinerID(cs)
	if err != nil {
		return nil, false, err
	}
	if w.taken != nil && w.taken(joiner) {
		readFrame(conn) // answered after the joiner's first message, as acquire's errors
		return nil, false, ErrTaken
	}
	if !memberFirst {
		conn.SetReadDeadline(time.Now().Add(firstTimeout))
	}
	first, err := readFrame(conn)
	if err != nil {
		return nil, false, err
	}
	conn.SetReadDeadline(time.Time{})
	if ctx.Err() != nil {
		conn.SetDeadline(time.Unix(1, 0)) // as attempt's AfterFunc, which the line above may have undone
	}
	var info Info
	if err := json.Unmarshal(first.AD, &info); err != nil {
		return nil, false, fmt.Errorf("pair: bad device description: %w", err)
	}
	if err := info.check(); err != nil {
		return nil, false, err
	}
	ci, sid, err := binding(cs, w.admin.Cert.Raw, cs.PeerCertificates[0].Raw)
	if err != nil {
		return nil, false, err
	}
	ad, err := json.Marshal(memberAD{Device: w.admin.ID, Group: group.Tag(w.admin.GroupCA.Cert)})
	if err != nil {
		return nil, false, err
	}
	st, msg, err := cpace.Start(&cpace.Config{Role: cpace.Responder, Password: w.code, ChannelID: ci, SessionID: sid, AD: ad})
	if err != nil {
		return nil, false, err
	}
	reply := &frame{Msg: msg, AD: ad}
	if memberFirst {
		if _, err := st.Finish(first.Msg, first.AD); err != nil {
			return nil, false, err
		}
		reply.Tag = st.Tag()
	}
	if err := writeFrame(conn, reply); err != nil {
		return nil, true, err
	}
	if !memberFirst {
		if _, err := st.Finish(first.Msg, first.AD); err != nil {
			return nil, true, err
		}
	}
	confirm, err := readFrame(conn)
	if err != nil {
		return nil, true, err
	}
	if confirm.Error != "" {
		return nil, true, errorOf(confirm.Error)
	}
	if err := st.Verify(confirm.Tag); err != nil {
		return nil, true, ErrWrongCode
	}
	if w.confirm != nil {
		r := Request{Device: joiner, Info: info, Fingerprint: group.KeyHashOf(cs.PeerCertificates[0]).String()}
		if err := w.confirm(ctx, r); err != nil {
			if ctx.Err() != nil {
				return nil, true, ctx.Err()
			}
			return nil, true, ErrDeclined
		}
	}
	// A phone that offers an admin key joins only through the root, which
	// makes it an admin at once with that key (docs/protocol.md, section 6,
	// "A phone joins a computer's group"); one without an admin key joins
	// any admin's window as a member.
	if info.Phone() && info.AdminKey != nil && !w.admin.IsRoot() {
		writeFrame(conn, &frame{Error: "refused"})
		return nil, true, ErrPhoneNeedsRoot
	}
	// The code alone makes no admin: only a window that the user opened
	// for one (cbb pair -admin) certifies an admin key.
	if info.AdminKey != nil && !w.admins {
		writeFrame(conn, &frame{Error: "refused"})
		return nil, true, ErrAdminNotAllowed
	}
	// The phone proves it holds the admin key, on this connection, and
	// the key is a new one.
	if info.AdminKey != nil {
		if !info.provesAdminKey(sid) {
			writeFrame(conn, &frame{Error: "refused"})
			return nil, true, ErrAdminProof
		}
		if w.known != nil && w.known(group.KeyHash(sha256.Sum256(info.AdminKey))) {
			writeFrame(conn, &frame{Error: "refused"})
			return nil, true, ErrAdminProof
		}
	}
	// The joiner knows the code. Certify the key it proved it holds in the
	// TLS handshake.
	pub := cs.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
	ca, _ := w.admin.Signer()
	cert, err := ca.IssueMember(joiner, pub, w.now())
	if err != nil {
		return nil, true, err
	}
	welcome, err := w.welcome(cert)
	if err != nil {
		return nil, true, err
	}
	var adminCA *x509.Certificate
	if info.Phone() && info.AdminKey != nil {
		key, err := parseAdminKey(info.AdminKey)
		if err != nil {
			return nil, true, err
		}
		if adminCA, err = ca.IssueAdmin(joiner, key, w.now()); err != nil {
			return nil, true, err
		}
		welcome.AdminCA = adminCA.Raw
	}
	if err := w.commit(); err != nil {
		return nil, true, err
	}
	// From here on the device counts as admitted: the welcome may reach it
	// even if this side sees an error.
	res = &Result{Device: joiner, Info: info, Cert: cert, AdminCA: adminCA}
	final := &frame{Welcome: welcome}
	if !memberFirst {
		final.Tag = st.Tag()
	}
	if err := writeFrame(conn, final); err != nil {
		return res, true, err
	}
	done, err := readFrame(conn)
	switch {
	case err != nil:
		return res, true, err
	case !done.OK:
		return res, true, errorOf(done.Error)
	}
	res.Confirmed = true
	return res, true, nil
}

// welcomeRoom is what a Welcome leaves in its frame for the frame's other
// fields.
const welcomeRoom = 4 << 10

// welcome makes the Welcome for a new device's certificate. It carries no
// CA key: no device gets one by joining (docs/protocol.md, section 6).
func (w *Window) welcome(cert *x509.Certificate) (*Welcome, error) {
	wel := &Welcome{Cert: cert.Raw, GroupCA: w.admin.GroupCA.Cert.Raw}
	// An admin that is not the root issues from its admin CA.
	if w.admin.AdminCA != nil {
		wel.Issuer = w.admin.AdminCA.Raw
	}
	for _, r := range w.admin.Roots {
		wel.Roots = append(wel.Roots, r.Raw)
	}
	// The group's records let the new device take its peers at once: in
	// records v:2 a member is taken only when a device record names it.
	// A group handed over needs them, or the new device refuses the
	// Welcome; any other leaves them out when they do not fit in a frame,
	// and the new device gets them over records-only connections.
	if w.records != nil {
		wel.Records = w.records()
		if w.claims != nil {
			wel.ClaimTimes = w.claims()
		}
		if len(wel.Roots) == 0 {
			if data, err := json.Marshal(wel); err != nil || len(data) > maxFrame-welcomeRoom {
				wel.Records, wel.ClaimTimes = nil, nil
			}
		}
	}
	return wel, nil
}
