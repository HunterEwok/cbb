// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package androidtv

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/HunterEwok/cbb/internal/netguard"
	"github.com/HunterEwok/cbb/internal/tvremote/androidtv/wire"
)

// The TV's ports: pairing, and the remote.
const (
	PairPort   = 6467
	RemotePort = 6466
)

// stepTimeout is how long one step waits for the TV, which answers each
// one by itself.
const stepTimeout = 10 * time.Second

// Client is the remote's identity on the TV: a self-signed RSA
// certificate, as the pairing's secret is made of the RSA keys of both
// ends. It is the remote's own, apart from the member's keys.
type Client struct {
	CertPEM []byte
	KeyPEM  []byte
}

// NewClient makes a 2048-bit RSA key and its certificate, named for the
// TV's list of paired remotes.
func NewClient(name string) (Client, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Client{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return Client{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, Organization: []string{"CBB"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(30, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Client{}, err
	}
	return Client{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}, nil
}

func (c Client) tls() (tls.Certificate, error) {
	return tls.X509KeyPair(c.CertPEM, c.KeyPEM)
}

// dial opens TLS to the TV with the client's certificate. The TV's own is
// self-signed: with pin set it must be that one (its SHA-256), and the
// first time, for pairing, it is taken as it is and pinned after.
func dial(ctx context.Context, addr string, c Client, pin []byte) (*tls.Conn, error) {
	cert, err := c.tls()
	if err != nil {
		return nil, fmt.Errorf("the remote's certificate: %w", err)
	}
	cfg := tlsVerifiedByPin(cert, pin)
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: stepTimeout, Control: netguard.ControlHome}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// addr is the address of the TV's pairing port, or with remote its
// remote port. A host may name the pairing port itself, for tests; the
// remote port is the one below it, as 6466 is below 6467.
func addr(host string, remote bool) string {
	port := PairPort
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 1 {
			host, port = h, n
		}
	}
	if remote {
		port--
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// tlsVerifiedByPin is the TLS of a connection to the TV: its certificate is
// self-signed and has no name, so crypto/tls cannot check it, and
// VerifyConnection checks it against the pin instead. Without a pin, at
// pairing, any certificate is taken and pinned after: the code the TV
// shows checks it. Its first byte is the first byte of a hash of both
// ends' keys as the TV sees them, which Finish compares with the keys this
// end sees, so a device in between is caught 255 times in 256, as far as
// the protocol allows. (The name, like the pairing's
// clientTLSVerifiedByFingerprint, tells CodeQL that InsecureSkipVerify is
// checked here.)
func tlsVerifiedByPin(cert tls.Certificate, pin []byte) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the TV sent no certificate")
			}
			if pin != nil {
				if sum := sha256.Sum256(cs.PeerCertificates[0].Raw); !equal(sum[:], pin) {
					return errors.New("the TV's certificate is not the one it had at pairing: pair it again if it was reset")
				}
			}
			return nil
		},
	}
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The fields of the polo protocol's OuterMessage and its parts.
const (
	poloVersion  = 1
	poloStatus   = 2
	poloRequest  = 10
	poloReqAck   = 11
	poloOptions  = 20
	poloConfig   = 30
	poloConfAck  = 31
	poloSecret   = 40
	poloSecAck   = 41
	statusOK     = 200
	statusBadKey = 402

	encodingHex = 3
	roleInput   = 1
	codeLength  = 6
)

func outer(part int, body wire.Builder) wire.Builder {
	return wire.New().Int(poloVersion, 2).Int(poloStatus, statusOK).Sub(protowire.Number(part), body)
}

// hexEncoding is the six hexadecimal digits a TV shows.
func hexEncoding() wire.Builder {
	return wire.New().Int(1, encodingHex).Int(2, codeLength)
}

// Pairing is a pairing in progress: the TV shows its code until Finish
// gets it or Close ends it.
type Pairing struct {
	conn   *tls.Conn
	r      *bufio.Reader
	client Client
	// TV is the TV's name as it says it.
	TV string
}

// Pair asks the TV at host (an address, without the port) to pair with
// the client, under name ; the TV shows a code, which Finish takes.
func Pair(ctx context.Context, host string, c Client, name string) (*Pairing, error) {
	conn, err := dial(ctx, addr(host, false), c, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the TV's pairing port %d: %w", PairPort, err)
	}
	p := &Pairing{conn: conn, r: bufio.NewReader(conn), client: c}
	ack, err := p.step(outer(poloRequest, wire.New().Str(1, "atvremote").Str(2, name)), poloReqAck)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if ack, err := ack.Sub(poloReqAck); err == nil {
		p.TV = ack.Str(1)
	}
	options := wire.New().Sub(1, hexEncoding()).Int(3, roleInput)
	if _, err := p.step(outer(poloOptions, options), poloOptions); err != nil {
		conn.Close()
		return nil, err
	}
	config := wire.New().Sub(1, hexEncoding()).Int(2, roleInput)
	if _, err := p.step(outer(poloConfig, config), poloConfAck); err != nil {
		conn.Close()
		return nil, err
	}
	return p, nil
}

// ErrCode is a code that is not the one the TV shows.
var ErrCode = errors.New("that is not the code the TV shows")

// Finish sends the code the TV shows, and returns the pin of the TV's
// certificate for the remote to check.
func (p *Pairing) Finish(code string) (pin []byte, err error) {
	defer p.conn.Close()
	code = strings.ToLower(strings.TrimSpace(code))
	digits, err := hex.DecodeString(code)
	if err != nil || len(code) != codeLength {
		return nil, fmt.Errorf("%w: it has six digits and letters A to F", ErrCode)
	}
	state := p.conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("the TV sent no certificate")
	}
	mine, err := p.clientKey()
	if err != nil {
		return nil, err
	}
	tv, ok := state.PeerCertificates[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the TV's certificate has no RSA key, which the pairing needs")
	}
	secret := Secret(mine, tv, digits[1:])
	// The code's first byte checks the rest before the TV sees it.
	if secret[0] != digits[0] {
		return nil, ErrCode
	}
	m, err := p.exchange(outer(poloSecret, wire.New().Bytes(1, secret)))
	if err != nil {
		return nil, err
	}
	if m.Int(poloStatus) == statusBadKey {
		return nil, ErrCode
	}
	if err := check(m, poloSecAck); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return sum[:], nil
}

// Close ends the pairing; the TV stops showing the code.
func (p *Pairing) Close() error { return p.conn.Close() }

// clientKey is the RSA key of the client's certificate.
func (p *Pairing) clientKey() (*rsa.PublicKey, error) {
	return publicKey(p.client.CertPEM)
}

func publicKey(certPEM []byte) (*rsa.PublicKey, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("the remote's certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the remote's certificate: %w", err)
	}
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the remote's certificate has no RSA key")
	}
	return key, nil
}

// Secret is the pairing's secret: the SHA-256 of both ends' RSA modulus
// and exponent, the client's first, and the code's digits after the
// first byte.
func Secret(client, tv *rsa.PublicKey, code []byte) []byte {
	h := sha256.New()
	h.Write(client.N.Bytes())
	h.Write(big.NewInt(int64(client.E)).Bytes())
	h.Write(tv.N.Bytes())
	h.Write(big.NewInt(int64(tv.E)).Bytes())
	h.Write(code)
	return h.Sum(nil)
}

// step sends a message and reads the TV's answer, which must carry the
// part want.
func (p *Pairing) step(m wire.Builder, want int) (wire.Message, error) {
	ans, err := p.exchange(m)
	if err != nil {
		return nil, err
	}
	return ans, check(ans, want)
}

func (p *Pairing) exchange(m wire.Builder) (wire.Message, error) {
	p.conn.SetDeadline(time.Now().Add(stepTimeout))
	defer p.conn.SetDeadline(time.Time{})
	if err := wire.Write(p.conn, m); err != nil {
		return nil, fmt.Errorf("the TV's pairing: %w", err)
	}
	b, err := wire.Read(p.r)
	if err != nil {
		return nil, fmt.Errorf("the TV's pairing: %w", err)
	}
	return wire.Parse(b)
}

func check(m wire.Message, want int) error {
	if st := m.Int(poloStatus); st != statusOK {
		return fmt.Errorf("the TV refused the pairing (status %d)", st)
	}
	if !m.Has(protowire.Number(want)) {
		return fmt.Errorf("the TV answered the pairing with something else than part %d", want)
	}
	return nil
}
