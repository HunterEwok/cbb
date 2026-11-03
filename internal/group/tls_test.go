// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/testnet"
)

func socketPair(t *testing.T) (net.Conn, net.Conn) { return testnet.SocketPair(t) }

// handshake runs a TLS handshake over a local connection and returns what
// each side saw and the errors of the client and the server.
func handshake(t *testing.T, client, server *tls.Config) (ccs, scs tls.ConnectionState, cerr, serr error) {
	t.Helper()
	a, b := socketPair(t)
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, s := tls.Client(a, client), tls.Server(b, server)
	done := make(chan struct{})
	go func() {
		defer close(done)
		serr = s.HandshakeContext(ctx)
		scs = s.ConnectionState()
		if serr != nil {
			b.Close() // the client may still wait for the server's flight
		}
	}()
	cerr = c.HandshakeContext(ctx)
	ccs = c.ConnectionState()
	if cerr != nil {
		a.Close()
	}
	<-done
	return ccs, scs, cerr, serr
}

func TestMemberHandshake(t *testing.T) {
	admin := newGroup(t)
	mac := join(t, admin, t0)
	at := func(when time.Time) TLSOptions { return TLSOptions{Now: func() time.Time { return when }} }
	ccs, scs, cerr, serr := handshake(t, mac.ClientTLS(admin.ID, at(t0)), admin.ServerTLS(at(t0)))
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: client %v, server %v", cerr, serr)
	}
	if got, err := PeerID(ccs); err != nil || got != admin.ID {
		t.Errorf("the client reached %q, %v; want %q", got, err, admin.ID)
	}
	if got, err := PeerID(scs); err != nil || got != mac.ID {
		t.Errorf("the server saw %q, %v; want %q", got, err, mac.ID)
	}
	if ccs.Version != tls.VersionTLS13 || ccs.NegotiatedProtocol != MemberProtocol {
		t.Errorf("version %x, protocol %q", ccs.Version, ccs.NegotiatedProtocol)
	}
}

func TestMemberHandshakeRejects(t *testing.T) {
	admin := newGroup(t)
	mac := join(t, admin, t0)
	other := join(t, admin, t0)
	stranger := newGroup(t)
	at := func(when time.Time) TLSOptions { return TLSOptions{Now: func() time.Time { return when }} }
	now := at(t0)
	revoked := errors.New("revoked")
	deny := func(bad DeviceID) TLSOptions {
		return TLSOptions{Now: now.Now, Allow: func(id DeviceID, chain []*x509.Certificate) error {
			if len(chain) == 0 || chain[0].Subject.CommonName != string(id) {
				return errors.New("Allow got the wrong certificates")
			}
			if id == bad {
				return revoked
			}
			return nil
		}}
	}
	tls12 := mac.ClientTLS(admin.ID, now)
	tls12.MinVersion, tls12.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	otherALPN := mac.ClientTLS(admin.ID, now)
	otherALPN.NextProtos = []string{"http/1.1"}
	noALPN := mac.ClientTLS(admin.ID, now)
	noALPN.NextProtos, noALPN.VerifyConnection = nil, nil // so only the server can object
	noCert := mac.ClientTLS(admin.ID, now)
	noCert.Certificates = nil
	phoneCert := admin.ClientTLS(admin.ID, now)
	phoneCert.Certificates = []tls.Certificate{admin.tlsCert(admin.Phone)}
	// A stranger that trusts this group's CA, so only the server can object
	// to its certificate.
	strangerClient := stranger.ClientTLS(admin.ID, now)
	strangerClient.RootCAs = admin.groupPool()
	// A server with a self-signed certificate that names the expected
	// device, and asks for no client certificate it could reject.
	forged := forgedServer(t, admin.ID)
	tests := []struct {
		name           string
		client, server *tls.Config
		fails          string // the side that must reject: "client" or "server"
	}{
		{"a server from another group", mac.ClientTLS(stranger.ID, now), stranger.ServerTLS(now), "client"},
		{"a forged server that names the expected device", mac.ClientTLS(admin.ID, now), forged, "client"},
		{"a client from another group", strangerClient, admin.ServerTLS(now), "server"},
		{"another member than expected", mac.ClientTLS(admin.ID, now), other.ServerTLS(now), "client"},
		{"a revoked client", mac.ClientTLS(admin.ID, now), admin.ServerTLS(deny(mac.ID)), "server"},
		{"a revoked server", mac.ClientTLS(admin.ID, deny(admin.ID)), admin.ServerTLS(now), "client"},
		{"an expired server", mac.ClientTLS(admin.ID, at(t0.AddDate(3, 0, 0))), admin.ServerTLS(at(t0.AddDate(3, 0, 0))), "client"},
		{"an expired client", mac.ClientTLS(admin.ID, now), admin.ServerTLS(at(t0.AddDate(3, 0, 0))), "server"},
		{"TLS 1.2", tls12, admin.ServerTLS(now), "server"},
		{"another protocol", otherALPN, admin.ServerTLS(now), "server"},
		{"no protocol", noALPN, admin.ServerTLS(now), "server"},
		{"no client certificate", noCert, admin.ServerTLS(now), "server"},
		{"the clipboardbridge.local certificate as a client", phoneCert, admin.ServerTLS(now), "server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, cerr, serr := handshake(t, tt.client, tt.server)
			if tt.fails == "client" && cerr == nil {
				t.Errorf("the client accepted the server (server error: %v)", serr)
			}
			if tt.fails == "server" && serr == nil {
				t.Errorf("the server accepted the client (client error: %v)", cerr)
			}
		})
	}
	// The error from Allow reaches the caller.
	if _, _, _, serr := handshake(t, mac.ClientTLS(admin.ID, now), admin.ServerTLS(deny(mac.ID))); !errors.Is(serr, revoked) {
		t.Errorf("server error %v, want the Allow error", serr)
	}
}

// forgedServer returns a server configuration with a self-signed
// certificate that looks like the member certificate of id.
func forgedServer(t *testing.T, id DeviceID) *tls.Config {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: string(id)},
		DNSNames:    []string{id.HostName()},
		NotBefore:   t0.Add(-time.Hour),
		NotAfter:    t0.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{MemberProtocol},
		ClientAuth:   tls.RequestClientCert,
	}
}

func TestMemberHandshakeWithClockBehind(t *testing.T) {
	// A Raspberry Pi without a real-time clock may run years behind until
	// it synchronizes; it still accepts the group's certificates.
	admin := newGroup(t)
	mac := join(t, admin, t0)
	behind := TLSOptions{Now: func() time.Time { return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC) }}
	if _, _, cerr, serr := handshake(t, mac.ClientTLS(admin.ID, behind), admin.ServerTLS(behind)); cerr != nil || serr != nil {
		t.Errorf("handshake with the clock in 1970: client %v, server %v", cerr, serr)
	}
}

func TestPhoneTLS(t *testing.T) {
	admin := newGroup(t)
	roots := x509.NewCertPool()
	roots.AddCert(admin.PhoneCA.Cert)
	phone := &tls.Config{RootCAs: roots, ServerName: PhoneName, Time: func() time.Time { return t0 }}
	ccs, _, cerr, serr := handshake(t, phone, admin.PhoneTLS())
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: client %v, server %v", cerr, serr)
	}
	if len(ccs.PeerCertificates) != 2 || !ccs.PeerCertificates[1].Equal(admin.PhoneCA.Cert) {
		t.Error("the server does not send the iPhone CA after its certificate")
	}
	// The iPhone does not accept the member certificate, and a member does
	// not accept the clipboardbridge.local certificate.
	member := &tls.Config{RootCAs: roots, ServerName: PhoneName, Time: phone.Time}
	if _, _, cerr, _ := handshake(t, member, admin.ServerTLS(TLSOptions{})); cerr == nil {
		t.Error("an iPhone client accepted the member certificate")
	}
	mac := join(t, admin, t0)
	if _, _, cerr, _ := handshake(t, mac.ClientTLS(admin.ID, TLSOptions{}), admin.PhoneTLS()); cerr == nil {
		t.Error("a member accepted the clipboardbridge.local certificate")
	}
}
