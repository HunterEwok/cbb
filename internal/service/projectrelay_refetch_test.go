// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/relay"
	"github.com/HunterEwok/cbb/internal/release"
)

// listsMirror plays the mirror on the project relay's server
// (dl.cbb.tools) for a device built with the test hooks: an HTTPS server
// on loopback, beside the test's relay, under a certificate for
// dl.cbb.tools of a root only the device's CBB_TEST_LISTS_MIRROR names.
type listsMirror struct {
	srv *httptest.Server
	ca  string // the root's PEM file

	mu    sync.Mutex
	files map[string][]byte
}

func newListsMirror(t *testing.T) *listsMirror {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mirror"},
		DNSNames:              []string{"dl.cbb.tools"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	m := &listsMirror{ca: filepath.Join(t.TempDir(), "mirror.pem"), files: map[string][]byte{}}
	if err := os.WriteFile(m.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	m.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		data, ok := m.files[r.URL.Path]
		m.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	m.srv.Listener.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.srv.Listener = ln
	m.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	m.srv.StartTLS()
	t.Cleanup(m.srv.Close)
	return m
}

// env is the device's CBB_TEST_LISTS_MIRROR for this mirror.
func (m *listsMirror) env() string {
	_, port, _ := net.SplitHostPort(m.srv.Listener.Addr().String())
	return fmt.Sprintf("CBB_TEST_LISTS_MIRROR=%s %s", port, m.ca)
}

// serve has the mirror give keys.json and entries.json as given.
func (m *listsMirror) serve(keys, entries []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files["/keys.json"], m.files["/entries.json"] = keys, entries
}

// relaySet splits what signRelay signs into the two files the mirror
// serves, each as the signer writes it.
func relaySet(t *testing.T, signed string) (keys, entries release.File) {
	t.Helper()
	var set entriesSet
	if err := json.Unmarshal([]byte(signed), &set); err != nil {
		t.Fatal(err)
	}
	return set.Keys, set.Entries
}

func fileBytes(t *testing.T, f release.File) []byte {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestProjectRelayRefetch walks the path a relay's outage takes: the
// project's relay comes back under a new key, the device refuses it, fetches
// the signed lists again from the mirror on the relay's server, and takes
// the new key only from lists it would take from any source. Lists signed
// by one half of a key only, older than those it holds, or over the
// largest file leave it where it was.
func TestProjectRelayRefetch(t *testing.T) {
	signer := newReleaseSigner(t)
	mirror := newListsMirror(t)
	var h hub
	pi := startEnv(t, &h, "pi", signer.rootsEnv(t), mirror.env(), "CBB_TEST_REFETCH_EVERY=300",
		"CBB_TEST_RESOLVE=cbb.tools=none")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	group := pi.status(t).Group
	oldKeys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	newKeys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, stop := runRelay(t, oldKeys, "127.0.0.1:0", group)
	at := r.Addr().String()

	if _, err := pi.do(t, control.Header{Op: control.OpEntries}, signer.signRelayKeys(t, 5, oldKeys)); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: at, RelayKey: projectRelay, Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	connected := func() bool {
		a := pi.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected
	}
	waitUpTo(t, 60*time.Second, "the pi registers with the relay's listed key", connected)

	stop()
	_, stop = runRelay(t, newKeys, at, group)
	defer stop()

	// A refused set is refused for a reason of its own, which the device
	// logs once it read the set: a refusal of the set before it cannot be
	// taken for it. The link to the relay fails again after a backoff of
	// up to a minute, and each failure may fetch the lists once.
	refusals := func(reason string) int {
		n := 0
		for _, l := range pi.linesWith("fetching the signed lists for the relay: ") {
			if strings.Contains(l, reason) {
				n++
			}
		}
		return n
	}
	refused := func(what, reason string, keys, entries []byte) {
		t.Helper()
		before := refusals(reason)
		mirror.serve(keys, entries)
		waitUpTo(t, 150*time.Second, "the pi fetches and refuses "+what, func() bool { return refusals(reason) > before })
		if connected() {
			t.Fatalf("the pi took the relay's new key from %s", what)
		}
	}

	k, e := relaySet(t, signer.signRelayKeys(t, 6, oldKeys, newKeys))
	half := k
	half.Sigs = nil
	for _, s := range k.Sigs {
		if s.Alg == release.AlgES256 {
			half.Sigs = append(half.Sigs, s)
		}
	}
	if len(half.Sigs) != 1 || len(k.Sigs) != 2 {
		t.Fatalf("keys.json has %d signatures, %d of them ES256", len(k.Sigs), len(half.Sigs))
	}
	refused("a keys.json signed by one half of the root", "keys.json is not valid: the signature is not valid", fileBytes(t, half), fileBytes(t, e))

	ok, e := relaySet(t, signer.signRelayKeys(t, 4, oldKeys, newKeys))
	refused("lists older than those it holds", "older than one already seen", fileBytes(t, ok), fileBytes(t, e))

	k, e = relaySet(t, signer.signRelayKeys(t, 6, oldKeys, newKeys))
	large := append(fileBytes(t, k), bytes.Repeat([]byte{' '}, release.MaxFile)...)
	// A download cut at the largest file names the URL; the readers'
	// refusals name only the file.
	refused("a keys.json over the largest file", "/keys.json", large, fileBytes(t, e))

	mirror.serve(fileBytes(t, k), fileBytes(t, e))
	waitUpTo(t, 150*time.Second, "the pi registers with the key the refetched lists name", connected)
	if a := pi.status(t).Away; a.Relay.Error != "" {
		t.Errorf("an error left in status: %q", a.Relay.Error)
	}
}
