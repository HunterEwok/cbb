// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

func TestMirror(t *testing.T) {
	dir := t.TempDir()
	root, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	status, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(status)
	keyPath := filepath.Join(dir, "status-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	rootSPKI, _ := x509.MarshalPKIXPublicKey(&root.PublicKey)
	statusSPKI, _ := x509.MarshalPKIXPublicKey(&status.PublicKey)
	t0 := time.UnixMilli(1_800_000_000_000)
	now = func() time.Time { return t0 }
	keys, err := release.Sign(release.Keys{V: 1, Type: release.TypeKeys, Seq: 1, TimeMS: t0.UnixMilli(), ExpiresMS: t0.Add(90 * 24 * time.Hour).UnixMilli(),
		Keys: []release.Key{{Key: statusSPKI, Name: "status", Use: release.UseStatus}}}, root)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"entries":{"0A1b":{"status":"REVOKED","reason":"KEY_COMPROMISE"},"ff":{"status":"SUSPENDED"},"3":{"status":"REVOKED"}}}`
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 10:48:00 GMT")
		w.Write([]byte(body))
	}))
	defer google.Close()
	googleURL = google.URL
	mirror := func(args ...string) (release.Status, error) {
		if err := run(append([]string{"-key", keyPath, "-out", dir}, args...)); err != nil {
			return release.Status{}, err
		}
		data, err := os.ReadFile(filepath.Join(dir, "attest-status.json"))
		if err != nil {
			t.Fatal(err)
		}
		var f release.File
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		s, _, err := release.CheckStatus(keys, f, [][]byte{rootSPKI}, now(), release.Seen{})
		if err != nil {
			t.Fatal(err)
		}
		return s, nil
	}

	s, err := mirror()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.AndroidRevoked, ",") != "3,ff,a1b" || s.Seq != 1 || s.SourceMS == 0 {
		t.Fatalf("the first list: %+v", s)
	}
	// The same list a day later is not signed again; a week later it is.
	now = func() time.Time { return t0.Add(24 * time.Hour) }
	if s, _ = mirror(); s.Seq != 1 {
		t.Errorf("the same list was signed again: %d", s.Seq)
	}
	now = func() time.Time { return t0.Add(7*24*time.Hour + time.Second) }
	if s, _ = mirror(); s.Seq != 2 {
		t.Errorf("a list a day from expiry was not signed again: %d", s.Seq)
	}
	// A list that drops a serial number needs -allow-drop.
	body = `{"entries":{"3":{"status":"REVOKED"},"ff":{"status":"REVOKED"}}}`
	if _, err := mirror(); err == nil {
		t.Error("a list that drops a1b was taken")
	}
	if s, err = mirror("-allow-drop"); err != nil || strings.Join(s.AndroidRevoked, ",") != "3,ff" || s.Seq != 3 {
		t.Errorf("-allow-drop: %+v, %v", s, err)
	}
	body = `{"entries":{"xyz":{"status":"REVOKED"}}}`
	if _, err := mirror("-allow-drop"); err == nil {
		t.Error("a list with a bad serial number was taken")
	}
}

// TestFetchGivesUp: a server that stops answering fails the fetch in time.
func TestFetchGivesUp(t *testing.T) {
	stop := make(chan struct{})
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-stop
	}))
	defer google.Close()
	defer close(stop)
	old, oldClient := googleURL, client
	defer func() { googleURL, client = old, oldClient }()
	googleURL = google.URL
	client = &http.Client{Timeout: 200 * time.Millisecond}
	if fetchTimeout <= 0 || oldClient.Timeout != fetchTimeout {
		t.Errorf("the client's timeout is %v", oldClient.Timeout)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := fetch()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a fetch from a server that stopped answering succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fetch did not give up")
	}
}
