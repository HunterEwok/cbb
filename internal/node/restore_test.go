// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

func (r *recordStore) GroupCA() *x509.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.s.GroupCA()
}

// restoreFixture returns a full member whose records list it and name the
// group's recovery key, with its store, the key and the key's admin CA
// (docs/protocol.md, section 10, "The recovery key").
func restoreFixture(t *testing.T) (*member, *recordStore, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	st := newRecordStore()
	server := newMember(t, Full, withRecords(st))
	st.node = func() *Node { return server.Node }
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := admin.GroupCA.IssueAdmin(group.NewDeviceID(), &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dev := group.KeyHashOf(server.id.Cert)
	k := group.KeyHashOf(ca)
	st.Add("", []group.Record{
		server.record(t, group.RecordBody{Type: group.RecordDevice, Device: string(server.id.ID), Name: "pi", Role: group.RoleFull, Key: &dev}),
		server.record(t, group.RecordBody{Type: group.RecordRecovery, Admin: &k, Cert: ca.Raw}),
	})
	if n := <-st.added; n != 2 {
		t.Fatalf("the store took %d of the 2 records", n)
	}
	return server, st, key, ca
}

// TestRecordsOnlyHelloCarriesGroupCA checks that a full member sends the
// group's first root in its hello to a device no record names, as a new
// phone whose certificate the recovery key issued, on the connection that
// carries records only.
func TestRecordsOnlyHelloCarriesGroupCA(t *testing.T) {
	server, st, key, ca := restoreFixture(t)
	phoneKey, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := group.NewDeviceID()
	cert, err := (&group.CA{Cert: ca, Key: key}).IssueMember(dev, &phoneKey.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	phone := &group.Identity{ID: dev, Key: phoneKey, Cert: cert, Issuer: ca, GroupCA: group.CA{Cert: admin.GroupCA.Cert}}
	a, b := socketPair(t)
	go server.Serve(context.Background(), tls.Server(b, server.ServerTLS()))
	tc := tls.Client(a, phone.ClientTLS(server.id.ID, group.TLSOptions{}))
	defer tc.Close()
	m, err := readMessage(tc, 5*time.Second)
	if err != nil || m.Type != typeHello {
		t.Fatalf("the first message: %+v, %v", m, err)
	}
	var h struct {
		Records string `json:"records"`
		GroupCA []byte `json:"group_ca"`
	}
	if err := json.Unmarshal(m.Hello, &h); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h.GroupCA, admin.GroupCA.Cert.Raw) {
		t.Error("the hello does not carry the group's first root")
	}
	if h.Records != st.Digest() {
		t.Error("the hello does not carry the records' digest")
	}
}

// TestSwiftRestoresWithRecoveryKey runs the phone kit's restore against a
// Go member over TLS: clipboardbridge-interop (the Swift tool, or the
// Kotlin kit's twin), named by CBB_SWIFT_INTEROP_TLS, reads the recovery
// sheet's QR code, takes the records from the member, checks them, and
// sends its claim on a second connection, which the member's records then
// hold, waiting the group's delay.
func TestSwiftRestoresWithRecoveryKey(t *testing.T) {
	tool := os.Getenv("CBB_SWIFT_INTEROP_TLS")
	if tool == "" {
		t.Skip("CBB_SWIFT_INTEROP_TLS names no clipboardbridge-interop binary")
	}
	server, st, key, ca := restoreFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go server.Serve(context.Background(), tls.Server(c, server.ServerTLS()))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b64 := base64.StdEncoding.EncodeToString
	cmd := exec.CommandContext(ctx, tool, "restore-tls", "127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		b64(key.D.FillBytes(make([]byte, 32))), b64(ca.Raw), group.Tag(admin.GroupCA.Cert))
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("the tool: %v: %s", err, errOut.String())
	}
	lines := strings.Fields(out.String())
	if len(lines) != 2 {
		t.Fatalf("the tool printed %q", out.String())
	}
	if _, err := group.ParseDeviceID(lines[0]); err != nil {
		t.Errorf("the phone's device ID: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	claims := st.s.State().Claims
	st.mu.Unlock()
	if len(claims) != 1 || claims[0].Root != group.KeyHashOf(root) || claims[0].Claimant != group.KeyHashOf(ca) || claims[0].State != "pending" {
		t.Fatalf("the member's claims: %+v", claims)
	}
}
