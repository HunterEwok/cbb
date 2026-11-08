// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
)

// TestSwiftMemberTLS runs the phone app's member code against this node
// over real TLS: cbb-interop (apps/ios/CBBKit), named by
// CBB_SWIFT_INTEROP_TLS on macOS, makes a key in the keychain and a secret
// for sealed messages, gets a member certificate and the group's records,
// dials, sends a sealed text, and waits for one; a picture goes each way
// in its sealed blob.
func TestSwiftMemberTLS(t *testing.T) {
	tool := os.Getenv("CBB_SWIFT_INTEROP_TLS")
	if tool == "" {
		t.Skip("CBB_SWIFT_INTEROP_TLS names no cbb-interop binary")
	}
	var store memContent
	server := newMember(t, Full, withContent(&store))
	server.blobs = &store
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, "member-tls", "127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), string(server.id.ID))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errOut strings.Builder
	cmd.Stderr = &errOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	lines := bufio.NewScanner(stdout)
	fail := func(format string, args ...any) {
		t.Helper()
		cmd.Process.Kill()
		t.Fatalf("%s; the tool said: %s", fmt.Sprintf(format, args...), errOut.String())
	}

	// The tool's key, and a certificate for it.
	if !lines.Scan() || !strings.HasPrefix(lines.Text(), "key ") {
		fail("no key line")
	}
	spki, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(lines.Text(), "key "))
	if err != nil {
		fail("the key: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		fail("the key: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		fail("the key is not ECDSA")
	}
	if !lines.Scan() || !strings.HasPrefix(lines.Text(), "seal ") {
		fail("no seal line")
	}
	phoneSeal, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(lines.Text(), "seal "))
	if err != nil {
		fail("the key for sealed messages: %v", err)
	}
	phoneID := group.NewDeviceID()
	cert, err := admin.GroupCA.IssueMember(phoneID, ecPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The records name both, with their keys for sealed messages, so each
	// seals its copies to the other.
	testReaders.addKey(t, phoneID, phoneSeal)
	var serverSeal []byte
	for _, r := range testReaders.of(t) {
		if r.ID == string(server.id.ID) {
			serverSeal = r.Seal
		}
	}
	serverKey, phoneKey := group.KeyHashOf(server.id.Cert), group.KeyHashOf(cert)
	recs, err := json.Marshal([]group.Record{
		server.record(t, group.RecordBody{Type: group.RecordDevice, Device: string(server.id.ID), Name: "pi", Role: group.RoleFull, Key: &serverKey, Seal: serverSeal}),
		server.record(t, group.RecordBody{Type: group.RecordDevice, Device: string(phoneID), Name: "iPhone", Role: group.RolePhone, Key: &phoneKey, Seal: phoneSeal}),
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(stdin, "cert %s\nca %s\nrecords %s\n", base64.StdEncoding.EncodeToString(cert.Raw), base64.StdEncoding.EncodeToString(admin.GroupCA.Cert.Raw),
		base64.StdEncoding.EncodeToString(recs))

	ln.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
	raw, err := ln.Accept()
	if err != nil {
		fail("the tool did not connect: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(context.Background(), tls.Server(raw, server.ServerTLS())) }()

	select {
	case w := <-server.writes:
		if w.Text != "from swift" {
			fail("wrote %q, want %q", w.Text, "from swift")
		}
	case <-time.After(5 * time.Second):
		fail("never wrote %q", "from swift")
	}
	if p := server.Peers(); len(p) != 1 || p[0].ID != phoneID || p[0].Role != Phone || (p[0].Name != "iPhone" && p[0].Name != "Android") {
		fail("peers %+v, want the phone", p)
	}
	if err := server.Send("from go", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	if p := server.Peers(); len(p) != 1 || !p[0].Media {
		fail("the phone's hello does not say it serves content")
	}
	// A picture each way: the phone fetches Go's and sends its bytes
	// reversed, which Go fetches from the phone.
	png := random(t, 300<<10+5)
	part := store.put(png)
	part.Type = clip.TypePNG
	if err := server.SendMedia(&clip.Manifest{Size: part.Size, Parts: []clip.Part{part}}, "go picture", clip.Copy); err != nil {
		t.Fatal(err)
	}
	var w Write
	for timeout := time.After(15 * time.Second); w.Text != "phone picture"; {
		select {
		case w = <-server.writes:
		case <-timeout:
			fail("the phone sent no picture")
		}
	}
	if w.Media == nil || len(w.Media.Parts) != 1 || w.Media.Parts[0].Type != clip.TypePNG || w.Blob == nil || w.Key == nil {
		fail("the phone's picture %+v", w)
	}
	sealed, err := fetchAll(context.Background(), server, &member{id: &group.Identity{ID: phoneID}}, clip.Part{SHA256: w.Blob.SHA256, Size: w.Blob.Size}, 0)
	if err != nil {
		fail("fetching the phone's picture: %v", err)
	}
	if sum := sha256.Sum256(sealed); !bytes.Equal(sum[:], w.Blob.SHA256) {
		fail("the phone's picture does not match its hash")
	}
	var opened bytes.Buffer
	if err := clip.OpenBlob(w.Key, bytes.NewReader(sealed), w.Blob, w.Media.Size, &opened); err != nil {
		fail("opening the phone's picture: %v", err)
	}
	got := opened.Bytes()
	slices.Reverse(got)
	if !bytes.Equal(got, png) {
		fail("the phone's picture is not Go's reversed")
	}
	if err := server.Send("done", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	if !lines.Scan() || lines.Text() != "ok" {
		fail("the tool did not get the text (%q)", lines.Text())
	}
	if err := wait(t, served, "the connection to end"); err != nil {
		t.Errorf("the connection ended with %v, want a goodbye", err)
	}
}
