// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
// CBB_SWIFT_INTEROP_TLS on macOS, makes a key in the keychain, gets
// a member certificate for it, dials, sends a text, and waits for one.
func TestSwiftMemberTLS(t *testing.T) {
	tool := os.Getenv("CBB_SWIFT_INTEROP_TLS")
	if tool == "" {
		t.Skip("CBB_SWIFT_INTEROP_TLS names no cbb-interop binary")
	}
	var store memContent
	server := newMember(t, Full, withContent(&store))
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
	phoneID := group.NewDeviceID()
	cert, err := admin.GroupCA.IssueMember(phoneID, ecPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(stdin, "cert %s\nca %s\n", base64.StdEncoding.EncodeToString(cert.Raw), base64.StdEncoding.EncodeToString(admin.GroupCA.Cert.Raw))

	ln.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
	raw, err := ln.Accept()
	if err != nil {
		fail("the tool did not connect: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(context.Background(), tls.Server(raw, server.ServerTLS())) }()

	waitWrite(t, server, "from swift")
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
	if w.Media == nil || len(w.Media.Parts) != 1 || w.Media.Parts[0].Type != clip.TypePNG {
		fail("the phone's picture %+v", w)
	}
	got, err := fetchAll(context.Background(), server, &member{id: &group.Identity{ID: phoneID}}, w.Media.Parts[0], 0)
	if err != nil {
		fail("fetching the phone's picture: %v", err)
	}
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
