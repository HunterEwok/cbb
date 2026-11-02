// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// TestSwiftMemberAdmitsGoJoiner runs the phone app's pairing code against
// this joiner: clipboardbridge-interop (apps/ios/ClipboardBridgeKit), named by
// CBB_SWIFT_INTEROP, creates a group as the phone does, dials, and
// admits the Linux joiner without CA keys. The two exchange certificates
// over plain TCP in place of a TLS handshake, with a fixed session ID; the
// CPace exchange, the frames, the welcome and the certificates are the real
// ones.
func TestSwiftMemberAdmitsGoJoiner(t *testing.T) {
	tool := os.Getenv("CBB_SWIFT_INTEROP")
	if tool == "" {
		t.Skip("CBB_SWIFT_INTEROP names no clipboardbridge-interop binary")
	}
	for _, tc := range []struct {
		name, code, toolCode string
		ok                   bool
	}{
		{"the right code", "135790", "135790", true},
		{"a wrong code", "135790", "135791", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			addr := ln.Addr().(*net.TCPAddr)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, tool, "admit", "127.0.0.1", strconv.Itoa(addr.Port), tc.toolCode)
			var out, errOut strings.Builder
			cmd.Stdout, cmd.Stderr = &out, &errOut
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			conn := acceptTool(t, ln, cmd, &errOut)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(20 * time.Second))

			j := newJoiner(t, "linux")
			memberDER, err := readBlob(conn)
			if err != nil {
				t.Fatal(err)
			}
			memberCert, err := x509.ParseCertificate(memberDER)
			if err != nil {
				t.Fatalf("the phone's certificate: %v", err)
			}
			own, err := j.cert()
			if err != nil {
				t.Fatal(err)
			}
			if err := writeBlob(conn, own); err != nil {
				t.Fatal(err)
			}
			saved := 0
			id, joinErr := j.exchange(conn, []byte(tc.code), channelID(memberDER, own), make([]byte, 32), memberCert, true,
				func(*group.Identity) error { saved++; return nil })
			conn.Close()
			toolErr := cmd.Wait()

			if !tc.ok {
				if joinErr == nil || Spent(joinErr) || toolErr == nil || saved != 0 {
					t.Fatalf("a wrong code: join %v (spent %v), tool %v, saved %d", joinErr, Spent(joinErr), toolErr, saved)
				}
				return
			}
			if joinErr != nil || toolErr != nil {
				t.Fatalf("join %v; tool %v: %s", joinErr, toolErr, errOut.String())
			}
			if err := id.Check(); err != nil || id.ServesPhone() || saved != 1 {
				t.Fatalf("the identity from the phone: %v, admin %v, saved %d", err, id.ServesPhone(), saved)
			}
			caDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out.String()))
			if err != nil || string(caDER) != string(id.GroupCA.Cert.Raw) {
				t.Errorf("the joiner holds another group CA than the phone made")
			}
			if ca := id.GroupCA.Cert; ca.MaxPathLen != 1 || !strings.HasPrefix(ca.Subject.CommonName, "clipboardbridge group root ") {
				t.Errorf("the phone's group CA is %q with path length %d, want its root with 1", ca.Subject.CommonName, ca.MaxPathLen)
			}
		})
	}
}

// acceptTool accepts the tool's connection, or fails with what the tool
// wrote when it ends or does not connect within 20 seconds.
func acceptTool(t *testing.T, ln net.Listener, cmd *exec.Cmd, errOut *strings.Builder) net.Conn {
	t.Helper()
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("the tool did not connect (%v): %s", err, errOut.String())
	}
	return conn
}

func readBlob(r io.Reader) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint32(n[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeBlob(w io.Writer, b []byte) error {
	_, err := w.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...))
	return err
}

// TestSwiftMemberAdmitsGoJoinerTLS is the same with real TLS: the joiner
// listens with Accept, as cbb pair does, and the phone app's code
// dials it with Network.framework, checks the QR code's fingerprint and
// binds CPace to the TLS exporter. It needs macOS (CBB_SWIFT_INTEROP_TLS
// names the tool there).
func TestSwiftMemberAdmitsGoJoinerTLS(t *testing.T) {
	tool := os.Getenv("CBB_SWIFT_INTEROP_TLS")
	if tool == "" {
		t.Skip("CBB_SWIFT_INTEROP_TLS names no clipboardbridge-interop binary")
	}
	for _, tc := range []struct {
		name   string
		code   string
		goodFP bool
		ok     bool
	}{
		{"the right code", "246802", true, true},
		{"a wrong code", "246803", true, false},
		{"another certificate", "246802", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			j := newJoiner(t, "macos")
			fp, err := j.Fingerprint()
			if err != nil {
				t.Fatal(err)
			}
			if !tc.goodFP {
				fp = CertFingerprint([]byte("another certificate"))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, tool, "admit-tls", "127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), tc.code, fp)
			var out, errOut strings.Builder
			cmd.Stdout, cmd.Stderr = &out, &errOut
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			conn := acceptTool(t, ln, cmd, &errOut)
			saved := 0
			id, joinErr := j.Accept(ctx, conn, "246802", func(*group.Identity) error { saved++; return nil })
			toolErr := cmd.Wait()
			if !tc.ok {
				if joinErr == nil || Spent(joinErr) || toolErr == nil || saved != 0 {
					t.Fatalf("join %v (spent %v), tool %v, saved %d", joinErr, Spent(joinErr), toolErr, saved)
				}
				return
			}
			if joinErr != nil || toolErr != nil {
				t.Fatalf("join %v; tool %v: %s", joinErr, toolErr, errOut.String())
			}
			if err := id.Check(); err != nil || id.ServesPhone() || saved != 1 {
				t.Fatalf("the identity from the phone: %v, admin %v, saved %d", err, id.ServesPhone(), saved)
			}
			caDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out.String()))
			if err != nil || string(caDER) != string(id.GroupCA.Cert.Raw) {
				t.Errorf("the joiner holds another group CA than the phone made")
			}
			if ca := id.GroupCA.Cert; ca.MaxPathLen != 1 || !strings.HasPrefix(ca.Subject.CommonName, "clipboardbridge group root ") {
				t.Errorf("the phone's group CA is %q with path length %d, want its root with 1", ca.Subject.CommonName, ca.MaxPathLen)
			}
		})
	}
}

// TestSwiftHubAdmitsInvitedGoJoiner runs the phones' pairing window of a
// remote invitation (docs/protocol.md, section 12) against this joiner: the
// tool opens it with the secret, as the phone that is the hub does, the
// joiner dials it with TLS and the secret, as cbb pair -invite does through
// the guest tunnel, and the tool's admin confirms the device by the
// fingerprint the joiner shows, or declines it.
func TestSwiftHubAdmitsInvitedGoJoiner(t *testing.T) {
	tool := os.Getenv("CBB_SWIFT_INTEROP_TLS")
	if tool == "" {
		t.Skip("CBB_SWIFT_INTEROP_TLS names no clipboardbridge-interop binary")
	}
	secret := make([]byte, MinSecret)
	rand.Read(secret)
	for _, tc := range []struct {
		name   string
		secret []byte
		answer string
		want   error // nil: admitted
	}{
		{"admitted", secret, "yes", nil},
		{"declined", secret, "no", ErrDeclined},
		{"a wrong secret", make([]byte, MinSecret), "yes", ErrWrongCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, tool, "invite-window", base64.StdEncoding.EncodeToString(secret), tc.answer)
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
			next := func(prefix string) string {
				if !lines.Scan() || !strings.HasPrefix(lines.Text(), prefix) {
					cmd.Process.Kill()
					t.Fatalf("the tool did not say %q: %q, %s", prefix, lines.Text(), errOut.String())
				}
				return strings.TrimPrefix(lines.Text(), prefix)
			}
			port := next("port ")
			conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
			if err != nil {
				t.Fatal(err)
			}
			j := newJoiner(t, "linux")
			fp, _ := j.Fingerprint()
			saved := 0
			id, joinErr := j.JoinSecret(ctx, conn, tc.secret, 30*time.Second, func(*group.Identity) error { saved++; return nil })
			if tc.want != nil {
				if !errors.Is(joinErr, tc.want) || saved != 0 {
					t.Fatalf("join %v, want %v; saved %d", joinErr, tc.want, saved)
				}
				return
			}
			if joinErr != nil {
				t.Fatalf("join %v: %s", joinErr, errOut.String())
			}
			if got := next("fingerprint "); got != fp {
				t.Errorf("the admin was shown %s, the device shows %s", got, fp)
			}
			ca := next("")
			if err := cmd.Wait(); err != nil {
				t.Fatalf("tool %v: %s", err, errOut.String())
			}
			if err := id.Check(); err != nil || id.ServesPhone() || saved != 1 {
				t.Fatalf("the identity from the phone: %v, admin %v, saved %d", err, id.ServesPhone(), saved)
			}
			if caDER, err := base64.StdEncoding.DecodeString(ca); err != nil || string(caDER) != string(id.GroupCA.Cert.Raw) {
				t.Errorf("the joiner holds another group CA than the phone made")
			}
		})
	}
}

// TestSwiftJoinsComputerRoot runs the phones' joining side against a
// computer's pairing window (docs/protocol.md, section 6, "A phone joins a
// computer's group"): the tool dials the window as a phone with an admin
// key, confirms the code first and checks the Welcome. The group's root
// admits it with an admin CA for that key; a wrong code fails on both
// sides; an admin computer refuses a phone.
func TestSwiftJoinsComputerRoot(t *testing.T) {
	tool := os.Getenv("CBB_SWIFT_INTEROP_TLS")
	if tool == "" {
		t.Skip("CBB_SWIFT_INTEROP_TLS names no clipboardbridge-interop binary")
	}
	for _, tc := range []struct {
		name  string
		admin bool // the window is an admin computer's, not the root's
		wrong bool // the tool takes a wrong code
		want  error
	}{
		{"the root admits it", false, false, nil},
		{"a wrong code", false, true, ErrWrongCode},
		{"an admin computer", true, false, ErrPhoneNeedsRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.admin {
				admin, _ := computerAdmin(t)
				f = fixtureFor(t, admin)
			}
			code := f.code
			if tc.wrong {
				code = f.wrongCode()
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, tool, "join-tls", "127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), code)
			var out, errOut strings.Builder
			cmd.Stdout, cmd.Stderr = &out, &errOut
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			conn := acceptTool(t, ln, cmd, &errOut)
			conn.SetDeadline(time.Now().Add(20 * time.Second))
			served := f.window.Serve(ctx, tls.Server(conn, ServerTLS(f.admin)))
			conn.Close()
			toolErr := cmd.Wait()
			if tc.want != nil {
				if !errors.Is(served, tc.want) || toolErr == nil {
					t.Fatalf("Serve %v, want %v; tool %v", served, tc.want, toolErr)
				}
				return
			}
			if served != nil || toolErr != nil {
				t.Fatalf("Serve %v; tool %v: %s", served, toolErr, errOut.String())
			}
			lines := strings.Fields(out.String())
			res, err := f.window.Result()
			if err != nil || len(lines) != 2 || !res.Info.Phone() || res.AdminCA == nil {
				t.Fatalf("Result %+v, %v; the tool printed %q", res, err, out.String())
			}
			if ca, err := base64.StdEncoding.DecodeString(lines[0]); err != nil || string(ca) != string(f.admin.Root().Raw) {
				t.Error("the phone holds another group CA than the computer's")
			}
			if ca, err := base64.StdEncoding.DecodeString(lines[1]); err != nil || string(ca) != string(res.AdminCA.Raw) {
				t.Error("the phone holds another admin CA than the root issued")
			}
		})
	}
}
