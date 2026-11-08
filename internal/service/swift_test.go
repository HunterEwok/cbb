// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/phone"
)

// The phone kits' interop tool, cbb-interop (apps/ios/CBBKit's on macOS, or
// the Android kit's twin on Linux), plays the phone against the Rust
// service here: pairing both ways over real TLS, the phone's member, and
// restoring with the recovery key. CBB_SWIFT_INTEROP_TLS names the tool.

// interopTool is the tool, or skips the test without it or the service.
func interopTool(t *testing.T) string {
	t.Helper()
	tool := os.Getenv("CBB_SWIFT_INTEROP_TLS")
	if tool == "" {
		t.Skip("CBB_SWIFT_INTEROP_TLS names no cbb-interop binary")
	}
	if rustService() == "" {
		t.Skip("CBB_TEST_RUST_SERVICE is not set")
	}
	return tool
}

// runInterop runs the tool with args to its end, within a minute, and
// returns what it printed and how it ended.
func runInterop(t *testing.T, tool string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var out, errOut strings.Builder
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if err != nil {
		t.Logf("cbb-interop %s: %v: %s", args[0], err, errOut.String())
	}
	return out.String(), err
}

// otherCode is a pairing code that is not code.
func otherCode(code string) string {
	last := (code[len(code)-1]-'0'+1)%10 + '0'
	return code[:len(code)-1] + string(last)
}

// TestSwiftAdmitsComputer: the phone app's pairing code makes a group and
// admits a computer that waits for a phone (cbb pair): it dials the
// address of the QR code with Network.framework (or Conscrypt), checks the
// QR code's fingerprint and binds CPace to the TLS exporter. A wrong code
// or another certificate admits nothing.
func TestSwiftAdmitsComputer(t *testing.T) {
	tool := interopTool(t)
	for _, tc := range []struct {
		name          string
		wrong, softFP bool
	}{
		{"the right code", false, false},
		{"a wrong code", true, false},
		{"another certificate", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h hub
			laptop, qr := listeningJoin(t, &h, "laptop")
			jc, ok := phone.ParseJoinQR(qr)
			if !ok || len(jc.Addrs) == 0 {
				t.Fatalf("not a QR code of a listening joiner: %q", qr)
			}
			host, port, err := net.SplitHostPort(jc.Addrs[0])
			if err != nil {
				t.Fatal(err)
			}
			code, fp := jc.Code, jc.Fingerprint
			if tc.wrong {
				code = otherCode(code)
			}
			if tc.softFP {
				sum := sha256.Sum256([]byte("another certificate"))
				fp = base64.StdEncoding.EncodeToString(sum[:])
			}
			out, toolErr := runInterop(t, tool, "admit-tls", host, port, code, fp)
			if tc.wrong || tc.softFP {
				if toolErr == nil {
					t.Fatal("the phone admitted the computer")
				}
				time.Sleep(time.Second)
				if g := laptop.status(t).Group; g != "" {
					t.Fatalf("the computer joined %s", g)
				}
				return
			}
			if toolErr != nil {
				t.Fatal(toolErr)
			}
			waitFor(t, "the computer in the phone's group", func() bool { return laptop.status(t).Group != "" })
			id, err := group.Load(laptop.dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := id.Check(); err != nil {
				t.Fatalf("the identity from the phone: %v", err)
			}
			caDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
			if err != nil || !bytes.Equal(caDER, id.GroupCA.Cert.Raw) {
				t.Error("the computer holds another group CA than the phone made")
			}
			if ca := id.GroupCA.Cert; ca.MaxPathLen != 1 || !strings.HasPrefix(ca.Subject.CommonName, "cbb group root ") {
				t.Errorf("the phone's group CA is %q with path length %d, want its root with 1", ca.Subject.CommonName, ca.MaxPathLen)
			}
		})
	}
}

// TestSwiftJoinsComputerRoot runs the phones' joining side against a
// computer's pairing window (docs/protocol.md, section 6, "A phone joins a
// computer's group"): the tool dials the window as a phone with an admin
// key, confirms the code first and checks the Welcome. The group's root
// admits it with an admin CA for that key; a wrong code fails on both
// sides.
func TestSwiftJoinsComputerRoot(t *testing.T) {
	tool := interopTool(t)
	for _, tc := range []struct {
		name  string
		wrong bool
	}{
		{"the root admits it", false},
		{"a wrong code", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h hub
			pi := startService(t, &h, "pi")
			if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
				t.Fatal(err)
			}
			// The window admits a phone, which asks to be an admin.
			c := pi.dial(t)
			defer c.Close()
			m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair, Admins: true}})
			if err != nil {
				t.Fatal(err)
			}
			code := m.Code
			if tc.wrong {
				code = otherCode(code)
			}
			host, port, err := net.SplitHostPort(pi.addr())
			if err != nil {
				t.Fatal(err)
			}
			out, toolErr := runInterop(t, tool, "join-tls", host, port, code)
			if tc.wrong {
				if toolErr == nil {
					t.Fatal("the phone joined with a wrong code")
				}
				if n := len(pi.devices(t)); n != 1 {
					t.Fatalf("the root lists %d devices, want itself", n)
				}
				return
			}
			if toolErr != nil {
				t.Fatal(toolErr)
			}
			if _, err := c.Receive(); err != nil {
				t.Fatalf("the window: %v", err)
			}
			id, err := group.Load(pi.dir)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Fields(out)
			if len(lines) != 2 {
				t.Fatalf("the tool printed %q", out)
			}
			if ca, err := base64.StdEncoding.DecodeString(lines[0]); err != nil || !bytes.Equal(ca, id.GroupCA.Cert.Raw) {
				t.Error("the phone holds another group CA than the computer's")
			}
			der, err := base64.StdEncoding.DecodeString(lines[1])
			if err != nil {
				t.Fatal(err)
			}
			adminCA, err := x509.ParseCertificate(der)
			if err != nil || !adminCA.IsCA || adminCA.CheckSignatureFrom(id.GroupCA.Cert) != nil {
				t.Fatalf("the phone's admin CA is not one the group's root issued: %v", err)
			}
			waitFor(t, "the root lists the phone", func() bool {
				for _, d := range pi.devices(t) {
					if d.Role == group.RolePhone {
						return true
					}
				}
				return false
			})
		})
	}
}

// TestSwiftMemberTLS runs the phone app's member (the Rust core's, signing
// with a key in the keychain or the Keystore) against a computer: the tool
// makes the key and a secret for sealed messages, gets a member
// certificate and the group's records with its own, dials, sends a sealed
// text and waits for one; a picture goes each way in its sealed blob.
func TestSwiftMemberTLS(t *testing.T) {
	tool := interopTool(t)
	var h hub
	// The root's key stays in a file, for the test to sign with.
	pi := startEnv(t, &h, "pi", "CBB_TPM=off")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	id, err := group.Load(pi.dir)
	if err != nil || id.GroupCA.Key == nil {
		t.Fatalf("the root's identity: %v, its group CA's key %v", err, id.GroupCA.Key)
	}
	host, port, err := net.SplitHostPort(pi.addr())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, "member-tls", host, port, pi.status(t).Device)
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
	field := func(name string) []byte {
		t.Helper()
		if !lines.Scan() || !strings.HasPrefix(lines.Text(), name+" ") {
			fail("no %s line (%q)", name, lines.Text())
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(lines.Text(), name+" "))
		if err != nil {
			fail("the %s line: %v", name, err)
		}
		return b
	}

	// The tool's key, a certificate for it, and the root's record of the
	// phone with its key for sealed messages, which the computer takes from
	// the phone once it connects.
	pub, err := x509.ParsePKIXPublicKey(field("key"))
	if err != nil {
		fail("the key: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		fail("the key is not ECDSA")
	}
	seal := field("seal")
	phoneID := group.NewDeviceID()
	cert, err := id.GroupCA.IssueMember(phoneID, ecPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recs, err := group.LoadRecords(pi.dir, id.GroupCA.Cert)
	if err != nil {
		t.Fatal(err)
	}
	key := group.KeyHashOf(cert)
	r, err := recs.Sign(group.RecordBody{Type: group.RecordDevice, Device: string(phoneID), Name: "iPhone", Role: group.RolePhone, Key: &key, Seal: seal}, id.GroupCA.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recs.Add(r); err != nil {
		t.Fatal(err)
	}
	all, err := json.Marshal(recs.All())
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	fmt.Fprintf(stdin, "cert %s\nca %s\nrecords %s\n", b64(cert.Raw), b64(id.GroupCA.Cert.Raw), b64(all))

	waitFor(t, "the computer has the phone's text", func() bool { return pi.paste(t) == "from swift" })
	waitFor(t, "the phone is the computer's peer", func() bool {
		p := pi.status(t).Peers
		return len(p) == 1 && p[0].ID == string(phoneID)
	})
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "from go"); err != nil {
		t.Fatal(err)
	}
	// A picture each way: the phone fetches the computer's and sends its
	// bytes reversed, which the computer fetches from the phone.
	png := randomBytes(300<<10 + 5)
	if err := pi.copyMedia(t, "go picture", sentPart{Part: control.Part{Type: "image/png", Size: int64(len(png))}, data: png}); err != nil {
		t.Fatal(err)
	}
	var parts []sentPart
	waitFor(t, "the computer has the phone's picture", func() bool {
		text, p, err := pi.pasteMedia(t)
		parts = p
		return err == nil && text == "phone picture" && len(p) == 1
	})
	got := slices.Clone(parts[0].data)
	slices.Reverse(got)
	if parts[0].Type != "image/png" || !bytes.Equal(got, png) {
		fail("the phone's picture (%s) is not the computer's reversed", parts[0].Type)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "done"); err != nil {
		t.Fatal(err)
	}
	if !lines.Scan() || lines.Text() != "ok" {
		fail("the tool did not get the text (%q)", lines.Text())
	}
}

// TestSwiftRestoresWithRecoveryKey runs the phone kit's restore against a
// computer: the tool reads the recovery sheet's QR code, takes the records
// from the computer, checks them, and sends its claim on a second
// connection, which the computer's records then hold, waiting the group's
// delay.
func TestSwiftRestoresWithRecoveryKey(t *testing.T) {
	tool := interopTool(t)
	var h hub
	pi := startEnv(t, &h, "pi", "CBB_TPM=off")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	pi.stop()
	sheet := addRecovery(t, pi)
	pi = restartService(t, &h, pi)
	id, err := group.Load(pi.dir)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(pi.addr())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sheet.Key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	out, err := runInterop(t, tool, "restore-tls", host, port, b64(raw), b64(sheet.Cert), group.Tag(id.GroupCA.Cert))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(out)
	if len(lines) != 2 {
		t.Fatalf("the tool printed %q", out)
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
	ca, err := x509.ParseCertificate(sheet.Cert)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the computer holds the phone's claim", func() bool {
		recs, err := group.LoadRecords(pi.dir, id.GroupCA.Cert)
		if err != nil {
			return false
		}
		claims := recs.State().Claims
		return len(claims) == 1 && claims[0].Root == group.KeyHashOf(root) && claims[0].Claimant == group.KeyHashOf(ca) && claims[0].State == "pending"
	})
}
