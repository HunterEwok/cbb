// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/seal"
)

// sealedVectors is testdata/interop/go-sealed-commands.json.
type sealedVectors struct {
	GroupCA  []byte         `json:"group_ca"`
	Self     DeviceID       `json:"self"`
	NowMS    int64          `json:"now_ms"`
	Secret   []byte         `json:"secret"`
	Public   []byte         `json:"public"` // the secret's public key, for the kits that seal
	Commands []sealedVector `json:"commands"`
}

type sealedVector struct {
	Name    string `json:"name"`
	Command Record `json:"command"`
	// OK: the receiver takes the command as signed; Opens: its orders
	// then open with the secret and pass the checks of a command.
	OK    bool   `json:"ok"`
	Opens bool   `json:"opens"`
	Mode  string `json:"mode,omitempty"`
	Text  string `json:"text,omitempty"`
}

// signRawCommand signs data, a command's body however it is, with the
// root's key.
func signRawCommand(t *testing.T, ca *CA, data string) Record {
	t.Helper()
	sum := sha256.Sum256([]byte(data))
	sig, err := ca.Key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return Record{Body: []byte(data), Sig: sig}
}

// TestSealedCommandVectors writes (with -update) and checks
// testdata/interop/go-sealed-commands.json: commands with their orders
// sealed to the receiver (docs/protocol.md, section 15, "Sealed
// commands"), which ones the receiver takes as signed, and which of those
// open with its secret, for the lite member and the phone kits to agree
// with.
func TestSealedCommandVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-sealed-commands.json")
	if *update {
		writeSealedVectors(t, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v sealedVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if pub, err := seal.PublicKey(v.Secret); err != nil || !bytes.Equal(pub, v.Public) {
		t.Fatalf("the vectors' public key is not their secret's: %v", err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if len(v.Commands) != 10 {
		t.Fatalf("the file has %d commands", len(v.Commands))
	}
	for _, c := range v.Commands {
		body, err := s.VerifyCommand(c.Command, v.Self, time.UnixMilli(v.NowMS))
		if (err == nil) != c.OK {
			t.Errorf("%s: VerifyCommand = %v, the file says ok %v", c.Name, err, c.OK)
			continue
		}
		if err != nil {
			continue
		}
		err = body.Open(v.Secret)
		if (err == nil) != c.Opens {
			t.Errorf("%s: Open = %v, the file says opens %v", c.Name, err, c.Opens)
		}
		if err == nil && (body.Mode != c.Mode || body.Text != c.Text || !body.Opened) {
			t.Errorf("%s: opened %q %q %v, the file has %q %q", c.Name, body.Mode, body.Text, body.Opened, c.Mode, c.Text)
		}
	}
}

func writeSealedVectors(t *testing.T, path string) {
	pg := newPhoneGroup(t)
	secret, err := seal.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	public, err := seal.PublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	otherSecret, _ := seal.GenerateSecret()
	otherPublic, _ := seal.PublicKey(otherSecret)
	self, now := NewDeviceID(), int64(1_800_000_000_000)
	tag := Tag(pg.root.Cert)
	body := func(typ string) CommandBody {
		return CommandBody{Type: typ, Group: tag, By: NewDeviceID(), To: self, ID: NewCommandID(), TimeMS: now, ExpiresMS: now + CommandLifetime.Milliseconds()}
	}
	text := "ls -l <dir> & echo \"done\"\n"
	pasteBody := body(CommandPaste)
	pasteBody.Mode, pasteBody.Kind, pasteBody.Text, pasteBody.Enter = PasteByClipboard, "text", text, true
	sealSign := func(b CommandBody, to []byte) Record {
		t.Helper()
		sb, err := SealCommand(b, to)
		if err != nil {
			t.Fatal(err)
		}
		r, err := SignCommand(sb, pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	paste := sealSign(pasteBody, public)
	mode := body(CommandMode)
	mode.Mode = "own"

	// The paste's sealed part under a new header: another ID.
	var sealed CommandBody
	if err := json.Unmarshal(paste.Body, &sealed); err != nil {
		t.Fatal(err)
	}
	moved := sealed
	moved.ID = NewCommandID()
	movedRec, err := SignCommand(moved, pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}
	// Orders sealed under the right header that are no paste's.
	bad := body(CommandPaste)
	badSealed, err := seal.Seal(public, bad.aad(), []byte(`{"mode":"paste","kind":"text"}`))
	if err != nil {
		t.Fatal(err)
	}
	bad.V, bad.Sealed = sealedCommandVersion, badSealed
	badRec, err := SignCommand(bad, pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}

	header := func(v int, typ, rest string) string {
		b := body(typ)
		h, _ := json.Marshal(struct {
			V         int      `json:"v"`
			Type      string   `json:"type"`
			Group     string   `json:"group"`
			By        DeviceID `json:"by"`
			To        DeviceID `json:"to"`
			ID        string   `json:"id"`
			TimeMS    int64    `json:"time_ms"`
			ExpiresMS int64    `json:"expires_ms"`
		}{v, b.Type, b.Group, b.By, b.To, b.ID, b.TimeMS, b.ExpiresMS})
		return strings.TrimSuffix(string(h), "}") + rest + "}"
	}
	someSealed := `"` + strings.Repeat("AAAA", 300) + `"`
	v := sealedVectors{GroupCA: pg.root.Cert.Raw, Self: self, NowMS: now, Secret: secret, Public: public}
	v.Commands = []sealedVector{
		{Name: "a sealed paste", Command: paste, OK: true, Opens: true, Mode: PasteByClipboard, Text: text},
		{Name: "a sealed mode", Command: sealSign(mode, public), OK: true, Opens: true, Mode: "own"},
		{Name: "sealed to another key", Command: sealSign(mode, otherPublic), OK: true},
		{Name: "a sealed part under another header", Command: movedRec, OK: true},
		{Name: "sealed orders that are not a paste's", Command: badRec, OK: true},
		{Name: "orders in the open beside the sealed ones", Command: signRawCommand(t, pg.root, header(2, CommandMode, `,"mode":"own","sealed":`+someSealed))},
		{Name: "version 1 with a sealed part", Command: signRawCommand(t, pg.root, header(1, CommandMode, `,"mode":"own","sealed":`+someSealed))},
		{Name: "version 2 with nothing sealed", Command: signRawCommand(t, pg.root, header(2, CommandMode, ``))},
		{Name: "a sealed part not in the one form of base64", Command: signRawCommand(t, pg.root, header(2, CommandMode, `,"sealed":"AAB="`))},
		{Name: "an unknown type, sealed", Command: signRawCommand(t, pg.root, header(2, "launch", `,"sealed":`+someSealed))},
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSealCommand: a sealed command keeps only its header in the open,
// opens with the receiver's secret into the orders it was sealed with, and
// a command in the open stays as it is.
func TestSealCommand(t *testing.T) {
	secret, _ := seal.GenerateSecret()
	public, _ := seal.PublicKey(secret)
	now := int64(1_800_000_000_000)
	b := CommandBody{Type: CommandHub, Group: "g", By: NewDeviceID(), To: NewDeviceID(), ID: NewCommandID(), TimeMS: now, ExpiresMS: now + 1000,
		Hub: &HubOrder{Endpoints: []string{"192.0.2.1:8764"}, Clients: []HubClient{{Device: NewDeviceID(), Key: make([]byte, 32), PSK: make([]byte, 32)}}}}
	sb, err := SealCommand(b, public)
	if err != nil {
		t.Fatal(err)
	}
	if sb.V != sealedCommandVersion || sb.Hub != nil || len(sb.Sealed) == 0 {
		t.Fatalf("sealed: %+v", sb)
	}
	r, err := SignCommand(sb, newRoot(t).Key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.Body), "192.0.2.1") {
		t.Error("the hub's address shows in the sealed command")
	}
	got, err := parseCommandBody(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Open(secret); err != nil {
		t.Fatal(err)
	}
	if got.Hub == nil || len(got.Hub.Clients) != 1 || got.Hub.Endpoints[0] != "192.0.2.1:8764" || !got.Opened {
		t.Errorf("opened: %+v", got)
	}
	plain := b
	if err := plain.Open(nil); err != nil || plain.Opened {
		t.Errorf("a command in the open: %v %v", err, plain.Opened)
	}
	if err := sb.Open(nil); err == nil {
		t.Error("a sealed command opened without a secret")
	}
	if _, err := SealCommand(CommandBody{Type: CommandMode, ID: "x"}, public); err == nil {
		t.Error("an invalid command was sealed")
	}
}
