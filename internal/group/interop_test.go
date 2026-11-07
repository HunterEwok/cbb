// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the interop test vectors")

// TestSwiftCertificates checks the group CA and member certificate that the
// phone app's CBBKit issues (testdata/interop/swift-certs.json,
// written by its CertificateTests): a computer must take them as its own
// identity and use them in member TLS.
func TestSwiftCertificates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "swift-certs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA   []byte `json:"group_ca"`
		Member    []byte `json:"member"`
		Device    string `json:"device"`
		MemberKey []byte `json:"member_key"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(v.Member)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), v.MemberKey)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{ID: DeviceID(v.Device), Key: key, Cert: cert, GroupCA: CA{Cert: ca}}
	if err := id.Check(); err != nil {
		t.Fatalf("a computer refuses the phone's certificates: %v", err)
	}
	if len(ca.SubjectKeyId) == 0 || string(cert.AuthorityKeyId) != string(ca.SubjectKeyId) {
		t.Error("the key identifiers do not link the member certificate to the CA")
	}
	// The member certificate works in member TLS with itself on the other
	// side, both checking the chain to the phone's CA.
	at := TLSOptions{Now: func() time.Time { return cert.NotBefore.Add(48 * time.Hour) }}
	ccs, scs, cerr, serr := handshake(t, id.ClientTLS(id.ID, at), id.ServerTLS(at))
	if cerr != nil || serr != nil {
		t.Fatalf("member TLS with the phone's certificates: client %v, server %v", cerr, serr)
	}
	if got, _ := PeerID(ccs); got != id.ID {
		t.Errorf("client saw %s", got)
	}
	if got, _ := PeerID(scs); got != id.ID {
		t.Errorf("server saw %s", got)
	}
}

// TestSwiftRecords reads the records the phone app's CBBKit signs
// (testdata/interop/swift-records.json, or the file in the directory
// CBB_INTEROP_OUT names, which CI fills from a fresh Swift run) and
// checks that Go reads the same devices, revocations and digest.
func TestSwiftRecords(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-records.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA []byte   `json:"group_ca"`
		Records []Record `json:"records"`
		Digest  string   `json:"digest"`
		Devices []string `json:"devices"`
		Revoked [][]byte `json:"revoked"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	if ca.MaxPathLen != 1 {
		t.Errorf("the phone's root has path length %d, want 1", ca.MaxPathLen)
	}
	s := NewRecords(ca)
	for i, r := range v.Records {
		if _, err := s.Add(r); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if s.Digest() != v.Digest {
		t.Errorf("digest %s, Swift says %s", s.Digest(), v.Digest)
	}
	var got []string
	for _, d := range s.Devices() {
		got = append(got, string(d.ID))
		if d.Role != RolePhone {
			t.Errorf("device %s has role %q", d.ID, d.Role)
		}
	}
	if strings.Join(got, ",") != strings.Join(v.Devices, ",") {
		t.Errorf("devices %v, Swift says %v", got, v.Devices)
	}
	for _, k := range v.Revoked {
		var h KeyHash
		copy(h[:], k)
		if len(k) != len(h) || !s.Revoked(h) {
			t.Errorf("key %x is not revoked in Go", k)
		}
	}
}

// TestSwiftRenewal checks that a member keeps a certificate that the phone
// app renewed for it (testdata/interop/swift-renewal.json, or the file in
// CBB_INTEROP_OUT), as it does when a cert message arrives.
func TestSwiftRenewal(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-renewal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Device  string `json:"device"`
		GroupCA []byte `json:"group_ca"`
		Key     []byte `json:"key"`
		Cert    []byte `json:"cert"`
		Renewed []byte `json:"renewed"`
		// From an admin phone, with its admin CA as the cert message's
		// issuer; absent in copies written before it.
		AdminCA      []byte `json:"admin_ca"`
		AdminRenewed []byte `json:"admin_renewed"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(v.Cert)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(v.Key)
	var key *ecdsa.PrivateKey
	if err == nil {
		key, _ = k.(*ecdsa.PrivateKey)
	} else if key, err = x509.ParseECPrivateKey(v.Key); err != nil {
		t.Fatalf("the key: %v", err)
	}
	id := &Identity{ID: DeviceID(v.Device), Key: key, Cert: cert, GroupCA: CA{Cert: ca}}
	if err := id.Check(); err != nil {
		t.Fatalf("the member before the renewal: %v", err)
	}
	next, err := id.WithCert(v.Renewed)
	if err != nil {
		t.Fatalf("the renewed certificate: %v", err)
	}
	if !next.Cert.NotAfter.After(cert.NotAfter) {
		t.Errorf("the renewal ends %v, not after %v", next.Cert.NotAfter, cert.NotAfter)
	}
	if v.AdminRenewed == nil {
		return
	}
	byAdmin, err := id.WithCertFrom(v.AdminRenewed, v.AdminCA)
	if err != nil {
		t.Fatalf("the certificate an admin phone renewed: %v", err)
	}
	if byAdmin.Issuer == nil || string(byAdmin.Issuer.Raw) != string(v.AdminCA) {
		t.Error("the member did not take the admin CA as its issuer")
	}
}

// TestSwiftAdmin checks what an admin phone makes in the phone app's
// CBBKit (testdata/interop/swift-admin.json, or the file in
// CBB_INTEROP_OUT): its admin CA under the root, a computer's
// certificate from that CA, which the computer takes as its identity, and
// records signed through the admin CA.
func TestSwiftAdmin(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA []byte   `json:"group_ca"`
		AdminCA []byte   `json:"admin_ca"`
		Cert    []byte   `json:"cert"`
		Key     []byte   `json:"key"`
		Device  string   `json:"device"`
		Records []Record `json:"records"`
		Devices []string `json:"devices"`
		Digest  string   `json:"digest"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := x509.ParseCertificate(v.AdminCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminCA(admin, ca); err != nil {
		t.Fatalf("the phone's admin CA: %v", err)
	}
	cert, err := x509.ParseCertificate(v.Cert)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(v.Key)
	key, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		t.Fatalf("the key: %v", err)
	}
	id := &Identity{ID: DeviceID(v.Device), Key: key, Cert: cert, Issuer: admin, GroupCA: CA{Cert: ca}}
	if err := id.Check(); err != nil {
		t.Fatalf("a computer refuses a certificate from the admin CA: %v", err)
	}
	at := TLSOptions{Now: func() time.Time { return cert.NotBefore.Add(48 * time.Hour) }}
	if _, _, cerr, serr := handshake(t, id.ClientTLS(id.ID, at), id.ServerTLS(at)); cerr != nil || serr != nil {
		t.Fatalf("member TLS through the admin CA: client %v, server %v", cerr, serr)
	}
	s := NewRecords(ca)
	for i, r := range v.Records {
		if _, err := s.Add(r); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if s.Digest() != v.Digest {
		t.Errorf("digest %s, Swift says %s", s.Digest(), v.Digest)
	}
	var got []string
	for _, d := range s.Devices() {
		got = append(got, string(d.ID))
	}
	if strings.Join(got, ",") != strings.Join(v.Devices, ",") {
		t.Errorf("devices %v, Swift says %v", got, v.Devices)
	}
	if err := s.Refused([]*x509.Certificate{cert, admin}); err != nil {
		t.Errorf("the computer is refused: %v", err)
	}
}

type rootChain struct {
	Name    string   `json:"name"`
	Chain   [][]byte `json:"chain"` // leaf first, then its admin CA
	Refused bool     `json:"refused"`
}

// TestGoRootVectors checks a handover by a claim (TestRootHandover) for
// the chains a member takes and refuses after it, and the cases of
// testdata/interop/v2-records.json about claims that take effect through a
// Records set.
func TestGoRootVectors(t *testing.T) {
	checkV2Cases(t, "claim waits and takes effect", "chain of claims", "settings delay")
	h := newHandover(t)
	s := h.records(t)
	thiefCA := adminCA(t, h.pg.root)
	refused := 0
	for _, c := range []struct {
		name    string
		chain   []*x509.Certificate
		refused bool
	}{
		{"the lost phone", []*x509.Certificate{h.lost}, true},
		{"the computer the old root admitted", []*x509.Certificate{h.byRoot}, false},
		{"the computer B admitted", []*x509.Certificate{h.byB, h.pg.b.Cert}, false},
		{"phone B", []*x509.Certificate{h.b, h.pg.b.Cert}, false},
		{"a device from the new root", []*x509.Certificate{h.fromNew}, false},
		{"a new certificate from the old root", []*x509.Certificate{member(t, h.pg.root)}, true},
		{"a new admin CA under the old root", []*x509.Certificate{member(t, thiefCA), thiefCA.Cert}, true},
		// Certificates the issuer is not: the issuer checked is the one
		// that signed the leaf, wherever it comes.
		{"the computer B admitted, another CA first", []*x509.Certificate{h.byB, thiefCA.Cert, h.pg.b.Cert}, false},
		{"a new admin CA under the old root, behind B's", []*x509.Certificate{member(t, thiefCA), h.pg.b.Cert, thiefCA.Cert}, true},
		{"a new certificate from the old root, with B's CA", []*x509.Certificate{member(t, h.pg.root), h.pg.b.Cert}, true},
		{"the computer B admitted, without its issuer", []*x509.Certificate{h.byB, thiefCA.Cert}, true},
	} {
		if got := s.Refused(c.chain) != nil; got != c.refused {
			t.Errorf("%s: refused %v, want %v", c.name, got, c.refused)
		}
		if c.refused {
			refused++
		}
	}
	if refused != 6 {
		t.Errorf("%d chains refused, want the lost phone, the two from the old root's key, those two with another CA, and one without its issuer", refused)
	}
}

// TestGoUpgradeVectors checks that the records of a legacy group that cbb
// upgrade gave a root (version 1) are refused: legacy groups and cbb
// upgrade went with version 1.
func TestGoUpgradeVectors(t *testing.T) {
	checkV1Refused(t)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestSwiftRoot reads a takeover that the phone kit signs (swift-root.json
// from its RootTests, in the directory CBB_INTEROP_OUT names, or
// testdata/interop): Go must follow it to the same root and devices, refuse
// the lost phone and keep the computer the old root admitted.
func TestSwiftRoot(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-root.json"))
	if os.IsNotExist(err) && os.Getenv("CBB_INTEROP_OUT") == "" {
		t.Skip("no swift-root.json; the phone kit's tests write it")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA []byte   `json:"group_ca"`
		Records []Record `json:"records"`
		Roots   [][]byte `json:"roots"`
		Devices []string `json:"devices"`
		Digest  string   `json:"digest"`
		Lost    []byte   `json:"lost"`
		Kept    []byte   `json:"kept"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) > 0 {
		t.Fatalf("Go refuses the phone's records: %v", errs)
	}
	s.SetClock(afterDelay)
	if s.Digest() != v.Digest {
		t.Error("the digest differs")
	}
	roots := s.Roots()
	if len(roots) != len(v.Roots) || len(roots) != 1 || string(roots[0].Raw) != string(v.Roots[0]) {
		t.Fatalf("Go follows %d roots, the phone %d", len(roots), len(v.Roots))
	}
	var got []string
	for _, d := range s.Devices() {
		got = append(got, string(d.ID))
	}
	if strings.Join(got, " ") != strings.Join(v.Devices, " ") {
		t.Errorf("devices %v, the phone lists %v", got, v.Devices)
	}
	lost, err := x509.ParseCertificate(v.Lost)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := x509.ParseCertificate(v.Kept)
	if err != nil {
		t.Fatal(err)
	}
	if s.Refused([]*x509.Certificate{lost}) == nil {
		t.Error("the lost phone is not refused")
	}
	if err := s.Refused([]*x509.Certificate{kept}); err != nil {
		t.Errorf("the computer the old root admitted is refused: %v", err)
	}
}

// TestSwiftComputerAdmin reads the admin CA that the phone kit's root
// issued for a computer's admin key, and the records that list the
// computer as an admin (ComputerAdminTests.testComputerAdminForGo): the CA
// is the one an Identity takes, and Go lists the computer as an admin.
func TestSwiftComputerAdmin(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-computer-admin.json"))
	if os.IsNotExist(err) && os.Getenv("CBB_INTEROP_OUT") == "" {
		t.Skip("no swift-computer-admin.json; the phone kit's tests write it")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA  []byte   `json:"group_ca"`
		Device   DeviceID `json:"device"`
		AdminKey []byte   `json:"admin_key"`
		AdminCA  []byte   `json:"admin_ca"`
		Records  []Record `json:"records"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.AdminCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminCA(ca, root); err != nil {
		t.Fatalf("Go refuses the admin CA: %v", err)
	}
	if ca.Subject.CommonName != AdminName(v.Device) || string(ca.RawSubjectPublicKeyInfo) != string(v.AdminKey) {
		t.Error("the admin CA does not name the computer or its admin key")
	}
	s := NewRecords(root)
	if _, errs := s.AddAll(v.Records); len(errs) > 0 {
		t.Fatalf("Go refuses the phone's records: %v", errs)
	}
	for _, d := range s.Devices() {
		if d.ID == v.Device {
			if !d.Admin || d.AdminKey == nil || *d.AdminKey != KeyHashOf(ca) {
				t.Errorf("Go does not list the computer as an admin: %+v", d)
			}
			return
		}
	}
	t.Error("Go does not list the computer")
}

// TestGoAdminVectors checks what a computer's admin CA may do in a phone's
// group, as TestAdminPowers tells it: the cases of
// testdata/interop/v2-records.json about powers through a Records set.
func TestGoAdminVectors(t *testing.T) {
	checkV2Cases(t, "powers", "one record under two admin CAs", "two histories of an admin")
}

// TestGoFreezeVectors checks an admin computer freezing another, as
// TestFreeze tells it: the cases of testdata/interop/v2-records.json about
// freezes through a Records set.
func TestGoFreezeVectors(t *testing.T) {
	checkV2Cases(t, "freeze and thaw", "freezes crossed")
}

// TestGoTakeoverVectors checks claims to take a group over, as
// TestComputerTakeover tells it for an admin computer: the cases of
// testdata/interop/v2-records.json about claims that are disputed, void or
// early through a Records set.
func TestGoTakeoverVectors(t *testing.T) {
	checkV2Cases(t, "claim disputed", "claim while another waits", "claimed root signs early", "stranger's claim", "two histories of the root", "checkpoint", "times at the ends", "record of a later version", "device seal")
}

// TestSwiftCommand checks the commands a phone kit signed
// (swift-command.json, which the kits' tests write) with the records it
// signed: mode commands with the root's key and with an admin CA's, a hub, a
// paste, a paste-off, an action, an actions-off, a mute and an unmute
// command are taken, for the device they name.
func TestSwiftCommand(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-command.json"))
	if os.IsNotExist(err) && os.Getenv("CBB_INTEROP_OUT") == "" {
		t.Skip("no swift-command.json; the phone kit's tests write it")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA  []byte   `json:"group_ca"`
		Records  []Record `json:"records"`
		To       DeviceID `json:"to"`
		Commands []Record `json:"commands"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) > 0 {
		t.Fatalf("Go refuses the phone's records: %v", errs)
	}
	// Two mode commands, by the root and by an admin, a hub command by the
	// root with one client, a typed paste by the admin, paste-off by the
	// root, lock by the admin, actions-off by the root, and a paste by the
	// admin sealed to the key of go-sealed-commands.json, then a mute for an
	// hour by the admin and an unmute by the root.
	if len(v.Commands) != 10 {
		t.Fatalf("%d commands, want 10", len(v.Commands))
	}
	var sealed sealedVectors
	data, err = os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "go-sealed-commands.json"))
	if err == nil {
		err = json.Unmarshal(data, &sealed)
	}
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range v.Commands {
		var b CommandBody
		if err := json.Unmarshal(c.Body, &b); err != nil {
			t.Fatal(err)
		}
		got, err := s.VerifyCommand(c, v.To, time.UnixMilli(b.TimeMS))
		if err != nil {
			t.Fatalf("command %d: %v", i, err)
		}
		if i < 2 && (got.Type != CommandMode || got.Mode != "receive") {
			t.Errorf("command %d: %+v", i, got)
		}
		if i == 2 && (got.Type != CommandHub || got.Hub.Forwarder == nil || got.Hub.Forwarder.Endpoint != "203.0.113.9:8764" ||
			len(got.Hub.Clients) != 1 || len(got.Hub.Clients[0].PSK) != 32) {
			t.Errorf("the hub command: %+v", got.Hub)
		}
		if i == 3 && (got.Type != CommandPaste || got.Mode != PasteByTyping || !got.Enter || got.Kind != "text" || got.Text != "echo <ok> & \"done\"\n") {
			t.Errorf("the paste command: %+v", got)
		}
		if i == 4 && got.Type != CommandPasteOff {
			t.Errorf("the paste-off command: %+v", got)
		}
		if i == 5 && (got.Type != CommandAction || got.Action != "lock") {
			t.Errorf("the action command: %+v", got)
		}
		if i == 6 && got.Type != CommandActionsOff {
			t.Errorf("the actions-off command: %+v", got)
		}
		if i == 8 && (got.Type != CommandMute || got.ForMS != time.Hour.Milliseconds()) {
			t.Errorf("the mute command: %+v", got)
		}
		if i == 9 && got.Type != CommandUnmute {
			t.Errorf("the unmute command: %+v", got)
		}
		if i == 7 {
			if got.V != sealedCommandVersion || got.Text != "" {
				t.Errorf("the sealed paste came in the open: %+v", got)
			}
			if err := got.Open(sealed.Secret); err != nil || got.Type != CommandPaste || got.Text != "sealed <text>" {
				t.Errorf("the sealed paste: %v, %+v", err, got)
			}
		}
		if _, err := s.VerifyCommand(c, NewDeviceID(), time.UnixMilli(b.TimeMS)); err == nil {
			t.Errorf("command %d was taken by another device", i)
		}
	}
}

type hubVectors struct {
	GroupCA  []byte     `json:"group_ca"`
	Records  []Record   `json:"records"`
	HubOrder []DeviceID `json:"hub_order"`
}

// TestGoHubVectors writes (with -update) and checks
// testdata/interop/v2-hubs.json: the order of a group's hubs
// (docs/protocol.md, section 11, "Several hubs"), the phones first and the
// root's own device first among them, then the admin computers by device
// ID, without a plain computer or a removed admin, for the phone kits and
// the lite member to agree with.
func TestGoHubVectors(t *testing.T) {
	var file hubVectors
	pg := newPhoneGroup(t)
	{
		g := pg.root.Cert
		rootMember := member(t, pg.root)
		rootDev := DeviceID(rootMember.Subject.CommonName)
		key := KeyHashOf(rootMember)
		own, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: nextTime(), Device: string(rootDev), Name: "root phone", Role: RolePhone, Key: &key, HoldsRoot: true}, pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		pcOne, pcTwo, gone := adminCA(t, pg.root), adminCA(t, pg.root), adminCA(t, pg.root)
		all := []Record{
			own,
			adminRecord(t, g, pg.root, nil, member(t, pg.root), "admin phone", KeyHashOf(pg.a.Cert)),
			computerAdminRecord(t, pg, member(t, pg.root), "pc one", KeyHashOf(pcOne.Cert)),
			computerAdminRecord(t, pg, member(t, pg.root), "pc two", KeyHashOf(pcTwo.Cert)),
			computerAdminRecord(t, pg, member(t, pg.root), "removed pc", KeyHashOf(gone.Cert)),
			deviceRecord(t, g, pg.root, nil, member(t, pg.root), "plain pc", 1),
			revokeRecord(t, g, pg.root, nil, []KeyHash{KeyHashOf(gone.Cert)}),
		}
		s := NewRecords(g)
		if _, errs := s.AddAll(all); len(errs) != 0 {
			t.Fatal(errs)
		}
		v := hubVectors{GroupCA: g.Raw, Records: all, HubOrder: s.HubOrder()}
		file = v
		writeV2Vectors(t, "v2-hubs.json", v)
	}
	v := file
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) != 0 {
		t.Fatal(errs)
	}
	got := s.HubOrder()
	if !slices.Equal(got, v.HubOrder) {
		t.Errorf("HubOrder = %v, the file has %v", got, v.HubOrder)
	}
	names := map[DeviceID]string{}
	for _, d := range s.Devices() {
		names[d.ID] = d.Name
	}
	var gotNames []string
	for _, d := range got {
		gotNames = append(gotNames, names[d])
	}
	if len(gotNames) != 4 || gotNames[0] != "root phone" || gotNames[1] != "admin phone" || !slices.Contains(gotNames[2:], "pc one") || !slices.Contains(gotNames[2:], "pc two") {
		t.Errorf("the hubs are %v", gotNames)
	}
	if string(got[2]) > string(got[3]) {
		t.Error("the computers are not in the order of their device IDs")
	}

	// The root's hubs table puts its main hubs first, in its order,
	// without a device that may not be a hub; the others follow.
	ids := map[string]string{}
	for id, n := range names {
		ids[n] = string(id)
	}
	table, err := signRecord(RecordBody{Type: RecordHubs, Group: Tag(ca), TimeMS: nextTime(), Hubs: []string{ids["pc two"], ids["plain pc"], ids["pc one"]}}, pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, s, table)
	gotNames = nil
	for _, d := range s.HubOrder() {
		gotNames = append(gotNames, names[d])
	}
	if want := []string{"pc two", "pc one", "root phone", "admin phone"}; !slices.Equal(gotNames, want) {
		t.Errorf("with a table the hubs are %v, want %v", gotNames, want)
	}
}

type commandVectors struct {
	GroupCA  []byte          `json:"group_ca"`
	Records  []Record        `json:"records"`
	Self     DeviceID        `json:"self"`
	NowMS    int64           `json:"now_ms"`
	Commands []commandVector `json:"commands"`
}

type commandVector struct {
	Name    string `json:"name"`
	Command Record `json:"command"`
	OK      bool   `json:"ok"`
	Mode    string `json:"mode,omitempty"`
	// Verified: whether the records show that by holds the signing key,
	// for the limits per sender and the logs (Records.CommandSender).
	Verified bool `json:"verified,omitempty"`
}

// TestGoCommandVectors writes (with -update) and checks
// testdata/interop/v2-commands.json: mode, paste and paste-off commands for one phone, signed by
// the root, an admin phone and admin computers (one frozen, one removed),
// or for another device or group, expired, from the future or altered, and
// whether each counts (docs/protocol.md, section 15), for the phone kits
// and the lite member to agree with.
func TestGoCommandVectors(t *testing.T) {
	var file commandVectors
	{
		pg := newPhoneGroup(t)
		g := pg.root.Cert
		phone, pc, frozen, removed := pg.a, adminCA(t, pg.root), adminCA(t, pg.root), adminCA(t, pg.root)
		self := member(t, pg.root)
		selfID := DeviceID(self.Subject.CommonName)
		phoneM, pcM, frozenM, removedM := member(t, phone), member(t, pc), member(t, frozen), member(t, removed)
		// A command's by is its signer's device; the root has none here,
		// so its by names a device the records do not show.
		rootBy := NewDeviceID()
		byOf := map[*CA]DeviceID{phone: DeviceID(phoneM.Subject.CommonName), pc: DeviceID(pcM.Subject.CommonName),
			frozen: DeviceID(frozenM.Subject.CommonName), removed: DeviceID(removedM.Subject.CommonName), pg.root: rootBy}
		all := []Record{
			adminRecord(t, g, pg.root, nil, phoneM, "admin phone", KeyHashOf(phone.Cert)),
			computerAdminRecord(t, pg, pcM, "pc", KeyHashOf(pc.Cert)),
			computerAdminRecord(t, pg, frozenM, "frozen pc", KeyHashOf(frozen.Cert)),
			computerAdminRecord(t, pg, removedM, "removed pc", KeyHashOf(removed.Cert)),
			deviceRecord(t, g, pg.root, nil, self, "my phone", 1),
			freezeRecord(t, g, pc, []*x509.Certificate{pc.Cert}, []KeyHash{KeyHashOf(frozen.Cert)}),
			revokeRecord(t, g, pg.root, nil, []KeyHash{KeyHashOf(removed.Cert)}),
		}
		now := int64(1_800_000_000_000)
		sign := func(signer *CA, chain []*x509.Certificate, to DeviceID, tag string, at int64, mode string) Record {
			by := byOf[signer]
			if by == "" {
				by = NewDeviceID() // a key of another group
			}
			r, err := SignCommand(CommandBody{Type: CommandMode, Group: tag, By: by, To: to, ID: NewCommandID(),
				TimeMS: at, ExpiresMS: at + CommandLifetime.Milliseconds(), Mode: mode}, signer.Key, chain...)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		tag := Tag(g)
		paste := func(signer *CA, chain []*x509.Certificate, typ string) Record {
			b := CommandBody{Type: typ, Group: tag, By: byOf[signer], To: selfID, ID: NewCommandID(), TimeMS: now, ExpiresMS: now + CommandLifetime.Milliseconds()}
			if typ == CommandPaste {
				b.Mode, b.Kind, b.Text, b.Enter = PasteByClipboard, "text", "ls -l <dir> & echo \"done\"\n", true
			}
			r, err := SignCommand(b, signer.Key, chain...)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		altered := sign(pg.root, nil, selfID, tag, now, "own")
		misnamed, err := SignCommand(CommandBody{Type: CommandMode, Group: tag, By: byOf[phone], To: selfID, ID: NewCommandID(),
			TimeMS: now, ExpiresMS: now + CommandLifetime.Milliseconds(), Mode: "own"}, pc.Key, pc.Cert)
		if err != nil {
			t.Fatal(err)
		}
		rootAsSelf, err := SignCommand(CommandBody{Type: CommandMode, Group: tag, By: selfID, To: selfID, ID: NewCommandID(),
			TimeMS: now, ExpiresMS: now + CommandLifetime.Milliseconds(), Mode: "own"}, pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		rootAsPC, err := SignCommand(CommandBody{Type: CommandMode, Group: tag, By: byOf[pc], To: selfID, ID: NewCommandID(),
			TimeMS: now, ExpiresMS: now + CommandLifetime.Milliseconds(), Mode: "own"}, pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		altered.Body = []byte(strings.Replace(string(altered.Body), `"own"`, `"send"`, 1))
		v := commandVectors{GroupCA: g.Raw, Records: all, Self: selfID, NowMS: now}
		for _, c := range []commandVector{
			{Name: "the root", Command: sign(pg.root, nil, selfID, tag, now, "shared"), Mode: "shared"},
			{Name: "the admin phone", Command: sign(phone, []*x509.Certificate{phone.Cert}, selfID, tag, now-1000, "receive"), Mode: "receive", Verified: true},
			{Name: "an admin computer", Command: sign(pc, []*x509.Certificate{pc.Cert}, selfID, tag, now, "send"), Mode: "send", Verified: true},
			{Name: "a frozen admin computer", Command: sign(frozen, []*x509.Certificate{frozen.Cert}, selfID, tag, now, "own")},
			{Name: "a removed admin computer", Command: sign(removed, []*x509.Certificate{removed.Cert}, selfID, tag, now, "own")},
			{Name: "a key of another group", Command: sign(newRoot(t), nil, selfID, tag, now, "own")},
			{Name: "for another device", Command: sign(pg.root, nil, NewDeviceID(), tag, now, "own")},
			{Name: "for another group", Command: sign(pg.root, nil, selfID, Tag(newRoot(t).Cert), now, "own")},
			{Name: "expired", Command: sign(pg.root, nil, selfID, tag, now-CommandLifetime.Milliseconds(), "own")},
			{Name: "signed in the future", Command: sign(pg.root, nil, selfID, tag, now+CommandAhead.Milliseconds()+1, "own")},
			{Name: "altered", Command: altered},
			{Name: "an admin computer naming another device", Command: misnamed},
			{Name: "the root, with no device here, naming this device", Command: rootAsSelf},
			{Name: "the root, with no device here, naming an admin computer", Command: rootAsPC},
			{Name: "a paste by an admin computer", Command: paste(pc, []*x509.Certificate{pc.Cert}, CommandPaste), Mode: PasteByClipboard, Verified: true},
			{Name: "a paste by a frozen admin computer", Command: paste(frozen, []*x509.Certificate{frozen.Cert}, CommandPaste)},
			{Name: "paste-off by the root", Command: paste(pg.root, nil, CommandPasteOff), OK: true},
		} {
			c.OK = c.OK || c.Mode != ""
			v.Commands = append(v.Commands, c)
		}
		file = v
	}
	writeV2Vectors(t, "v2-commands.json", file)
	v := file
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(v.Commands) != 17 {
		t.Fatalf("the file has %d commands", len(v.Commands))
	}
	for _, c := range v.Commands {
		body, err := s.VerifyCommand(c.Command, v.Self, time.UnixMilli(v.NowMS))
		if (err == nil) != c.OK {
			t.Errorf("%s: VerifyCommand = %v, the file says ok %v", c.Name, err, c.OK)
		}
		if err == nil && body.Mode != c.Mode {
			t.Errorf("%s: the mode is %q, the file has %q", c.Name, body.Mode, c.Mode)
		}
		if _, verified := s.CommandSender(c.Command, body.By); err == nil && verified != c.Verified {
			t.Errorf("%s: the sender is verified %v, the file says %v", c.Name, verified, c.Verified)
		}
	}
}
