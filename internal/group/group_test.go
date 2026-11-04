// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// newGroup creates a group on a Linux member at t0.
func newGroup(t *testing.T) *Identity {
	t.Helper()
	id, err := Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Check(); err != nil {
		t.Fatalf("a new identity does not check: %v", err)
	}
	return id
}

// join admits a new device to admin's group, as pairing does: the member
// gets no CA keys.
func join(t *testing.T, admin *Identity, now time.Time) *Identity {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	id := NewDeviceID()
	cert, err := admin.GroupCA.IssueMember(id, &key.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	member := &Identity{ID: id, Key: key, Cert: cert, GroupCA: CA{Cert: admin.GroupCA.Cert}}
	if err := member.Check(); err != nil {
		t.Fatal(err)
	}
	return member
}

func TestDeviceID(t *testing.T) {
	a, b := NewDeviceID(), NewDeviceID()
	if a == b {
		t.Errorf("two device IDs are equal: %s", a)
	}
	if _, err := ParseDeviceID(string(a)); err != nil {
		t.Errorf("ParseDeviceID(%q): %v", a, err)
	}
	if got := a.HostName(); got != "cb-"+string(a)+".local" || len(strings.Split(got, ".")[0]) > 63 {
		t.Errorf("HostName() = %q", got)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("A", 32), strings.Repeat("0", 31) + "g",
		strings.Repeat("0", 33), strings.Repeat("0", 30) + "é"} {
		if _, err := ParseDeviceID(bad); err == nil {
			t.Errorf("ParseDeviceID(%q) succeeded", bad)
		}
	}
}

func TestCAs(t *testing.T) {
	id := newGroup(t)
	if ca := id.GroupCA.Cert; ca.MaxPathLen != 1 || ca.MaxPathLenZero || !strings.HasPrefix(ca.Subject.CommonName, "cbb group root ") {
		t.Errorf("%s: not a root with path length 1", ca.Subject.CommonName)
	}
	if !id.IsRoot() || !id.IsAdmin() || id.NeedsAdminKey() {
		t.Error("the creator of a group is not its root")
	}
	for _, ca := range []*x509.Certificate{id.GroupCA.Cert} {
		if !ca.IsCA || !ca.BasicConstraintsValid {
			t.Errorf("%s: not a CA", ca.Subject.CommonName)
		}
		if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Errorf("%s: cannot sign certificates", ca.Subject.CommonName)
		}
		if got := ca.NotAfter.Sub(t0); got < 19*365*24*time.Hour {
			t.Errorf("%s: valid for %v, want 20 years", ca.Subject.CommonName, got)
		}
		if ca.NotBefore.After(t0) {
			t.Errorf("%s: starts at %v, after its creation", ca.Subject.CommonName, ca.NotBefore)
		}
		if pub, ok := ca.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
			t.Errorf("%s: not a P-256 key", ca.Subject.CommonName)
		}
		if ca.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			t.Errorf("%s: signed with %v", ca.Subject.CommonName, ca.SignatureAlgorithm)
		}
	}
	if len(id.GroupCA.Cert.PermittedDNSDomains) != 0 {
		t.Errorf("the group CA has name constraints")
	}
	if Tag(id.GroupCA.Cert) == Tag(newGroup(t).GroupCA.Cert) || len(Tag(id.GroupCA.Cert)) != 16 {
		t.Errorf("Tag = %q", Tag(id.GroupCA.Cert))
	}
}

func TestMemberCertificate(t *testing.T) {
	admin := newGroup(t)
	later := t0.AddDate(1, 0, 0)
	mac := join(t, admin, later)
	c := mac.Cert
	if !c.NotBefore.Equal(admin.GroupCA.Cert.NotBefore) {
		t.Errorf("NotBefore = %v, want the CA's %v", c.NotBefore, admin.GroupCA.Cert.NotBefore)
	}
	if want := later.AddDate(2, 0, 0); !c.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, want %v", c.NotAfter, want)
	}
	if c.IsCA || c.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("IsCA = %v, KeyUsage = %v", c.IsCA, c.KeyUsage)
	}
	if got, err := DeviceOf(c); err != nil || got != mac.ID {
		t.Errorf("DeviceOf = %q, %v; want %q", got, err, mac.ID)
	}
	// Near the end of the CA's lifetime the certificate ends with the CA.
	end := admin.GroupCA.Cert.NotAfter.Add(-24 * time.Hour)
	key, _ := NewKey()
	last, err := admin.GroupCA.IssueMember(NewDeviceID(), &key.PublicKey, end)
	if err != nil {
		t.Fatal(err)
	}
	if !last.NotAfter.Equal(admin.GroupCA.Cert.NotAfter) {
		t.Errorf("a certificate issued a day before the CA ends lasts until %v, after the CA", last.NotAfter)
	}
}

func TestIssueErrors(t *testing.T) {
	admin := newGroup(t)
	key, _ := NewKey()
	if _, err := admin.GroupCA.IssueMember("not-an-id", &key.PublicKey, t0); err == nil {
		t.Error("issued a certificate for a bad device ID")
	}
	if _, err := admin.GroupCA.IssueMember(NewDeviceID(), &key.PublicKey, t0.AddDate(-1, 0, 0)); err == nil {
		t.Error("issued a certificate with the clock before the CA")
	}
	if _, err := admin.GroupCA.IssueMember(NewDeviceID(), &key.PublicKey, t0.AddDate(21, 0, 0)); err == nil {
		t.Error("issued a certificate with the clock after the CA")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := admin.GroupCA.IssueMember(NewDeviceID(), &other.PublicKey, t0); err == nil {
		t.Error("certified a P-384 key")
	}
	noKey := CA{Cert: admin.GroupCA.Cert}
	if _, err := noKey.IssueMember(NewDeviceID(), &key.PublicKey, t0); err == nil {
		t.Error("issued a certificate without the CA key")
	}
}

func TestSaveLoad(t *testing.T) {
	admin := newGroup(t)
	mac := join(t, admin, t0)
	for _, tt := range []struct {
		name  string
		id    *Identity
		admin bool
	}{
		{"group creator", admin, true}, {"member", mac, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := tt.id.Save(dir); err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(filepath.Join(dir, FileName))
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
				t.Errorf("the identity file has mode %v", fi.Mode().Perm())
			}
			got, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != tt.id.ID || !SameKey(got.Key, tt.id.Key.Public()) || !got.Cert.Equal(tt.id.Cert) ||
				!got.GroupCA.Cert.Equal(tt.id.GroupCA.Cert) {
				t.Error("the loaded identity differs")
			}
			if got.IsRoot() != tt.admin {
				t.Errorf("IsRoot() = %v, want %v", got.IsRoot(), tt.admin)
			}
			if tt.admin && !SameKey(got.GroupCA.Key, tt.id.GroupCA.Key.Public()) {
				t.Error("the loaded CA key differs")
			}
			if !tt.admin && got.GroupCA.Key != nil {
				t.Error("a member identity holds the CA key")
			}
		})
	}
	if _, err := Load(t.TempDir()); !errors.Is(err, ErrNoGroup) {
		t.Errorf("Load of an empty directory: %v, want ErrNoGroup", err)
	}
}

func TestLoadRejectsBadFiles(t *testing.T) {
	admin := newGroup(t)
	other := newGroup(t)
	dir := t.TempDir()
	if err := admin.Save(dir); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	var f identityFile
	if err := json.Unmarshal(good, &f); err != nil {
		t.Fatal(err)
	}
	otherKey, _ := x509.MarshalPKCS8PrivateKey(other.Key)
	otherCAKey, _ := x509.MarshalPKCS8PrivateKey(other.GroupCA.Key)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKCS8PrivateKey(p384)
	tests := []struct {
		name   string
		change func(f *identityFile)
	}{
		{"another version", func(f *identityFile) { f.Version = 2 }},
		{"another device ID", func(f *identityFile) { f.Device = string(NewDeviceID()) }},
		{"a bad device ID", func(f *identityFile) { f.Device = "x" }},
		{"another device key", func(f *identityFile) { f.Key = otherKey }},
		{"a P-384 device key", func(f *identityFile) { f.Key = p384DER }},
		{"a corrupt key", func(f *identityFile) { f.Key = []byte("junk") }},
		{"a member certificate from another group", func(f *identityFile) { f.Cert = other.Cert.Raw }},
		{"another group CA", func(f *identityFile) { f.GroupCA = other.GroupCA.Cert.Raw }},
		{"the key of another CA", func(f *identityFile) { f.GroupCAKey = otherCAKey }},
		{"a member certificate as the group CA", func(f *identityFile) { f.GroupCA, f.GroupCAKey = f.Cert, nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := f
			tt.change(&bad)
			data, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, FileName), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(dir); err == nil {
				t.Error("Load accepted the file")
			}
		})
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("Load accepted truncated JSON")
	}
	// Save refuses an identity whose parts do not belong together.
	broken := *admin
	broken.Cert = other.Cert
	if err := broken.Save(t.TempDir()); err == nil {
		t.Error("Save accepted a broken identity")
	}
}

func TestRenew(t *testing.T) {
	admin := newGroup(t)
	mac := join(t, admin, t0)
	if next, changed, err := admin.Renew(t0.AddDate(0, 6, 0)); err != nil || changed || next.Cert != admin.Cert {
		t.Errorf("Renew half a year in = changed %v, %v; want no change", changed, err)
	}
	// 18 months in, the member certificate has less than 240 days.
	at := t0.AddDate(1, 6, 0)
	next, changed, err := admin.Renew(at)
	if err != nil || !changed || !next.Cert.NotAfter.Equal(at.AddDate(2, 0, 0)) {
		t.Fatalf("Renew = %v, %v; member certificate ends at %v", changed, err, next.Cert.NotAfter)
	}
	if err := next.Check(); err != nil {
		t.Error(err)
	}
	if admin.Cert.NotAfter.Equal(next.Cert.NotAfter) {
		t.Error("Renew changed the old identity")
	}
	// A Mac cannot renew by itself.
	if _, changed, err := mac.Renew(at); changed || err != nil {
		t.Errorf("a Mac renewed its own certificate: %v, %v", changed, err)
	}
	// With the clock outside the CA's lifetime, Renew reports the error.
	if _, _, err := admin.Renew(t0.AddDate(30, 0, 0)); err == nil {
		t.Error("Renew 30 years later succeeded")
	}
	// With the clock before the CA's start, nothing can be renewed, and
	// nothing is.
	if _, changed, err := admin.Renew(t0.AddDate(-1, 0, 0)); changed || err != nil {
		t.Errorf("Renew with the clock a year behind: %v, %v", changed, err)
	}
}

func TestRenewMember(t *testing.T) {
	admin := newGroup(t)
	mac := join(t, admin, t0)
	other := newGroup(t)
	// Half a year in, nothing is due.
	if c, _, err := admin.RenewMember(mac.Cert, t0.AddDate(0, 6, 0)); c != nil || err != nil {
		t.Errorf("RenewMember half a year in = %v, %v", c, err)
	}
	at := t0.AddDate(1, 6, 0)
	// Only a member with the group CA key renews.
	if c, _, err := mac.RenewMember(admin.Cert, at); c != nil || err != nil {
		t.Errorf("a Mac renewed a certificate: %v, %v", c, err)
	}
	// A certificate of another group is not renewed.
	if c, _, err := admin.RenewMember(other.Cert, at); c != nil || err == nil {
		t.Errorf("RenewMember renewed another group's certificate: %v, %v", c, err)
	}
	cert, _, err := admin.RenewMember(mac.Cert, at)
	if err != nil || cert == nil {
		t.Fatalf("RenewMember = %v, %v", cert, err)
	}
	next, err := mac.WithCert(cert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Cert.NotAfter.Equal(at.AddDate(2, 0, 0)) || next.ID != mac.ID || mac.Cert == next.Cert {
		t.Errorf("WithCert: ends at %v", next.Cert.NotAfter)
	}
	// A Mac takes only a certificate for itself that ends later.
	if _, err := next.WithCert(mac.Cert.Raw); err == nil {
		t.Error("WithCert took an older certificate")
	}
	if _, err := mac.WithCert(admin.Cert.Raw); err == nil {
		t.Error("WithCert took another member's certificate")
	}
	if _, err := mac.WithCert([]byte("junk")); err == nil {
		t.Error("WithCert took junk")
	}
	forged, err := other.GroupCA.IssueMember(mac.ID, PublicKey(mac.Key), at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mac.WithCert(forged.Raw); err == nil {
		t.Error("WithCert took a certificate from another group CA")
	}
}

func TestRenewNearTheEndOfTheCA(t *testing.T) {
	// In the last months of the CA, certificates end with it; Renew must
	// not issue a new one on every call.
	admin := newGroup(t)
	late := admin.GroupCA.Cert.NotAfter.Add(-30 * 24 * time.Hour)
	next, changed, err := admin.Renew(late)
	if err != nil || !changed {
		t.Fatalf("first Renew near the end: %v, %v", changed, err)
	}
	if !next.Cert.NotAfter.Equal(admin.GroupCA.Cert.NotAfter) {
		t.Errorf("the member certificate ends at %v, not with the CA", next.Cert.NotAfter)
	}
	if _, changed, err := next.Renew(late.Add(time.Hour)); changed || err != nil {
		t.Errorf("second Renew near the end: %v, %v; want no change", changed, err)
	}
}

func TestCheckRejectsOtherCurves(t *testing.T) {
	// A group CA with a P-384 key, and a member certificate it issued
	// properly: Load refuses CA keys that are not P-256, so Check refuses
	// such a CA first.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "P-384 CA"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.AddDate(20, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &CA{Cert: caCert, Key: key}
	devKey, _ := NewKey()
	id := &Identity{ID: NewDeviceID(), Key: devKey, GroupCA: CA{Cert: caCert}}
	if id.Cert, err = ca.IssueMember(id.ID, &devKey.PublicKey, t0); err != nil {
		t.Fatal(err)
	}
	if err := id.Check(); err == nil {
		t.Error("Check accepted a P-384 group CA")
	}
}

func TestFileIsJSON(t *testing.T) {
	dir := t.TempDir()
	if err := join(t, newGroup(t), t0).Save(dir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, FileName))
	if !json.Valid(data) || !bytes.HasSuffix(data, []byte("\n")) || bytes.Contains(data, []byte("group_ca_key")) {
		t.Errorf("the identity file of a Mac:\n%s", data)
	}
}
