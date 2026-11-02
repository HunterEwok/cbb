// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"errors"
	"testing"
)

// TestRecoveryCertificateCarriesRecords checks that a member certificate
// the recovery key's admin CA issued, as a new phone's after every phone
// was lost, gets a connection that carries records only (docs/protocol.md,
// section 10, "The recovery key"), so that its claim reaches the group,
// and nothing once the root removed the key.
func TestRecoveryCertificateCarriesRecords(t *testing.T) {
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	recs := NewRecords(g)
	k := KeyHashOf(pg.b.Cert)
	r, err := signRecord(RecordBody{Type: RecordRecovery, Group: Tag(g), TimeMS: nextTime(), Admin: &k, Cert: pg.b.Cert.Raw}, pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, recs, r)
	if st := recs.State(); st.Recovery == nil || *st.Recovery != k {
		t.Fatalf("the state names no recovery key: %+v", st)
	}
	phone := member(t, pg.b)
	err = recs.Refused([]*x509.Certificate{phone, pg.b.Cert})
	if !errors.Is(err, ErrRecordsOnly) {
		t.Fatalf("a certificate from the recovery key: Refused = %v, want records only", err)
	}
	r, err = signRecord(RecordBody{Type: RecordRevoke, Group: Tag(g), TimeMS: nextTime(), Keys: []KeyHash{k}}, pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, recs, r)
	if err := recs.Refused([]*x509.Certificate{phone, pg.b.Cert}); err == nil || errors.Is(err, ErrRecordsOnly) {
		t.Fatalf("a certificate from a removed recovery key: Refused = %v, want refused", err)
	}
}
