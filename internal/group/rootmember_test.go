// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"testing"
)

// rootOf returns the root's own device and the role the devices list
// gives it, as a member that asks whether the root is a computer reads it.
func rootOf(s *Records) (DeviceID, string) {
	root := s.RootDevice()
	for _, d := range s.Devices() {
		if d.ID == root {
			return root, d.Role
		}
	}
	return root, ""
}

// TestGoRootMemberVectors checks the root's own device: the device of the
// root's newest record that says it holds the root, whether it is a phone
// or a computer, the same in every order of the records.
func TestGoRootMemberVectors(t *testing.T) {
	type story struct {
		root *CA
		a, b *x509.Certificate
	}
	newStory := func() story {
		root := newRoot(t)
		return story{root, member(t, root), member(t, root)}
	}
	own := func(st story, name, role string, cert *x509.Certificate) Record {
		key := KeyHashOf(cert)
		r, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(st.root.Cert), TimeMS: nextTime(), Device: cert.Subject.CommonName, Name: name, Role: role, Key: &key, HoldsRoot: true}, st.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	s1, s2, s3 := newStory(), newStory(), newStory()
	dev := func(c *x509.Certificate) DeviceID { return DeviceID(c.Subject.CommonName) }
	for _, c := range []struct {
		name string
		st   story
		recs []Record
		dev  DeviceID
		role string
	}{
		{"a phone, then a computer", s1, []Record{own(s1, "phone a", RolePhone, s1.a), own(s1, "pc b", RoleMember, s1.b), deviceRecord(t, s1.root.Cert, s1.root, nil, member(t, s1.root), "plain pc", 1)}, dev(s1.b), RoleMember},
		{"a computer, then a phone", s2, []Record{own(s2, "pc a", RoleMember, s2.a), own(s2, "phone b", RolePhone, s2.b)}, dev(s2.b), RolePhone},
		{"one device as a phone, then as a computer", s3, []Record{own(s3, "as a phone", RolePhone, s3.a), own(s3, "as a pc", RoleMember, s3.a)}, dev(s3.a), RoleMember},
	} {
		permute(len(c.recs), func(order []int) {
			s := NewRecords(c.st.root.Cert)
			for _, k := range order {
				mustAdd(t, s, c.recs[k])
			}
			if dev, role := rootOf(s); dev != c.dev || role != c.role {
				t.Errorf("%s, order %v: the root is %s, %s; want %s, %s", c.name, order, dev, role, c.dev, c.role)
			}
		})
	}
}
