// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package core

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/authority"
)

// TestEvaluate gives every vector's state through Evaluate, from the core
// when it is linked and from Go's rules otherwise, and checks it against
// both the vector and Go's rules.
func TestEvaluate(t *testing.T) {
	data, err := os.ReadFile("../../testdata/interop/v2-records.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name        string `json:"name"`
			GroupCA     []byte `json:"group_ca"`
			Group       string `json:"group"`
			NowMS       int64  `json:"now_ms"`
			TimeUnknown bool   `json:"time_unknown"`
			FirstSeen   []struct {
				Record authority.Hash `json:"record"`
				MS     int64          `json:"ms"`
			} `json:"first_seen"`
			Records []authority.Record `json:"records"`
			State   string             `json:"state"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatal(err)
		}
		in := authority.Input{GroupCA: ca, Group: c.Group, NowMS: c.NowMS, TimeUnknown: c.TimeUnknown, Records: c.Records, FirstSeen: map[authority.Hash]int64{}}
		for _, s := range c.FirstSeen {
			in.FirstSeen[s.Record] = s.MS
		}
		got, err := Evaluate(in)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		want, err := authority.Evaluate(in)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(want) {
			t.Fatalf("%s: Evaluate and Go's rules differ", c.Name)
		}
		if b, _ := got.Encode(); string(b) != c.State {
			t.Fatalf("%s:\n got %s\nwant %s", c.Name, b, c.State)
		}
	}
	if r := Rules(); linked == strings.Contains(r, "Go's") {
		t.Fatalf("Rules says %q", r)
	}
}
