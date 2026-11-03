// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/strict"
)

// fuzzSeeds adds the bodies of a section of strict-generated-*.json, valid
// and not, as the seed corpus of a fuzz target.
func fuzzSeeds(f *testing.F, section string) {
	v, err := readGenFiles("../../testdata/interop")
	if err != nil {
		f.Fatal(err)
	}
	for _, c := range map[string][]genVector{"records": v.Records, "commands": v.Commands, "manifests": v.Manifests}[section] {
		if c.Pad == 0 {
			f.Add(c.Body)
		}
	}
}

// FuzzRecordBody reads record bodies as they come from other members
// (docs/protocol.md, Conventions, "Signed bodies"): a body it takes
// is within the size limit, and encoding what it read gives the same bytes.
func FuzzRecordBody(f *testing.F) {
	fuzzSeeds(f, "records")
	data, err := os.ReadFile("../../testdata/interop/v2-records.json")
	if err != nil {
		f.Fatal(err)
	}
	var v struct {
		Cases []v2Case `json:"cases"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		f.Fatal(err)
	}
	for _, c := range v.Cases {
		for _, r := range c.Records {
			f.Add(r.Body)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := authority.ParseBody(data)
		if err != nil {
			return
		}
		if len(data) > authority.MaxCheckpointBody || b.Type != RecordCheckpoint && len(data) > authority.MaxBody {
			t.Fatalf("took a body of %d bytes", len(data))
		}
		again, err := b.Encode()
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("took a body that is not in its canonical form: %v", err)
		}
	})
}

// FuzzCommand reads command bodies as a member receives them.
func FuzzCommand(f *testing.F) {
	fuzzSeeds(f, "commands")
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := parseCommandBody(data); err != nil {
			return
		}
		if err := strict.Check(data, "v", "type", "group", "by", "to", "id", "time_ms", "expires_ms"); err != nil {
			t.Fatalf("took a command not in the strict form: %v", err)
		}
	})
}
