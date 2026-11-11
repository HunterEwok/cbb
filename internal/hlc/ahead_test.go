// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package hlc

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the interop test vectors")

// aheadVectors is testdata/interop/hlc-ahead.json: a clock that reads Now
// takes each wall time of Accepted in turn and observes it, then refuses
// Refused, which is just past Now and MaxAhead.
type aheadVectors struct {
	Now      int64   `json:"now"`
	MaxAhead int64   `json:"max_ahead"`
	Accepted []int64 `json:"accepted"`
	Refused  int64   `json:"refused"`
}

// TestAheadVectors writes (with -update) and checks
// testdata/interop/hlc-ahead.json: the timestamps a clock took do not move
// how far ahead it takes the next one (docs/protocol.md, section 5), for
// the Rust core and the phone kits to agree with.
func TestAheadVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "hlc-ahead.json")
	if *update {
		now, day := int64(1792886400000), int64(24*3600*1000) // 2026-10-25
		ahead := MaxAhead.Milliseconds()
		v := aheadVectors{Now: now, MaxAhead: ahead, Accepted: []int64{now + 3*day, now + 6*day, now + ahead}, Refused: now + ahead + 1}
		data, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v aheadVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.MaxAhead != MaxAhead.Milliseconds() {
		t.Fatalf("the file's MaxAhead is %d", v.MaxAhead)
	}
	c := NewClock((&fakeTime{v.Now}).now, Timestamp{}, nil)
	for _, w := range v.Accepted {
		ts := Timestamp{Wall: w}
		if c.Ahead(ts) {
			t.Fatalf("%d refused", w)
		}
		c.Observe(ts)
	}
	if !c.Ahead(Timestamp{Wall: v.Refused}) {
		t.Fatalf("%d taken after a chain of timestamps ahead", v.Refused)
	}
}
