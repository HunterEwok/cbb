// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// TestArrangementVectors checks the model against the vectors that the
// Kotlin and Swift kits read too.
func TestArrangementVectors(t *testing.T) {
	b, err := os.ReadFile("../../testdata/arrangement/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name    string       `json:"name"`
			Group   string       `json:"group"`
			Self    string       `json:"self"`
			Devices []string     `json:"devices"`
			Stored  *Arrangement `json:"stored"`
			Prune   bool         `json:"prune"`
			Ops     []ArrangeOp  `json:"ops"`
			Error   bool         `json:"error"`
			Items   []Item       `json:"items"`
			View    []Item       `json:"view"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range doc.Cases {
		var stored Arrangement
		if c.Stored != nil {
			stored = *c.Stored
		}
		a := arrangeFor(stored, c.Group)
		if c.Prune {
			a.Prune(c.Devices)
		}
		for i, op := range c.Ops {
			err := a.Apply(op, c.Devices, c.Self)
			last := i == len(c.Ops)-1
			if (err != nil) != (c.Error && last) {
				t.Errorf("%s: op %d (%s): %v", c.Name, i, op.Op, err)
			}
		}
		if got := a.Items; !reflect.DeepEqual(norm(got), norm(c.Items)) {
			t.Errorf("%s: items %s, want %s", c.Name, show(got), show(c.Items))
		}
		if got := a.View(c.Devices, c.Self); !reflect.DeepEqual(norm(got), norm(c.View)) {
			t.Errorf("%s: view %s, want %s", c.Name, show(got), show(c.View))
		}
	}
}

// norm makes empty lists nil, as JSON has no difference between them here.
func norm(items []Item) []Item {
	if len(items) == 0 {
		return nil
	}
	out := cloneItems(items)
	for _, it := range out {
		if it.Collection != nil && len(it.Collection.Devices) == 0 {
			it.Collection.Devices = nil
		}
	}
	return out
}

func show(items []Item) string {
	b, _ := json.Marshal(items)
	return string(b)
}
