// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"encoding/json"
	"testing"
)

// TestKindAndViaJSON: a kind and a way travel by their names, and an
// unknown name is refused.
func TestKindAndViaJSON(t *testing.T) {
	for _, k := range []Kind{Text, Secret, Media} {
		b, err := json.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}
		var back Kind
		if err := json.Unmarshal(b, &back); err != nil || back != k {
			t.Errorf("kind %s came back as %v, %v", b, back, err)
		}
	}
	for _, v := range []Via{Copy, Phone, Universal} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var back Via
		if err := json.Unmarshal(b, &back); err != nil || back != v {
			t.Errorf("via %s came back as %v, %v", b, back, err)
		}
	}
	var k Kind
	if err := json.Unmarshal([]byte(`"image"`), &k); err == nil {
		t.Error("the kind image was taken")
	}
	var v Via
	if err := json.Unmarshal([]byte(`"fax"`), &v); err == nil {
		t.Error("the way fax was taken")
	}
	if _, err := json.Marshal(Kind(9)); err == nil {
		t.Error("an unknown kind was written")
	}
	if _, err := json.Marshal(Via(9)); err == nil {
		t.Error("an unknown way was written")
	}
}
