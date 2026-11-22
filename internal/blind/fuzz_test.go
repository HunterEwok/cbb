// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package blind

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// FuzzCredential feeds the forwarder's reader any bytes, seeded with the
// format's credentials and frames: nothing panics, an item the profile
// takes is written again to the same bytes, a credential taken reads the
// same twice, and a frame's message taken is written again as a frame that
// reads back the same. The nightly run fuzzes it (docs/differential.md).
func FuzzCredential(f *testing.F) {
	for _, name := range []string{"credentials.json", "frames.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "format", name))
		if err != nil {
			f.Fatal(err)
		}
		var v struct {
			Take, Refuse []struct {
				Envelope string `json:"envelope"`
				Frame    string `json:"frame"`
			}
		}
		if err := json.Unmarshal(b, &v); err != nil {
			f.Fatal(err)
		}
		for _, r := range append(v.Take, v.Refuse...) {
			for _, s := range []string{r.Envelope, r.Frame} {
				if x, err := hex.DecodeString(s); err == nil && len(x) > 0 {
					f.Add(x)
				}
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, err := Decode(b); err == nil && !bytes.Equal(Encode(v), b) {
			t.Fatalf("%x written again as %x", b, Encode(v))
		}
		if c, err := ReadCredential(b); err == nil {
			again, err := ReadCredential(b)
			if err != nil || !reflect.DeepEqual(c, again) {
				t.Fatalf("read twice: %v", err)
			}
		}
		if len(b) >= 4 {
			if _, m, err := Message(b[4:]); err == nil {
				ty, back, body, err := ReadFrame(bytes.NewReader(WriteFrame(m.Map...)), len(b)+gridStep)
				if err != nil || !bytes.Equal(Encode(back), Encode(m)) || !bytes.Equal(body, b[4:]) {
					t.Fatalf("frame %x written again: %v (t %d)", b[4:], err, ty)
				}
			}
		}
	})
}
