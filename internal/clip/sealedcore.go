// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/HunterEwok/cbb/internal/core"
	"github.com/HunterEwok/cbb/internal/hlc"
)

// A build that links the Rust core (every release build: docs/core-api.md)
// opens and seals copies through it, so that every member reads and writes
// the sealed copies with the same code; a build without it (go test, go
// build) uses the Go code of sealed.go, which the vectors
// (testdata/interop/copies-go.json, copies-rust.json) and the differential
// run keep the same. The blob's segments stay in Go everywhere: they are
// plain ChaCha20-Poly1305 with nothing to parse, and the core runs one call
// at a time, interpreted on the routers' MIPS, which a blob of a gigabyte
// in segments of 64 KiB would wait on.

// coreOpened is the answer of the core's open_copy.
type coreOpened struct {
	Kind  Kind            `json:"kind"`
	Via   Via             `json:"via"`
	Text  string          `json:"text"`
	Media json.RawMessage `json:"media"`
	Key   []byte          `json:"key"`
}

// openInCore opens s for the reader me through the core. The caller has
// checked that s has a wrap for me.
func openInCore(s *Sealed, me string, secret []byte) (Content, []byte, error) {
	var out coreOpened
	if err := core.Do("open_copy", map[string]any{"event": s, "me": me, "secret": secret}, &out); err != nil {
		return Content{}, nil, fmt.Errorf("clip: the copy does not open: %w", err)
	}
	c := Content{Kind: out.Kind, Via: out.Via, Text: out.Text}
	if len(out.Media) > 0 && string(out.Media) != "null" {
		m, err := ParseManifest(out.Media)
		if err != nil {
			return Content{}, nil, err
		}
		c.Media = m
	}
	if len(out.Key) != KeySize {
		return Content{}, nil, errors.New("clip: the core gave a copy's key that is not 32 bytes")
	}
	return c, out.Key, nil
}

// coreReader is a reader as seal_copy_to takes it.
type coreReader struct {
	ID   string `json:"id"`
	Seal []byte `json:"seal"`
}

// sealInCore seals a copy through the core and returns it unsigned, with
// what its origin signs.
func sealInCore(id, origin string, t hlc.Timestamp, cert, issuer []byte, readers []Reader, c Content, blob *Blob, key []byte) (*Sealed, []byte, error) {
	rs := make([]coreReader, len(readers))
	for i, r := range readers {
		rs[i] = coreReader(r)
	}
	args := map[string]any{
		"id": id, "origin": origin, "time": t, "cert": cert, "readers": rs,
		"kind": c.Kind, "via": c.Via, "text": c.Text, "key": key,
	}
	if len(issuer) > 0 {
		args["issuer"] = issuer
	}
	if c.Media != nil {
		args["media"] = c.Media
	}
	if blob != nil {
		args["blob"] = blob
	}
	var out struct {
		Event  json.RawMessage `json:"event"`
		ToSign []byte          `json:"to_sign"`
	}
	if err := core.Do("seal_copy_to", args, &out); err != nil {
		return nil, nil, fmt.Errorf("clip: the copy cannot be sealed: %w", err)
	}
	s := new(Sealed)
	if err := json.Unmarshal(out.Event, s); err != nil {
		return nil, nil, fmt.Errorf("clip: the core's sealed copy: %w", err)
	}
	return s, out.ToSign, nil
}
