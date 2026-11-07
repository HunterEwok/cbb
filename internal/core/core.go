// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package core calls the Rust core's one entry point (docs/core-api.md):
// JSON bytes in, JSON bytes out, through the C functions of ffi/
// (ffi/include/cbb_core.h). A build links the core with cgo under the
// tag cbbcore, after building the library:
//
//	cargo build --locked --release -p cbb-ffi
//	go test -tags cbbcore ./internal/core
//
// The builds for Windows, macOS and FreeBSD run the same core as
// WebAssembly under wazero instead, under the tag cbbwasm, with the module
// built and laid over cbb_core.wasm here by an overlay, so that it never
// lands in the source tree:
//
//	sh wasm/build.sh
//	go test -overlay target/cbb-core-overlay.json -tags cbbwasm ./internal/core
//
// Without either tag Call says the core is not linked.
package core

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ABI is the version of the request and answer shapes this package
// speaks; Call refuses a core of another.
const ABI = 1

// ErrUnavailable is Call in a build without the core.
var ErrUnavailable = errors.New("core: this build does not link the Rust core")

// Call sends one request to the core and returns its answer, after
// checking that the core speaks ABI. A refusal of the request is an answer
// with an error, not an error of Call.
func Call(request []byte) ([]byte, error) {
	if !linked {
		return nil, ErrUnavailable
	}
	got, err := abi()
	if err != nil {
		return nil, err
	}
	if got != ABI {
		return nil, fmt.Errorf("core: the linked core speaks ABI %d, not %d", got, ABI)
	}
	return call(request)
}

// Version is the core's answer to the op version.
type Version struct {
	ABI    int    `json:"abi"`
	Core   string `json:"core"`
	Source string `json:"source,omitempty"`
}

// Refusal is an error answer of the core: a stable code and name, a
// message for the user and the details under it.
type Refusal struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (r *Refusal) Error() string {
	if r.Details == "" {
		return fmt.Sprintf("core: %s (%s, code %d)", r.Message, r.Name, r.Code)
	}
	return fmt.Sprintf("core: %s (%s, code %d): %s", r.Message, r.Name, r.Code, r.Details)
}

// Do sends the operation op with args (nil for none) and decodes the
// answer's ok into out; a refusal comes back as a *Refusal.
func Do(op string, args, out any) error {
	req := map[string]any{"abi": ABI, "op": op}
	if args != nil {
		req["args"] = args
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("core: write the request: %w", err)
	}
	answer, err := Call(raw)
	if err != nil {
		return err
	}
	var a struct {
		OK    json.RawMessage `json:"ok"`
		Error *Refusal        `json:"error"`
	}
	if err := json.Unmarshal(answer, &a); err != nil {
		return fmt.Errorf("core: read the answer: %w", err)
	}
	if a.Error != nil {
		return a.Error
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(a.OK, out); err != nil {
		return fmt.Errorf("core: read the answer to %s: %w", op, err)
	}
	return nil
}

// CoreVersion asks the core its version.
func CoreVersion() (Version, error) {
	var v Version
	err := Do("version", nil, &v)
	return v, err
}
