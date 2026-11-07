// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/helper"
)

func TestRun(t *testing.T) {
	var out, errw bytes.Buffer
	if code := run(nil, strings.NewReader(""), &out, &errw, true); code != 2 || !strings.Contains(errw.String(), "run cbb instead") {
		t.Errorf("on a terminal: code %d, %q", code, errw.String())
	}
	errw.Reset()
	if code := run([]string{"service"}, strings.NewReader(""), &out, &errw, false); code != 2 {
		t.Errorf("with arguments: code %d", code)
	}
	out.Reset()
	if code := run([]string{"version"}, nil, &out, &errw, true); code != 0 || !strings.HasPrefix(out.String(), "cbb ") {
		t.Errorf("version: code %d, %q", code, out.String())
	}

	var in bytes.Buffer
	if err := control.Write(&in, &control.Message{Header: control.Header{Op: helper.OpHello, Seq: 1}}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run(nil, &in, &out, &errw, false); code != 0 {
		t.Fatalf("serving: code %d, %q", code, errw.String())
	}
	m, err := control.NewReader(&out).Read()
	if err != nil {
		t.Fatal(err)
	}
	var h helper.Hello
	if err := json.Unmarshal(m.Payload, &h); err != nil || h.Version == "" {
		t.Fatalf("hello: %+v %q %v", m.Header, m.Payload, err)
	}
}
