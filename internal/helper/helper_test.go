// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// exchange sends reqs to a server and returns its answers by Seq.
func exchange(t *testing.T, s *Server, reqs ...control.Message) map[uint64]*control.Message {
	t.Helper()
	var in bytes.Buffer
	for i := range reqs {
		if err := control.Write(&in, &reqs[i]); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := s.Serve(&in, &out); err != nil {
		t.Fatal(err)
	}
	got := map[uint64]*control.Message{}
	rd := control.NewReader(&out)
	for {
		m, err := rd.Read()
		if errors.Is(err, io.EOF) {
			return got
		}
		if err != nil {
			t.Fatal(err)
		}
		if m.Op != control.OpReply || !m.Done {
			t.Fatalf("answer %+v is not a done reply", m.Header)
		}
		if got[m.Seq] != nil {
			t.Fatalf("two answers to seq %d", m.Seq)
		}
		got[m.Seq] = m
	}
}

func TestHello(t *testing.T) {
	s := New("cbb v9.9.9 test")
	s.Handle("sign", func(*control.Message) (*control.Message, error) { return nil, nil })
	got := exchange(t, s, control.Message{Header: control.Header{Op: OpHello, Seq: 7}})
	ans := got[7]
	if ans == nil || ans.Error != "" {
		t.Fatalf("hello: %+v", ans)
	}
	var h Hello
	if err := json.Unmarshal(ans.Payload, &h); err != nil {
		t.Fatal(err)
	}
	if h.Version != "cbb v9.9.9 test" || !slices.Equal(h.Ops, []string{"hello", "sign"}) {
		t.Fatalf("hello = %+v", h)
	}
}

func TestRequests(t *testing.T) {
	s := New("v")
	s.Handle("echo", func(req *control.Message) (*control.Message, error) {
		return &control.Message{Header: control.Header{Name: req.Name}, Payload: req.Payload}, nil
	})
	s.Handle("fail", func(*control.Message) (*control.Message, error) {
		return nil, fmt.Errorf("the key is gone: %w", errors.New("TPM_RC_HANDLE"))
	})
	s.Handle("bug", func(*control.Message) (*control.Message, error) { panic("index out of range") })
	got := exchange(t, s,
		control.Message{Header: control.Header{Op: "echo", Seq: 1, Name: "n"}, Payload: []byte("payload")},
		control.Message{Header: control.Header{Op: "fail", Seq: 2}},
		control.Message{Header: control.Header{Op: "bug", Seq: 3}},
		control.Message{Header: control.Header{Op: "unknown", Seq: 4}},
		control.Message{Header: control.Header{Op: "echo", Seq: 5}},
	)
	if len(got) != 5 {
		t.Fatalf("%d answers to 5 requests", len(got))
	}
	if a := got[1]; a.Error != "" || a.Name != "n" || string(a.Payload) != "payload" {
		t.Errorf("echo: %+v %q", a.Header, a.Payload)
	}
	if a := got[2]; a.Error != "the key is gone" || a.Detail != "the key is gone: TPM_RC_HANDLE" {
		t.Errorf("fail: error %q, detail %q", a.Error, a.Detail)
	}
	if a := got[3]; a.Error == "" {
		t.Error("a panicking handler answered without an error")
	}
	if a := got[4]; a.Error != `cbb-helper does not serve "unknown"` {
		t.Errorf("unknown: %q", a.Error)
	}
	if a := got[5]; a.Error != "" || len(a.Payload) != 0 {
		t.Errorf("echo after the failures: %+v", a.Header)
	}
}

func TestBrokenChannel(t *testing.T) {
	if err := New("v").Serve(bytes.NewBufferString("not json\n"), io.Discard); err == nil {
		t.Fatal("a broken request did not end Serve with an error")
	}
}
