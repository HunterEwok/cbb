// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package androidtv_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/tvremote/androidtv"
	"github.com/HunterEwok/cbb/internal/tvremote/androidtv/atvtest"
)

func pair(t *testing.T, tv *atvtest.TV, c androidtv.Client) []byte {
	t.Helper()
	p, err := androidtv.Pair(context.Background(), tv.Addr(), c, "test")
	if err != nil {
		t.Fatal(err)
	}
	if p.TV != "Fake TV" {
		t.Errorf("the TV's name is %q", p.TV)
	}
	pin, err := p.Finish(strings.ToLower(tv.Code()))
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func TestPairAndType(t *testing.T) {
	tv := atvtest.New(t)
	c, err := androidtv.NewClient("test")
	if err != nil {
		t.Fatal(err)
	}
	pin := pair(t, tv, c)
	if !bytes.Equal(pin, tv.Pin()) {
		t.Fatal("the pin is not the TV's certificate")
	}
	r, err := androidtv.Dial(context.Background(), tv.Addr(), c, pin)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Type("hello"); !errors.Is(err, androidtv.ErrNoField) {
		t.Fatalf("Type with no text field: %v", err)
	}
	tv.Focus()
	if err := r.WaitField(context.Background(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := r.Type("hello\r\nworld\n"); err != nil {
		t.Fatal(err)
	}
	tv.Wait(t, 4)
	text, keys := tv.Text()
	if !slices.Equal(text, []string{"hello", "world"}) || !slices.Equal(keys, []uint64{66, 66}) {
		t.Fatalf("the TV got %q and keys %v", text, keys)
	}
}

func TestWrongCode(t *testing.T) {
	tv := atvtest.New(t)
	c, err := androidtv.NewClient("test")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"12345", "zzzzzz"} {
		p, err := androidtv.Pair(context.Background(), tv.Addr(), c, "test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Finish(code); !errors.Is(err, androidtv.ErrCode) {
			t.Errorf("Finish(%q): %v", code, err)
		}
	}
	// A code of the right form that is not the one shown: its first byte
	// does not check the rest, so it never reaches the TV.
	p, err := androidtv.Pair(context.Background(), tv.Addr(), c, "test")
	if err != nil {
		t.Fatal(err)
	}
	code := tv.Code()
	first := "0"
	if code[0] == '0' {
		first = "1"
	}
	wrong := first + code[1:]
	if _, err := p.Finish(wrong); !errors.Is(err, androidtv.ErrCode) {
		t.Errorf("Finish(%q) for %q: %v", wrong, code, err)
	}
}

func TestPinAndReset(t *testing.T) {
	tv := atvtest.New(t)
	other := atvtest.New(t)
	c, err := androidtv.NewClient("test")
	if err != nil {
		t.Fatal(err)
	}
	pin := pair(t, tv, c)
	// Another TV at the address: its certificate is not the pinned one.
	if _, err := androidtv.Dial(context.Background(), other.Addr(), c, pin); err == nil {
		t.Fatal("Dial took a TV with another certificate")
	}
	// A reset TV forgets the remote.
	tv.Forget()
	if _, err := androidtv.Dial(context.Background(), tv.Addr(), c, pin); err == nil {
		t.Fatal("Dial worked with a TV that forgot the remote")
	}
	if _, err := androidtv.Dial(context.Background(), tv.Addr(), c, nil); err == nil {
		t.Fatal("Dial worked with no pin")
	}
}
