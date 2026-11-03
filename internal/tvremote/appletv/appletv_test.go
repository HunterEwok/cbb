// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package appletv_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/tvremote/appletv"
	"github.com/HunterEwok/clipboardbridge/internal/tvremote/appletv/atvtest"
)

func pair(t *testing.T, tv *atvtest.TV) appletv.Credentials {
	t.Helper()
	p, err := appletv.Pair(context.Background(), tv.Addr(), "CBB deck")
	if err != nil {
		t.Fatal(err)
	}
	cr, err := p.Finish(tv.PIN())
	if err != nil {
		t.Fatal(err)
	}
	return cr
}

// TestRemote pairs with the fake TV by its PIN and types on it.
func TestRemote(t *testing.T) {
	tv := atvtest.New(t)
	ctx := context.Background()
	cr := pair(t, tv)
	if names := tv.Names(); !slices.Equal(names, []string{"CBB deck"}) {
		t.Errorf("the TV knows the remote as %q", names)
	}

	r, err := appletv.Dial(ctx, tv.Addr(), cr, "deck")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Type("hi"); !errors.Is(err, appletv.ErrNoField) {
		t.Errorf("typing with no field open: %v", err)
	}
	tv.Focus()
	if err := r.Type("\u041f\u0440\u0438\u0432\u0435\u0442 👋"); err != nil {
		t.Fatal(err)
	}
	if err := r.Type("second"); err != nil {
		t.Fatal(err)
	}
	r.Close()
	tv.Wait(t, 2)
	if got := tv.Text(); !slices.Equal(got, []string{"\u041f\u0440\u0438\u0432\u0435\u0442 👋", "second"}) {
		t.Errorf("the field has %q", got)
	}

	// The TV forgets the remote: pair-verify fails and says so.
	tv.Forget()
	if _, err := appletv.Dial(ctx, tv.Addr(), cr, "deck"); !errors.Is(err, appletv.ErrNotPaired) {
		t.Errorf("a forgotten remote: %v", err)
	}
	// Another TV at the address does not pass for the paired one.
	other := atvtest.New(t)
	pair(t, other)
	if _, err := appletv.Dial(ctx, other.Addr(), cr, "deck"); err == nil {
		t.Error("another TV passed for the paired one")
	}
}

// TestPairCode: a wrong PIN, or one that is not four digits, fails the
// pairing.
func TestPairCode(t *testing.T) {
	tv := atvtest.New(t)
	ctx := context.Background()
	p, err := appletv.Pair(ctx, tv.Addr(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Finish("12a4"); !errors.Is(err, appletv.ErrCode) {
		t.Errorf("letters: %v", err)
	}
	p, err = appletv.Pair(ctx, tv.Addr(), "x")
	if err != nil {
		t.Fatal(err)
	}
	wrong := "0000"
	if tv.PIN() == wrong {
		wrong = "1111"
	}
	if _, err := p.Finish(wrong); !errors.Is(err, appletv.ErrCode) {
		t.Errorf("a wrong PIN: %v", err)
	}
	if _, err := appletv.Pair(ctx, "8.8.8.8:49153", "x"); err == nil {
		t.Error("a TV outside the home network was dialed")
	}
}
