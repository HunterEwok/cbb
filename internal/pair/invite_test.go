// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

// secretWindow opens a window with a secret whose admin answers with
// confirm.
func secretWindow(t *testing.T, confirm func(context.Context, Request) error) (*fixture, []byte) {
	t.Helper()
	admin, err := group.Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, MinSecret)
	rand.Read(secret)
	clk := &clock{up: time.Hour}
	w, err := Open(admin, "", Options{Secret: secret, Lifetime: 24 * time.Hour,
		Confirm: confirm, ConfirmWait: time.Minute,
		Now: func() time.Time { return t0 }, Uptime: clk.uptime, AfterFunc: clk.afterFunc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	if clk.timer != 24*time.Hour {
		t.Errorf("the window expires after %v, want 24h", clk.timer)
	}
	return &fixture{admin: admin, window: w, clock: clk}, secret
}

func (f *fixture) attemptSecret(t *testing.T, j *Joiner, secret []byte) outcome {
	t.Helper()
	a, b := socketPair(t)
	var out outcome
	done := make(chan struct{})
	go func() {
		defer close(done)
		out.serveErr = f.window.Serve(context.Background(), tls.Server(b, ServerTLS(f.admin)))
	}()
	out.id, out.joinErr = j.JoinSecret(context.Background(), a, secret, time.Minute, func(*group.Identity) error {
		out.savedCalls++
		return nil
	})
	a.Close()
	<-done
	return out
}

// TestSecretConfirmed checks that a device with the invitation's secret is
// admitted once the admin confirms the device the joiner shows, and gets
// no CA keys.
func TestSecretConfirmed(t *testing.T) {
	var asked []Request
	f, secret := secretWindow(t, func(_ context.Context, r Request) error {
		asked = append(asked, r)
		return nil
	})
	j := newJoiner(t, "linux")
	out := f.attemptSecret(t, j, secret)
	if out.joinErr != nil || out.serveErr != nil {
		t.Fatalf("join: %v, serve: %v", out.joinErr, out.serveErr)
	}
	fp, err := j.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0].Device != j.ID || !reflect.DeepEqual(asked[0].Info, j.Info) || asked[0].Fingerprint != fp {
		t.Errorf("the admin was asked %+v, want %s %+v %s", asked, j.ID, j.Info, fp)
	}
	if out.id.GroupCA.Key != nil {
		t.Error("an invited device got the CA keys")
	}
	if !closed(f.window) {
		t.Error("the window stays open after its one use")
	}
}

// TestSecretDeclined checks that a device the admin does not confirm gets
// nothing, and that the refusal counts as a failed attempt.
func TestSecretDeclined(t *testing.T) {
	f, secret := secretWindow(t, func(context.Context, Request) error { return errors.New("no") })
	out := f.attemptSecret(t, newJoiner(t, "macos"), secret)
	if !errors.Is(out.joinErr, ErrDeclined) || out.id != nil || out.savedCalls != 0 {
		t.Errorf("join: %v, %v, %d saves", out.joinErr, out.id, out.savedCalls)
	}
	if !errors.Is(out.serveErr, ErrDeclined) {
		t.Errorf("serve: %v", out.serveErr)
	}
	if f.failures() != 1 || closed(f.window) {
		t.Errorf("%d failures, closed %v", f.failures(), closed(f.window))
	}
}

// TestWrongSecret checks that the admin is never asked about a device
// that does not know the secret, and that three of them close the window.
func TestWrongSecret(t *testing.T) {
	f, secret := secretWindow(t, func(context.Context, Request) error {
		t.Error("the admin was asked about a device with a wrong secret")
		return nil
	})
	wrong := bytes.Clone(secret)
	wrong[0] ^= 1
	for range MaxFailures {
		out := f.attemptSecret(t, newJoiner(t, "linux"), wrong)
		if out.id != nil || out.joinErr == nil {
			t.Fatalf("a wrong secret joined: %v", out.joinErr)
		}
	}
	if !closed(f.window) {
		t.Error("three wrong secrets left the window open")
	}
}

// TestCloseWhileConfirming checks that closing the window ends an attempt
// that waits for the admin, and admits nothing.
func TestCloseWhileConfirming(t *testing.T) {
	asked := make(chan struct{})
	var f *fixture
	f, secret := secretWindow(t, func(ctx context.Context, _ Request) error {
		close(asked)
		<-ctx.Done()
		return ctx.Err()
	})
	go func() {
		<-asked
		f.window.Close()
	}()
	out := f.attemptSecret(t, newJoiner(t, "linux"), secret)
	if out.id != nil || !errors.Is(out.serveErr, ErrClosed) {
		t.Errorf("join: %v, serve: %v", out.joinErr, out.serveErr)
	}
	if _, err := f.window.Result(); !errors.Is(err, ErrClosed) {
		t.Errorf("result: %v", err)
	}
}

// TestShortSecret checks that a window and a joiner refuse a secret under
// 128 bits.
func TestShortSecret(t *testing.T) {
	admin, err := group.Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(admin, "", Options{Secret: make([]byte, MinSecret-1)}); err == nil {
		t.Error("a window took a short secret")
	}
	a, _ := socketPair(t)
	if _, err := newJoiner(t, "linux").JoinSecret(context.Background(), a, make([]byte, MinSecret-1), 0, nil); err == nil {
		t.Error("a joiner took a short secret")
	}
}
