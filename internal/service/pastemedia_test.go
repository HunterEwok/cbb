// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestRemotePasteMedia: an admin pastes the group's copy of files; the
// receiver hands the paste to a desktop connector whose clipboard takes
// files, which fetches that copy by its ID, and tmux takes none.
func TestRemotePasteMedia(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	pasteCopy := func() error {
		_, err := pi.do(t, control.Header{Op: control.OpPasteOn, Device: "deck", Kind: control.KindMedia}, "")
		return err
	}
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "a text"); err != nil {
		t.Fatal(err)
	}
	if err := pasteCopy(); err == nil || !strings.Contains(err.Error(), "no images or files") {
		t.Errorf("a paste of a text copy as images or files: %v", err)
	}
	sent := []sentPart{file("report.pdf", randomBytes(70_000))}
	if err := pi.copyMedia(t, "", sent...); err != nil {
		t.Fatal(err)
	}

	// tmux pastes only text.
	tm := deck.dial(t)
	if _, err := tm.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetTmux}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "deck offers tmux", func() bool { p := deck.status(t).Paste; return p != nil && len(p.Targets) == 1 })
	if err := pasteCopy(); err == nil || !strings.Contains(err.Error(), "take only text") {
		t.Errorf("a paste of files with only tmux: %v", err)
	}
	tm.Close()

	w := deck.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetDesktop, Files: true}}); err != nil {
		t.Fatal(err)
	}
	got := make(chan []sentPart, 1)
	go func() {
		for {
			m, err := w.Receive()
			if err != nil {
				return
			}
			if m.Op != control.OpInject {
				continue
			}
			ans := control.Header{Op: control.OpInjected, Seq: m.Seq}
			if m.Kind != control.KindMedia || m.Method != "paste" {
				ans.Error = "not a paste of images or files"
				w.Send(&control.Message{Header: ans})
				continue
			}
			// As the connector does: fetch the copy the paste names.
			c := deck.dial(t)
			r, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPasteMedia, Value: string(m.Payload)}})
			var parts []sentPart
			for err == nil && r != nil && !r.Done {
				if r, err = c.Receive(); err != nil || r.Done {
					break
				}
				if r.Part != nil {
					parts = append(parts, sentPart{Part: *r.Part})
				} else if len(parts) > 0 {
					parts[len(parts)-1].data = append(parts[len(parts)-1].data, r.Payload...)
				}
			}
			c.Close()
			if err != nil {
				ans.Error = err.Error()
			}
			got <- parts
			w.Send(&control.Message{Header: ans})
		}
	}()
	waitFor(t, "deck offers the desktop", func() bool { p := deck.status(t).Paste; return p != nil && len(p.Targets) == 1 })
	time.Sleep(time.Second) // one paste a second from one sender
	if err := pasteCopy(); err != nil {
		t.Fatal(err)
	}
	select {
	case parts := <-got:
		if len(parts) != 1 || parts[0].Part != sent[0].Part || !bytes.Equal(parts[0].data, sent[0].data) {
			t.Errorf("the desktop fetched %d parts", len(parts))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the desktop got no paste")
	}
	// paste-media names a copy that is no longer the current one.
	if _, err := deck.do(t, control.Header{Op: control.OpPasteMedia, Value: strings.Repeat("0", 32)}, ""); err == nil {
		t.Error("paste-media served a copy that is not current")
	}
}
