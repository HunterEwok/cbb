// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tmuxpaste

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/connector"
)

// TestTmux pastes and types into a pane running cat, with a client
// attached through script. It needs tmux 3.2 or later and script.
func TestTmux(t *testing.T) {
	for _, tool := range []string{"tmux", "script"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	tm := &Tmux{Args: []string{"-S", filepath.Join(dir, "sock"), "-f", "/dev/null"}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tm.run(ctx, "", "new-session", "-d", "-s", "test", "sh -c 'stty -echo; exec cat >"+out+"'"); err != nil {
		t.Fatal(err)
	}
	defer tm.run(context.Background(), "", "kill-server")

	var r *connector.Refusal
	if err := tm.Inject(ctx, "nobody looks", "paste", false, false); !errors.As(err, &r) {
		t.Fatalf("a paste with no client attached: %v", err)
	}

	// util-linux's script takes the command with -c; the BSDs' and the
	// Mac's after the file.
	attach := exec.Command("script", "-q", "-c", "tmux "+strings.Join(tm.Args, " ")+" attach -t test", "/dev/null")
	if runtime.GOOS != "linux" {
		attach = exec.Command("script", append(append([]string{"-q", "/dev/null", "tmux"}, tm.Args...), "attach", "-t", "test")...)
	}
	// tmux attaches only with a terminal type it knows, which CI has not.
	attach.Env = append(os.Environ(), "TERM=xterm")
	var attachOut strings.Builder
	attach.Stdout, attach.Stderr = &attachOut, &attachOut
	stdin, err := attach.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := attach.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); attach.Process.Kill(); attach.Wait() }()
	attached := false
	for range 100 {
		if o, _ := tm.output(ctx, "list-clients", "-F", "#{client_name}"); o != "" {
			attached = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !attached {
		t.Fatalf("no tmux client attached: %s", attachOut.String())
	}

	tricky := `it's "q" $HOME; #x ~ \ {} 'end'` + "\ttab"
	if err := tm.Inject(ctx, "pasted "+tricky, "paste", true, false); err != nil {
		t.Fatal(err)
	}
	if err := tm.Inject(ctx, "typed "+tricky+"\nline two", "type", true, false); err != nil {
		t.Fatal(err)
	}
	if err := tm.Inject(ctx, "a secret", "paste", true, true); err != nil {
		t.Fatal(err)
	}
	want := "pasted " + tricky + "\ntyped " + tricky + "\nline two\na secret\n"
	var got []byte
	for range 50 {
		if got, _ = os.ReadFile(out); string(got) == want {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if string(got) != want {
		t.Errorf("the pane got %q, want %q", got, want)
	}
	if o, _ := tm.output(ctx, "list-buffers", "-F", "#{buffer_name}"); strings.Contains(o, buffer) {
		t.Error("a paste left its buffer behind")
	}
}
