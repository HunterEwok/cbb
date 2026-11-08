// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestLiteAgent: the Rust cbb agent links an X11 session's clipboard with
// the Rust service through cbb-helper, both ways, and the helper ends with
// the agent. CBB_LITE names the Rust member's binary; CBB_TEST_X11 asks for
// an X server in DISPLAY and xclip.
func TestLiteAgent(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	if os.Getenv("CBB_TEST_X11") == "" {
		t.Skip("set CBB_TEST_X11 with an X server in DISPLAY and xclip installed")
	}
	helper := filepath.Join(t.TempDir(), "cbb-helper")
	if out, err := exec.Command("go", "build", "-o", helper, "github.com/HunterEwok/cbb/cmd/cbb-helper").CombinedOutput(); err != nil {
		t.Fatalf("go build cbb-helper: %v\n%s", err, out)
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinLite(t, bin, pi)
	lite := startLite(t, bin, dir, "-no-mdns", "-peer", pi.addr())
	waitFor(t, "the Rust member connected", func() bool {
		st, err := lite.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 1
	})
	if _, err := lite.do(t, control.Header{Op: control.OpMode, Name: "shared"}, ""); err != nil {
		t.Fatal(err)
	}

	agent := exec.Command(bin, "-socket", lite.socket, "agent")
	agent.Env = append(os.Environ(), "CBB_HELPER="+helper, "XDG_RUNTIME_DIR="+t.TempDir(), "WAYLAND_DISPLAY=", "XDG_CACHE_HOME="+t.TempDir())
	// A file, not a pipe: the helper inherits it, and a pipe would keep
	// Wait waiting for the helper too.
	logFile, err := os.Create(filepath.Join(t.TempDir(), "agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		b, _ := os.ReadFile(logFile.Name())
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			t.Log("agent: " + l)
		}
		logFile.Close()
	})
	agent.Stdout, agent.Stderr = logFile, logFile
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	go func() { agent.Wait(); close(ended) }()
	t.Cleanup(func() {
		agent.Process.Kill()
		<-ended
		exec.Command("pkill", "-f", helper).Run()
	})

	xclipIn := func(text string) {
		t.Helper()
		cmd := exec.Command("xclip", "-selection", "clipboard", "-i")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			t.Fatalf("xclip -i: %v", err)
		}
	}
	xclipOut := func() string {
		out, _ := exec.Command("xclip", "-selection", "clipboard", "-o").Output()
		return string(out)
	}
	// The agent links the clipboard once its helper runs; a copy made before
	// is not sent, so each try copies a new text.
	try := 0
	waitUpTo(t, 15*time.Second, "the agent's copy reaches pi", func() bool {
		try++
		text := fmt.Sprintf("from the X11 session, try %d", try)
		xclipIn(text)
		time.Sleep(300 * time.Millisecond)
		return pi.paste(t) == text
	}, func() string { return "the Rust member has " + lite.paste(t) }, func() string { return "X11 has " + xclipOut() })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "from pi"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the X11 clipboard has pi's text", func() bool { return xclipOut() == "from pi" })

	// The helper ends with the agent: the end of its channel ends it.
	if err := agent.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the agent did not end")
	}
	left := ""
	waitUpTo(t, 10*time.Second, "cbb-helper ended with the agent", func() bool {
		out, _ := exec.Command("pgrep", "-a", "-f", helper).Output()
		left = strings.TrimSpace(string(out))
		return left == ""
	}, func() string { return "still running: " + left })
}
