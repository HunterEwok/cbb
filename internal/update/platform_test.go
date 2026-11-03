// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// fakeService answers each status request on a control socket with the
// version versions gives for that request.
func fakeService(t *testing.T, versions func(n int) string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "cbu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "c.sock")
	t.Setenv("CBB_SOCKET", socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for n := 0; ; n++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if _, err := control.NewReader(c).Read(); err == nil {
				a := control.Message{Header: control.Header{Op: control.OpReply, Done: true}}
				if v := versions(n); v != "-" {
					a.Status = &control.Status{Version: v}
				}
				control.Write(c, &a)
			}
			c.Close()
		}
	}()
}

func TestHealthy(t *testing.T) {
	// The new version answers on the second ask.
	fakeService(t, func(n int) string {
		if n == 0 {
			return "cbb v0.5.0 (linux/amd64)"
		}
		return "cbb v0.6.0 (linux/amd64)"
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Healthy(ctx, "0.6.0"); err != nil {
		t.Fatalf("Healthy: %v", err)
	}
}

func TestHealthyGivesUp(t *testing.T) {
	for _, c := range []struct {
		name    string
		version string
		want    string
	}{
		{"an older version", "cbb v0.6.0-rc.1 (linux/amd64)", "it runs cbb v0.6.0-rc.1"},
		{"no status", "-", "sent no status"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fakeService(t, func(int) string { return c.version })
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			if err := Healthy(ctx, "0.6.0"); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Healthy: %v, want %q", err, c.want)
			}
		})
	}
	t.Run("no service", func(t *testing.T) {
		t.Setenv("CBB_SOCKET", filepath.Join(t.TempDir(), "none.sock"))
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		// The cause stays, under a message that does not tell the user to
		// start the service: the previous version goes back in.
		err := Healthy(ctx, "0.6.0")
		if err == nil || !strings.Contains(err.Error(), "does not answer; the system's service log tells why") {
			t.Errorf("Healthy: %v", err)
		}
	})
}

func TestInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the installer is install.ps1 under PowerShell there; CI's windows installer job runs it")
	}
	root := t.TempDir()
	script := InstallScript(root)
	if !strings.HasPrefix(script, filepath.Join(root, "packaging")) || !strings.HasSuffix(script, "install.sh") {
		t.Fatalf("InstallScript: %s", script)
	}
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "args")
	write := func(body string) {
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(`echo "$CBB_UPDATING $*" >"` + out + `"` + "\n")
	if err := Install(context.Background(), root, "/new/cbb"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	b, _ := os.ReadFile(out)
	if got := strings.TrimSpace(string(b)); got != "1 /new/cbb" && got != "1 --rootless /new/cbb" {
		t.Errorf("the installer got %q", got)
	}
	write("echo working\necho 'install.sh: copying the program failed: no space left on device'\necho more\nexit 3\n")
	err := Install(context.Background(), root, "/new/cbb")
	if err == nil || !strings.Contains(err.Error(), "install.sh: exit status 3: copying the program failed: no space left on device") {
		t.Errorf("a failing installer: %v", err)
	}
}

func TestPrograms(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "cbb")
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "cbb-link")
	if err := os.Symlink(exe, link); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	got, err := Programs(link)
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(exe)
	want := []string{real}
	if runtime.GOOS == "windows" {
		want = []string{filepath.Join(filepath.Dir(real), "cbb.exe"), filepath.Join(filepath.Dir(real), "cbbw.exe")}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Programs(%s) = %v, want %v", link, got, want)
	}
	if p, err := Programs(""); err != nil || len(p) == 0 {
		t.Errorf("Programs of this test: %v, %v", p, err)
	}
}

func TestArchiveName(t *testing.T) {
	got := ArchiveName()
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	if !strings.HasPrefix(got, "cbb-"+runtime.GOOS+"-") || !strings.HasSuffix(got, ext) {
		t.Errorf("ArchiveName() = %s", got)
	}
}

func TestMethodCommands(t *testing.T) {
	for _, c := range []struct{ method, want string }{
		{MethodBrew, "brew upgrade cbb"},
		{MethodWinget, "winget upgrade HunterEwok.cbb"},
		{MethodDocker, "docker compose pull"},
		{MethodPackage, ""},
	} {
		got := MethodCommands(c.method)
		if len(got) == 0 || !strings.Contains(got[0], c.want) {
			t.Errorf("MethodCommands(%s) = %q", c.method, got)
		}
	}
	if got := MethodCommands(MethodGet); got != nil {
		t.Errorf("cbb update replaces a get.sh install itself, but %q", got)
	}
}

func TestTimerHelpers(t *testing.T) {
	if got := xmlEscape(`/Apps/a&b <c>`); got != "/Apps/a&amp;b &lt;c&gt;" {
		t.Errorf("xmlEscape: %s", got)
	}
	for range 100 {
		if h, m := at(); h < 1 || h > 6 || m < 0 || m > 59 {
			t.Fatalf("at() = %d:%d, want between 01:00 and 06:59", h, m)
		}
	}
	dir, work := Paths()
	if dir == "" || work == "" {
		t.Errorf("Paths() = %q, %q", dir, work)
	}
}
