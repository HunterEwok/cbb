// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.toml")
	os.WriteFile(path, []byte(`
controller = "controller"

[device.desktop]
os = "linux"
ssh = "user@desktop.lan"
clipboard = "wayland"
roles = ["member", "hub"]

[device.lite]
os = "linux-lite"
ssh = "user@pi.lan"

[device.win]
os = "windows"
ssh = "user@win.lan"
clipboard = "windows"
vm = { host = "mac", vmx = "win.vmx", snapshot = "clean" }

[router]
ssh = "root@router.lan"
kind = "openwrt"
`), 0o600)
	inv, err := LoadInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := inv.Select("")
	if err != nil || len(ds) != 3 || ds[0].Name != "desktop" || !ds[0].Has("hub") {
		t.Fatalf("Select = %v, %v", ds, err)
	}
	if ds[1].Clipboard != "none" || ds[2].VM.Snapshot != "clean" {
		t.Fatalf("defaults: %+v %+v", ds[1], ds[2].VM)
	}
	if _, err := inv.Select("desktop,nope"); err == nil {
		t.Fatal("Select took an unknown device")
	}

	os.WriteFile(path, []byte("[device.nas]\nos = \"docker\"\nssh = \"a@b\"\nroles = [\"hub\"]\n"), 0o600)
	if _, err := LoadInventory(path); err == nil || !strings.Contains(err.Error(), "ordinary member") {
		t.Fatalf("a container as the hub: %v", err)
	}
	os.WriteFile(path, []byte("[device.nas]\nos = \"docker\"\nssh = \"a@b\"\n"), 0o600)
	inv, err = LoadInventory(path)
	if err != nil || inv.Device["nas"].Container != "cbb" || cbbCmd(inv.Device["nas"]) != "docker exec -i cbb cbb" {
		t.Fatalf("a container: %+v, %v", inv, err)
	}
	os.WriteFile(path, []byte("[device.nas]\nos = \"docker\"\nssh = \"a@b\"\nclipboard = \"x11\"\n"), 0o600)
	if _, err := LoadInventory(path); err == nil {
		t.Fatal("a container with a desktop clipboard")
	}
	os.WriteFile(path, []byte("[device.x]\nos = \"linux\"\nssh = \"a@b\"\ncontainer = \"c\"\n"), 0o600)
	if _, err := LoadInventory(path); err == nil {
		t.Fatal("a container name on a device that is not one")
	}

	os.WriteFile(path, []byte("[device.vpn]\nos = \"netns\"\nssh = \"a@b\"\nroles = [\"away\"]\n"), 0o600)
	inv, err = LoadInventory(path)
	if err != nil {
		t.Fatalf("a member in a namespace: %v", err)
	}
	if vpn := inv.Device["vpn"]; cbbCmd(vpn) != "sudo -n /opt/cbbbench-netns/vpn/cbb" || serviceCmd(vpn, "restart") != "sudo -n systemctl restart cbbbench-vpn" {
		t.Fatalf("a member in a namespace: %q, %q", cbbCmd(vpn), serviceCmd(vpn, "restart"))
	}
	for _, bad := range []string{
		"[device.vpn]\nos = \"netns\"\nssh = \"a@b\"\nroles = [\"hub\"]\n",
		"[device.vpn]\nos = \"netns\"\nssh = \"a@b\"\nclipboard = \"x11\"\n",
		"[device.Remote-VPN]\nos = \"netns\"\nssh = \"a@b\"\n",
		"[device.waytoolongname]\nos = \"netns\"\nssh = \"a@b\"\n",
	} {
		os.WriteFile(path, []byte(bad), 0o600)
		if _, err := LoadInventory(path); err == nil {
			t.Fatalf("took %q", bad)
		}
	}

	os.WriteFile(path, []byte("[device.x]\nos = \"plan9\"\nssh = \"a@b\"\n"), 0o600)
	if _, err := LoadInventory(path); err == nil || !strings.Contains(err.Error(), "plan9") {
		t.Fatalf("an unknown os: %v", err)
	}
	os.WriteFile(path, []byte("[device.x]\nos = \"linux\"\nssh = \"a@b\"\ncolour = 1\n"), 0o600)
	if _, err := LoadInventory(path); err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("an unknown key: %v", err)
	}
}

func TestEncodePS(t *testing.T) {
	s := "Set-Clipboard 'café'"
	b, err := base64.StdEncoding.DecodeString(encodePS(s))
	if err != nil {
		t.Fatal(err)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	if got := string(utf16.Decode(u)); got != s {
		t.Fatalf("decoded %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote(`a 'b' $c`); got != `'a '\''b'\'' $c'` {
		t.Fatalf("shellQuote = %s", got)
	}
}

// The patterns read what the full and the lite member print; keep them in step with
// cmd/cbb/commands.go and member/src/lib.rs.
func TestPatterns(t *testing.T) {
	if m := codeRE.FindStringSubmatch("Pairing code: 123 456"); m == nil || m[1]+m[2] != "123456" {
		t.Fatalf("code: %v", m)
	}
	if m := addrRE.FindStringSubmatch("If it cannot find this one: cbb pair -code 192.168.1.10:8764"); m == nil || m[1] != "192.168.1.10:8764" {
		t.Fatalf("address: %v", m)
	}
	for _, s := range []string{
		"Device desktop (linux), group 0a1b2c3d4e5f6a7b",
		"device  abc\ngroup   0a1b2c3d4e5f6a7b\nrole    lite",
	} {
		if m := groupRE.FindStringSubmatch(s); m == nil || m[1] != "0a1b2c3d4e5f6a7b" {
			t.Fatalf("group in %q: %v", s, m)
		}
	}
}

func TestNoLocale(t *testing.T) {
	got := noLocale([]string{"HOME=/home/u", "LANG=ru_RU.UTF-8", "LC_ALL=ru_RU.UTF-8", "LC_CTYPE=C", "LANGUAGE=ru", "PATH=/bin"})
	if strings.Join(got, " ") != "HOME=/home/u PATH=/bin" {
		t.Errorf("noLocale = %q", got)
	}
}

func TestDeviceRE(t *testing.T) {
	for _, out := range []string{"Device 3f2a9c01d4 (linux), group 0a1b2c3d4e5f6a7b\n", "device  3f2a9c01d4\ngroup   0a1b2c3d4e5f6a7b\n"} {
		if m := deviceRE.FindStringSubmatch(out); m == nil || m[1] != "3f2a9c01d4" {
			t.Errorf("deviceRE on %q = %v", out, m)
		}
	}
}

// TestTextCases checks the matrix's texts: none is empty or ends with a
// line ending, which the readers trim, and each sender's text differs.
func TestTextCases(t *testing.T) {
	for _, tc := range textCases {
		a, b := tc.text("20261024-120000", "mac"), tc.text("20261024-120000", "win")
		if a == "" || strings.TrimRight(a, "\r\n") != a {
			t.Errorf("%s: %q is empty or ends with a line ending", tc.id, a)
		}
		if a == b {
			t.Errorf("%s: two senders send the same text %q", tc.id, a)
		}
	}
}

func TestSeen(t *testing.T) {
	lin, win := &Device{OS: "linux"}, &Device{OS: "windows"}
	text := "L1\nL2\r\nL3\n"
	for _, c := range []struct {
		from, to *Device
		want     string
	}{
		{lin, lin, text},
		{lin, win, "L1\r\nL2\r\nL3\r\n"},
		{win, lin, "L1\nL2\nL3\n"},
		{win, win, "L1\r\nL2\r\nL3\r\n"},
	} {
		if got := seen(text, c.from, c.to); got != c.want {
			t.Errorf("seen(%q, %s, %s) = %q, want %q", text, c.from.OS, c.to.OS, got, c.want)
		}
	}
}

func TestContainer(t *testing.T) {
	// As docker inspect prints the container of compose.home.yaml.
	good := "false|true|[ALL]|65532:65532|[no-new-privileges:true]|host|unless-stopped"
	if err := checkLockedDown(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"true|true|[ALL]|65532:65532|[no-new-privileges:true]|host|unless-stopped",
		"false|false|[ALL]|65532:65532|[no-new-privileges:true]|host|unless-stopped",
		"false|true|[]|65532:65532|[no-new-privileges:true]|host|unless-stopped",
		"false|true|[ALL]|0|[no-new-privileges:true]|host|unless-stopped",
		"false|true|[ALL]||[no-new-privileges:true]|host|unless-stopped",
		"false|true|[ALL]|65532:65532|[]|host|unless-stopped",
		"false|true|[ALL]|65532:65532|[no-new-privileges:true]|bridge|unless-stopped",
		"false|true|[ALL]|65532:65532|[no-new-privileges:true]|host|no",
		"false|true",
	} {
		if checkLockedDown(bad) == nil {
			t.Errorf("checkLockedDown took %q", bad)
		}
	}
	if got, want := recreateCmd("cbb|/srv/cbb/compose.home.yaml|cbb"),
		"docker compose -p 'cbb' -f '/srv/cbb/compose.home.yaml' up -d --force-recreate 'cbb'"; got != want {
		t.Errorf("recreateCmd = %s, want %s", got, want)
	}
	if got := recreateCmd("||"); got != "" {
		t.Errorf("recreateCmd without compose = %q", got)
	}
}

func TestAdmin(t *testing.T) {
	for os, want := range map[string]string{
		"linux":      "sudo -n cbb",
		"linux-lite": "sudo -n cbb",
		"darwin":     "sudo -n cbb",
		"windows":    `& "$env:ProgramFiles\cbb\cbb.exe"`,
		"docker":     "docker exec -i c cbb",
	} {
		if got := adminCmd(&Device{OS: os, Container: "c"}); got != want {
			t.Errorf("adminCmd(%s) = %q, want %q", os, got, want)
		}
	}
	refused := &RunError{Device: "mac", Output: "sudo: a password is required\n"}
	if !sudoRefused(refused) || sudoRefused(&RunError{Output: "only the administrator may run it"}) || sudoRefused(nil) {
		t.Fatal("sudoRefused")
	}
	var buf strings.Builder
	r := NewReport("t", &buf, false)
	if err := r.Do("a", func() error { return noSudo(&Device{Name: "mac"}, refused) }); err == nil {
		t.Fatal("a skipped case returned nil")
	}
	r.Do("b", func() error { return noSudo(&Device{Name: "x"}, errors.New("broken")) })
	if r.Failed() != 1 || !strings.Contains(buf.String(), "SKIP a: mac runs no sudo") || !strings.Contains(buf.String(), "FAIL b") {
		t.Fatalf("report:\n%s", buf.String())
	}
}

func TestAway(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.toml")
	os.WriteFile(path, []byte(`
[device.desktop]
os = "linux"
ssh = "a@desktop"
roles = ["member", "hub", "away"]

[device.remote]
os = "linux"
ssh = "a@remote"
roles = ["away"]

[forwarder]
ssh = "a@relay"
address = "relay.example.net:8764"
key = "AAAA"
service = "cbb-forward"

[relay]
address = "relay.example.net:8765"
key = "BBBB"
`), 0o600)
	inv, err := LoadInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Forwarder.Address != "relay.example.net:8764" || inv.Forwarder.Service != "cbb-forward" || inv.Relay.Key != "BBBB" {
		t.Fatalf("servers: %+v %+v", inv.Forwarder, inv.Relay)
	}
	ds, _ := inv.Select("")
	if home := atHome(ds); len(home) != 1 || home[0].Name != "desktop" {
		t.Fatalf("atHome = %v", home)
	}
	if away := awayOnly(ds); len(away) != 1 || away[0].Name != "remote" {
		t.Fatalf("awayOnly = %v", away)
	}
	if m := fingerprintRE.FindStringSubmatch("Its key fingerprint:  ab12 cd34 ef56"); m == nil || m[1] != "ab12 cd34 ef56" {
		t.Fatalf("fingerprint: %q", m)
	}
}

func TestReset(t *testing.T) {
	for _, c := range []struct{ os, machine, want string }{
		{"linux", "x86_64", "cbb-linux-amd64.tar.gz"},
		{"docker", "aarch64", "cbb-linux-arm64.tar.gz"},
		{"linux-lite", "armv6l", "cbb-lite-linux-armv6.tar.gz"},
		{"darwin", "arm64", "cbb-darwin-arm64.tar.gz"},
		{"windows", "ARM64", "cbb-windows-arm64.zip"},
		{"windows", "AMD64", "cbb-windows-amd64.zip"},
		{"openwrt", "aarch64_cortex-a53", "cbb-linux-arm64.tar.gz"},
		{"openwrt", "arm_cortex-a7_neon-vfpv4", "cbb-linux-armv7.tar.gz"},
		{"openwrt", "arm_arm1176jzf-s_vfp", "cbb-linux-armv6.tar.gz"},
		{"openwrt", "mipsel_24kc", "cbb-linux-mipsle.tar.gz"},
		{"openwrt", "mips_24kc", "cbb-linux-mips.tar.gz"},
		{"openwrt", "x86_64", "cbb-linux-amd64.tar.gz"},
		{"freebsd", "amd64", "cbb-freebsd-amd64.tar.gz"},
	} {
		if got, err := archiveFor(&Device{OS: c.os}, c.machine); err != nil || got != c.want {
			t.Errorf("archiveFor(%s, %s) = %q, %v", c.os, c.machine, got, err)
		}
	}
	if _, err := archiveFor(&Device{OS: "linux"}, "mips"); err == nil {
		t.Error("archiveFor took an unknown CPU")
	}
	if _, err := archiveFor(&Device{OS: "openwrt"}, "riscv64_generic"); err == nil {
		t.Error("archiveFor took an unknown OpenWrt architecture")
	}
	if _, err := archiveFor(&Device{OS: "freebsd"}, "armv7"); err == nil {
		t.Error("archiveFor took a CPU FreeBSD has no build for")
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cbb-linux-amd64.tar.gz"), []byte("archive"), 0o600)
	b, err := LoadBuild(dir)
	if err != nil || len(b.sums) != 1 || len(b.sums["cbb-linux-amd64.tar.gz"]) != 64 {
		t.Fatalf("LoadBuild = %+v, %v", b, err)
	}
	os.WriteFile(filepath.Join(dir, "cbb-windows-arm64.zip"), []byte("zip"), 0o600)
	if b, err := LoadBuild(dir); err != nil || len(b.sums) != 2 {
		t.Fatalf("LoadBuild with a zip = %+v, %v", b, err)
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Repeat("0", 64)+"  cbb-linux-amd64.tar.gz\n"), 0o600)
	if _, err := LoadBuild(dir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a wrong checksum: %v", err)
	}
	if _, err := LoadBuild(t.TempDir()); err == nil {
		t.Fatal("LoadBuild took a directory without archives")
	}

	if got := composeCmd("cbb-nas|/home/u/cbb-nas/compose.yaml|cbb"); got != "docker compose -p 'cbb-nas' -f '/home/u/cbb-nas/compose.yaml'" {
		t.Fatalf("composeCmd = %q", got)
	}
	if composeCmd("||") != "" {
		t.Fatal("composeCmd of a container docker compose did not start")
	}
}

func TestCatalogue(t *testing.T) {
	cases, funcs, err := loadCatalogue(filepath.Join("..", "..", "docs"))
	if err != nil {
		t.Fatal(err)
	}
	if bad := checkCatalogue(cases, funcs); len(bad) > 0 {
		t.Fatalf("the catalogue does not hold together:\n%s", strings.Join(bad, "\n"))
	}
	// Every row of a table is read: a row the patterns miss would drop a
	// case or a function without a word.
	for _, f := range []struct {
		name, row string
		n         int
	}{
		{"testbench-catalogue.md", `^\| [A-Z][0-9]+ \|`, len(cases)},
		{"testbench-functions.md", `^\| [A-Z]\.[0-9]+ \|`, len(funcs)},
	} {
		b, err := os.ReadFile(filepath.Join("..", "..", "docs", f.name))
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		if rows := len(regexp.MustCompile(`(?m)`+f.row).FindAllIndex(b, -1)); rows != f.n {
			t.Errorf("%s has %d rows, read %d", f.name, rows, f.n)
		}
	}
	var out strings.Builder
	if err := Coverage(&out, filepath.Join("..", "..", "docs")); err != nil || !strings.Contains(out.String(), "functions with a case") {
		t.Fatalf("Coverage: %v\n%s", err, out.String())
	}
}

func TestReadCatalogue(t *testing.T) {
	cs, err := readCatalogue("| Y1 | Short ASCII, every pair [C1, F2] | real, fleet | |\n| T19 | TVs | person | phase 9, TV |\n")
	if err != nil || len(cs) != 2 {
		t.Fatalf("readCatalogue = %v, %v", cs, err)
	}
	if !cs[0].automatic() || cs[1].automatic() || strings.Join(cs[0].Old, " ") != "C1 F2" || strings.Join(cs[1].Needs, "/") != "phase 9/TV" {
		t.Fatalf("cases: %+v", cs)
	}
	if _, err := readCatalogue("| Y1 | a | robot | |\n"); err == nil {
		t.Fatal("an unknown kind was taken")
	}
	if _, err := readCatalogue("| Y1 | a | real | |\n| Y1 | b | real | |\n"); err == nil {
		t.Fatal("a case listed twice was taken")
	}
}

func TestCheckMessage(t *testing.T) {
	ec := errorCase{want: []string{"not running"}, detail: true}
	for _, c := range []struct {
		out, mode string
		ok        bool
	}{
		{"cbb: the CBB service is not running; start it with: sudo systemctl start cbb", "0", true},
		{"cbb: the CBB service is not running (dial unix /run/cbb/control.sock: connect: no such file or directory)", "0", false},
		{"cbb: the service is not running\n  Detail: dial unix /run/x: connect: no such file or directory", "0", false},
		{"cbb: the service is not running\n  Detail: dial unix /run/x: connect: no such file or directory", "1", true},
		{"cbb: the service is not running", "1", false},
		{"cbb: something went wrong", "0", false},
		{"cbb: no group", "0", false},
		{"", "0", false},
	} {
		if err := checkMessage(c.out, ec, c.mode); (err == nil) != c.ok {
			t.Errorf("checkMessage(%q, %s) = %v", c.out, c.mode, err)
		}
	}
}

func TestWithDebug(t *testing.T) {
	for _, c := range []struct {
		os, cmd, mode, want string
	}{
		{"linux", "cbb status", "1", "CBB_DEBUG=1 cbb status"},
		{"linux", "sudo -n cbb new", "0", "sudo -n env CBB_DEBUG=0 cbb new"},
		{"darwin", "sudo -n cbb new", "", "sudo -n cbb new"},
		{"windows", "cbb status", "1", "$env:CBB_DEBUG='1'; cbb status"},
		{"docker", "docker exec -i cbb cbb status", "0", "docker exec -e CBB_DEBUG=0 -i cbb cbb status"},
	} {
		if got := withDebug(&Device{OS: c.os}, c.cmd, c.mode); got != c.want {
			t.Errorf("withDebug(%s, %q, %q) = %q, want %q", c.os, c.cmd, c.mode, got, c.want)
		}
	}
}

func TestSoakFlat(t *testing.T) {
	flat := []soakSample{{rss: 20000, fds: 30}, {rss: 21000, fds: 31}, {rss: 22000, fds: 32}}
	if _, err := soakFlat(flat); err != nil {
		t.Errorf("a flat run failed: %v", err)
	}
	leak := []soakSample{{rss: 20000, fds: 30}, {rss: 40000, fds: 31}, {rss: 80000, fds: 32}}
	if _, err := soakFlat(leak); err == nil {
		t.Error("memory that quadrupled passed")
	}
	fds := []soakSample{{rss: 20000, fds: 30}, {rss: 20000, fds: 60}}
	if _, err := soakFlat(fds); err == nil {
		t.Error("descriptors that doubled passed")
	}
}

func TestCaseMissing(t *testing.T) {
	saved := automated
	defer func() { automated = saved }()
	automated = map[string][]string{
		"X1": {"fleet"}, "X2": {"fleet"}, "X3": {"desktop"}, "X4": {"phone"}, "X5": {"fleet"},
	}
	for _, tc := range []struct {
		c    catCase
		want string
	}{
		{catCase{ID: "X1", How: []string{"real", "fleet"}}, ""},
		{catCase{ID: "X2", How: []string{"real"}}, "real"},
		{catCase{ID: "X3", How: []string{"real", "helper", "person"}}, "person"},
		{catCase{ID: "X4", How: []string{"ui", "real"}}, "real"},
		{catCase{ID: "X5", How: []string{"fleet", "time"}}, "time"},
		{catCase{ID: "X6", How: []string{"fleet"}}, ""},
	} {
		if got := strings.Join(tc.c.missing(), ","); got != tc.want {
			t.Errorf("%s %v: missing %q, want %q", tc.c.ID, tc.c.How, got, tc.want)
		}
	}
}
