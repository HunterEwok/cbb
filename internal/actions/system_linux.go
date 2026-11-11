// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package actions

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/HunterEwok/cbb/internal/atomicfile"
)

// On Linux the Rust service asks logind over the system bus, and a polkit
// rule that cbb action enable writes, with the user's consent, lets the
// service's user do exactly the presets that are on: the unit's
// NoNewPrivileges keeps sudo out (design.md, "Quick actions").

// serviceUser is the service's user, which the polkit rule lets act.
const serviceUser = "cbb"

// rights are the polkit actions of each preset that needs one. A reboot or
// shutdown while someone is logged in needs the multiple-sessions right
// too; cancelling one needs the right that scheduled it.
var rights = map[string][]string{
	Lock:     {"org.freedesktop.login1.lock-sessions"},
	Sleep:    {"org.freedesktop.login1.suspend", "org.freedesktop.login1.suspend-multiple-sessions"},
	Reboot:   {"org.freedesktop.login1.reboot", "org.freedesktop.login1.reboot-multiple-sessions"},
	Shutdown: {"org.freedesktop.login1.power-off", "org.freedesktop.login1.power-off-multiple-sessions"},
}

// Rights lists the polkit actions that the presets in on need.
func Rights(on []string) []string {
	var out []string
	for _, p := range Presets {
		if slices.Contains(on, p) {
			out = append(out, rights[p]...)
		}
	}
	return out
}

// The places of polkit's rules: JavaScript rules since polkit 0.106, and
// the .pkla files of older ones (Debian until 12, Ubuntu 22.04).
var (
	polkitRoot = "/"
	rulesDir   = "etc/polkit-1/rules.d"
	rulesFile  = "60-cbb.rules"
	pklaDir    = "etc/polkit-1/localauthority/50-local.d"
	pklaFile   = "cbb.pkla"
)

// Grant writes the polkit rule that lets the service do the presets in on,
// and only those, or removes it when none needs a right. It returns the
// file it wrote; it runs as root, from cbb action enable.
func Grant(on []string) (string, error) {
	ids := Rights(on)
	rules := filepath.Join(polkitRoot, rulesDir)
	pkla := filepath.Join(polkitRoot, pklaDir)
	if !exists(filepath.Join(polkitRoot, "etc/polkit-1")) && !exists(filepath.Join(polkitRoot, "usr/share/polkit-1")) {
		if len(ids) == 0 {
			return "", nil
		}
		return "", errors.New("polkit is not installed here, so logind lets no service reboot or lock this computer; install polkit (policykit-1) and turn the action on again")
	}
	// The old polkit has the local authority and no rules directory.
	js := exists(rules) || !exists(filepath.Dir(pkla))
	path := filepath.Join(rules, rulesFile)
	data := jsRule(ids)
	if !js {
		path, data = filepath.Join(pkla, pklaFile), pklaRule(ids)
	}
	if len(ids) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return path, err
		}
		return path, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return path, err
	}
	return path, atomicfile.Write(path, []byte(data), 0o644)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func jsRule(ids []string) string {
	q := make([]string, len(ids))
	for i, id := range ids {
		q[i] = fmt.Sprintf("%q", id)
	}
	return `// Written by cbb action enable: lets the CBB service ask logind
// for the quick actions this computer's user turned on, and nothing else.
polkit.addRule(function (action, subject) {
	if (subject.user != "` + serviceUser + `") return polkit.Result.NOT_HANDLED;
	var allowed = [` + strings.Join(q, ", ") + `];
	return allowed.indexOf(action.id) >= 0 ? polkit.Result.YES : polkit.Result.NOT_HANDLED;
});
`
}

func pklaRule(ids []string) string {
	return `# Written by cbb action enable: lets the CBB service ask logind
# for the quick actions this computer's user turned on, and nothing else.
[CBB quick actions]
Identity=unix-user:` + serviceUser + `
Action=` + strings.Join(ids, ";") + `
ResultAny=yes
ResultInactive=yes
ResultActive=yes
`
}
