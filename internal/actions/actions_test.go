// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSettings(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir)
	if err != nil || len(s.On()) != 0 || s.Get(Reboot).On {
		t.Fatalf("a new device: %+v, %v", s, err)
	}
	s.Set(Action{Name: Restart, On: true})
	s.Set(Action{Name: Reboot, On: true, By: []string{ByPhone}})
	s.Set(Action{Name: Lock, On: false})
	s.Set(Action{Name: Restart, On: true, AnyKey: true})
	if err := Save(dir, s); err != nil {
		t.Fatal(err)
	}
	s, _ = Load(dir)
	if fmt.Sprint(s.On()) != "[reboot restart]" || len(s.Actions) != 3 || s.Actions[0].Name != Lock || !s.Get(Restart).AnyKey {
		t.Errorf("saved: %+v", s)
	}
	if es, err := ReadLog(dir); err != nil || es != nil {
		t.Errorf("no log: %v, %v", es, err)
	}
	if err := os.WriteFile(filepath.Join(dir, LogFile), []byte(`[{"time_ms":3,"by":"x","action":"lock","result":"done"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if es, err := ReadLog(dir); err != nil || len(es) != 1 || es[0].TimeMS != 3 || es[0].Action != Lock {
		t.Errorf("the log: %+v, %v", es, err)
	}
	if err := os.WriteFile(filepath.Join(dir, LogFile), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLog(dir); err == nil {
		t.Error("a broken log read")
	}
	if err := os.WriteFile(filepath.Join(dir, "actions.json"), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("broken settings read")
	}
}

// A refusal's reason is its error, word for word, as the sender gets it.
func TestRefusal(t *testing.T) {
	var err error = &Refusal{Reason: "the action lock is off on this device"}
	if err.Error() != "the action lock is off on this device" {
		t.Errorf("Refusal.Error() = %q", err.Error())
	}
}

// The user's own settings are in the cbb folder of the system's place for
// them.
func TestOwnDir(t *testing.T) {
	base, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("no config folder here: %v", err)
	}
	if d, err := OwnDir(); err != nil || d != filepath.Join(base, "cbb") {
		t.Errorf("OwnDir() = %q, %v", d, err)
	}
}
