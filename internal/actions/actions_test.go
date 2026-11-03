// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package actions

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/group"
)

func TestCheck(t *testing.T) {
	phone := Signer{Role: group.RolePhone, Store: group.StoreHardware}
	rootPhone := Signer{Root: true, Role: group.RolePhone, Store: group.StoreHardware}
	fileComputer := Signer{Role: group.RoleFull, Store: group.StoreFile}
	tpmComputer := Signer{Role: group.RoleFull, Store: group.StoreProven}
	watch := Signer{Role: group.RoleWatch, Store: group.StoreHardware}
	unknown := Signer{}
	for _, tt := range []struct {
		a      Action
		s      Signer
		refuse string
	}{
		{Action{Name: Lock}, phone, "is off on this device"},
		{Action{Name: Lock, On: true}, fileComputer, ""},
		{Action{Name: Lock, On: true}, unknown, ""},
		{Action{Name: Lock, On: true, By: []string{ByPhone}}, fileComputer, "only for phone"},
		{Action{Name: Lock, On: true, By: []string{ByPhone}}, phone, ""},
		{Action{Name: Lock, On: true, By: []string{ByRoot}}, phone, "only for root"},
		{Action{Name: Lock, On: true, By: []string{ByRoot}}, rootPhone, ""},
		{Action{Name: Reboot, On: true}, fileComputer, "keys are in hardware"},
		{Action{Name: Reboot, On: true}, unknown, "keys are in hardware"},
		{Action{Name: Reboot, On: true}, tpmComputer, ""},
		{Action{Name: Shutdown, On: true}, phone, ""},
		{Action{Name: Shutdown, On: true, AnyKey: true}, fileComputer, ""},
		{Action{Name: Sleep, On: true}, fileComputer, ""},
		{Action{Name: Lock, On: true, By: []string{ByPhone, ByComputer}}, watch, "only for phone, computer"},
		{Action{Name: Lock, On: true, By: []string{ByWatch}}, watch, ""},
		{Action{Name: Reboot, On: true}, watch, ""},
	} {
		err := Check(tt.a, tt.s)
		var r *Refusal
		switch {
		case tt.refuse == "" && err != nil:
			t.Errorf("%+v for %+v: %v", tt.a, tt.s, err)
		case tt.refuse != "" && (!errors.As(err, &r) || !strings.Contains(r.Reason, tt.refuse)):
			t.Errorf("%+v for %+v: %v, want %q", tt.a, tt.s, err, tt.refuse)
		}
	}
}

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
	s.AllOff()
	if len(s.On()) != 0 || s.Get(Reboot).By[0] != ByPhone {
		t.Errorf("all off: %+v", s)
	}
	if k, err := ParseKinds("phone, computer,phone"); err != nil || fmt.Sprint(k) != "[phone computer]" {
		t.Errorf("ParseKinds: %v, %v", k, err)
	}
	if _, err := ParseKinds("tv"); err == nil {
		t.Error("ParseKinds took a kind it does not know")
	}
	if k, err := ParseKinds("watch"); err != nil || fmt.Sprint(k) != "[watch]" {
		t.Errorf("ParseKinds(watch): %v, %v", k, err)
	}
	for i := range LogSize + 3 {
		if err := Append(dir, Entry{TimeMS: int64(i), By: "x", Action: Lock, Result: "done"}); err != nil {
			t.Fatal(err)
		}
	}
	if es, err := ReadLog(dir); err != nil || len(es) != LogSize || es[0].TimeMS != 3 {
		t.Errorf("the log: %d entries, %v", len(es), err)
	}
}
