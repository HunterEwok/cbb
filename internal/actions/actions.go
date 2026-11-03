// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package actions holds a member's quick actions (design.md, "Quick
// actions"): the presets it knows, which of them its own user turned on and
// for which signers, the checks a signed action command passes before one
// runs, and the log of the last ones. The network carries only an action's
// name; what it does is defined here.
package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/group"
)

// The presets: lock the screen, sleep, reboot, shut down, cancel a reboot
// or shutdown that is pending, restart the service, and switch the layout
// the computer's Bluetooth keyboard types in to the next one, after the
// device it types on switched its own.
const (
	Lock     = "lock"
	Sleep    = "sleep"
	Reboot   = "reboot"
	Shutdown = "shutdown"
	Cancel   = "cancel-shutdown"
	Restart  = "restart"
	Layout   = "keyboard-layout"
)

// Presets lists the presets in the order the apps show them.
var Presets = []string{Lock, Sleep, Reboot, Shutdown, Cancel, Restart, Layout}

// IsPreset reports whether name is a preset.
func IsPreset(name string) bool { return slices.Contains(Presets, name) }

// The kinds of signers an action may allow: the group's root, an admin
// phone, an admin computer, a watch with an admin key of its own.
const (
	ByRoot     = "root"
	ByPhone    = "phone"
	ByComputer = "computer"
	ByWatch    = "watch"
)

// Kinds lists the kinds of signers.
var Kinds = []string{ByRoot, ByPhone, ByComputer, ByWatch}

// An Action is one action as this device's user set it: on or off, the
// kinds of admins that may run it (every kind when none), and whether a
// signer whose key is in a file may run it too.
type Action struct {
	Name string   `json:"name"`
	On   bool     `json:"on"`
	By   []string `json:"by,omitempty"`
	// AnyKey lets admins whose keys sit in files run it. Without it, an
	// action that hardware alone runs by default (reboot and shut down)
	// takes only signers whose keys are in hardware.
	AnyKey bool `json:"any_key,omitempty"`
	// Command is the program and its arguments of the user's own action,
	// which the agent runs as the user signed in; empty for a preset.
	Command []string `json:"command,omitempty"`
}

// MaxOwn is how many actions of their own a device's user may add.
const MaxOwn = 32

// CommandWait bounds how long the agent waits for an action's program to
// end, inside the service's wait for the result.
const CommandWait = 15 * time.Second

// CheckOwn says why name and command cannot be an action of the user's
// own, or nil: a name that is not a preset, and a program by its full path,
// so that nothing in PATH or a shell decides what runs.
func CheckOwn(name string, command []string) error {
	switch {
	case !group.ValidActionName(name):
		return fmt.Errorf("%q is not an action's name: 1 to %d of a-z, 0-9 and -, starting with a letter", name, group.MaxActionName)
	case IsPreset(name):
		return fmt.Errorf("%s is a preset; give your own action another name", name)
	case len(command) == 0:
		return errors.New("an action of your own needs a command: cbb action add NAME -- PROGRAM ARGS")
	case !filepath.IsAbs(command[0]):
		return fmt.Errorf("give the program by its full path, not %q", command[0])
	}
	return nil
}

// RunCommand runs an action's program, without a shell, and waits for it
// up to CommandWait; only its exit status comes back.
func RunCommand(ctx context.Context, command []string) error {
	ctx, cancel := context.WithTimeout(ctx, CommandWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	err := cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("%s ran longer than %v; an action starts longer work in the background", filepath.Base(command[0]), CommandWait)
	}
	return err
}

// HardwareByDefault reports whether only admins with keys in hardware run
// the action name until its user says otherwise: reboot and shut down,
// which a stolen key in a file must not do (D-71).
func HardwareByDefault(name string) bool { return name == Reboot || name == Shutdown }

// Settings are this device's actions: every one is off until its own user
// turns it on there.
type Settings struct {
	Actions []Action `json:"actions,omitempty"`
}

const (
	settingsFile = "actions.json"
	logFile      = "actions-log.json"
	// LogSize is how many actions the log keeps.
	LogSize = 100
)

// Load reads the settings from dir: all off when there are none.
func Load(dir string) (Settings, error) {
	var s Settings
	b, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", settingsFile, err)
	}
	return s, nil
}

// Save writes the settings to dir.
func Save(dir string, s Settings) error {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, settingsFile), append(b, '\n'), 0o600)
}

// Has reports whether this device has the action name: a preset, or one
// of its user's own.
func (s Settings) Has(name string) bool {
	return IsPreset(name) || slices.ContainsFunc(s.Actions, func(a Action) bool { return a.Name == name })
}

// Own lists the user's own actions.
func (s Settings) Own() []Action {
	var out []Action
	for _, a := range s.Actions {
		if len(a.Command) > 0 {
			out = append(out, a)
		}
	}
	return out
}

// Remove takes the user's own action name away.
func (s *Settings) Remove(name string) bool {
	n := len(s.Actions)
	s.Actions = slices.DeleteFunc(s.Actions, func(a Action) bool { return a.Name == name && len(a.Command) > 0 })
	return len(s.Actions) != n
}

// Get returns the action name: as its user set it, or off.
func (s Settings) Get(name string) Action {
	for _, a := range s.Actions {
		if a.Name == name {
			return a
		}
	}
	return Action{Name: name}
}

// Set replaces or adds a, keeping the presets' order.
func (s *Settings) Set(a Action) {
	s.Actions = slices.DeleteFunc(s.Actions, func(x Action) bool { return x.Name == a.Name })
	s.Actions = append(s.Actions, a)
	slices.SortStableFunc(s.Actions, func(x, y Action) int { return order(x.Name) - order(y.Name) })
}

// AllOff turns every action off, as an admin's actions-off command does,
// and keeps who may run each, for when its user turns it on again.
func (s *Settings) AllOff() {
	for i := range s.Actions {
		s.Actions[i].On = false
	}
}

// On lists the actions that are on.
func (s Settings) On() []string {
	var out []string
	for _, a := range s.Actions {
		if a.On {
			out = append(out, a.Name)
		}
	}
	return out
}

func order(name string) int {
	if i := slices.Index(Presets, name); i >= 0 {
		return i
	}
	return len(Presets)
}

// ParseKinds reads a list of signer kinds, such as "phone,computer".
func ParseKinds(s string) ([]string, error) {
	var out []string
	for k := range strings.SplitSeq(s, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if !slices.Contains(Kinds, k) {
			return nil, fmt.Errorf("%q is not a kind of admin: root, phone, computer or watch", k)
		}
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out, nil
}

// Signer is the admin that signed an action command, as the group's
// records show it (group.Records.CommandSigner).
type Signer struct {
	Root  bool   // the group's root key signed it
	Role  string // the device's role, group.RolePhone, group.RoleFull or group.RoleWatch; "" when no record names it
	Store string // where its keys live, group.StoreFile and the others; "" when unknown
}

// Kinds returns the kinds of signers s is: the root, and the kind of its
// device.
func (s Signer) Kinds() []string {
	var out []string
	if s.Root {
		out = append(out, ByRoot)
	}
	switch s.Role {
	case group.RolePhone:
		out = append(out, ByPhone)
	case group.RoleFull:
		out = append(out, ByComputer)
	case group.RoleWatch:
		out = append(out, ByWatch)
	}
	return out
}

// InHardware reports whether s's keys are in hardware.
func (s Signer) InHardware() bool {
	return s.Store == group.StoreHardware || s.Store == group.StoreProven
}

// Refusal says why a member does not run an action; its reason goes to the
// sender as it is.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

// Check says why the action a, as this device's user set it, may not run
// for the signer s, or nil if it may.
func Check(a Action, s Signer) error {
	switch {
	case !a.On:
		return &Refusal{Reason: fmt.Sprintf("the action %s is off on this device; its user turns it on there with sudo cbb action enable %s", a.Name, a.Name)}
	case len(a.By) > 0 && !slices.ContainsFunc(s.Kinds(), func(k string) bool { return slices.Contains(a.By, k) }):
		return &Refusal{Reason: fmt.Sprintf("this device runs %s only for %s", a.Name, strings.Join(a.By, ", "))}
	case HardwareByDefault(a.Name) && !a.AnyKey && !s.InHardware():
		return &Refusal{Reason: fmt.Sprintf("this device runs %s only for admins whose keys are in hardware, and the sender's key is in a file; its user allows that with sudo cbb action enable %s -any-key", a.Name, a.Name)}
	}
	return nil
}

// An Entry is one action in the log: who asked, when, and how it ended.
type Entry struct {
	TimeMS int64  `json:"time_ms"`
	By     string `json:"by"`             // the sender's device ID
	Name   string `json:"name,omitempty"` // the sender's name, when known
	// Unverified: the records do not show that the device By names
	// signed; By is then only the signer's word.
	Unverified bool   `json:"unverified,omitempty"`
	Action     string `json:"action"`
	Result     string `json:"result"` // done, refused or failed
	Reason     string `json:"reason,omitempty"`
}

// Append adds an entry to the log in dir, keeping the last LogSize.
func Append(dir string, e Entry) error {
	es, err := ReadLog(dir)
	if err != nil {
		es = nil
	}
	es = append(es, e)
	if len(es) > LogSize {
		es = es[len(es)-LogSize:]
	}
	b, err := json.Marshal(es)
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, logFile), b, 0o600)
}

// ReadLog returns the log in dir, oldest first.
func ReadLog(dir string) ([]Entry, error) {
	b, err := os.ReadFile(filepath.Join(dir, logFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, fmt.Errorf("%s: %w", logFile, err)
	}
	return es, nil
}
