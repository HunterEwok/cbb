// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package actions is the Go side of a member's quick actions (design.md,
// "Quick actions"), which the Rust cbb decides on: the agent's part, which
// runs a preset in the user's session (Session) or a command the user set
// as that user (OwnCommandAllowed, RunCommand), and the files cbb keeps
// them in, the settings and the log, as the service's tests read them.
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
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
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

// The kinds of signers an action may allow: the group's root, an admin
// phone, an admin computer, a watch with an admin key of its own.
const (
	ByRoot     = "root"
	ByPhone    = "phone"
	ByComputer = "computer"
	ByWatch    = "watch"
)

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

// CommandWait bounds how long the agent waits for an action's program to
// end, inside the service's wait for the result.
const CommandWait = 15 * time.Second

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

// Settings are this device's actions: every one is off until its own user
// turns it on there.
type Settings struct {
	Actions []Action `json:"actions,omitempty"`
}

const (
	settingsFile = "actions.json"
	// LogFile keeps the last LogSize actions in the state directory.
	LogFile = "actions-log.json"
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

// Refusal says why a member does not run an action; its reason goes to the
// sender as it is.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

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

// ReadLog returns the log in dir, oldest first.
func ReadLog(dir string) ([]Entry, error) {
	b, err := os.ReadFile(filepath.Join(dir, LogFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, fmt.Errorf("%s: %w", LogFile, err)
	}
	return es, nil
}
