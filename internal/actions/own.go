// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package actions

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
)

// OwnFile is where a user's own commands are, in the cbb folder of the
// user's settings (os.UserConfigDir), by the action's name: cbb action add
// writes it as the user (member/src/actions.rs, set_own_command). The
// agent of the user's session runs a command the service names only when
// it is there, so that an account of the service cannot make the session
// run one its user did not set (design.md, "Quick actions").
const OwnFile = "own-actions.json"

// OwnCommands reads the user's own commands in dir.
func OwnCommands(dir string) (map[string][]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, OwnFile))
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var all map[string][]string
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}
	return all, nil
}

// OwnCommandAllowed says why the session may not run command for the action name:
// nil when its user set that very command for it in dir.
func OwnCommandAllowed(dir, name string, command []string) error {
	all, err := OwnCommands(dir)
	if err != nil {
		return &Refusal{Reason: "this session cannot read its user's own commands: " + err.Error()}
	}
	if c, ok := all[name]; ok && len(c) > 0 && slices.Equal(c, command) {
		return nil
	}
	return &Refusal{Reason: "this session runs only the commands its user set as this user (cbb action add " + name + " -- ...)"}
}

// OwnDir is the cbb folder of this user's settings.
func OwnDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "cbb"), nil
}
