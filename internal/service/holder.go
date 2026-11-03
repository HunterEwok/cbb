// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/HunterEwok/cbb/internal/atomicfile"
)

// holderFile holds the holder setting, in the state directory; without it
// the setting is HolderAuto.
const holderFile = "holder"

// The holder settings: whether this member comes first, only as a fallback,
// or never, when the members elect the holder of cbb.local.
// HolderAuto picks first or fallback by whether the machine has a battery.
const (
	HolderAuto     = "auto"
	HolderFirst    = "first"
	HolderFallback = "fallback"
	HolderNever    = "never"
)

// The priorities in the TXT key h: the lower number comes first.
const (
	prioFirst    = 1
	prioFallback = 2
)

// validHolder reports whether v is a holder setting.
func validHolder(v string) bool {
	switch v {
	case HolderAuto, HolderFirst, HolderFallback, HolderNever:
		return true
	}
	return false
}

// loadHolder reads the holder setting from dir.
func loadHolder(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, holderFile))
	if errors.Is(err, os.ErrNotExist) {
		return HolderAuto, nil
	}
	if err != nil {
		return HolderAuto, err
	}
	v := strings.TrimSpace(string(b))
	if !validHolder(v) {
		return HolderAuto, fmt.Errorf("%s says %q, not auto, first, fallback or never", holderFile, v)
	}
	return v, nil
}

// saveHolder writes the holder setting to dir.
func saveHolder(dir, v string) error {
	return atomicfile.Write(filepath.Join(dir, holderFile), []byte(v+"\n"), 0o600)
}

// priority returns this member's priority for cbb.local, or 0
// if it never holds the name: only a member that serves the shortcut, with
// the iPhone CA key, can hold it. A machine without a battery, which does
// not sleep as a laptop does, comes first; the setting overrides the guess.
func priority(setting string, canHold, battery bool) int {
	switch {
	case !canHold || setting == HolderNever:
		return 0
	case setting == HolderFirst:
		return prioFirst
	case setting == HolderFallback:
		return prioFallback
	case battery:
		return prioFallback
	}
	return prioFirst
}

// parsePriority reads the TXT key h of a member, 0 if absent or unknown.
func parsePriority(v string) int {
	n, err := strconv.Atoi(v)
	if err != nil || (n != prioFirst && n != prioFallback) {
		return 0
	}
	return n
}

// setHolder changes the holder setting, saves it, publishes the new
// priority and elects the holder again.
func (s *Service) setHolder(v string) error {
	if !validHolder(v) {
		return fmt.Errorf("the holder setting is auto, first, fallback or never, not %q", v)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := saveHolder(s.cfg.StateDir, v); err != nil {
		return fmt.Errorf("saving the holder setting: %w", err)
	}
	s.holdSetting = v
	if s.id != nil && s.responder != nil && !s.stopping {
		s.responder.SetTXT(s.txtLocked())
		s.electLocked()
	}
	return nil
}
