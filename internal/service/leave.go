// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/remotepaste"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// ErrLeft is what Run returns once the device has left its group (cbb
// leave): systemd, launchd and the Windows service manager start it again,
// in no group.
var ErrLeft = errors.New("restarting after leaving the group")

// groupFiles are what a device keeps of its group in the state directory,
// files and folders: its keys (or the TPM's and the Secure Enclave's blobs
// of them, which open nothing without the file), the records, the
// credentials and the keys for the servers, the tunnel's keys, the entry
// points, the known networks where it met the group, the cache of the
// group's images and files, the logs that name the group's devices, the
// proof of its keys and a group left before 0.6. The records go last, as in
// leaveVersion1Group, so that a leave cut short is seen as a group still.
var groupFiles = []string{
	group.FileName, group.CredentialsFileName, group.ServerKeysFileName, group.SealKeyFileName,
	signedFile, tunnel.StateFile, entriesFile, networksFile, statusFile, contentDir,
	remotepaste.LogFile, actions.LogFile, oldGroupDir, group.RecordsFileName,
}

// errRootLeaves is why the group's root does not leave while the group
// has other devices: nobody could then add or remove one.
func errRootLeaves(others []string) error {
	return fmt.Errorf("this device is the group's root, and the group has other devices (%s): make one of them an admin (cbb admin) and hand the group over to it (cbb handover) first, or remove them", strings.Join(others, ", "))
}

// leave takes this device out of its group (D-83): it stops the group and
// deletes the group's files, keeps the program and its settings, turns
// remote paste and the quick actions off, since they were allowed to the
// admins of the group it leaves, and restarts the service, which then is
// in no group and may join this group again or another one. The group's
// root leaves only when it is alone in the group. A device whose group
// file is damaged leaves too, which is how it starts again.
func (s *Service) leave() error {
	s.mu.Lock()
	id, busy := s.id, s.opening || s.joining || s.window != nil
	s.mu.Unlock()
	switch {
	case busy:
		return errors.New("a pairing is running here; let it end, then leave")
	case id == nil && s.broken == nil:
		return errors.New("this device is in no group")
	}
	if id != nil {
		var others []string
		s.recMu.Lock()
		if s.records != nil && s.records.RootDevice() == id.ID {
			for _, d := range s.records.Devices() {
				if d.ID != id.ID {
					others = append(others, d.Name)
				}
			}
		}
		s.recMu.Unlock()
		if len(others) > 0 {
			return errRootLeaves(others)
		}
	}
	s.stopGroup()
	err := leaveGroup(s.cfg.StateDir)
	if err != nil {
		s.logf("cbb: leaving the group: %v", err)
	} else {
		s.logf("cbb: this device left its group: its keys and the group's files are deleted; it restarts in no group")
	}
	// The service restarts either way: its group is stopped.
	go func() {
		time.Sleep(restartAfter)
		select {
		case s.left <- struct{}{}:
		default:
		}
	}()
	return err
}

// leaveGroup deletes the group's files from dir and turns remote paste and
// the quick actions off; the rest of the settings stay.
func leaveGroup(dir string) error {
	var errs []error
	for _, name := range groupFiles {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := remotepaste.Save(dir, remotepaste.Settings{}); err != nil {
		errs = append(errs, fmt.Errorf("turning remote paste off: %w", err))
	}
	if set, err := actions.Load(dir); err != nil {
		errs = append(errs, fmt.Errorf("turning the quick actions off: %w", err))
	} else if len(set.On()) > 0 {
		set.AllOff()
		if err := actions.Save(dir, set); err != nil {
			errs = append(errs, fmt.Errorf("turning the quick actions off: %w", err))
		}
	}
	return errors.Join(errs...)
}
