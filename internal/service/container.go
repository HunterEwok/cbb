// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"os"

	"github.com/HunterEwok/cbb/internal/group"
)

// The image sets CBB_CONTAINER (packaging/docker/Dockerfile). A container
// keeps its keys in a file in its volume, which whoever copies the volume
// has, so it holds no key that admits or removes devices: it is never the
// group's root and takes no admin key, unless the user allowed it with
// CBB_KEYS_IN_FILE=yes after reading why not (docs/design.md, "Docker",
// and the key levels).
const (
	containerEnv  = "CBB_CONTAINER"
	keysInFileEnv = "CBB_KEYS_IN_FILE"
)

// InContainer reports whether the service runs in the image.
func InContainer() bool { return os.Getenv(containerEnv) != "" }

// KeysInFileAllowed reports whether the user allowed a container to hold
// the group's keys.
func KeysInFileAllowed() bool { return os.Getenv(keysInFileEnv) == "yes" }

// errKeysInContainer refuses what would put a key that admits devices in
// a container.
var errKeysInContainer = errors.New("this device runs in a container, whose keys are in a file in its volume, where anyone who copies the volume has them; " +
	"the group's root and admins belong on the devices you hold, so make the group or the admin there. " +
	"To allow it here anyway, set " + keysInFileEnv + "=yes in the container's environment")

// errKeysRootless refuses the group's keys to a rootless install.
var errKeysRootless = errors.New("this device is installed without root, so every program of its user can read its keys; " +
	"it is never the group's root or an admin, so make the group or the admin on another device, " +
	"or install it with sudo (docs/guide/install.md)")

// keysAllowed returns errKeysRootless for a rootless install,
// errKeysInContainer in a container whose user did not allow it to hold
// the group's keys, and nil anywhere else.
func (s *Service) keysAllowed() error {
	if s.cfg.Rootless {
		return errKeysRootless
	}
	if s.cfg.Container && !s.cfg.KeysInFile {
		return errKeysInContainer
	}
	return nil
}

// keyStore is where this device says its keys live: group.StoreRootless
// for a rootless install, else where id's member key is; on the group's
// root, group.StoreFile when its CA key, which signs the records and the
// certificates, is a file, whatever its member key.
func (s *Service) keyStore(id *group.Identity) string {
	if s.cfg.Rootless {
		return group.StoreRootless
	}
	if ca := id.RootCA(); ca != nil && group.KeyStoreOf(ca.Key) == group.StoreFile {
		return group.StoreFile
	}
	return group.KeyStoreOf(id.Key)
}
