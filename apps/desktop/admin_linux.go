// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const deniedText = "No permission to use the service: add your user to the cbb group and log in again."

// userConfirms: the service has polkit confirm admin actions on Linux.
const userConfirms = true

func hideWindow(*exec.Cmd) {}

// runAdmin runs cbb through pkexec, which asks for the password in the
// desktop's own dialog; pkexec passes the arguments as they are, without a
// shell, and clears the environment, so CBB_DEBUG goes through env. input,
// unless empty, is cbb's standard input.
func runAdmin(args []string, input string, details bool) error {
	cbb := cbbPath()
	if cbb == "" {
		return &adminError{msg: "cbb is not installed where the installer puts it, owned by root: install it again, or run the command with sudo in a terminal.",
			detail: "sudo cbb " + strings.Join(args, " ") + "; none of " + strings.Join(cbbPlaces, ", ") + " is a file that root owns and only root may change"}
	}
	pkexec, err := exec.LookPath("pkexec")
	if err != nil {
		return &adminError{msg: "pkexec is not installed: run sudo cbb " + strings.Join(args, " ") + " in a terminal instead.", detail: err.Error()}
	}
	cmd := exec.Command(pkexec, pkexecArgs(cbb, args, details)...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &exit) && exit.ExitCode() == 126:
		// pkexec: the user dismissed the dialog.
		return errCancelled
	case errors.As(err, &exit) && exit.ExitCode() == 127 && out.Len() == 0:
		return &adminError{msg: "Not authorized to run cbb as the administrator.", detail: err.Error()}
	}
	return cbbFailed(out.String(), err.Error())
}

func pkexecArgs(cbb string, args []string, details bool) []string {
	var a []string
	if details {
		a = append(a, "/usr/bin/env", "CBB_DEBUG=1")
	}
	return append(append(a, cbb), args...)
}

// cbbPath is where the installer puts cbb (/opt/cbb on
// SteamOS), the first of them that root owns and only root may change;
// pkexec runs it as root, so cbb is never taken from PATH, where the user's
// own programs come first. It is "" when there is none: a cbb that root
// does not own is never run as root.
func cbbPath() string {
	for _, p := range cbbPlaces {
		if rootOnly(p) {
			return p
		}
	}
	return ""
}

var cbbPlaces = []string{"/usr/local/bin/cbb", "/opt/cbb/bin/cbb"}

// rootOnly tells whether p and the directories above it are owned by root
// and writable by no one else, so that no other user could have put or
// swapped what pkexec runs.
func rootOnly(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	for {
		var st unix.Stat_t
		if unix.Stat(p, &st) != nil || st.Uid != 0 || st.Mode&0o022 != 0 {
			return false
		}
		up := filepath.Dir(p)
		if up == p {
			return true
		}
		p = up
	}
}
