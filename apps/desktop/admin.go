// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// What changes the group goes to the service's admin socket, which only the
// administrator reaches. Where the service has the system confirm the
// action instead (polkit on Linux: once for five minutes, or each time for
// what cannot be undone; docs/design.md, "Confirming admin actions"), the
// app runs cbb as the user; otherwise, and where cbb needs root itself, it
// runs cbb as the administrator after the system asks: pkexec on Linux, the
// UAC prompt on Windows (admin_linux.go, admin_windows.go).

// adminRun runs cbb for an admin action; the window's tests put a stand-in
// here.
var adminRun = runConfirmed

// cbb's exit codes (member/src/confirm.rs): the user cancelled the prompt;
// nothing here confirms the action for this user, so it takes the
// administrator.
const (
	cancelledExit  = 75
	needsAdminExit = 77
)

// errNeedsAdmin is an action the service could not have confirmed.
var errNeedsAdmin = errors.New("needs the administrator")

// runConfirmed runs cbb as the user where the system confirms admin
// actions, and as the administrator where it does not, or cbb needs root.
func runConfirmed(args []string, input string, details bool) error {
	if userConfirms && !needsRoot(args) {
		if err := runAsUser(cbbPath(), args, input, details); !errors.Is(err, errNeedsAdmin) {
			return err
		}
	}
	return runAdmin(args, input, details)
}

// needsRoot tells the commands where cbb itself needs root: installing an
// update, and joining a group, where cbb writes the service's files.
func needsRoot(args []string) bool {
	return len(args) > 0 && (args[0] == "update" || args[0] == "pair" && slices.Contains(args, "-app"))
}

// runAsUser runs cbb as the user, which reaches the service's control
// socket; the service has the system confirm the action.
func runAsUser(cbb string, args []string, input string, details bool) error {
	if cbb == "" {
		return errNeedsAdmin
	}
	cmd := exec.Command(cbb, args...)
	cmd.Env = append(os.Environ(), "CBB_DEBUG="+map[bool]string{true: "1", false: "0"}[details])
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	hideWindow(cmd)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	return userResult(cmd.Run(), out.String())
}

// userResult is what a run of cbb as the user ended with.
func userResult(err error, output string) error {
	var exit *exec.ExitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &exit) && exit.ExitCode() == cancelledExit:
		return errCancelled
	case errors.As(err, &exit) && exit.ExitCode() == needsAdminExit:
		return errNeedsAdmin
	}
	return cbbFailed(output, err.Error())
}

// errCancelled is a prompt the user closed: nothing changed, and the
// window says nothing.
var errCancelled = errors.New("cancelled")

// An adminError is cbb failing: its last line for the user, all it printed
// underneath.
type adminError struct{ msg, detail string }

func (e *adminError) Error() string { return e.msg }

// cbbFailed makes the error of a cbb run from what it printed.
func cbbFailed(output, fallback string) *adminError {
	out := strings.TrimSpace(strings.ReplaceAll(output, "\r\n", "\n"))
	msg := fallback
	if out != "" {
		lines := strings.Split(out, "\n")
		msg = strings.TrimPrefix(strings.TrimSpace(lines[len(lines)-1]), "cbb: ")
	}
	return &adminError{msg: msg, detail: out}
}
