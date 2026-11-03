// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/HunterEwok/cbb/internal/control"
)

// maxSheetText bounds what cbb recovery reads: the QR code's text with its
// admin CA fits well within it, as the core's own limit.
const maxSheetText = 4096

// cmdRecovery claims the group with its recovery key, on a computer of the
// group whose root phone is lost: it reads the sheet's key, or the text of
// its QR code, from the standard input, never from the command line, which
// other users and the shell's history see. With -yubikey the key is on a
// YubiKey, and it reads the YubiKey's PIN instead; the service signs the
// claim on the YubiKey, which may ask for a touch.
func cmdRecovery(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := "cbb: usage: cbb recovery [-yubikey], then type the recovery key from the sheet (or paste its QR code's text), or with -yubikey the YubiKey's PIN; cbb status shows the claim"
	h := control.Header{Op: control.OpRecovery, Kind: control.KindSecret}
	switch {
	case len(args) == 1 && (args[0] == "-yubikey" || args[0] == "--yubikey"):
		h.Name = control.RecoveryCard
	case len(args) != 0:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	f, _ := stdin.(*os.File)
	terminal := f != nil && isTerminal(f)
	var text string
	if h.Name == control.RecoveryCard {
		if terminal {
			fmt.Fprint(stderr, "Plug in the YubiKey with the group's recovery key, then type its PIN and press Enter: ")
		}
		pin, err := readSecretLine(f, stdin, terminal, 64)
		if terminal {
			fmt.Fprintln(stderr)
		}
		if err != nil {
			return fail(stderr, err)
		}
		if text = pin; text == "" {
			fmt.Fprintln(stderr, "cbb: no PIN was typed")
			return 2
		}
	} else {
		if terminal {
			fmt.Fprintln(stderr, "Type the recovery key from the sheet, in groups of four, or paste the text of its QR code, then press Enter:")
		}
		line, err := bufio.NewReaderSize(io.LimitReader(stdin, maxSheetText+1), maxSheetText+1).ReadString('\n')
		if err != nil && err != io.EOF {
			return fail(stderr, err)
		}
		text = strings.TrimSpace(line)
		switch {
		case len(line) > maxSheetText:
			fmt.Fprintln(stderr, "cbb: that is too long for a recovery key")
			return 2
		case text == "":
			fmt.Fprintln(stderr, "cbb: no recovery key was typed")
			return 2
		}
	}
	c, err := control.DialFor(control.OpRecovery)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if h.Name == control.RecoveryCard && terminal {
		fmt.Fprintln(stderr, "Touch the YubiKey when it blinks.")
	}
	if _, err := c.Do(&control.Message{Header: h, Payload: []byte(text)}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "Claimed the group with its recovery key. This device becomes the group's root when the waiting time ends (72 hours unless the root set another), unless the root phone cancels the claim; cbb status shows the time left.")
	fmt.Fprintln(stdout, "Then a new phone joins it (cbb pair), and cbb handover gives that phone the group at once.")
	return 0
}

// readSecretLine reads one line from stdin, without echo when it is the
// terminal f, at most limit bytes.
func readSecretLine(f *os.File, stdin io.Reader, terminal bool, limit int) (string, error) {
	if terminal {
		b, err := term.ReadPassword(int(f.Fd()))
		if len(b) > limit {
			return "", fmt.Errorf("that is longer than %d characters", limit)
		}
		return strings.TrimSpace(string(b)), err
	}
	line, err := bufio.NewReaderSize(io.LimitReader(stdin, int64(limit)+1), limit+1).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	if len(line) > limit {
		return "", fmt.Errorf("that is longer than %d characters", limit)
	}
	return strings.TrimSpace(line), nil
}

// cmdHandover hands the group to an admin, on the root: its claim then
// takes effect at once.
func cmdHandover(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || helpFlag(args[0]) {
		fmt.Fprintln(stderr, "cbb: usage: cbb handover <name or device ID of an admin>; on the group's root, it lets that admin take the group over at once")
		return 2
	}
	c, err := control.DialFor(control.OpHandover)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpHandover, Name: args[0]}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Handed the group over to %s: when it claims the group, its claim takes effect at once and it becomes the root.\n", m.Name)
	return 0
}
