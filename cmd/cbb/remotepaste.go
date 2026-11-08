// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
)

// cmdPasteOn has another member put a text where its focus is (design.md,
// "Remote paste"): standard input, or this member's clipboard when standard
// input is a terminal. With files, or -copy, it pastes images or files
// instead: the files, copied to the group first, or the group's current
// copy of images or files.
func cmdPasteOn(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("paste", flag.ContinueOnError)
	fs.SetOutput(stderr)
	on := fs.String("on", "", "the device, by name or ID, to paste on (on an admin)")
	typed := fs.Bool("type", false, "type the text key by key instead of pasting it (at most 4 KiB)")
	enter := fs.Bool("enter", false, "press Enter after the text, where the device's user allowed it")
	secret := fs.Bool("secret", false, "send the text as a secret: not logged, and the clipboard there is cleared after")
	image := fs.Bool("image", false, "paste the one file given, a PNG or JPEG, as an image rather than as a file")
	current := fs.Bool("copy", false, "paste the group's current copy of images or files")
	if fs.Parse(args) != nil {
		return 2
	}
	if *on == "" || (fs.NArg() > 0 || *current || *image) && (*typed || *secret) || *current && fs.NArg() > 0 || *image && fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: cbb paste -on DEVICE [-type] [-enter] [-secret] < text\n       cbb paste -on DEVICE [-enter] [-image] FILE...\n       cbb paste -on DEVICE [-enter] -copy")
		return 2
	}
	h := control.Header{Op: control.OpPasteOn, Device: *on, Method: group.PasteByClipboard, Enter: *enter, Kind: control.KindText}
	if fs.NArg() > 0 || *current {
		return pasteCopyOn(h, fs.Args(), *image, stdout, stderr)
	}
	if *typed {
		h.Method = group.PasteByTyping
	}
	if *secret {
		h.Kind = control.KindSecret
	}
	var text []byte
	if f, ok := stdin.(*os.File); ok && isTerminal(f) {
		c, err := control.DialFor(control.OpPaste)
		if err != nil {
			return fail(stderr, err)
		}
		m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPaste}})
		c.Close()
		if err != nil {
			return fail(stderr, err)
		}
		text = m.Payload
		if m.Kind == control.KindSecret {
			h.Kind = control.KindSecret
		}
	} else {
		var err error
		if text, err = io.ReadAll(io.LimitReader(stdin, maxText+1)); err != nil {
			return fail(stderr, err)
		}
		if len(text) > maxText {
			return fail(stderr, errors.New("the text is larger than 1 MiB"))
		}
	}
	if *typed && len(text) > group.MaxTypeText {
		return fail(stderr, fmt.Errorf("the text is longer than %d bytes, too long to type; paste it without -type", group.MaxTypeText))
	}
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: h, Payload: text}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Pasted on %s.\n", *on)
	return 0
}

// isTerminal reports whether f is a terminal rather than a pipe or a file.
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// cmdPasteReceive shows or sets remote paste on this device, or, on an
// admin, turns it off on another device or every device.
func cmdPasteReceive(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("paste-receive", flag.ContinueOnError)
	fs.SetOutput(stderr)
	enter := fs.Bool("enter", false, "with on: let a paste press Enter")
	console := fs.Bool("console", false, "with on: let pastes reach text consoles and root's tmux")
	noLockCheck := fs.Bool("no-lock-check", false, "with on: paste also where nothing tells whether the session is locked")
	on := fs.String("on", "", "with off, on an admin: the device, by name or ID, to turn remote paste off on")
	all := fs.Bool("all", false, "with off, on an admin: turn remote paste off on every device of the group")
	// on or off comes first, as the usage shows; before the flags, it
	// would end them.
	name := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if fs.Parse(args) != nil {
		return 2
	}
	usage := "usage: cbb paste-receive [on [-enter] [-console] [-no-lock-check] | off [-on DEVICE | -all]]"
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if fs.NArg() > 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	h := control.Header{Op: control.OpStatus}
	if name != "" {
		h = control.Header{Op: control.OpReceive, Name: name, Enter: *enter, Console: *console, NoLockCheck: *noLockCheck, Device: *on, All: *all}
	} else if *enter || *console || *noLockCheck || *on != "" || *all {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h})
	if err != nil {
		return fail(stderr, err)
	}
	switch {
	case *all:
		fmt.Fprintln(stdout, "Remote paste is off on every device of the group.")
		return 0
	case *on != "":
		fmt.Fprintf(stdout, "Remote paste is off on %s.\n", *on)
		return 0
	}
	if m.Status == nil || m.Status.Paste == nil {
		return fail(stderr, errors.New("this device is in no group"))
	}
	fmt.Fprintln(stdout, pasteLine(m.Status.Paste))
	return 0
}

// pasteLine says how remote paste stands on this device.
func pasteLine(p *control.Paste) string {
	if !p.On {
		return "Remote paste is off: the group's admins cannot paste here."
	}
	line := "Remote paste is on: the group's admins may paste here"
	switch {
	case p.Enter && p.Console:
		line += ", press Enter, and reach text consoles."
	case p.Enter:
		line += " and press Enter."
	case p.Console:
		line += " and reach text consoles, without Enter."
	default:
		line += ", without Enter."
	}
	if p.NoLockCheck {
		line += " It pastes also where nothing tells whether the session is locked."
	}
	if len(p.Targets) == 0 {
		return line + " Nothing here can paste yet: the desktop connector, the Mac app or the tmux and console helpers do it."
	}
	return line
}

// pasteCopyOn has the member that h names paste images or files: paths,
// copied to the group first, as an image with image, or else the group's
// current copy.
func pasteCopyOn(h control.Header, paths []string, image bool, stdout, stderr io.Writer) int {
	if len(paths) > 0 {
		typ := ""
		if image {
			ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(paths[0])), ".")
			if ext != "png" && ext != "jpg" && ext != "jpeg" {
				return fail(stderr, fmt.Errorf("-image takes a .png or .jpg file, not %s", paths[0]))
			}
			typ = ext
		}
		if code := copyMedia(paths, typ, "", stdout, stderr); code != 0 {
			return code
		}
	}
	h.Kind = control.KindMedia
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: h}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Pasted on %s.\n", h.Device)
	return 0
}
