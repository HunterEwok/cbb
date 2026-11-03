// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/HunterEwok/cbb/internal/control"
)

// remoteUsage is cbb remote's usage.
const remoteUsage = "usage: cbb remote [add [-appletv | -roku -consent] [-name NAME] ADDRESS | code CODE | cancel | remove TV | pastes TV on|off | type [-tv TV] [TEXT]]"

// cmdRemote shows the TVs this device is the remote of, pairs with one,
// sends the remote pastes to one, or types a text on one.
func cmdRemote(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("remote", flag.ContinueOnError)
	fs.SetOutput(stderr)
	isRoku := fs.Bool("roku", false, "with add: the TV is a Roku, typed on over plain HTTP")
	isApple := fs.Bool("appletv", false, "with add: the TV is an Apple TV, paired with the PIN it shows")
	consent := fs.Bool("consent", false, "with add -roku: agree that the text crosses the home network unencrypted")
	name := fs.String("name", "", "with add: the TV's name here, the one it gives if not set")
	tv := fs.String("tv", "", "with type: the TV, if there are several")
	// Flags may come before, between and after the words.
	var words []string
	for {
		if fs.Parse(args) != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		words = append(words, fs.Arg(0))
		args = fs.Args()[1:]
	}
	var verb string
	var rest []string
	if len(words) > 0 {
		verb, rest = words[0], words[1:]
	}
	h := control.Header{Op: control.OpRemote, Name: verb}
	var payload []byte
	usage := func() int {
		fmt.Fprintln(stderr, remoteUsage)
		return 2
	}
	if verb != "add" && (*isRoku || *isApple || *consent || *name != "") || verb != "type" && *tv != "" || *isRoku && *isApple {
		return usage()
	}
	switch verb {
	case "":
		if len(rest) != 0 {
			return usage()
		}
	case "add":
		if len(rest) != 1 {
			return usage()
		}
		h.Address, h.NewName, h.Consent = rest[0], *name, *consent
		switch {
		case *isRoku:
			h.Value = "roku"
		case *isApple:
			h.Value = "appletv"
		}
	case "code":
		if len(rest) != 1 {
			return usage()
		}
		h.Code = rest[0]
	case "cancel":
		if len(rest) != 0 {
			return usage()
		}
	case "remove":
		if len(rest) != 1 {
			return usage()
		}
		h.Device = rest[0]
	case "pastes":
		if len(rest) != 2 || rest[1] != "on" && rest[1] != "off" {
			return usage()
		}
		h.Device, h.Value = rest[0], rest[1]
	case "type":
		h.Device = *tv
		switch len(rest) {
		case 0:
			b, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
			if err != nil {
				return fail(stderr, err)
			}
			payload = []byte(strings.TrimSuffix(string(b), "\n"))
		case 1:
			payload = []byte(rest[0])
		default:
			return usage()
		}
	default:
		return usage()
	}
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h, Payload: payload})
	if err != nil {
		return fail(stderr, err)
	}
	if verb == "type" {
		fmt.Fprintln(stdout, "Typed.")
		return 0
	}
	var tvs []control.TV
	if m.Status != nil {
		tvs = m.Status.TVs
	}
	if verb == "add" && *isApple {
		fmt.Fprintln(stdout, "The Apple TV shows a PIN now: run cbb remote code PIN with it within two minutes.")
		return 0
	}
	if verb == "add" && !*isRoku {
		fmt.Fprintln(stdout, "The TV shows a code now: run cbb remote code CODE with it within two minutes.")
		return 0
	}
	fmt.Fprint(stdout, remoteLines(tvs))
	return 0
}

// remoteLines lists the TVs.
func remoteLines(tvs []control.TV) string {
	if len(tvs) == 0 {
		return "This device is the remote of no TV: cbb remote add ADDRESS pairs with an Android TV or a Google TV, cbb remote add -appletv ADDRESS with an Apple TV, cbb remote add -roku -consent ADDRESS takes a Roku.\n"
	}
	var w strings.Builder
	for _, t := range tvs {
		kind := "Android TV"
		switch t.Kind {
		case "roku":
			kind = "Roku, plain HTTP"
		case "appletv":
			kind = "Apple TV"
		}
		switch {
		case t.Pairing:
			what := "a code"
			if t.Kind == "appletv" {
				what = "a PIN"
			}
			fmt.Fprintf(&w, "Pairing with the TV at %s: it shows %s for cbb remote code.\n", t.Host, what)
		case t.Pastes:
			fmt.Fprintf(&w, "%s (%s) at %s: remote pastes go to it.\n", t.Name, kind, t.Host)
		default:
			fmt.Fprintf(&w, "%s (%s) at %s.\n", t.Name, kind, t.Host)
		}
	}
	return w.String()
}
