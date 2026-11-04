// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/release"
)

// entriesPrefix starts the string that carries the signed entry points
// from one device to another (docs/protocol.md, section 16, "Entry
// points").
const entriesPrefix = "cbb-entries:"

// cmdGlobalEntries shows the signed entry points this device holds, gives
// them as a string or a QR code for another device, or takes them from one.
func cmdGlobalEntries(args []string, stdout, stderr io.Writer) int {
	usage := "usage: cbb global entries               show the signed entry points of the project's servers\n" +
		"       cbb global entries export [-qr]   give them as a string, or a QR code, for another device\n" +
		"       cbb global entries import STRING  take them from another device's string"
	switch {
	case len(args) == 0:
		set, err := heldEntries()
		if err != nil {
			return fail(stderr, err)
		}
		var e release.Entries
		if err := json.Unmarshal(set.Entries.Body, &e); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "Signed entry points %d, valid until %s:\n", e.Seq, time.UnixMilli(e.ExpiresMS).UTC().Format(time.DateOnly))
		for _, f := range e.Forwarders {
			fmt.Fprintf(stdout, "  the forwarder %s\n", f.Name)
			for _, v := range f.VLESS {
				fmt.Fprintf(stdout, "    over VLESS: XHTTP at %s, port %d, %s\n", v.ServerName, v.Port, v.Path)
			}
		}
		return 0
	case args[0] == "export" && (len(args) == 1 || len(args) == 2 && args[1] == "-qr"):
		set, err := heldEntries()
		if err != nil {
			return fail(stderr, err)
		}
		text, err := entriesString(set)
		if err != nil {
			return fail(stderr, err)
		}
		if len(args) == 2 {
			if err := writeQR(stdout, text); err != nil {
				return fail(stderr, fmt.Errorf("%w; cbb global entries export gives them as a string", err))
			}
			return 0
		}
		fmt.Fprintln(stdout, text)
		return 0
	case args[0] == "import" && len(args) == 2:
		set, err := parseEntries(args[1])
		if err != nil {
			return fail(stderr, err)
		}
		data, err := json.Marshal(set)
		if err != nil {
			return fail(stderr, err)
		}
		c, err := control.DialFor(control.OpEntries)
		if err != nil {
			return fail(stderr, err)
		}
		defer c.Close()
		if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpEntries}, Payload: data}); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintln(stdout, "The signed entry points check out; this device keeps the newest it has and passes them to its group.")
		return 0
	}
	fmt.Fprintln(stderr, usage)
	return 2
}

func heldEntries() (node.EntriesSet, error) {
	var set node.EntriesSet
	c, err := control.DialFor(control.OpEntriesGet)
	if err != nil {
		return set, err
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpEntriesGet}})
	if err != nil {
		return set, err
	}
	return set, json.Unmarshal(m.Payload, &set)
}

// entriesString writes the signed entry points as a string: the prefix and
// their JSON in unpadded base64url.
func entriesString(set node.EntriesSet) (string, error) {
	data, err := json.Marshal(set)
	if err != nil {
		return "", err
	}
	return entriesPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// parseEntries reads such a string; the service checks the signatures.
func parseEntries(s string) (node.EntriesSet, error) {
	var set node.EntriesSet
	b64, ok := strings.CutPrefix(strings.TrimSpace(s), entriesPrefix)
	if !ok {
		return set, errors.New("that is not a string of signed entry points; it starts with " + entriesPrefix)
	}
	data, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(data) > 2*release.MaxBody {
		return set, errors.New("the string of signed entry points is damaged")
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return set, errors.New("the string of signed entry points is damaged")
	}
	return set, nil
}
