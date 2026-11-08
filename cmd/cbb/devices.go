// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/release"
)

// writeDevices prints the devices list, with the clock of each connected
// peer from peers.
func writeDevices(w io.Writer, devs, peers []control.Device, newest string, now time.Time) {
	if len(devs) == 0 {
		return
	}
	skew := map[string]int64{}
	for _, p := range peers {
		skew[p.ID] = p.SkewMS
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSYSTEM\tVERSION\tROLE\tADMIN\tKEYS\tSYNC\tSEEN\tCLOCK\tID")
	unlisted, old := false, false
	for _, d := range devs {
		name := d.Name
		if d.Self {
			name += " (this device)"
		}
		if !d.Listed {
			name += " *"
			unlisted = true
		}
		admin := ""
		switch {
		case d.Root:
			admin = "root"
		case d.Frozen:
			admin = "frozen"
		case d.Admin:
			admin = "admin"
		}
		clock := ""
		if ms, ok := skew[d.ID]; ok {
			clock = "ok"
			if d := time.Duration(ms) * time.Millisecond; d > 5*time.Second || d < -5*time.Second {
				clock = fmt.Sprintf("off by %v; check its time", d.Round(time.Second))
			}
		}
		// The version and the sync mode, as each device's hello says them.
		ver := d.Version
		if ver != "" && newest != "" && release.Compare(ver, newest) < 0 {
			ver += " (old)"
			old = true
		}
		// A hub says which kind it is: one that only passes the copies on
		// reads none (docs/protocol.md, section 11, "Two kinds of hub").
		role := d.Role
		switch {
		case d.ForwardOnly:
			role += ", hub that only passes copies on"
		case d.Hub:
			role += ", hub"
		}
		mode := map[string]string{"shared": "on", "own": "off"}[d.Mode]
		if d.Muted {
			mode = strings.TrimSpace(mode + " muted")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, group.OSName(d.OS), ver, role, admin, keys(d), mode, seen(d, now), clock, d.ID)
	}
	tw.Flush()
	if unlisted {
		fmt.Fprintln(w, "* not in the devices list yet; the group's root adds it when they meet.")
	}
	if old {
		fmt.Fprintf(w, "(old): below CBB %s, the newest release the group passed around; update it.\n", newest)
	}
}

// keys says where a device's keys live: "in a file" warns that whoever
// copies the file holds them, "rootless" that any program of its user may.
func keys(d control.Device) string {
	switch d.Store {
	case group.StoreProven:
		return "proven hardware"
	case group.StoreHardware:
		return "hardware"
	case group.StoreFile:
		return "in a file"
	case group.StoreRootless:
		return "in a file, rootless"
	}
	return ""
}

// seen says when a device was last seen, in words.
func seen(d control.Device, now time.Time) string {
	switch {
	case d.Online:
		return "online"
	case d.LastSeenMS == 0:
		return "not seen here"
	}
	ago := now.Sub(time.UnixMilli(d.LastSeenMS))
	switch {
	case ago < time.Minute:
		return "just now"
	case ago < time.Hour:
		return fmt.Sprintf("%d min ago", int(ago/time.Minute))
	case ago < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(ago/time.Hour))
	}
	return fmt.Sprintf("%d days ago", int(ago/(24*time.Hour)))
}

// cmdRemove removes a device from the group.
func cmdRemove(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || helpFlag(args[0]) {
		fmt.Fprintln(stderr, "cbb: usage: cbb remove <name or device ID>; cbb status lists them")
		return 2
	}
	c, err := control.DialFor(control.OpRevoke)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpRevoke, Name: args[0]}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Removed %s from the group. The other members refuse it as soon as they hear of it.\n", m.Name)
	return 0
}

// cmdRename gives a device of the group a new name, on an admin.
func cmdRename(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "cbb: usage: cbb rename <name or device ID> <new name>; cbb status lists them")
		return 2
	}
	c, err := control.DialFor(control.OpRename)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpRename, Name: args[0], NewName: args[1]}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Renamed %s to %s. The other devices show the new name as soon as they hear of it.\n", m.Name, strings.TrimSpace(args[1]))
	return 0
}

// cmdTakeoverDelay sets, on the group's root, how long an admin's claim to
// take the group over waits on each member.
func cmdTakeoverDelay(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || helpFlag(args[0]) {
		fmt.Fprintln(stderr, "cbb: usage: cbb takeover -delay <duration>, from 0s to 168h, as 72h")
		return 2
	}
	c, err := control.DialFor(control.OpDelay)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpDelay, Value: args[0]}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "A claim to take the group over now waits %s on each member, from when it first holds the claim.\n", args[0])
	return 0
}

// cmdIncoming shows how long a copy from another device stays live after it
// arrives, or sets it on the group's root or an admin.
func cmdIncoming(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 || len(args) == 1 && helpFlag(args[0]) {
		fmt.Fprintln(stderr, "cbb: usage: cbb incoming [duration], from 5s to 1h, as 1m")
		return 2
	}
	if len(args) == 0 {
		c, err := control.DialFor(control.OpStatus)
		if err != nil {
			return fail(stderr, err)
		}
		defer c.Close()
		m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
		if err != nil {
			return fail(stderr, err)
		}
		if m.Status == nil || m.Status.Group == "" {
			fmt.Fprintln(stderr, "cbb: this device is in no group")
			return 1
		}
		fmt.Fprintln(stdout, incomingLine(time.Duration(m.Status.IncomingMS)*time.Millisecond))
		return 0
	}
	d, err := time.ParseDuration(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "cbb: usage: cbb incoming [duration], from 5s to 1h, as 1m")
		return 2
	}
	c, err := control.DialFor(control.OpIncoming)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpIncoming, Value: args[0]}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, incomingLine(d))
	return 0
}

// incomingLine tells what happens to a copy from another device.
func incomingLine(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return fmt.Sprintf("A copy from another device goes into the clipboard for %s after it arrives; after that this device keeps its own clipboard, however old.", s)
}

// cmdKeys shows the group's key level or sets it on the group's root:
// which keys may be its root, an admin or a hub.
func cmdKeys(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 || len(args) == 1 && helpFlag(args[0]) {
		fmt.Fprintln(stderr, "cbb: usage: cbb keys [proven|hardware|files]")
		return 2
	}
	if len(args) == 0 {
		c, err := control.DialFor(control.OpStatus)
		if err != nil {
			return fail(stderr, err)
		}
		defer c.Close()
		m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
		if err != nil {
			return fail(stderr, err)
		}
		if m.Status == nil || m.Status.Group == "" {
			fmt.Fprintln(stderr, "cbb: this device is in no group")
			return 1
		}
		fmt.Fprintln(stdout, keyLevelLine(m.Status.KeyLevel))
		return 0
	}
	c, err := control.DialFor(control.OpKeyLevel)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpKeyLevel, Value: args[0]}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, keyLevelLine(args[0]))
	if len(m.Below) > 0 {
		fmt.Fprintf(stdout, "Below it: %s. They stay until you remove them (cbb remove) or take back their admin or hub role.\n", strings.Join(m.Below, ", "))
	}
	return 0
}

// keyLevelLine tells what the group's key level lets in.
func keyLevelLine(level string) string {
	switch level {
	case "proven":
		return "Key level proven: only keys that attestation proves are in hardware may be the group's root, an admin or a hub."
	case "hardware":
		return "Key level hardware: only keys in hardware (a TPM, the Secure Enclave, a phone's keystore) may be the group's root, an admin or a hub."
	case "files":
		return "Key level files: keys in files may be the group's root, an admin or a hub too, each after a warning."
	}
	return ""
}

// cmdHubs sets the group's main hubs, in the order they serve.
func cmdHubs(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || len(args) == 1 && helpFlag(args[0]) {
		fmt.Fprintln(stderr, "cbb: usage: cbb global hubs <name or ID>..., the group's main hubs in the order they serve")
		return 2
	}
	c, err := control.DialFor(control.OpHubs)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpHubs, Hubs: args}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "The group's main hubs are now %s, in this order; the other hubs serve after them.\n", strings.Join(args, ", "))
	return 0
}

// helpFlag reports whether a command's only argument asks for its usage,
// which no device's name or ID can be taken for.
func helpFlag(arg string) bool {
	return arg == "-h" || arg == "-help" || arg == "--help"
}

// cmdFreeze freezes (on true) or unfreezes an admin computer.
func cmdFreeze(args []string, on bool, stdout, stderr io.Writer) int {
	op, cmd := control.OpFreeze, "freeze"
	if !on {
		op, cmd = control.OpThaw, "unfreeze"
	}
	if len(args) != 1 || helpFlag(args[0]) {
		fmt.Fprintf(stderr, "cbb: usage: cbb %s <name or device ID>; cbb status lists them\n", cmd)
		return 2
	}
	c, err := control.DialFor(op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: op, Name: args[0]}})
	if err != nil {
		return fail(stderr, err)
	}
	if on {
		fmt.Fprintf(stdout, "Froze %s: it is no admin and the members refuse it as soon as they hear of it.\n"+
			"The group's root or an admin phone unfreezes it (cbb unfreeze) or removes it (cbb remove).\n", m.Name)
	} else {
		fmt.Fprintf(stdout, "Unfroze %s: it is an admin again.\n", m.Name)
	}
	return 0
}

// cmdAdmin makes a device an admin of the group, on the group's root.
func cmdAdmin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	allow := fs.Bool("allow-file-key", false, "make it an admin although its keys sit in a file")
	if fs.Parse(args) != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "cbb: usage: cbb admin [-allow-file-key] <name or device ID>; cbb status lists them")
		return 2
	}
	args = fs.Args()
	c, err := control.DialFor(control.OpAdmin)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpAdmin, Name: args[0], Consent: *allow}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s is an admin now: it can admit and remove devices.\n", m.Name)
	if *allow {
		fmt.Fprintf(stdout, "If it keeps its keys in a file, guard it: whoever copies that file acts as an admin until another admin removes %s.\n", m.Name)
	}
	return 0
}

// cmdTakeover takes the group over from its lost root computer, on an
// admin.
func cmdTakeover(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "-delay" {
		return cmdTakeoverDelay(args[1:], stdout, stderr)
	}
	if len(args) != 1 || helpFlag(args[0]) {
		fmt.Fprintln(stderr, "cbb: usage: cbb takeover <name or device ID of the lost root>; cbb status shows it")
		return 2
	}
	c, err := control.DialFor(control.OpTakeover)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpTakeover, Name: args[0]}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Claimed the group from %s. This device becomes its root when the waiting time ends (72 hours unless the root set another), unless the root cancels the claim; cbb status shows the time left.\n", m.Name)
	fmt.Fprintln(stdout, "Then it removes the old root.")
	return 0
}

// cmdResolve, on the group's root, voids both histories of every key that
// signed two.
func cmdResolve(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "cbb: usage: cbb resolve; on the group's root, it voids both histories of every key that signed two (cbb status shows them)")
		return 2
	}
	c, err := control.DialFor(control.OpResolve)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpResolve}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Voided both histories of %s: each goes on from the record before them, and signs again what it still needs.\n"+
		"Check that the group's devices are the ones you expect (cbb status): records signed with a stolen key are gone too.\n", m.Name)
	return 0
}
