// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/control"
)

const actionUsage = `usage: cbb action                       list this device's quick actions
       cbb action enable NAME [-by root,phone,computer,watch] [-any-key] [-yes]
       cbb action disable NAME
       cbb action add NAME [-by root,phone,computer,watch] [-yes] -- PROGRAM [ARGS...]
       cbb action remove NAME
       cbb action -on DEVICE NAME        on an admin: run NAME on DEVICE
       cbb action off [-on DEVICE | -all]`

// cmdAction shows and sets this device's quick actions, or, on an admin,
// runs one on another device or turns them off there (design.md, "Quick
// actions").
func cmdAction(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "enable", "disable":
			return cmdActionSet(args[0] == "enable", args[1:], stdin, stdout, stderr)
		case "off":
			return cmdActionsOff(args[1:], stdout, stderr)
		case "add":
			return cmdActionAdd(args[1:], stdin, stdout, stderr)
		case "remove":
			return cmdActionRemove(args[1:], stdout, stderr)
		}
	}
	fs := flag.NewFlagSet("action", flag.ContinueOnError)
	fs.SetOutput(stderr)
	on := fs.String("on", "", "the device, by name or ID, to run the action on (on an admin)")
	if fs.Parse(args) != nil {
		return 2
	}
	switch {
	case *on == "" && fs.NArg() == 0:
		return showActions(stdout, stderr)
	case *on == "" || fs.NArg() != 1:
		fmt.Fprintln(stderr, actionUsage)
		return 2
	}
	c, err := control.DialFor(control.OpActionOn)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpActionOn, Device: *on, Name: fs.Arg(0)}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s ran %s.\n", *on, fs.Arg(0))
	return 0
}

func showActions(stdout, stderr io.Writer) int {
	c, err := control.DialFor(control.OpStatus)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err != nil {
		return fail(stderr, err)
	}
	if m.Status == nil || len(m.Status.Actions) == 0 {
		return fail(stderr, errors.New("this device is in no group"))
	}
	for _, a := range m.Status.Actions {
		fmt.Fprintf(stdout, "%-16s %s\n", a.Name, actionLine(a))
	}
	return 0
}

// actionLine says how an action stands and who may run it.
func actionLine(a control.Action) string {
	run := ""
	if len(a.Command) > 0 {
		run = ": " + strings.Join(a.Command, " ")
	}
	if !a.On {
		return "off" + run
	}
	who := "every admin"
	if len(a.By) > 0 {
		who = strings.Join(a.By, ", ")
	}
	if actions.HardwareByDefault(a.Name) && !a.AnyKey {
		who += ", keys in hardware only"
	}
	return "on, for " + who + run
}

// cmdActionSet serves cbb action enable and disable. Enabling asks the
// user first, and on Linux grants the service the right that the preset
// needs, a polkit rule, which needs root; disabling takes the right back.
func cmdActionSet(enable bool, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("action", flag.ContinueOnError)
	fs.SetOutput(stderr)
	by := fs.String("by", "", "with enable: the kinds of admins that may run it, of root, phone and computer (every kind if empty)")
	anyKey := fs.Bool("any-key", false, "with enable: let admins whose keys are in files run reboot and shutdown too")
	yes := fs.Bool("yes", false, "with enable: do not ask")
	if len(args) == 0 {
		fmt.Fprintln(stderr, actionUsage)
		return 2
	}
	name := args[0]
	if fs.Parse(args[1:]) != nil {
		return 2
	}
	if fs.NArg() != 0 || (!enable && (*by != "" || *anyKey || *yes)) {
		fmt.Fprintln(stderr, actionUsage)
		return 2
	}
	kinds, err := actions.ParseKinds(*by)
	if err != nil {
		return fail(stderr, err)
	}
	a := control.Action{Name: name, On: enable, By: kinds, AnyKey: *anyKey}
	if enable && !*yes {
		fmt.Fprint(stdout, actionWarning(a))
		fmt.Fprint(stdout, "Type yes to turn it on: ")
		line, err := readLine(stdin)
		if err != nil || !strings.EqualFold(strings.TrimSpace(line), "yes") {
			fmt.Fprintln(stdout, "Nothing changed.")
			return 1
		}
	}
	st, err := setAction(a)
	if err != nil {
		return fail(stderr, err)
	}
	if path, err := actions.Grant(onActions(st)); err != nil {
		if enable {
			// Without the right the action would only fail; leave it off.
			a.On = false
			setAction(a)
		}
		return fail(stderr, fmt.Errorf("giving the service the right to %s (%s): %w", name, path, err))
	}
	fmt.Fprintf(stdout, "%s: %s.\n", name, actionLine(a))
	return 0
}

func setAction(a control.Action) (*control.Status, error) {
	c, err := control.DialFor(control.OpActionSet)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpActionSet, Actions: []control.Action{a}}})
	if err != nil {
		return nil, err
	}
	return m.Status, nil
}

// onActions lists the actions a status says are on.
func onActions(st *control.Status) []string {
	var on []string
	if st != nil {
		for _, a := range st.Actions {
			if a.On {
				on = append(on, a.Name)
			}
		}
	}
	return on
}

// actionWarning says what turning a on lets the group's admins do, and the
// rights it grants here.
func actionWarning(a control.Action) string {
	what := map[string]string{
		actions.Lock:     "lock this computer's screen",
		actions.Sleep:    "put this computer to sleep",
		actions.Reboot:   "reboot this computer, a minute after they ask",
		actions.Shutdown: "shut this computer down, a minute after they ask",
		actions.Cancel:   "cancel a reboot or shutdown that is pending",
		actions.Restart:  "restart the CBB service here",
	}[a.Name]
	if len(a.Command) > 0 {
		what = "run " + strings.Join(a.Command, " ") + " as the user signed in here"
	}
	who := "the group's admins"
	if len(a.By) > 0 {
		who = "the group's admins of the kinds " + strings.Join(a.By, ", ")
	}
	if actions.HardwareByDefault(a.Name) && !a.AnyKey {
		who += " whose keys are in hardware (phones, computers with the key in a TPM)"
	}
	s := fmt.Sprintf("Turning %s on lets %s %s, from wherever they are in the group.\n", a.Name, who, what)
	if rights := actions.Rights([]string{a.Name}); len(rights) > 0 {
		s += "It gives the CBB service these rights, in a polkit rule, and no others:\n"
		for _, r := range rights {
			s += "  " + r + "\n"
		}
		if os.Geteuid() != 0 {
			s += "Writing the rule needs root: run this with sudo.\n"
		}
	}
	return s + "Any admin can turn it off from afar (cbb action off -on), and only you turn it on again.\n\n"
}

// cmdActionsOff turns every quick action off here, or, on an admin, on
// another device or every device.
func cmdActionsOff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("action off", flag.ContinueOnError)
	fs.SetOutput(stderr)
	on := fs.String("on", "", "on an admin: the device, by name or ID, to turn the actions off on")
	all := fs.Bool("all", false, "on an admin: turn the actions off on every device of the group")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 || (*on != "" && *all) {
		fmt.Fprintln(stderr, actionUsage)
		return 2
	}
	c, err := control.DialFor(control.OpActionOff)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpActionOff, Device: *on, All: *all}})
	if err != nil {
		return fail(stderr, err)
	}
	if *on == "" {
		// The rights go too, when this runs as root here.
		if _, err := actions.Grant(onActions(m.Status)); err != nil && os.Geteuid() == 0 {
			fmt.Fprintf(stderr, "cbb: the actions are off, but the rights stay: %v\n", err)
		}
	}
	switch {
	case *all:
		fmt.Fprintln(stdout, "The quick actions are off on every device of the group.")
	case *on != "":
		fmt.Fprintf(stdout, "The quick actions are off on %s.\n", *on)
	default:
		fmt.Fprintln(stdout, "The quick actions are off here.")
	}
	return 0
}

// cmdActionAdd serves cbb action add: an action of the user's own, a
// program with fixed arguments that the agent runs as the user signed in.
// Nothing from the network reaches its arguments.
func cmdActionAdd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("action add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	by := fs.String("by", "", "the kinds of admins that may run it, of root, phone and computer (every kind if empty)")
	yes := fs.Bool("yes", false, "do not ask")
	if len(args) == 0 {
		fmt.Fprintln(stderr, actionUsage)
		return 2
	}
	name := args[0]
	if fs.Parse(args[1:]) != nil {
		return 2
	}
	command := fs.Args()
	if err := actions.CheckOwn(name, command); err != nil {
		return fail(stderr, err)
	}
	kinds, err := actions.ParseKinds(*by)
	if err != nil {
		return fail(stderr, err)
	}
	a := control.Action{Name: name, On: true, By: kinds, Command: command}
	if !*yes {
		fmt.Fprint(stdout, actionWarning(a))
		fmt.Fprint(stdout, "Type yes to add it: ")
		line, err := readLine(stdin)
		if err != nil || !strings.EqualFold(strings.TrimSpace(line), "yes") {
			fmt.Fprintln(stdout, "Nothing changed.")
			return 1
		}
	}
	if _, err := setAction(a); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s: %s.\n", name, actionLine(a))
	return 0
}

// cmdActionRemove serves cbb action remove.
func cmdActionRemove(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, actionUsage)
		return 2
	}
	c, err := control.DialFor(control.OpActionDel)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpActionDel, Name: args[0]}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "The action %s is removed.\n", args[0])
	return 0
}
