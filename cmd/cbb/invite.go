// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/invite"
)

// defaultInviteFile is where cbb invite writes the invitation unless told
// otherwise.
const defaultInviteFile = "cbb" + invite.Ext

// cmdInvite makes a remote invitation on the group's hub, writes it to a
// file, and asks the user to confirm the device that uses it.
func cmdInvite(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	fs.SetOutput(stderr)
	valid := fs.Duration("for", invite.DefaultLifetime, "how long the invitation is valid, at most 24h")
	out := fs.String("o", defaultInviteFile, "the file to write the invitation to")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 || *valid <= 0 || *valid > invite.MaxLifetime {
		fmt.Fprintln(stderr, "usage: cbb invite [-for 1h] [-o file]   (valid for up to 24h)")
		return 2
	}
	c, err := control.DialFor(control.OpInvite)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpInvite, Expires: int(*valid / time.Second)}})
	if err != nil {
		return fail(stderr, err)
	}
	// The file is a secret until it is used: only its owner reads it, and
	// it never replaces another file.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		_, err = fmt.Fprintln(f, m.Invite)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return fail(stderr, fmt.Errorf("writing the invitation: %w", err))
	}
	defer os.Remove(*out)
	// Ctrl+C, or a stop, ends the process before the deferred removal
	// runs: the invitation goes with the connection, and the file here.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		os.Remove(*out)
		fmt.Fprintln(stdout, "\nThe invitation is cancelled and its file deleted.")
		os.Exit(130)
	}()
	until := time.Now().Add(time.Duration(m.Expires) * time.Second)
	fmt.Fprintf(stdout, "The invitation is in %s, valid until %s.\n\n", *out, until.Format("15:04 on Jan 2"))
	fmt.Fprintln(stdout, "Copy it to the new device only through a channel you trust: until it is used,")
	fmt.Fprintln(stdout, "whoever has it can ask to join. On the new device run:")
	fmt.Fprintf(stdout, "\n  cbb pair -invite %s\n\n", *out)
	fmt.Fprintln(stdout, "You confirm the device here before it is admitted. Keep this running; Ctrl+C")
	fmt.Fprintln(stdout, "cancels the invitation, and the file is deleted when it ends.")
	for {
		m, err := c.Receive()
		if err != nil {
			return fail(stderr, err)
		}
		if m.Done {
			fmt.Fprintf(stdout, "%s joined the group.\n", m.Name)
			return 0
		}
		if m.Joining == nil {
			continue
		}
		j := m.Joining
		fmt.Fprintf(stdout, "\n%s (%s, device %s) used the invitation.\n", j.Name, osName(j.OS), j.ID)
		fmt.Fprintf(stdout, "Its key fingerprint:  %s\n", shortFingerprint(j.Fingerprint))
		fmt.Fprintln(stdout, "The new device shows its fingerprint too; admit it only if they are the same.")
		fmt.Fprint(stdout, "Admit it? Type yes to admit: ")
		line, err := readLine(stdin)
		yes := err == nil && strings.EqualFold(strings.TrimSpace(line), "yes")
		if err := c.Send(&control.Message{Header: control.Header{Op: control.OpAnswer, Consent: yes}}); err != nil {
			return fail(stderr, err)
		}
		if !yes {
			fmt.Fprintln(stdout, "Not admitted. The invitation stays open for another attempt.")
		}
	}
}

// osName names a joining device's system for the user.
func osName(os string) string { return group.OSName(os) }

// cmdJoinInvite joins with a remote invitation from the file at path.
func cmdJoinInvite(path string, stdin io.Reader, stdout, stderr io.Writer) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return fail(stderr, err)
	}
	in, err := invite.Parse(string(data))
	if err != nil {
		return fail(stderr, err)
	}
	if time.Now().After(in.Expires) {
		return fail(stderr, errors.New("the invitation has expired; ask for a new one"))
	}
	if err := checkAwayNet(); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "A device that joins with an invitation syncs away from home through the")
	fmt.Fprint(stdout, "group's hub, so sync away from home is turned on here.\n\n")
	fmt.Fprint(stdout, keysWarning)
	fmt.Fprint(stdout, "Type yes to join and turn sync away from home on: ")
	line, err := readLine(stdin)
	if err != nil {
		return fail(stderr, err)
	}
	if !strings.EqualFold(strings.TrimSpace(line), "yes") {
		fmt.Fprintln(stdout, "Nothing changed.")
		return 1
	}
	// The join reaches the hub on the internet, so the service must be
	// allowed to reach its addresses before it starts; a failed join takes
	// that back again.
	g := grant{on: true}
	for _, ep := range in.Endpoints {
		if a := ep.Addr().Unmap(); !slices.Contains(g.addrs, a) {
			g.addrs = append(g.addrs, a)
		}
	}
	slices.SortFunc(g.addrs, netip.Addr.Compare)
	before := granted(g)
	opened, _, err := setAwayNet(g)
	if err != nil {
		return fail(stderr, err)
	}
	var joined atomic.Bool
	takeBack := func() {
		if _, _, err := setAwayNet(before); err != nil {
			fmt.Fprintf(stderr, "cbb: the service may still reach the hub's addresses: %v\n", err)
		}
	}
	if opened {
		defer func() {
			if !joined.Load() {
				takeBack()
			}
		}()
	}
	// Ctrl+C gives up: the service ends the join when this connection
	// closes, and the hub's addresses are taken back here, which the
	// deferred call would not do once the signal ends the process.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		if !joined.Load() {
			if opened {
				takeBack()
			}
			fmt.Fprintln(stdout, "\nGave up; this device did not join.")
		}
		os.Exit(130)
	}()
	// The join changes the group: it goes to the admin socket.
	c, err := waitService(control.OpJoin)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Invite: strings.TrimSpace(string(data)), Consent: true}})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "\nThis device's key fingerprint:  %s\n", shortFingerprint(m.Fingerprint))
	fmt.Fprintln(stdout, "Whoever invited you sees it on the hub and admits this device if it matches.")
	fmt.Fprintln(stdout, "Waiting for them; press Ctrl+C to give up.")
	if _, err := c.Receive(); err != nil {
		return fail(stderr, err)
	}
	joined.Store(true)
	// It is used up, and was a secret; nothing needs it any more.
	os.Remove(path)
	// The group's servers as the service knows them now that it joined. Until
	// it has heard them, the invitation's addresses stay allowed: they are
	// how it reaches the hub to hear them at all.
	if !confined() {
		// Nothing limits where the service goes.
	} else if st, err := statusNow(); err != nil {
		fmt.Fprintf(stderr, "cbb: cannot ask the service for the group's servers: %v; %s\n", err, allowHint)
	} else if a := waitServers(st.Away); !knowsServers(a) {
		fmt.Fprintf(stdout, "The service may reach the invitation's addresses until it hears the group's servers; once cbb status shows the hub, %s.\n", allowHint)
	} else if err := applyGrant(stdout, grantFor(a)); err != nil {
		fmt.Fprintf(stderr, "cbb: the service's network did not follow the group's servers: %v; %s\n", err, allowHint)
	}
	fmt.Fprintln(stdout, "Joined the group. It syncs through the group's hub wherever this device is;")
	fmt.Fprintln(stdout, "cbb global shows how. The invitation file is deleted.")
	return 0
}

// statusNow asks the service for its status on a connection of its own.
func statusNow() (*control.Status, error) {
	c, err := control.DialFor(control.OpStatus)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err != nil {
		return nil, err
	}
	if m.Status == nil {
		return nil, errors.New("the service sent no status")
	}
	return m.Status, nil
}
