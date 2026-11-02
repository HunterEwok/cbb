// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/version"
)

// keysWarning is what a user agrees to before a device whose keys sit in
// files syncs away from home (docs/design.md, "Turning it on, step by
// step").
const keysWarning = `Sync away from home lets this device reach the group's hub from the internet,
through the group's own WireGuard tunnel, with the clipboard encrypted end to end.

This device keeps its keys in files, not in a security chip. Whoever copies those
files (with root on this device, from its disk or memory card, or from an
unencrypted backup) can act as this device from anywhere until you remove it from
the group. To keep that from happening:

  - encrypt the disk (LUKS, BitLocker, FileVault);
  - keep the service's state directory out of unencrypted backups;
  - remove the device at once (cbb revoke, or Remove on the phone) when it is lost
    or someone else may have had root on it.

`

// relayNotice says what a blind relay learns, before the user agrees to
// meet there (docs/design.md, "Blind relay").
const relayNotice = `A blind relay is a meeting point for the devices of a group that has no hub of its own.
The clipboard stays encrypted end to end between the devices: the relay cannot read it
or pose as a device. It does learn, while the devices use it:

  - which devices of the group are online, and their internet addresses;
  - which of them talk to each other, when, and how much they send.

A hub of the group's own lets none of this out. Use a relay you run yourself, or one
whose operator you trust with this; the project's relay keeps none of it in logs.

`

// cmdGlobal shows or changes sync away from home on this device.
func cmdGlobal(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := "usage: cbb global                     show sync away from home\n" +
		"       cbb global on                  turn it on here\n" +
		"       cbb global off [-yes]          turn it off here and forget its keys\n" +
		"       cbb global off -on DEVICE      on an admin: turn it off on another device, whose own user\n" +
		"                                      turns it on again\n" +
		"       cbb global hub [-port N] [-firewall ask|yes|no] [-obfuscate] [-forwarder address:port -forwarder-key KEY [-vless]] [address:port...]\n" +
		"                                      make this device the group's hub, reached at these addresses\n" +
		"                                      or through the forwarder; -obfuscate for networks that block WireGuard,\n" +
		"                                      -vless for clients that reach the forwarder only over VLESS\n" +
		"       cbb global move DEVICE [-forwarder address:port -forwarder-key KEY] [address:port...]\n" +
		"                                      on the hub: make DEVICE, an admin computer with sync away from\n" +
		"                                      home on, the hub in its place, reached through this hub's\n" +
		"                                      forwarder unless others are given; its clients move with it\n" +
		"       cbb global relay address:port -key KEY [-yes]\n" +
		"                                      meet the group's other devices at a blind relay, for a group\n" +
		"                                      without a hub\n" +
		"       cbb global allow               let this computer's service reach the group's servers as they\n" +
		"                                      are now, after the hub's addresses changed"
	if len(args) == 0 {
		return cmdGlobalStatus(stdout, stderr)
	}
	h := control.Header{Op: control.OpAway, Name: args[0]}
	firewall := "ask"
	switch args[0] {
	case "on":
		if len(args) != 1 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		if err := checkAwayNet(); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprint(stdout, keysWarning)
		fmt.Fprint(stdout, "Type yes to turn sync away from home on: ")
		line, err := readLine(stdin)
		if err != nil {
			return fail(stderr, err)
		}
		if !strings.EqualFold(strings.TrimSpace(line), "yes") {
			fmt.Fprintln(stdout, "Nothing changed.")
			return 1
		}
		h.Consent = true
	case "off":
		fs := flag.NewFlagSet("global off", flag.ContinueOnError)
		fs.SetOutput(stderr)
		yes := fs.Bool("yes", false, "turn it off without asking, even where it cuts this device off (for scripts)")
		on := fs.String("on", "", "on an admin: the device, by name or ID, to turn it off on")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		if fs.NArg() != 0 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		if *on != "" {
			h.Device = *on
			break
		}
		if granted(grant{}).on {
			if err := checkAwayNet(); err != nil {
				return fail(stderr, err)
			}
		}
		// The keys go with it, and new ones reach the hub only on the home
		// network: a device that meets the hub only through the tunnel would
		// be cut off from its group until it is at home again.
		if st, err := statusNow(); err == nil && st.Away != nil && st.Away.Through && !st.Away.Hub && !*yes {
			fmt.Fprintf(stdout, "This device reaches the hub %s only through the tunnel now. Turning sync away\n", st.Away.HubDevice)
			fmt.Fprintln(stdout, "from home off forgets its keys; new ones reach the hub only on the home network, so")
			fmt.Fprintln(stdout, "it syncs with its group again only once it is at home, even after cbb global on.")
			fmt.Fprint(stdout, "Type yes to turn it off anyway: ")
			line, err := readLine(stdin)
			if err != nil {
				return fail(stderr, err)
			}
			if !strings.EqualFold(strings.TrimSpace(line), "yes") {
				fmt.Fprintln(stdout, "Nothing changed.")
				return 1
			}
		}
	case "allow":
		if len(args) != 1 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		return cmdGlobalAllow(stdout, stderr)
	case "hub":
		if err := checkAwayNet(); err != nil {
			return fail(stderr, err)
		}
		fs := flag.NewFlagSet("global hub", flag.ContinueOnError)
		fs.SetOutput(stderr)
		port := fs.Int("port", 0, "the UDP port the hub listens on (default 8764)")
		fs.StringVar(&firewall, "firewall", "ask", "open the hub's UDP port in the firewall: ask, yes (without asking) or no (print the commands)")
		fwd := fs.String("forwarder", "", "the forwarder's address, for clients that cannot reach the hub directly")
		fwdKey := fs.String("forwarder-key", "", "the forwarder's key, which cbb forward prints")
		obfuscate := fs.Bool("obfuscate", false, "speak AmneziaWG, which hides that the packets are WireGuard, for networks that block it")
		vlessOnly := fs.Bool("vless", false, "the clients reach the forwarder only over VLESS, which looks like HTTPS to a well-known site")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		if fs.NArg() == 0 && *fwd == "" || !slices.Contains([]string{"ask", "yes", "no"}, firewall) {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		if *fwd != "" {
			var err error
			if *fwd, err = resolveAddrPort(*fwd, stdout); err != nil {
				return fail(stderr, err)
			}
		}
		h.Port, h.Addrs, h.Forwarder, h.ForwarderKey, h.Obfuscate, h.VLESS = *port, fs.Args(), *fwd, *fwdKey, *obfuscate, *vlessOnly
	case "move":
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		fs := flag.NewFlagSet("global move", flag.ContinueOnError)
		fs.SetOutput(stderr)
		fwd := fs.String("forwarder", "", "the forwarder through which the new hub is reached (default: this hub's)")
		fwdKey := fs.String("forwarder-key", "", "the forwarder's key, which cbb forward prints")
		if fs.Parse(args[2:]) != nil {
			return 2
		}
		if *fwd != "" {
			var err error
			if *fwd, err = resolveAddrPort(*fwd, stdout); err != nil {
				return fail(stderr, err)
			}
		}
		h.Device, h.Addrs, h.Forwarder, h.ForwarderKey = args[1], fs.Args(), *fwd, *fwdKey
	case "relay":
		if err := checkAwayNet(); err != nil {
			return fail(stderr, err)
		}
		fs := flag.NewFlagSet("global relay", flag.ContinueOnError)
		fs.SetOutput(stderr)
		key := fs.String("key", "", "the relay's key, which cbb relay prints")
		yes := fs.Bool("yes", false, "agree to what the relay learns without asking (for scripts)")
		// The address may come before the flag or after it.
		rest := args[1:]
		var addr string
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			addr, rest = rest[0], rest[1:]
		}
		if fs.Parse(rest) != nil {
			return 2
		}
		if addr == "" && fs.NArg() == 1 {
			addr = fs.Arg(0)
		} else if fs.NArg() != 0 {
			addr = ""
		}
		if addr == "" || *key == "" {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		addr, err := resolveAddrPort(addr, stdout)
		if err != nil {
			return fail(stderr, err)
		}
		h.Relay, h.RelayKey = addr, *key
		if !*yes {
			fmt.Fprint(stdout, relayNotice)
			// The relay turns sync away from home on where it is off, and
			// the same yes agrees to that.
			if st, err := statusNow(); err == nil && st.Away == nil {
				fmt.Fprint(stdout, "This turns sync away from home on here as well.\n\n")
				fmt.Fprint(stdout, keysWarning)
			}
			fmt.Fprint(stdout, "Type yes to meet at this relay: ")
			line, err := readLine(stdin)
			if err != nil {
				return fail(stderr, err)
			}
			if !strings.EqualFold(strings.TrimSpace(line), "yes") {
				fmt.Fprintln(stdout, "Nothing changed.")
				return 1
			}
		}
		h.Consent = true
	default:
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
	if m.Status != nil {
		a := m.Status.Away
		if args[0] == "on" && confined() {
			a = waitServers(a)
		}
		g := grantFor(a)
		if err := applyGrant(stdout, g); err != nil {
			return fail(stderr, fmt.Errorf("sync away from home changed, but the service's network did not: %w", err))
		}
		// The service cannot change the system's limit itself, so a client
		// that has not heard its hub yet needs another cbb global allow.
		if confined() && g.on && g.hubPort == 0 && len(g.addrs) == 0 {
			fmt.Fprintf(stdout, "The group's servers are not known yet, so this computer's service still reaches the home network only. Once cbb status shows the hub, %s.\n", allowHint)
		}
	}
	if m.Status != nil {
		syncHubPort(stdin, stdout, m.Status.Away, firewall)
		writeAway(stdout, m.Status.Away)
	}
	if args[0] == "hub" {
		fmt.Fprint(stdout, hubNote)
	}
	return 0
}

// serverWait is how long waitServers waits; tests shorten it.
var serverWait = 10 * time.Second

// waitServers waits a little for a client that has just turned sync away
// from home on to hear its hub's offer, which names the hub's addresses,
// so that the system's limit can let them through at once. Each status is
// asked on a connection of its own: the service takes one request on each.
func waitServers(a *control.Away) *control.Away {
	for deadline := time.Now().Add(serverWait); !knowsServers(a) && a != nil && time.Now().Before(deadline); {
		time.Sleep(500 * time.Millisecond)
		st, err := statusNow()
		if err != nil {
			break
		}
		a = st.Away
	}
	return a
}

// knowsServers reports whether the service knows the group's servers: it
// is a hub, meets at a relay, or has heard its hub's offer.
func knowsServers(a *control.Away) bool {
	return a != nil && (a.Hub || a.Relay != nil || len(a.Allow) > 0)
}

// applyGrant lets the service reach g and says so. When the service
// restarted for it, it returns once the service answers again, so that the
// next cbb command finds it running.
func applyGrant(stdout io.Writer, g grant) error {
	changed, restarted, err := setAwayNet(g)
	if err != nil {
		return err
	}
	if restarted {
		c, err := waitService(control.OpStatus)
		if err != nil {
			return err
		}
		c.Close()
	}
	if changed {
		msg := "This computer's service may now reach " + g.String()
		if restarted {
			msg += "; it restarted for that"
		}
		fmt.Fprintln(stdout, msg+".")
	}
	return nil
}

// cmdGlobalAllow lets the service reach the group's servers as the service
// knows them now.
func cmdGlobalAllow(stdout, stderr io.Writer) int {
	c, err := control.DialFor(control.OpStatus)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err != nil {
		return fail(stderr, err)
	}
	if m.Status == nil {
		return fail(stderr, fmt.Errorf("the service did not say what it reaches"))
	}
	// In no group, or with sync away from home off, this takes back what a
	// limit allowed before; the installers run it after an update for that.
	g := grantFor(m.Status.Away)
	if !confined() {
		fmt.Fprintln(stdout, "This computer has no limit outside the program; the service itself reaches only "+g.String()+".")
		return 0
	}
	if granted(g).equal(g) {
		fmt.Fprintln(stdout, "This computer's service may already reach "+g.String()+".")
		return 0
	}
	if err := checkAwayNet(); err != nil {
		return fail(stderr, err)
	}
	if err := applyGrant(stdout, g); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// hubNote tells the user what depends on the hub being on.
const hubNote = `
The hub does not have to stay on. While it is off, nothing syncs away from home;
at home the devices sync with each other without it. Keep it on all the time, turn
it on when you need it, or sync only at home.
`

func cmdGlobalStatus(stdout, stderr io.Writer) int {
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
		return fail(stderr, fmt.Errorf("this device is in no group"))
	}
	writeAway(stdout, m.Status.Away)
	return 0
}

// writeAway describes sync away from home: with the underlying error in a
// debug build or with CBB_DEBUG=1, and only the short message otherwise.
func writeAway(w io.Writer, a *control.Away) {
	if a == nil {
		fmt.Fprintln(w, "Sync away from home: off (cbb global on turns it on).")
		if confined() {
			if have := granted(grant{}); have.on {
				fmt.Fprintf(w, "This computer still lets the service reach %s: %s.\n", have, allowHint)
			}
		}
		return
	}
	if confined() {
		if want := grantFor(a); !granted(want).equal(want) {
			fmt.Fprintf(w, "This computer lets the service reach %s, but the group's servers are now %s: %s.\n",
				granted(want), want, allowHint)
		}
	}
	switch {
	case a.Hub && a.Standby:
		// A hub above this one serves, or this one looks for those: it is
		// their client meanwhile, and its own hub and forwarder rest.
		if a.HubDevice != "" {
			fmt.Fprintf(w, "Sync away from home: on; this device is one of the group's hubs. The hub %s, above it, serves, so this one stands by as its client.\n", a.HubDevice)
		} else {
			fmt.Fprintln(w, "Sync away from home: on; this device is one of the group's hubs. It looks for the hubs above it, and serves if none answers.")
		}
	case a.Hub:
		devices := "devices"
		if a.Clients == 1 {
			devices = "device"
		}
		fmt.Fprintf(w, "Sync away from home: on; this device is the hub, on UDP port %d, for %d %s.\n", a.Port, a.Clients, devices)
		if a.Obfuscated {
			fmt.Fprintln(w, "  Obfuscated: the tunnel speaks AmneziaWG, so it does not look like WireGuard.")
		}
		if a.VLESS {
			fmt.Fprintln(w, "  VLESS: the clients reach the forwarder only over VLESS, which looks like HTTPS to a well-known site.")
		}
		switch {
		case len(a.Endpoints) > 0:
			fmt.Fprintf(w, "  Reached at %s.\n", strings.Join(a.Endpoints, ", "))
			fmt.Fprintf(w, "  The router must forward UDP port %d to this device, and its firewall must allow it.\n", a.Port)
		case a.Forwarder == nil:
			fmt.Fprintln(w, "  The hub has no address away from home: cbb global hub address:port...")
		}
		if f := a.Forwarder; f != nil {
			switch {
			case f.Registered && f.Seen != "":
				fmt.Fprintf(w, "  Registered with the forwarder at %s, which reaches this hub at %s.\n", f.Endpoint, f.Seen)
			case f.Registered:
				fmt.Fprintf(w, "  Registered with the forwarder at %s; it has not heard the hub's UDP port yet.\n", f.Endpoint)
			case f.Error == "":
				fmt.Fprintf(w, "  Registering with the forwarder at %s.\n", f.Endpoint)
			default:
				fmt.Fprintf(w, "  Not registered with the forwarder at %s: %s.\n", f.Endpoint, f.Error)
				if f.Detail != "" && debugErrors() {
					fmt.Fprintf(w, "  Detail: %s\n", f.Detail)
				}
			}
		}
	case a.Relay != nil:
		r := a.Relay
		switch {
		case r.Connected && a.Through:
			fmt.Fprintf(w, "Sync away from home: on; connected to the relay at %s and through it to other devices.\n", r.Endpoint)
		case r.Connected && len(r.Online) == 0:
			fmt.Fprintf(w, "Sync away from home: on; connected to the relay at %s; no other device of the group is there now.\n", r.Endpoint)
		case r.Connected:
			fmt.Fprintf(w, "Sync away from home: on; connected to the relay at %s, with %d other devices of the group there.\n", r.Endpoint, len(r.Online))
		case r.Error == "":
			fmt.Fprintf(w, "Sync away from home: on; connecting to the relay at %s.\n", r.Endpoint)
		default:
			fmt.Fprintf(w, "Sync away from home: on; not connected to the relay at %s: %s.\n", r.Endpoint, r.Error)
			if r.Detail != "" && debugErrors() {
				fmt.Fprintf(w, "  Detail: %s\n", r.Detail)
			}
		}
	case a.HubDevice == "":
		fmt.Fprintln(w, "Sync away from home: on; waiting to meet the group's hub on the home network. The hub")
		fmt.Fprintln(w, "learns this device's keys there, so away from home it syncs only after that.")
	case a.Through:
		fmt.Fprintf(w, "Sync away from home: on; connected to the hub %s through the tunnel.\n", a.HubDevice)
	case a.VLESS:
		fmt.Fprintf(w, "Sync away from home: on; the hub is %s, reached over VLESS through its forwarder; not connected through the tunnel.\n", a.HubDevice)
	default:
		fmt.Fprintf(w, "Sync away from home: on; the hub is %s, at %s; not connected through the tunnel.\n", a.HubDevice, strings.Join(a.Endpoints, ", "))
	}
	if a.VLESS && !a.Hub {
		fmt.Fprintln(w, "  VLESS: the tunnel goes inside VLESS to the hub's forwarder, which looks like HTTPS to a well-known site.")
	}
	// Where the keys are is said once, when the user turns it on (keysWarning),
	// not every time the status is shown.
	if a.Error != "" {
		fmt.Fprintf(w, "  Problem: %s.\n", a.Error)
		if a.Detail != "" && debugErrors() {
			fmt.Fprintf(w, "  Detail: %s\n", a.Detail)
		}
	}
}

// debugErrors tells whether to show the underlying errors: in a build
// without a release version, unless CBB_DEBUG=0; in a release, only with
// CBB_DEBUG=1. The service's log always has them.
func debugErrors() bool {
	switch os.Getenv("CBB_DEBUG") {
	case "1":
		return true
	case "0":
		return false
	}
	return version.Version == "dev"
}

// resolveAddrPort turns a server's name and port, such as cbb.tools:8764,
// into an address with the port; the service keeps the address, so a
// server that moves needs the command again.
func resolveAddrPort(s string, stdout io.Writer) (string, error) {
	if _, err := netip.ParseAddrPort(s); err == nil {
		return s, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("%q is not an address or a name with a port, such as 203.0.113.9:8764", s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", fmt.Errorf("could not find the address of %s: %w", host, err)
	}
	// IPv4 first: a home network without IPv6 is the more common case.
	slices.SortStableFunc(ips, func(a, b netip.Addr) int {
		switch {
		case a.Unmap().Is4() == b.Unmap().Is4():
			return 0
		case a.Unmap().Is4():
			return -1
		}
		return 1
	})
	ep := net.JoinHostPort(ips[0].Unmap().String(), port)
	fmt.Fprintf(stdout, "%s is at %s.\n", host, ep)
	return ep, nil
}
