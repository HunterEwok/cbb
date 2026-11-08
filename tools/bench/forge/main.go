// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command forge is the bench's stand-in for an attacker on the member
// protocol (docs/testbench-catalogue.md, T8, S17, S23): in a fleet
// container, with a member's state copied from another, it connects to a
// target as that member and sends it commands that an admin's state signs,
// some of them replayed, changed or made for another group or device, and
// prints what the target answered, one line per case:
//
//	forge -state DIR -signer DIR -to DEVICE -addr HOST:PORT replay altered other-group other-target
//	forge ... flood:N:DEVICE
//	forge ... make:N:FILE send:FILE:SEED
//	forge ... event:TEXT:N
//	forge -os SYSTEM ... hold:N
//
// Each line of the commands is "CASE N: done", "CASE N: refused: REASON" or
// "CASE N: no answer: ERROR". flood signs N renames of DEVICE with the
// signer's key and sends them (G32); make signs N renames of the listed
// devices at times out of order into FILE, and send sends FILE's records in
// an order SEED picks (G31); hold stays connected for N seconds with a
// hello that names SYSTEM (G35). The tunnel's cases are in tunnel.go, the
// stand-in for a well-known site that VLESS borrows in site.go, the control
// socket's in control.go, the TVs in tv.go, the mDNS records in mdns.go,
// the renewals in cert.go, watching the writes in watch.go, the fetch
// limits in fetch.go, the phone that scans a QR code in qr.go, a relay
// between two pairing sessions in relay.go, looking for a text in the
// services' memory in memscan.go, the stand-in for the internet in
// outside.go, the web server in front of a forwarder's XHTTP in web.go. It
// is never part of a release.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/hlc"
)

func main() {
	state := flag.String("state", "", "the state directory of the member to connect as")
	signer := flag.String("signer", "", "the state directory of the admin whose key signs the commands")
	to := flag.String("to", "", "the target's device ID")
	addr := flag.String("addr", "", "the target's member port, HOST:PORT")
	endpoint := flag.String("endpoint", "", "the tunnel's cases: the hub's UDP address, HOST:PORT, instead of its first one")
	hubState := flag.String("hub-state", "", "the tunnel's cases: the state directory whose hub's offer to use instead of -state's")
	system := flag.String("os", "linux", "the system the forge's hello names")
	socket := flag.String("socket", "", "the control socket's cases: its path, if not the default")
	flag.StringVar(&targetState, "target-state", "", "the renewals' cases: the target's state directory, for its key")
	flag.Parse()
	if flag.NArg() > 0 && outsideCase(flag.Arg(0)) {
		// It serves until it fails.
		fmt.Fprintln(os.Stderr, "forge:", runOutside(*addr, flag.Arg(0)))
		os.Exit(1)
	}
	if flag.NArg() > 0 && webCase(flag.Arg(0)) {
		// It serves until it fails.
		fmt.Fprintln(os.Stderr, "forge:", runWeb(*addr, flag.Arg(0)))
		os.Exit(1)
	}
	if flag.Arg(0) == "memscan" {
		// forge memscan TEXT looks for TEXT in the services' memory.
		if err := runMemscan(flag.Arg(1)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if name, ok := strings.CutPrefix(flag.Arg(0), "site:"); ok {
		// forge -addr :443 site:NAME serves as the well-known site NAME.
		if err := runSite(*addr, name); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if kind, ok := strings.CutPrefix(flag.Arg(0), "tv:"); ok {
		// forge -addr DIR tv:KIND plays a TV, writing what it saw in DIR.
		if err := runTV(kind, *addr); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && fuzzCase(flag.Arg(0)) {
		if err := runFuzz(*state, group.DeviceID(*to), *addr, *socket, flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && relayCase(flag.Arg(0)) {
		if err := runRelay(*state, *addr, flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && qrCase(flag.Arg(0)) {
		if err := runQR(*socket, flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && inviteCase(flag.Arg(0)) {
		if err := runInvite(flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && fetchCase(flag.Arg(0)) {
		if err := runFetch(*state, group.DeviceID(*to), *addr, flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && probeCase(flag.Arg(0)) {
		if err := runProbe(flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && mdnsCase(flag.Arg(0)) {
		if err := runMDNS(*addr, flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && watchCase(flag.Arg(0)) {
		if err := runWatch(*socket, flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && controlCase(flag.Arg(0)) {
		if err := runControl(*socket, flag.Args()); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && tunnelCase(flag.Arg(0)) {
		if err := runTunnel(*state, *hubState, *endpoint, flag.Args()); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*state, *signer, group.DeviceID(*to), *addr, *system, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "forge:", err)
		os.Exit(1)
	}
}

func run(state, signerDir string, to group.DeviceID, addr, system string, cases []string) error {
	id, err := group.Load(state)
	if err != nil {
		return err
	}
	admin, err := group.Load(signerDir)
	if err != nil {
		return err
	}
	ca, chain := admin.Signer()
	if ca == nil {
		return fmt.Errorf("%s holds no admin key", signerDir)
	}
	eng := clip.New(clip.Config{Self: string(id.ID), Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil)})
	n, err := dialMember(id, to, addr, system)
	if err != nil {
		return fmt.Errorf("connecting to %s: %v", addr, err)
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tag := group.Tag(id.GroupCA.Cert)
	body := func(target group.DeviceID, mode string) group.CommandBody {
		now := time.Now()
		return group.CommandBody{Type: group.CommandMode, Group: tag, By: admin.ID, To: target, ID: group.NewCommandID(),
			TimeMS: now.UnixMilli(), ExpiresMS: now.Add(group.CommandLifetime).UnixMilli(), Mode: mode}
	}
	send := func(name string, cmd group.Record, cmdID string) {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		res, err := n.command(cctx, cmd, cmdID)
		switch {
		case err != nil:
			fmt.Printf("%s: no answer: %v\n", name, err)
		case res.Status == "done":
			fmt.Printf("%s: done\n", name)
		default:
			fmt.Printf("%s: refused: %s\n", name, res.Reason)
		}
	}
	// rename signs a record that renames the device d, as the next record
	// of this signer: each one goes into set, so that seq and prev follow
	// on.
	var set *group.Records
	rename := func(d group.Device, name string, at time.Time) (group.Record, error) {
		if set == nil {
			var err error
			if set, err = group.LoadRecords(signerDir, admin.GroupCA.Cert); err != nil {
				return group.Record{}, err
			}
		}
		var adminCA *x509.Certificate
		if len(chain) > 0 {
			adminCA = chain[0]
		}
		key := d.Key
		r, err := set.Sign(group.RecordBody{Type: group.RecordDevice, TimeMS: at.UnixMilli(),
			Device: string(d.ID), Name: name, Role: d.Role, OS: d.OS, Key: &key, Admin: d.AdminKey, Powers: d.Powers, Commands: d.Commands,
			Store: d.Store, Kind: d.Kind, Proof: d.Proof, Seal: d.Seal}, ca.Key, adminCA)
		if err != nil {
			return group.Record{}, err
		}
		if _, err := set.Add(r); err != nil {
			return group.Record{}, err
		}
		return r, nil
	}
	devices := func() ([]group.Device, error) {
		rs, err := group.LoadRecords(signerDir, admin.GroupCA.Cert)
		if err != nil {
			return nil, err
		}
		return rs.Devices(), nil
	}
	sendAll := func(rs []group.Record) {
		for len(rs) > 0 {
			k := min(len(rs), 64)
			if err := n.records(rs[:k]); err != nil {
				fmt.Printf("records: %v\n", err)
				return
			}
			rs = rs[k:]
		}
		// The records leave before the connection closes.
		time.Sleep(3 * time.Second)
	}
	for _, c := range cases {
		parts := strings.Split(c, ":")
		switch parts[0] {
		case "flood", "make":
			if len(parts) != 3 {
				return fmt.Errorf("%s takes N and a device or a file", parts[0])
			}
			count, err := strconv.Atoi(parts[1])
			if err != nil {
				return err
			}
			list, err := devices()
			if err != nil {
				return err
			}
			var rs []group.Record
			now := time.Now()
			for i := range count {
				d := list[i%len(list)]
				if parts[0] == "flood" {
					if d, err = find(list, parts[2]); err != nil {
						return err
					}
				}
				// make: times out of order, some of them equal.
				at := now.Add(-time.Duration(rand.IntN(count/2+1)) * time.Second)
				if parts[0] == "flood" {
					at = now.Add(time.Duration(i) * time.Millisecond)
				}
				r, err := rename(d, fmt.Sprintf("%s-%d", parts[0], i), at)
				if err != nil {
					return err
				}
				rs = append(rs, r)
			}
			if parts[0] == "make" {
				b, err := json.Marshal(rs)
				if err != nil {
					return err
				}
				if err := os.WriteFile(parts[2], b, 0o600); err != nil {
					return err
				}
				fmt.Printf("make: %d records\n", len(rs))
				continue
			}
			sendAll(rs)
			fmt.Printf("flood: sent %d records\n", len(rs))
		case "cert":
			// cert:KIND[:SIGNER] sends a certificate (cert.go).
			by := admin
			if len(parts) == 3 {
				if by, err = group.Load(parts[2]); err != nil {
					return err
				}
			}
			if err := sendCert(n, parts[1], by); err != nil {
				return err
			}
		case "event":
			// event:TEXT:N makes one event of TEXT and sends it N times, as
			// members passing it on would (Y15).
			if len(parts) != 3 {
				return fmt.Errorf("event takes a text and a count")
			}
			count, err := strconv.Atoi(parts[2])
			if err != nil {
				return err
			}
			ev, ok, err := eng.Copied(parts[1], clip.Text, clip.Copy)
			if err != nil || !ok {
				return fmt.Errorf("making the event: %v", err)
			}
			for range count {
				if err := n.event(ev); err != nil {
					return fmt.Errorf("sending the event to %s: %v", to, err)
				}
			}
			time.Sleep(2 * time.Second)
			fmt.Printf("event: sent %d times\n", count)
		case "hold":
			// hold:N stays connected for N seconds, as the member.
			secs, err := strconv.Atoi(parts[len(parts)-1])
			if err != nil {
				return err
			}
			time.Sleep(time.Duration(secs) * time.Second)
			fmt.Printf("hold: %d s\n", secs)
		case "send":
			if len(parts) != 3 {
				return fmt.Errorf("send takes a file and a seed")
			}
			b, err := os.ReadFile(parts[1])
			if err != nil {
				return err
			}
			var rs []group.Record
			if err := json.Unmarshal(b, &rs); err != nil {
				return err
			}
			seed, _ := strconv.ParseUint(parts[2], 10, 64)
			rand.New(rand.NewPCG(seed, seed)).Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
			sendAll(rs)
			fmt.Printf("send: sent %d records\n", len(rs))
		}
		switch c {
		case "replay":
			// The same signed command twice, as one captured on the way.
			b := body(to, "receive")
			cmd, err := group.SignCommand(b, ca.Key, chain...)
			if err != nil {
				return err
			}
			send("replay 1", cmd, b.ID)
			send("replay 2", cmd, b.ID)
		case "altered":
			// A command changed after it was signed, as by a member that
			// passes it on.
			b := body(to, "own")
			cmd, err := group.SignCommand(b, ca.Key, chain...)
			if err != nil {
				return err
			}
			cmd.Body = []byte(strings.Replace(string(cmd.Body), `"own"`, `"send"`, 1))
			send("altered 1", cmd, b.ID)
		case "other-group":
			// Signed by the root of a group of its own.
			root, err := group.NewRootCA(time.Now())
			if err != nil {
				return err
			}
			b := body(to, "send")
			b.Group = group.Tag(root.Cert)
			cmd, err := group.SignCommand(b, root.Key)
			if err != nil {
				return err
			}
			send("other-group 1", cmd, b.ID)
		case "other-target":
			// Signed for another device, sent to this one.
			b := body(group.NewDeviceID(), "send")
			cmd, err := group.SignCommand(b, ca.Key, chain...)
			if err != nil {
				return err
			}
			send("other-target 1", cmd, b.ID)
		default:
			if parts[0] != "flood" && parts[0] != "make" && parts[0] != "send" && parts[0] != "hold" && parts[0] != "cert" && parts[0] != "event" {
				return fmt.Errorf("no case %q", c)
			}
		}
	}
	return nil
}

// loadID is the device ID of the member whose state is in dir.
func loadID(dir string) (string, error) {
	id, err := group.Load(dir)
	if err != nil {
		return "", err
	}
	return string(id.ID), nil
}

// find returns the device named name, by name or device ID.
func find(list []group.Device, name string) (group.Device, error) {
	for _, d := range list {
		if d.Name == name || string(d.ID) == name {
			return d, nil
		}
	}
	return group.Device{}, fmt.Errorf("no device %q in the records", name)
}
