// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

// The project's relay, as the signed lists name it, and the address it
// moves to.
const (
	projectRelay = "cbb.tools:8765"
	relayPublic2 = "203.0.113.31"
	relayName2   = "relay2.cbb.tools"
)

// relayPublicKey reads the public key of the relay d from its key file
// into a PEM file of the feed's folder, for release-sign keys -relay.
func (fd *feed) relayPublicKey(ctx context.Context, d *Device, name string) (string, error) {
	data, err := Run(ctx, d, "cat "+relayState+"/relay.pem", "")
	if err != nil {
		return "", err
	}
	rest := []byte(data)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return "", fmt.Errorf("%s's key file holds no certificate", d.Name)
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return "", err
		}
		spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return "", err
		}
		path := filepath.Join(fd.dir, name+".pub")
		return path, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o644)
	}
}

// entriesString signs keys.json, by the first root, with the release key
// and the relays' keys as the project's relay's, and entries.json, by the
// release key, with the relay's endpoints, both of seq, and gives them as
// cbb global entries import takes them.
func (fd *feed) entriesString(ctx context.Context, seq int, relayKeys []string, endpoints []string) (string, error) {
	pub, err := fd.sign(ctx, "public", "-key", "file:"+fd.key("release"))
	if err != nil {
		return "", err
	}
	pubFile := filepath.Join(fd.dir, "release.pub")
	if err := os.WriteFile(pubFile, pub, 0o644); err != nil {
		return "", err
	}
	args := []string{"keys", "-seq", fmt.Sprint(seq)}
	for _, k := range relayKeys {
		args = append(args, "-relay", projectRelay+"="+k)
	}
	keysBody, err := fd.sign(ctx, append(args, "bench="+pubFile)...)
	if err != nil {
		return "", err
	}
	now := time.Now()
	entriesBody, err := json.Marshal(release.Entries{V: 1, Type: release.TypeEntries, Seq: uint64(seq), TimeMS: now.UnixMilli(),
		ExpiresMS: now.Add(30 * 24 * time.Hour).UnixMilli(), Forwarders: []release.EntryForwarder{},
		Relays: []release.EntryRelay{{Name: projectRelay, Endpoints: endpoints}}})
	if err != nil {
		return "", err
	}
	signed := map[string]json.RawMessage{}
	for _, s := range []struct {
		name, signer string
		body         []byte
	}{
		{"keys", "root1", keysBody}, {"entries", "release", entriesBody},
	} {
		body := filepath.Join(fd.dir, fmt.Sprintf("%s-%d.body", s.name, seq))
		if err := os.WriteFile(body, s.body, 0o644); err != nil {
			return "", err
		}
		f, err := fd.sign(ctx, "sign", "-key", "file:"+fd.key(s.signer), body)
		if err != nil {
			return "", err
		}
		signed[s.name] = f
	}
	data, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	return "cbb-entries:" + base64.RawURLEncoding.EncodeToString(data), nil
}

// projectRelayFollows (W48): a group without a hub meets at the project's
// relay (cbb global relay default), which it knows by its name and by the
// pins of the signed lists, with the bench's own release roots: when the
// relay takes a new key, the members follow the newer lists that one of
// them imports and the group passes on; when it moves, they find it where
// the newest entry points say, without the user.
func projectRelayFollows(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W48-project-relay/"
	var fd *feed
	defer func() { fd.remove() }()
	var nets []string
	var in *internet
	var rel *Device
	members := make([]*Device, 3)
	if r.Do(p+"start", func() error {
		var err error
		if fd, err = newFeed(ctx); err != nil {
			return err
		}
		for range 4 {
			n, err := f.Network(ctx)
			if err != nil {
				return err
			}
			nets = append(nets, n)
		}
		// The members trust the bench's release roots, from their start:
		// copied in as root's file before the members meet any release (a
		// file mounted from the host would be the bench user's, which cbb
		// does not take).
		for i := range members {
			if members[i], err = f.AddWith(ctx, nets[i], nil, "CBB_RELEASE_ROOTS=/feed/roots.pem"); err != nil {
				return err
			}
			if err := fd.rootsTo(ctx, members[i]); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	members[0].Roles = []string{"member", "hub"}
	// formGroup pairs over the network, so the members first share one.
	for _, d := range members[1:] {
		if r.Do(p+d.Name+"/home", func() error { return moveTo(ctx, d, members[0].Network) }) != nil {
			return
		}
	}
	g := formGroup(ctx, r, "fleet/W48-project-relay", members)
	if g == nil {
		return
	}
	if r.Do(p+"setup", func() error {
		for i, d := range members[1:] {
			if err := moveTo(ctx, d, nets[i+1]); err != nil {
				return err
			}
		}
		var err error
		if in, err = newInternet(ctx, f, nets...); err != nil {
			return err
		}
		if rel, _, err = startRelay(ctx, f, nets[3], "-open -listen :8765"); err != nil {
			return err
		}
		if err := in.publish(ctx, relayPublic, rel); err != nil {
			return err
		}
		for _, d := range members {
			if err := in.reach(ctx, d); err != nil {
				return err
			}
			if _, err := Run(ctx, d, "printf '%s cbb.tools\\n%s "+relayName2+"\\n' "+relayPublic+" "+relayPublic2+" >>/etc/hosts", ""); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	imports := func(seq int, keys, endpoints []string) error {
		s, err := fd.entriesString(ctx, seq, keys, endpoints)
		if err != nil {
			return err
		}
		// On every member: each reaches the others only through the relay,
		// which fails until it has the lists.
		for _, d := range members {
			if err := succeeds(ctx, d, "cbb global entries import "+s, "", "check out"); err != nil {
				return err
			}
		}
		return nil
	}
	meet := func(wait time.Duration) error {
		for _, d := range members {
			if err := globalShows(ctx, d, "; connected to the relay", wait); err != nil {
				return err
			}
		}
		return nil
	}
	if r.Do("fleet/W48-project-relay", func() error {
		k1, err := fd.relayPublicKey(ctx, rel, "relay1")
		if err != nil {
			return err
		}
		if err := imports(1, []string{k1}, nil); err != nil {
			return err
		}
		for _, d := range members {
			if _, err := Run(ctx, d, "cbb global relay default -yes", ""); err != nil {
				return err
			}
		}
		if err := meet(2 * time.Minute); err != nil {
			return err
		}
		return syncs(ctx, g, members[1], members[2], "through the project's relay", 2*timeout)
	}) != nil {
		return
	}
	r.Do("fleet/W48-new-key", func() error {
		// The relay starts again with a new key, which the members take
		// once the lists name it, without being asked; they reach each
		// other only through it.
		if _, err := Run(ctx, rel, "rm -f "+relayState+"/relay.pem", ""); err != nil {
			return err
		}
		if _, err := docker(ctx, "restart", "-t", "1", rel.Container); err != nil {
			return err
		}
		k2 := ""
		if err := eventually(ctx, 20*time.Second, func() error {
			var err error
			k2, err = fd.relayPublicKey(ctx, rel, "relay2")
			return err
		}); err != nil {
			return err
		}
		if err := imports(2, []string{k2}, nil); err != nil {
			return err
		}
		if err := meet(3 * time.Minute); err != nil {
			return err
		}
		return syncs(ctx, g, members[2], members[1], "with the relay's new key", 2*timeout)
	})
	r.Do("fleet/W48-moved", func() error {
		// The relay moves to another address with its key, its old one
		// no longer answering: the members find it where the newest entry
		// points say, and keep it.
		k2 := filepath.Join(fd.dir, "relay2.pub")
		if err := in.publish(ctx, relayPublic2, rel); err != nil {
			return err
		}
		if err := in.block(ctx, relayPublic, ""); err != nil {
			return err
		}
		defer in.unblock(ctx, relayPublic, "")
		if err := imports(3, []string{k2}, []string{relayName2 + ":8765"}); err != nil {
			return err
		}
		for _, d := range members {
			if err := eventually(ctx, 4*time.Minute, func() error {
				out, err := Run(ctx, d, "cat /var/lib/cbb/tunnel.json", "")
				if err == nil && !strings.Contains(out, relayPublic2+":8765") && !strings.Contains(out, relayName2+":8765") {
					err = fmt.Errorf("%s does not keep the relay's new address: %s", d.Name, strings.TrimSpace(out))
				}
				return err
			}); err != nil {
				return err
			}
		}
		if err := meet(2 * time.Minute); err != nil {
			return err
		}
		return syncs(ctx, g, members[0], members[2], "at the relay's new address", 2*timeout)
	})
}
