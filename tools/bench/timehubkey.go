// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// tunnelFile is what the bench reads of a member's tunnel.json: the hub's
// keys and the periods they serve, and on a client the hubs it knows.
type tunnelFile struct {
	ServingFor string `json:"serving_for"`
	NextFor    string `json:"next_for"`
	Hubs       []struct {
		Key  string `json:"key"`
		Next string `json:"next"`
	} `json:"hubs"`
}

func readTunnel(ctx context.Context, d *Device) (tunnelFile, error) {
	var t tunnelFile
	out, err := Run(ctx, d, "cat /var/lib/cbb/tunnel.json", "")
	if err != nil {
		return t, err
	}
	if err := json.Unmarshal([]byte(out), &t); err != nil {
		return t, fmt.Errorf("%s: tunnel.json: %w", d.Name, err)
	}
	return t, nil
}

// hubKeys (W12): the hub serves with a new WireGuard key in each period
// of the group's server credentials; a client has the next key before the
// hub switches to it, connects with it after, and a client that went off
// holding the next key and stayed off across the switch connects again
// with it when it is back.
func hubKeys(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "time/W12-hub-key/"
	a := newAwayGroup(ctx, r, f, "time/W12-hub-key", 2)
	if a == nil {
		return
	}
	client := a.join(ctx, r, p+"client")
	if client == nil {
		return
	}
	hub := a.hub
	period := scaled(30 * 24 * time.Hour) // a new period every 30 scaled days
	// switched waits until the hub serves a period other than from.
	switched := func(from string) (string, error) {
		var now string
		err := eventually(ctx, 3*period, func() error {
			t, err := readTunnel(ctx, hub)
			if err != nil {
				return err
			}
			if t.ServingFor == from || t.ServingFor == "" {
				return fmt.Errorf("%s still serves the period %q", hub.Name, from)
			}
			now = t.ServingFor
			return nil
		})
		return now, err
	}
	var first string
	if r.Do(p+"connected", func() error {
		if err := connected(ctx, client, timeout); err != nil {
			return err
		}
		t, err := readTunnel(ctx, hub)
		first = t.ServingFor
		if err == nil && first == "" {
			err = fmt.Errorf("%s serves no period", hub.Name)
		}
		return err
	}) != nil {
		return
	}
	var second string
	r.Do(p+"ahead", func() error {
		// Before the switch the client holds a next key that is not the
		// one in use.
		var next string
		if err := eventually(ctx, 3*period, func() error {
			t, err := readTunnel(ctx, client)
			if err != nil {
				return err
			}
			if len(t.Hubs) == 0 || t.Hubs[0].Next == "" || t.Hubs[0].Next == t.Hubs[0].Key {
				return fmt.Errorf("%s has no next key for the hub", client.Name)
			}
			h, err := readTunnel(ctx, hub)
			if err != nil {
				return err
			}
			if h.ServingFor != first {
				return fmt.Errorf("%s switched to %q before %s had the next key", hub.Name, h.ServingFor, client.Name)
			}
			next = t.Hubs[0].Next
			return nil
		}); err != nil {
			return err
		}
		var err error
		if second, err = switched(first); err != nil {
			return err
		}
		if err := eventually(ctx, timeout, func() error {
			t, err := readTunnel(ctx, client)
			if err != nil {
				return err
			}
			if len(t.Hubs) == 0 || t.Hubs[0].Key != next {
				return fmt.Errorf("%s does not use the key it had as next", client.Name)
			}
			return nil
		}); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, client, hub, "after the hub's new key", timeout)
	})
	r.Do(p+"offline", func() error {
		if second == "" {
			return fmt.Errorf("no switch seen")
		}
		// It goes off once it holds the next key (protocol.md section 11,
		// "The hub's key": a client away for the whole three days without
		// it reaches the hub again only at home).
		if err := eventually(ctx, 3*period, func() error {
			t, err := readTunnel(ctx, client)
			if err != nil {
				return err
			}
			if len(t.Hubs) == 0 || t.Hubs[0].Next == "" || t.Hubs[0].Next == t.Hubs[0].Key {
				return fmt.Errorf("%s has no next key for the hub", client.Name)
			}
			return nil
		}); err != nil {
			return err
		}
		if err := a.f.stop(ctx, client); err != nil {
			return err
		}
		if _, err := switched(second); err != nil {
			return err
		}
		if err := a.start(ctx, client); err != nil {
			return err
		}
		if err := connected(ctx, client, timeout); err != nil {
			return fmt.Errorf("a client off across the hub's switch: %w", err)
		}
		return syncs(ctx, a.benchGroup, client, hub, "back after the switch", timeout)
	})
}
