// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"

	"github.com/HunterEwok/cbb/internal/control"
)

// The device tiles as the member answers view and arrange (docs/apps.md,
// "What the member shows"): the member keeps the user's order and
// collections, and the window only draws them.

// Item is a device, or a collection of devices, as the window draws it.
type Item struct {
	Device     string      `json:"device,omitempty"`
	Collection *Collection `json:"collection,omitempty"`
}

// Collection is a named collection of devices, one level only.
type Collection struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Devices []string `json:"devices"`
}

// Ref names a device or a collection in a change.
type Ref struct {
	Device     string `json:"device,omitempty"`
	Collection string `json:"collection,omitempty"`
}

// ArrangeOp is a change the user makes: move (Item before Before, or to the
// end of its level), into (Device into Collection), out (Device out of its
// collection, after it), new (a collection Name of Devices, where the first
// of them was), rename (Collection to Name), ungroup (Collection's devices
// back where it was) and reset (the default order, collections kept).
type ArrangeOp struct {
	Op         string   `json:"op"`
	Item       *Ref     `json:"item,omitempty"`
	Before     *Ref     `json:"before,omitempty"`
	Device     string   `json:"device,omitempty"`
	Collection string   `json:"collection,omitempty"`
	Name       string   `json:"name,omitempty"`
	Devices    []string `json:"devices,omitempty"`
}

// memberView is the member's answer to view and arrange.
type memberView struct {
	Tiles []struct {
		Device     *control.Device `json:"device,omitempty"`
		Collection *struct {
			ID      string           `json:"id"`
			Name    string           `json:"name"`
			Devices []control.Device `json:"devices"`
		} `json:"collection,omitempty"`
	} `json:"tiles"`
	Custom bool `json:"custom"`
}

// readView is the member's view as the window takes it: the devices in
// the user's order, the tiles by their IDs, and whether the user changed
// the order.
func readView(raw json.RawMessage) (devices []control.Device, items []Item, custom bool, err error) {
	var v memberView
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, nil, false, err
	}
	for _, t := range v.Tiles {
		switch {
		case t.Device != nil:
			devices = append(devices, *t.Device)
			items = append(items, Item{Device: t.Device.ID})
		case t.Collection != nil:
			c := &Collection{ID: t.Collection.ID, Name: t.Collection.Name, Devices: []string{}}
			for _, d := range t.Collection.Devices {
				devices = append(devices, d)
				c.Devices = append(c.Devices, d.ID)
			}
			items = append(items, Item{Collection: c})
		}
	}
	return devices, items, v.Custom, nil
}
