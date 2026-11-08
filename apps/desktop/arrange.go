// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// The arrangement of the device tiles (docs/apps.md, "Collections and the
// order of the tiles"): the user's own order and collections, kept in this
// app's settings and never sent to the group. The same model is in the
// Kotlin kit (Arrangement.kt) and the Swift kit (Arrangement.swift), and
// all three are checked against testdata/arrangement/vectors.json.

// The arrangement's limits.
const (
	arrangementVersion = 1
	maxCollections     = 32
	maxCollectionName  = 64 // bytes
)

// Arrangement is the stored order: devices and collections at the top
// level, and devices in the collections, for the group Group.
type Arrangement struct {
	V     int    `json:"v"`
	Group string `json:"group"`
	Items []Item `json:"items"`
}

// Item is a device, or a collection of devices.
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

// Ref names a device or a collection in an operation.
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

// errArrange is an operation that does not fit the arrangement.
var errArrange = errors.New("the arrangement cannot take that")

// arrangeFor is the stored arrangement for the group: a fresh one when it
// was made for another group or by another version.
func arrangeFor(a Arrangement, group string) Arrangement {
	if a.V != arrangementVersion || a.Group != group {
		return Arrangement{V: arrangementVersion, Group: group}
	}
	a.Items = cloneItems(a.Items)
	return a
}

func cloneItems(items []Item) []Item {
	out := make([]Item, len(items))
	for i, it := range items {
		out[i] = it
		if it.Collection != nil {
			c := *it.Collection
			c.Devices = slices.Clone(c.Devices)
			out[i].Collection = &c
		}
	}
	return out
}

// View is what the app shows: the stored items in order without the
// devices that are not listed, collections without listed devices left
// out unless they were just made, then the listed devices that appear
// nowhere, in the order given. self, this device, is an item as the others
// are, first while the stored items do not place it.
func (a Arrangement) View(devices []string, self string) []Item {
	devices = selfFirst(devices, self)
	listed := map[string]bool{}
	for _, d := range devices {
		listed[d] = true
	}
	seen := map[string]bool{}
	var out []Item
	for _, it := range a.Items {
		if it.Collection == nil {
			if listed[it.Device] && !seen[it.Device] {
				seen[it.Device] = true
				out = append(out, it)
			}
			continue
		}
		c := *it.Collection
		c.Devices = nil
		for _, d := range it.Collection.Devices {
			if listed[d] && !seen[d] {
				seen[d] = true
				c.Devices = append(c.Devices, d)
			}
		}
		if len(c.Devices) > 0 || len(it.Collection.Devices) == 0 {
			out = append(out, Item{Collection: &c})
		}
	}
	for _, d := range devices {
		if listed[d] && !seen[d] {
			seen[d] = true
			if d == self {
				out = append([]Item{{Device: d}}, out...)
			} else {
				out = append(out, Item{Device: d})
			}
		}
	}
	return out
}

// selfFirst is devices with self, this device, first: the group's order
// as the app shows it.
func selfFirst(devices []string, self string) []string {
	if self == "" || !slices.Contains(devices, self) {
		return devices
	}
	out := []string{self}
	for _, d := range devices {
		if d != self {
			out = append(out, d)
		}
	}
	return out
}

// Prune drops the devices that are not listed, and the collections that
// lose their last device that way; the app calls it only when the list is
// whole (the group loaded, this device in it).
func (a *Arrangement) Prune(devices []string) {
	listed := map[string]bool{}
	for _, d := range devices {
		listed[d] = true
	}
	var items []Item
	for _, it := range a.Items {
		if it.Collection == nil {
			if listed[it.Device] {
				items = append(items, it)
			}
			continue
		}
		had := len(it.Collection.Devices)
		it.Collection.Devices = slices.DeleteFunc(it.Collection.Devices, func(d string) bool { return !listed[d] })
		if had == 0 || len(it.Collection.Devices) > 0 {
			items = append(items, it)
		}
	}
	a.Items = items
}

// Apply makes the change, on the arrangement as View shows it for devices;
// the stored items then hold the whole order. A change
// that does not fit leaves the arrangement as it was.
func (a *Arrangement) Apply(op ArrangeOp, devices []string, self string) error {
	b := Arrangement{V: a.V, Group: a.Group, Items: cloneItems(a.Items)}
	if err := b.apply(op, devices, self); err != nil {
		return err
	}
	*a = b
	return nil
}

func (a *Arrangement) apply(op ArrangeOp, devices []string, self string) error {
	// Hidden items stay where they are; the listed devices that appear
	// nowhere join at the end, as View shows them.
	shown := map[string]bool{}
	for _, it := range a.View(devices, self) {
		if it.Collection == nil {
			shown[it.Device] = true
		} else {
			for _, d := range it.Collection.Devices {
				shown[d] = true
			}
		}
	}
	for _, d := range selfFirst(devices, self) {
		if shown[d] && a.find(d) < 0 {
			if d == self {
				a.Items = append([]Item{{Device: d}}, a.Items...)
			} else {
				a.Items = append(a.Items, Item{Device: d})
			}
		}
	}
	switch op.Op {
	case "move":
		if op.Item == nil {
			return errArrange
		}
		return a.move(*op.Item, op.Before, shown)
	case "into":
		if !shown[op.Device] {
			return errArrange
		}
		ci := a.collection(op.Collection)
		if ci < 0 {
			return errArrange
		}
		if slices.Contains(a.Items[ci].Collection.Devices, op.Device) {
			return nil
		}
		a.take(op.Device)
		c := a.Items[a.collection(op.Collection)].Collection
		c.Devices = append(c.Devices, op.Device)
		return nil
	case "out":
		ci := a.find(op.Device)
		if !shown[op.Device] || ci < 0 || a.Items[ci].Collection == nil {
			return errArrange
		}
		id := a.Items[ci].Collection.ID
		a.take(op.Device)
		at := a.collection(id) + 1
		if at == 0 {
			at = ci
		}
		a.Items = slices.Insert(a.Items, at, Item{Device: op.Device})
		return nil
	case "new":
		name, err := collectionName(op.Name)
		if err != nil {
			return err
		}
		n := 0
		for _, it := range a.Items {
			if it.Collection != nil {
				n++
			}
		}
		if n >= maxCollections {
			return fmt.Errorf("%w: at most %d collections", errArrange, maxCollections)
		}
		var ds []string
		for _, d := range op.Devices {
			if !shown[d] || slices.Contains(ds, d) {
				return errArrange
			}
			ds = append(ds, d)
		}
		at := len(a.Items)
		if len(ds) > 0 {
			at = a.find(ds[0])
		}
		c := &Collection{ID: a.newID(), Name: name, Devices: ds}
		a.Items = slices.Insert(a.Items, at, Item{Collection: c})
		for _, d := range ds {
			a.takeExcept(d, c.ID)
		}
		return nil
	case "rename":
		ci := a.collection(op.Collection)
		if ci < 0 {
			return errArrange
		}
		name, err := collectionName(op.Name)
		if err != nil {
			return err
		}
		a.Items[ci].Collection.Name = name
		return nil
	case "ungroup":
		ci := a.collection(op.Collection)
		if ci < 0 {
			return errArrange
		}
		var items []Item
		for _, d := range a.Items[ci].Collection.Devices {
			items = append(items, Item{Device: d})
		}
		a.Items = slices.Replace(a.Items, ci, ci+1, items...)
		return nil
	case "reset":
		a.reset(selfFirst(devices, self))
		return nil
	}
	return fmt.Errorf("%w: no operation %q", errArrange, op.Op)
}

// move puts item before the item before names, or at the end of before's
// level when it is nil: the end of the top level, or of the item's own
// collection for a device in one. A device before a device in a collection
// joins that collection; a collection never goes into one.
func (a *Arrangement) move(item Ref, before *Ref, shown map[string]bool) error {
	if item.Device != "" {
		if !shown[item.Device] || a.find(item.Device) < 0 {
			return errArrange
		}
		if before != nil && before.Device == item.Device {
			return nil
		}
		src := a.Items[a.find(item.Device)].Collection
		switch {
		case before == nil && src != nil:
			id := src.ID
			a.take(item.Device)
			if ci := a.collection(id); ci >= 0 {
				a.Items[ci].Collection.Devices = append(a.Items[ci].Collection.Devices, item.Device)
			} else {
				a.Items = append(a.Items, Item{Device: item.Device})
			}
			return nil
		case before == nil:
			a.take(item.Device)
			a.Items = append(a.Items, Item{Device: item.Device})
			return nil
		case before.Collection != "":
			at := a.collection(before.Collection)
			if at < 0 {
				return errArrange
			}
			a.take(item.Device)
			// The collection may have gone with its last device: then
			// the device stands where it was.
			if ci := a.collection(before.Collection); ci >= 0 {
				at = ci
			}
			a.Items = slices.Insert(a.Items, at, Item{Device: item.Device})
			return nil
		}
		if !shown[before.Device] || a.find(before.Device) < 0 {
			return errArrange
		}
		a.take(item.Device)
		bi := a.find(before.Device)
		if c := a.Items[bi].Collection; c != nil {
			c.Devices = slices.Insert(c.Devices, slices.Index(c.Devices, before.Device), item.Device)
		} else {
			a.Items = slices.Insert(a.Items, bi, Item{Device: item.Device})
		}
		return nil
	}
	ci := a.collection(item.Collection)
	if ci < 0 {
		return errArrange
	}
	it := a.Items[ci]
	at := -1
	if before != nil {
		if before.Collection == item.Collection {
			return nil
		}
		if before.Collection != "" {
			at = a.collection(before.Collection)
		} else if shown[before.Device] {
			at = a.find(before.Device)
		}
		if at < 0 {
			return errArrange
		}
	}
	a.Items = slices.Delete(a.Items, ci, ci+1)
	if before == nil {
		a.Items = append(a.Items, it)
		return nil
	}
	if before.Collection != "" {
		at = a.collection(before.Collection)
	} else {
		at = a.find(before.Device)
	}
	a.Items = slices.Insert(a.Items, at, it)
	return nil
}

// reset puts the devices back in the order given, the collections kept:
// each collection stands where its first device comes, with its devices in
// that order too.
func (a *Arrangement) reset(devices []string) {
	rank := map[string]int{}
	for i, d := range devices {
		rank[d] = i
	}
	byRank := func(x, y string) int {
		rx, okx := rank[x]
		ry, oky := rank[y]
		switch {
		case okx && oky:
			return rx - ry
		case okx:
			return -1
		case oky:
			return 1
		}
		return strings.Compare(x, y)
	}
	first := func(it Item) string {
		if it.Collection == nil {
			return it.Device
		}
		if len(it.Collection.Devices) == 0 {
			return ""
		}
		return it.Collection.Devices[0]
	}
	for _, it := range a.Items {
		if it.Collection != nil {
			slices.SortStableFunc(it.Collection.Devices, byRank)
		}
	}
	slices.SortStableFunc(a.Items, func(x, y Item) int {
		fx, fy := first(x), first(y)
		switch {
		case fx == "" && fy == "":
			return 0
		case fx == "":
			return 1
		case fy == "":
			return -1
		}
		return byRank(fx, fy)
	})
}

// find is the index of the top-level item that is or holds device d.
func (a *Arrangement) find(d string) int {
	return slices.IndexFunc(a.Items, func(it Item) bool {
		if it.Collection == nil {
			return it.Device == d
		}
		return slices.Contains(it.Collection.Devices, d)
	})
}

// collection is the index of the collection id.
func (a *Arrangement) collection(id string) int {
	if id == "" {
		return -1
	}
	return slices.IndexFunc(a.Items, func(it Item) bool { return it.Collection != nil && it.Collection.ID == id })
}

// take removes device d from where it is; a collection it leaves empty
// goes away.
func (a *Arrangement) take(d string) { a.takeExcept(d, "") }

func (a *Arrangement) takeExcept(d, keep string) {
	var items []Item
	for _, it := range a.Items {
		switch {
		case it.Collection == nil:
			if it.Device == d {
				continue
			}
		case it.Collection.ID != keep && slices.Contains(it.Collection.Devices, d):
			it.Collection.Devices = slices.DeleteFunc(it.Collection.Devices, func(x string) bool { return x == d })
			if len(it.Collection.Devices) == 0 {
				continue
			}
		}
		items = append(items, it)
	}
	a.Items = items
}

// newID is the smallest "cN" no collection has.
func (a *Arrangement) newID() string {
	for n := 1; ; n++ {
		id := "c" + strconv.Itoa(n)
		if a.collection(id) < 0 {
			return id
		}
	}
}

// collectionName is a collection's name trimmed, 1 to 64 bytes.
func collectionName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxCollectionName {
		return "", fmt.Errorf("%w: a collection's name has 1 to %d bytes", errArrange, maxCollectionName)
	}
	return s, nil
}
