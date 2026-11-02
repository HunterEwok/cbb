// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/netid"
	"github.com/HunterEwok/clipboardbridge/internal/node"
)

const (
	networksFile = "networks.json"
	// maxNetworks is how many known networks are kept; the one seen least
	// recently goes first.
	maxNetworks = 64
	// gatewaysEvery is how long the gateways' addresses are kept before
	// they are read again.
	gatewaysEvery = 30 * time.Second
)

// networks is the list of networks where this device met its group: it
// was created or joined there, opened a pairing window there, or a member
// connection came up there (docs/design.md, "Known networks"). Only on
// those does it publish itself by mDNS and take connections on the member
// port; elsewhere, in a café or a hotel, it only browses, so that its
// device ID and group tag do not follow it around. The file keeps a random
// key and the networks' IDs under it, which say nothing about the networks.
type networks struct {
	path string
	logf func(string, ...any)

	mu    sync.Mutex
	key   []byte
	known map[string]knownNetwork // by network ID (netid.ID with the gateway)
	gw    map[int]string          // gateway addresses by interface index
	gwAt  time.Time
	now   func() time.Time
	// gateways reads the gateways (netid.Gateways), interfaces lists the
	// interfaces (systemInterfaces); tests replace them.
	gateways   func() map[int]string
	interfaces func() ([]netInterface, error)
}

// netInterface is an interface with its addresses and their networks.
type netInterface struct {
	index    int
	name     string
	prefixes []netip.Prefix
}

// knownNetwork is a known network: the ID of its addresses alone, which
// tells it while its gateway's address is not known yet (just after it
// came up), and when it was seen last.
type knownNetwork struct {
	Net  string `json:"net"`
	Seen int64  `json:"seen"` // Unix seconds
}

type networksJSON struct {
	Key   []byte                  `json:"key"`
	Known map[string]knownNetwork `json:"known"`
}

// loadNetworks reads the known networks from dir. Without the file, a
// device that is in a group already (inGroup) counts the networks it is
// on now as known, as it is most likely at home when it is updated to a
// version that keeps the list; otherwise it would go quiet everywhere.
// With only, the interfaces outside it count as on no network at all, so
// that none of them is ever learnt (Config.Interfaces).
func loadNetworks(dir string, inGroup bool, only []string, logf func(string, ...any)) *networks {
	ifs := systemInterfaces
	if allow := onlyIn(only); allow != nil {
		ifs = func() ([]netInterface, error) {
			all, err := systemInterfaces()
			return slices.DeleteFunc(all, func(f netInterface) bool { return !allow(f.name) }), err
		}
	}
	return loadNetworksWith(dir, inGroup, logf, netid.Gateways, ifs)
}

func loadNetworksWith(dir string, inGroup bool, logf func(string, ...any), gateways func() map[int]string,
	interfaces func() ([]netInterface, error)) *networks {
	n := &networks{path: filepath.Join(dir, networksFile), logf: logf, known: map[string]knownNetwork{}, now: time.Now,
		gateways: gateways, interfaces: interfaces}
	b, err := os.ReadFile(n.path)
	switch {
	case err == nil:
		var j networksJSON
		if err := json.Unmarshal(b, &j); err != nil || len(j.Key) < 16 {
			logf("cbb: %s cannot be read; this device takes the networks it is on now as known: %v", networksFile, err)
			n.learnAll()
			return n
		}
		n.key = j.Key
		maps.Copy(n.known, j.Known)
	case errors.Is(err, os.ErrNotExist):
		if inGroup {
			n.learnAll()
		}
	default:
		logf("cbb: reading %s: %v", networksFile, err)
	}
	return n
}

// takesOn tells whether the member port takes a connection that came to
// the local address a: on a known network, or on any while a pairing
// window is open, which the user opens where the group is.
func (s *Service) takesOn(a net.Addr) bool {
	s.mu.Lock()
	open := s.window != nil || s.profileConns != nil
	s.mu.Unlock()
	if open {
		return true
	}
	ap, err := netip.ParseAddrPort(a.String())
	return err == nil && s.nets.Knows(ap.Addr())
}

// learnNetworks takes the networks this device is on now as known: it
// created or joined its group, or opened a pairing window, here; or the
// user said so (cbb network).
func (s *Service) learnNetworks() {
	if s.nets.learnAll() {
		s.recheckNetworks()
	}
}

// learnFrom takes the networks of the member connections that are up as
// known.
func (s *Service) learnFrom(peers []node.Peer) {
	added := false
	for _, p := range peers {
		if p.Local.IsValid() && !p.Local.IsLoopback() && s.nets.Learn(p.Local) {
			added = true
		}
	}
	if added {
		s.recheckNetworks()
	}
}

// recheckNetworks has discovery ask again where it may publish this
// device.
func (s *Service) recheckNetworks() {
	s.mu.Lock()
	r := s.responder
	s.mu.Unlock()
	if rc, ok := r.(interface{ Recheck() }); ok {
		rc.Recheck()
	}
}

// systemInterfaces lists the interfaces that are up, with the addresses
// mDNS may publish.
func systemInterfaces() ([]netInterface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netInterface
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		f := netInterface{index: ifc.Index, name: ifc.Name}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || !mdns.Published(ip.Unmap()) {
				continue
			}
			bits, _ := ipn.Mask.Size()
			f.prefixes = append(f.prefixes, netip.PrefixFrom(ip.Unmap(), bits))
		}
		if len(f.prefixes) > 0 {
			out = append(out, f)
		}
	}
	return out, nil
}

// idsLocked returns the IDs of the network of an interface, with its
// gateway and without; "" when it has none.
func (n *networks) idsLocked(index int, prefixes []netip.Prefix) (full, addrs string) {
	if n.key == nil {
		n.key = make([]byte, 32)
		rand.Read(n.key)
	}
	if n.gw == nil || n.now().Sub(n.gwAt) > gatewaysEvery {
		n.gw, n.gwAt = n.gateways(), n.now()
	}
	return netid.ID(n.key, prefixes, n.gw[index]), netid.ID(n.key, prefixes, "")
}

// knownLocked tells whether the network of an interface is known: by its
// gateway's address and its addresses, or, while the gateway's address is
// not known yet, by its addresses alone.
func (n *networks) knownLocked(index int, prefixes []netip.Prefix) bool {
	full, addrs := n.idsLocked(index, prefixes)
	if full == "" {
		return false
	}
	if _, ok := n.known[full]; ok {
		return true
	}
	if n.gw[index] == "" {
		for _, k := range n.known {
			if k.Net == addrs {
				return true
			}
		}
		return false
	}
	// A network learned before its gateway's address was known is bound
	// to the first gateway seen on it.
	if k, ok := n.known[addrs]; ok {
		delete(n.known, addrs)
		n.known[full] = k
		n.saveLocked()
		return true
	}
	return false
}

// Publish tells whether the interface name, with the networks prefixes, is
// on a known network: mdns.Config.Publish.
func (n *networks) Publish(name string, prefixes []netip.Prefix) bool {
	index := 0
	if ifc, err := net.InterfaceByName(name); err == nil {
		index = ifc.Index
	}
	// The same addresses as systemInterfaces: those mDNS may publish.
	prefixes = slices.DeleteFunc(slices.Clone(prefixes), func(p netip.Prefix) bool { return !mdns.Published(p.Addr()) })
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.knownLocked(index, prefixes)
}

// find returns the interface that has the address a. A link-local address
// of a connection names its interface as its zone, which the interface's
// own addresses have not.
func (n *networks) find(a netip.Addr) (netInterface, bool) {
	ifs, err := n.interfaces()
	if err != nil {
		return netInterface{}, false
	}
	a = a.WithZone("").Unmap()
	for _, f := range ifs {
		if slices.ContainsFunc(f.prefixes, func(p netip.Prefix) bool { return p.Addr() == a }) {
			return f, true
		}
	}
	return netInterface{}, false
}

// Knows tells whether the local address a of a connection is on a known
// network. An address of no interface (the tunnel's, which lives in the
// process) is not.
func (n *networks) Knows(a netip.Addr) bool {
	f, ok := n.find(a)
	if !ok {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.knownLocked(f.index, f.prefixes)
}

// Learn makes the network of the local address a known, as a member
// connection came up there. It reports whether the network is new.
func (n *networks) Learn(a netip.Addr) bool {
	f, ok := n.find(a)
	if !ok {
		return false
	}
	return n.add([]netInterface{f})
}

// learnAll makes the networks of every interface known: this device
// created or joined its group, or opens a pairing window, here. It reports
// whether one is new.
func (n *networks) learnAll() bool {
	ifs, err := n.interfaces()
	if err != nil {
		n.logf("cbb: listing the network interfaces: %v", err)
		return false
	}
	return n.add(ifs)
}

// Unknown lists the interfaces that are on networks this device does not
// know, for status.
func (n *networks) Unknown() []string {
	ifs, err := n.interfaces()
	if err != nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, f := range ifs {
		if full, _ := n.idsLocked(f.index, f.prefixes); full != "" && !n.knownLocked(f.index, f.prefixes) {
			out = append(out, f.name)
		}
	}
	slices.Sort(out)
	return out
}

func (n *networks) add(ifs []netInterface) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now().Unix()
	added := false
	for _, f := range ifs {
		full, addrs := n.idsLocked(f.index, f.prefixes)
		if full == "" {
			continue
		}
		if _, ok := n.known[full]; !ok {
			added = true
		}
		n.known[full] = knownNetwork{Net: addrs, Seen: now}
	}
	for len(n.known) > maxNetworks {
		oldest := ""
		for id, k := range n.known {
			if oldest == "" || k.Seen < n.known[oldest].Seen {
				oldest = id
			}
		}
		delete(n.known, oldest)
	}
	if added {
		n.saveLocked()
	}
	return added
}

func (n *networks) saveLocked() {
	b, err := json.Marshal(networksJSON{Key: n.key, Known: n.known})
	if err == nil {
		err = atomicfile.Write(n.path, b, 0o600)
	}
	if err != nil {
		n.logf("cbb: saving the known networks: %v", err)
	}
}
