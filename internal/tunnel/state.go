// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/tpmkey"
)

// StateFile holds a member's tunnel state, next to its identity.
const StateFile = "tunnel.json"

const (
	maxMembers   = 256 // clients a hub keeps
	maxEndpoints = 8   // addresses of the hub a client keeps
)

// MarshalText encodes the key in standard base64, as WireGuard does.
func (k Key) MarshalText() ([]byte, error) {
	return base64.StdEncoding.AppendEncode(nil, k[:]), nil
}

// UnmarshalText decodes a key in standard base64.
func (k *Key) UnmarshalText(b []byte) error {
	var buf [33]byte // room for what 44 characters may decode to
	if len(b) != base64.StdEncoding.EncodedLen(len(k)) {
		return errors.New("tunnel: a key is not 32 bytes in base64")
	}
	n, err := base64.StdEncoding.Decode(buf[:], b)
	if err != nil || n != len(k) {
		return errors.New("tunnel: a key is not 32 bytes in base64")
	}
	copy(k[:], buf[:n])
	return nil
}

// State is a member's tunnel state: its own WireGuard key, the hubs it
// reaches away from home, and, on a hub, its clients. The member learns
// all of it inside the member protocol's TLS (docs/protocol.md, section 11).
type State struct {
	Key Key // this device's private key; it never leaves the device

	// PSK is this device's own preshared key, which its hello gives the
	// group's hubs, so that every hub uses the same one for it.
	PSK Key

	// Group is the tag of the group the rest belongs to; ForGroup clears
	// the rest when the device is in another group.
	Group string

	// Hubs are the offers of the group's hubs this device keeps, one per
	// hub, in the order they came; the member uses the first of them in
	// the group's order of hubs that answers (section 11, "Several hubs").
	Hubs []HubLink

	// IsHub tells whether this member is one of the group's hubs, which
	// admit the other members' keys. Endpoints are the hub's addresses that it
	// gives its clients, and ListenPort the UDP port it listens on (0 for
	// Port).
	IsHub      bool
	Endpoints  []netip.AddrPort
	ListenPort int
	Members    []Member

	// Obfuscation, on the hub, is the group's AmneziaWG settings, which
	// it gives its clients; nil for plain WireGuard.
	Obfuscation *Obfuscation

	// Forwarder is where the hub registers for the clients that cannot
	// reach it directly; nil without one.
	Forwarder *ForwarderLink

	// Relay is where this device meets the others of its group away from
	// home when the group has no hub: a blind relay the user runs; nil
	// without one. A device with a relay is neither a hub nor a client of
	// one.
	Relay *RelayLink

	// KeysInFile records that the user agreed to sync away from home
	// although this device keeps its keys in files, not in hardware
	// (docs/design.md, "Turning it on, step by step").
	KeysInFile bool

	// Serving, on a hub, is the WireGuard key it serves its clients with,
	// a new one for each period of the group's server credentials
	// (docs/protocol.md, section 11, "The hub's key"), so that a server on
	// the way cannot link the group's traffic from one period to the
	// next; zero while it serves with Key. ServingFor is the tag of its
	// period.
	Serving    Key
	ServingFor string

	// Next, on a hub, is the key it serves with from NextAt on, which its
	// offers give its clients ahead of time; zero for none. NextFor is the
	// tag of its period.
	Next    Key
	NextFor string
	NextAt  time.Time

	// The keys sealed by the TPM, as the state file keeps them.
	sealed, sealedServing, sealedNext sealing
}

// sealing is a key sealed by the TPM and the key it holds, so that a new
// key is sealed again.
type sealing struct {
	blob *tpmkey.Blob
	key  Key
}

// A Sealer keeps secrets in the device's TPM (docs/protocol.md, section
// 17): Seal returns nil, nil where secrets stay in files.
type Sealer interface {
	Seal(secret []byte) (*tpmkey.Blob, error)
	Unseal(*tpmkey.Blob) ([]byte, error)
}

// KeySealer seals the private key in the state file; nil keeps it in the
// file. The service sets it.
var KeySealer Sealer

// ForwarderLink is a hub's forwarder: its address, for UDP and TCP, and the
// pin of its key.
type ForwarderLink struct {
	Endpoint netip.AddrPort
	Pin      string
	// VLESSID, if set, is the group's VLESS user ID: the hub's clients
	// reach it only over VLESS to the forwarder, as VLESS says, which the
	// hub learns when it registers; nil until then.
	VLESSID string
	VLESS   *VLESS
	// Project marks the project's forwarder, whose pins the service takes
	// from keys.json at each start (forward.ProjectPins); Pin is the one
	// it accepted when the hub was set.
	Project bool
}

// RelayLink is a device's blind relay: its address, for UDP and TCP, and
// the pin of its key.
type RelayLink struct {
	Endpoint netip.AddrPort
	Pin      string
}

// HubEndpoints returns the addresses the hub gives its clients: its own,
// then the forwarder's, which clients try last.
func (s *State) HubEndpoints() []netip.AddrPort {
	eps := slices.Clone(s.Endpoints)
	if f := s.Forwarder; f != nil && !slices.Contains(eps, f.Endpoint) {
		eps = append(eps, f.Endpoint)
	}
	return eps
}

// Destinations returns the addresses on the internet that this device's
// tunnel reaches: a hub's forwarder, the hubs it keeps offers of and the
// forwarders it reaches over VLESS, or the relay. A hub answers its clients
// wherever they are, but only those that proved the group's keys.
func (s *State) Destinations() []netip.Addr {
	var out []netip.Addr
	add := func(ep netip.AddrPort) {
		if a := ep.Addr().Unmap(); a.IsValid() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	if s.Relay != nil {
		add(s.Relay.Endpoint)
		return out
	}
	if s.IsHub && s.Forwarder != nil {
		add(s.Forwarder.Endpoint)
		if v := s.Forwarder.VLESS; v != nil {
			add(v.Endpoint)
		}
	}
	for _, h := range s.Hubs {
		for _, ep := range h.Endpoints {
			add(ep)
		}
		if v := h.VLESS; v != nil {
			add(v.Endpoint)
		}
	}
	return out
}

// HubLink is what a client keeps of a hub's offer.
type HubLink struct {
	Device       string
	PublicKey    Key
	PresharedKey Key
	Endpoints    []netip.AddrPort
	Obfuscation  *Obfuscation // nil for plain WireGuard
	VLESS        *VLESS       // if set, the only way to the hub
	// Next is the key the hub serves with in its next period, which the
	// client tries after PublicKey; zero for none.
	Next Key
}

// Member is a client as its hub keeps it: its WireGuard key, its own
// preshared key, and the certificate chain it presented when it sent the
// key, so that the hub drops it when the group's records revoke it. A
// client that another hub handed over or shared has no chain until it meets
// this hub (docs/protocol.md, section 11, "Moving the hub" and "Several
// hubs"); the hub then keeps it by its device's records.
type Member struct {
	Device       string
	PublicKey    Key
	PresharedKey Key
	Chain        [][]byte // DER, the member certificate first
}

type stateFile struct {
	Version    int              `json:"v"`
	Key        *Key             `json:"key,omitempty"`
	KeyTPM     *tpmkey.Blob     `json:"key_tpm,omitempty"`
	PSK        *Key             `json:"psk,omitempty"`
	Group      string           `json:"group,omitempty"`
	ToHub      *hubFile         `json:"to_hub,omitempty"` // read from a state before several hubs
	Hubs       []hubFile        `json:"hubs,omitempty"`
	IsHub      bool             `json:"is_hub,omitempty"`
	Endpoints  []netip.AddrPort `json:"endpoints,omitempty"`
	ListenPort int              `json:"listen_port,omitempty"`
	Members    []memberFile     `json:"members,omitempty"`
	KeysInFile bool             `json:"keys_in_file,omitempty"`
	Forwarder  *forwarderFile   `json:"forwarder,omitempty"`
	Relay      *forwarderFile   `json:"relay,omitempty"`
	// Obfuscation is the hub's AmneziaWG settings.
	Obfuscation *Obfuscation `json:"obfuscation,omitempty"`
	// The hub's key for its clients, and the next one (State.Serving and
	// State.Next).
	Serving    *Key         `json:"serving,omitempty"`
	ServingTPM *tpmkey.Blob `json:"serving_tpm,omitempty"`
	ServingFor string       `json:"serving_for,omitempty"`
	Next       *Key         `json:"next,omitempty"`
	NextTPM    *tpmkey.Blob `json:"next_tpm,omitempty"`
	NextFor    string       `json:"next_for,omitempty"`
	NextAt     int64        `json:"next_at_ms,omitempty"`
}

type forwarderFile struct {
	Endpoint netip.AddrPort `json:"endpoint"`
	Pin      string         `json:"key"`
	VLESSID  string         `json:"vless_id,omitempty"`
	VLESS    *VLESS         `json:"vless,omitempty"`
	Project  bool           `json:"project,omitempty"`
}

type hubFile struct {
	Device       string           `json:"device"`
	PublicKey    Key              `json:"key"`
	PresharedKey Key              `json:"psk"`
	Endpoints    []netip.AddrPort `json:"endpoints,omitempty"`
	Obfuscation  *Obfuscation     `json:"obfuscation,omitempty"`
	VLESS        *VLESS           `json:"vless,omitempty"`
	Next         Key              `json:"next,omitzero"`
}

type memberFile struct {
	Device       string   `json:"device"`
	PublicKey    Key      `json:"key"`
	PresharedKey Key      `json:"psk"`
	Chain        [][]byte `json:"chain"`
}

// NewState returns a state with a new private key and preshared key.
func NewState() (*State, error) {
	k, err := NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("tunnel: making the key: %w", err)
	}
	psk, err := NewPresharedKey()
	if err != nil {
		return nil, fmt.Errorf("tunnel: making the key: %w", err)
	}
	return &State{Key: k, PSK: psk}, nil
}

// LoadState reads the state in dir. Without a state file it makes one with
// a new key; a state from before several hubs gets its own preshared key.
func LoadState(dir string) (*State, error) {
	data, err := os.ReadFile(filepath.Join(dir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		s, err := NewState()
		if err != nil {
			return nil, err
		}
		return s, s.Save(dir)
	}
	if err != nil {
		return nil, err
	}
	var f stateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", StateFile, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%s: unknown version %d", StateFile, f.Version)
	}
	s := &State{Group: f.Group, IsHub: f.IsHub, Endpoints: f.Endpoints, ListenPort: f.ListenPort, KeysInFile: f.KeysInFile,
		Obfuscation: f.Obfuscation, ServingFor: f.ServingFor, NextFor: f.NextFor}
	if f.NextAt != 0 {
		s.NextAt = time.UnixMilli(f.NextAt)
	}
	for _, k := range []struct {
		key    *Key
		sealed *sealing
		file   *Key
		blob   *tpmkey.Blob
	}{{&s.Key, &s.sealed, f.Key, f.KeyTPM}, {&s.Serving, &s.sealedServing, f.Serving, f.ServingTPM}, {&s.Next, &s.sealedNext, f.Next, f.NextTPM}} {
		switch {
		case k.blob != nil:
			if *k.key, err = unsealKey(k.blob); err != nil {
				return nil, fmt.Errorf("%s: %w", StateFile, err)
			}
			*k.sealed = sealing{k.blob, *k.key}
		case k.file != nil:
			*k.key = *k.file
		}
	}
	if f.ToHub != nil {
		f.Hubs = append([]hubFile{*f.ToHub}, f.Hubs...)
	}
	for _, h := range f.Hubs {
		s.Hubs = append(s.Hubs, HubLink(h))
	}
	for _, c := range f.Members {
		s.Members = append(s.Members, Member(c))
	}
	if f.Forwarder != nil {
		s.Forwarder = &ForwarderLink{Endpoint: f.Forwarder.Endpoint, Pin: f.Forwarder.Pin, VLESSID: f.Forwarder.VLESSID, VLESS: f.Forwarder.VLESS, Project: f.Forwarder.Project}
	}
	if f.Relay != nil {
		s.Relay = &RelayLink{Endpoint: f.Relay.Endpoint, Pin: f.Relay.Pin}
	}
	if err := s.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", StateFile, err)
	}
	if f.PSK != nil {
		s.PSK = *f.PSK
	} else {
		if s.PSK, err = NewPresharedKey(); err != nil {
			return nil, err
		}
		if err := s.Save(dir); err != nil {
			return nil, err
		}
	}
	if f.KeyTPM == nil && KeySealer != nil {
		// Move a key from the file into the TPM, when there is one.
		if err := s.seal(); err != nil {
			return nil, err
		}
		if s.sealed.blob != nil {
			if err := s.Save(dir); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

// Save writes the state to dir, readable only by its owner.
func (s *State) Save(dir string) error {
	if err := s.seal(); err != nil {
		return err
	}
	f := stateFile{Version: 1, KeyTPM: s.sealed.blob, Group: s.Group, IsHub: s.IsHub, Endpoints: s.Endpoints, ListenPort: s.ListenPort, KeysInFile: s.KeysInFile,
		Obfuscation: s.Obfuscation}
	if s.sealed.blob == nil {
		f.Key = &s.Key
	}
	if !s.Serving.IsZero() {
		f.ServingFor, f.ServingTPM = s.ServingFor, s.sealedServing.blob
		if f.ServingTPM == nil {
			f.Serving = &s.Serving
		}
	}
	if !s.Next.IsZero() {
		f.NextFor, f.NextTPM, f.NextAt = s.NextFor, s.sealedNext.blob, s.NextAt.UnixMilli()
		if f.NextTPM == nil {
			f.Next = &s.Next
		}
	}
	if !s.PSK.IsZero() {
		f.PSK = &s.PSK
	}
	for _, h := range s.Hubs {
		f.Hubs = append(f.Hubs, hubFile(h))
	}
	for _, c := range s.Members {
		f.Members = append(f.Members, memberFile(c))
	}
	if fw := s.Forwarder; fw != nil {
		f.Forwarder = &forwarderFile{Endpoint: fw.Endpoint, Pin: fw.Pin, VLESSID: fw.VLESSID, VLESS: fw.VLESS, Project: fw.Project}
	}
	if r := s.Relay; r != nil {
		f.Relay = &forwarderFile{Endpoint: r.Endpoint, Pin: r.Pin}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, StateFile), append(data, '\n'), 0o600)
}

// seal seals the keys with KeySealer once, and again when they changed. A
// key that was in the file moves to the TPM when the device has one.
func (s *State) seal() error {
	for _, k := range []struct {
		key Key
		c   *sealing
	}{{s.Key, &s.sealed}, {s.Serving, &s.sealedServing}, {s.Next, &s.sealedNext}} {
		if err := k.c.seal(k.key); err != nil {
			return err
		}
	}
	return nil
}

func (c *sealing) seal(k Key) error {
	if c.blob != nil && c.key == k {
		return nil
	}
	c.blob = nil
	if KeySealer == nil || k.IsZero() {
		return nil
	}
	b, err := KeySealer.Seal(k[:])
	if err != nil {
		return fmt.Errorf("tunnel: sealing the key: %w", err)
	}
	*c = sealing{b, k}
	return nil
}

// ServingKey returns the WireGuard key the hub serves its clients with.
func (s *State) ServingKey() Key {
	if !s.Serving.IsZero() {
		return s.Serving
	}
	return s.Key
}

// ownKey reports whether pub is one of this device's public keys.
func (s *State) ownKey(pub Key) bool {
	return pub == s.Key.Public() || !s.Serving.IsZero() && pub == s.Serving.Public() || !s.Next.IsZero() && pub == s.Next.Public()
}

// Rotate brings the hub's key for its clients up to the period tagged
// period (docs/protocol.md, section 11, "The hub's key"): a period it has
// no key for yet gets the next key, which the hub serves with from
// now+ahead on, and once that time came the next key is the one it serves
// with. changed tells whether the state must be saved and the offers sent
// again, and switched whether the hub must start again with the new key.
func (s *State) Rotate(period string, now time.Time, ahead time.Duration) (changed, switched bool, err error) {
	if !s.IsHub {
		return false, false, nil
	}
	if !s.Next.IsZero() && !now.Before(s.NextAt) {
		s.Serving, s.ServingFor = s.Next, s.NextFor
		s.Next, s.NextFor, s.NextAt = Key{}, "", time.Time{}
		changed, switched = true, true
	}
	if period == "" || period == s.ServingFor || period == s.NextFor {
		return changed, switched, nil
	}
	k, err := NewPrivateKey()
	if err != nil {
		return changed, switched, fmt.Errorf("tunnel: making the key: %w", err)
	}
	s.Next, s.NextFor, s.NextAt = k, period, now.Add(ahead)
	return true, switched, nil
}

func unsealKey(b *tpmkey.Blob) (Key, error) {
	if KeySealer == nil {
		return Key{}, errors.New("the key is sealed by a TPM, which this program does not use")
	}
	data, err := KeySealer.Unseal(b)
	if err != nil {
		return Key{}, err
	}
	var k Key
	if len(data) != len(k) {
		return Key{}, errors.New("the sealed key has the wrong length")
	}
	copy(k[:], data)
	return k, nil
}

// check refuses a state that would break the tunnel's rules.
func (s *State) check() error {
	if s.Key.IsZero() {
		return errors.New("no private key")
	}
	if len(s.HubEndpoints()) > maxEndpoints {
		return errors.New("too many endpoints")
	}
	if fw := s.Forwarder; fw != nil {
		if !fw.Endpoint.IsValid() || fw.Endpoint.Port() == 0 || fw.Pin == "" {
			return errors.New("a bad forwarder")
		}
		if fw.VLESSID != "" {
			if err := CheckVLESSID(fw.VLESSID); err != nil {
				return err
			}
		}
		if v := fw.VLESS; v != nil {
			if err := v.Check(); err != nil {
				return err
			}
			if v.ID != fw.VLESSID {
				return errors.New("the forwarder's VLESS settings are not the group's")
			}
		}
	}
	if r := s.Relay; r != nil {
		if !r.Endpoint.IsValid() || r.Endpoint.Port() == 0 || r.Pin == "" {
			return errors.New("a bad relay")
		}
		if s.IsHub || len(s.Hubs) > 0 {
			return errors.New("a device with a relay is neither a hub nor a hub's client")
		}
	}
	if o := s.Obfuscation; o != nil {
		if !s.IsHub {
			return errors.New("obfuscation settings on a device that is not the hub")
		}
		if err := o.Check(); err != nil {
			return err
		}
	}
	if s.ListenPort < 0 || s.ListenPort > 65535 {
		return fmt.Errorf("a bad listen port %d", s.ListenPort)
	}
	hubs := make(map[string]bool, len(s.Hubs))
	for _, h := range s.Hubs {
		if err := h.check(); err != nil {
			return err
		}
		if s.ownKey(h.PublicKey) || !h.Next.IsZero() && s.ownKey(h.Next) {
			return errors.New("a hub has this device's key")
		}
		if hubs[h.Device] {
			return fmt.Errorf("the hub %s is there twice", h.Device)
		}
		hubs[h.Device] = true
	}
	if len(s.Hubs) > maxMembers {
		return errors.New("too many hubs")
	}
	if len(s.Members) > maxMembers {
		return errors.New("too many clients")
	}
	devices := make(map[string]bool, len(s.Members))
	for _, c := range s.Members {
		if devices[c.Device] {
			return fmt.Errorf("the client %s is there twice", c.Device)
		}
		devices[c.Device] = true
	}
	_, err := s.peers()
	return err
}

func (h *HubLink) check() error {
	if _, err := Addr(h.Device); err != nil {
		return err
	}
	switch {
	case h.PublicKey.IsZero():
		return errors.New("the hub has no key")
	case h.PresharedKey.IsZero():
		return errors.New("the hub gave no preshared key")
	case len(h.Endpoints) > maxEndpoints:
		return errors.New("the hub gave too many endpoints")
	}
	for _, ep := range h.Endpoints {
		if !ep.IsValid() || ep.Port() == 0 {
			return fmt.Errorf("the hub gave a bad endpoint %v", ep)
		}
	}
	if o := h.Obfuscation; o != nil {
		if err := o.Check(); err != nil {
			return err
		}
	}
	if v := h.VLESS; v != nil {
		if err := v.Check(); err != nil {
			return err
		}
	}
	return nil
}

// ForGroup keeps the key and forgets the rest when it belongs to another
// group than the one tagged group. changed tells whether the state must be
// saved.
func (s *State) ForGroup(group string) (changed bool) {
	if s.Group == group {
		return false
	}
	*s = State{Key: s.Key, PSK: s.PSK, Group: group}
	return true
}

// Peers returns the hub's clients as its WireGuard peers.
func (s *State) Peers() []Peer {
	peers, _ := s.peers()
	return peers
}

func (s *State) peers() ([]Peer, error) {
	peers := make([]Peer, 0, len(s.Members))
	for _, c := range s.Members {
		a, err := Addr(c.Device)
		if err != nil {
			return nil, err
		}
		peers = append(peers, Peer{PublicKey: c.PublicKey, PresharedKey: c.PresharedKey, Addr: a})
	}
	if err := checkPeers(peers, netip.Addr{}); err != nil {
		return nil, err
	}
	for _, p := range peers {
		if s.ownKey(p.PublicKey) {
			return nil, errors.New("tunnel: a client has the hub's key")
		}
	}
	return peers, nil
}

// Admit adds or updates the client device with the WireGuard key and the
// preshared key it sent and the certificate chain it presented, and
// returns the client as the hub keeps it. A zero psk, from a member before
// several hubs, keeps the preshared key the client has, or makes one for a
// new key. changed tells whether the state must be saved.
func (s *State) Admit(device string, pub, psk Key, chain [][]byte) (c Member, changed bool, err error) {
	if _, err := Addr(device); err != nil {
		return Member{}, false, err
	}
	if len(chain) == 0 {
		return Member{}, false, errors.New("tunnel: a client without a certificate")
	}
	if pub.IsZero() || s.ownKey(pub) {
		return Member{}, false, errors.New("tunnel: a client offered no key or the hub's own")
	}
	i := slices.IndexFunc(s.Members, func(c Member) bool { return c.Device == device })
	for j, o := range s.Members {
		if j != i && o.PublicKey == pub {
			return Member{}, false, fmt.Errorf("tunnel: %s offered the key of %s", device, o.Device)
		}
	}
	if i >= 0 {
		c := &s.Members[i]
		if c.PublicKey == pub && (psk.IsZero() || c.PresharedKey == psk) && slices.EqualFunc(c.Chain, chain, bytes.Equal) {
			return *c, false, nil
		}
		switch {
		case !psk.IsZero():
			c.PresharedKey = psk
		case c.PublicKey != pub:
			if c.PresharedKey, err = NewPresharedKey(); err != nil {
				return Member{}, false, err
			}
		}
		c.PublicKey, c.Chain = pub, chain
		return *c, true, nil
	}
	if len(s.Members) >= maxMembers {
		return Member{}, false, errors.New("tunnel: the hub has too many clients")
	}
	if psk.IsZero() {
		if psk, err = NewPresharedKey(); err != nil {
			return Member{}, false, err
		}
	}
	c = Member{Device: device, PublicKey: pub, PresharedKey: psk, Chain: chain}
	s.Members = append(s.Members, c)
	return c, true, nil
}

// Take adds a client that another hub handed over or shared, with the key
// and the preshared key it has and no chain yet (docs/protocol.md, section
// 11, "Moving the hub" and "Several hubs"). A client this hub met itself
// stays as it is; one only handed over or shared before takes the new
// keys. changed tells whether the state must be saved.
func (s *State) Take(device string, pub, psk Key) (changed bool, err error) {
	if _, err := Addr(device); err != nil {
		return false, err
	}
	switch {
	case pub.IsZero() || psk.IsZero():
		return false, errors.New("tunnel: a client without a key")
	case s.ownKey(pub):
		return false, fmt.Errorf("tunnel: %s has the hub's own key", device)
	}
	i := -1
	for j, o := range s.Members {
		switch {
		case o.Device == device:
			i = j
		case o.PublicKey == pub:
			return false, fmt.Errorf("tunnel: %s has the key of %s", device, o.Device)
		}
	}
	if i >= 0 {
		c := &s.Members[i]
		if len(c.Chain) > 0 || c.PublicKey == pub && c.PresharedKey == psk {
			return false, nil
		}
		c.PublicKey, c.PresharedKey = pub, psk
		return true, nil
	}
	if len(s.Members) >= maxMembers {
		return false, errors.New("tunnel: the hub has too many clients")
	}
	s.Members = append(s.Members, Member{Device: device, PublicKey: pub, PresharedKey: psk})
	return true, nil
}

// Prune forgets the clients keep refuses and returns their devices.
func (s *State) Prune(keep func(Member) bool) []string {
	var gone []string
	s.Members = slices.DeleteFunc(s.Members, func(c Member) bool {
		if keep(c) {
			return false
		}
		gone = append(gone, c.Device)
		return true
	})
	return gone
}

// SetHub keeps the offer of a hub, in place of that hub's earlier one.
// changed tells whether the state must be saved.
func (s *State) SetHub(h HubLink) (changed bool, err error) {
	if err := h.check(); err != nil {
		return false, fmt.Errorf("tunnel: %w", err)
	}
	if s.ownKey(h.PublicKey) || !h.Next.IsZero() && s.ownKey(h.Next) {
		return false, errors.New("tunnel: the hub offered this device's own key")
	}
	h.Endpoints = slices.Clone(h.Endpoints)
	i := slices.IndexFunc(s.Hubs, func(o HubLink) bool { return o.Device == h.Device })
	if i < 0 {
		if len(s.Hubs) >= maxMembers {
			return false, errors.New("tunnel: too many hubs")
		}
		s.Hubs = append(s.Hubs, h)
		return true, nil
	}
	if o := s.Hubs[i]; o.PublicKey == h.PublicKey && o.Next == h.Next && o.PresharedKey == h.PresharedKey && slices.Equal(o.Endpoints, h.Endpoints) &&
		o.Obfuscation.Equal(h.Obfuscation) && o.VLESS.Equal(h.VLESS) {
		return false, nil
	}
	s.Hubs[i] = h
	return true, nil
}

// Hub returns the offer of the hub device that this device keeps; nil for
// none.
func (s *State) Hub(device string) *HubLink {
	for i := range s.Hubs {
		if s.Hubs[i].Device == device {
			return &s.Hubs[i]
		}
	}
	return nil
}

// ForgetHubs forgets the offers of the hubs keep refuses and returns
// their devices.
func (s *State) ForgetHubs(keep func(HubLink) bool) []string {
	var gone []string
	s.Hubs = slices.DeleteFunc(s.Hubs, func(h HubLink) bool {
		if keep(h) {
			return false
		}
		gone = append(gone, h.Device)
		return true
	})
	return gone
}
