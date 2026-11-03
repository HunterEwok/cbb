// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package tvremote keeps the TVs a member types on as their remote
// (docs/roadmap.md, item 25, ways 2 and 4; cbb tv): an Android TV or a
// Google TV through its remote protocol (androidtv), an Apple TV through
// the Companion protocol (appletv), and a Roku through ECP (roku). A TV is a target, not a member: it holds no key of the
// group, and it is reached only on the home network.
package tvremote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/netguard"
	"github.com/HunterEwok/cbb/internal/tvremote/androidtv"
	"github.com/HunterEwok/cbb/internal/tvremote/appletv"
	"github.com/HunterEwok/cbb/internal/tvremote/roku"
)

// The kinds of TV.
const (
	AndroidTV = "androidtv"
	AppleTV   = "appletv"
	Roku      = "roku"
)

// stateFile is the TVs in the state directory. It holds the remote's
// private keys for the Android TVs and the Apple TVs, so it is the
// service's alone.
const stateFile = "tvs.json"

// MaxTVs is how many TVs a member keeps.
const MaxTVs = 16

// TV is one TV: its name, kind and address, for an Android TV the pin of
// its certificate, and for an Apple TV the pairing's keys. Pastes says the
// group's remote pastes go to it.
type TV struct {
	Name   string               `json:"name"`
	Kind   string               `json:"kind"`
	Host   string               `json:"host"`
	Pin    []byte               `json:"pin,omitempty"`
	Apple  *appletv.Credentials `json:"apple,omitempty"`
	Pastes bool                 `json:"pastes,omitempty"`
}

// State is the member's TVs, and the identity it pairs with Android TVs.
type State struct {
	TVs    []TV              `json:"tvs,omitempty"`
	Client *androidtv.Client `json:"client,omitempty"`
}

// Load reads the TVs from dir.
func Load(dir string) (State, error) {
	var s State
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("%s: %w", stateFile, err)
	}
	return s, nil
}

// Save writes the TVs to dir.
func Save(dir string, s State) error {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, stateFile), append(b, '\n'), 0o600)
}

// Find is the TV named name, any case, or the only TV when name is empty.
func (s State) Find(name string) (int, error) {
	if name == "" {
		if len(s.TVs) == 1 {
			return 0, nil
		}
		if len(s.TVs) == 0 {
			return -1, errors.New("no TV is added: add one with cbb remote add")
		}
		return -1, errors.New("there are several TVs: name one")
	}
	i := slices.IndexFunc(s.TVs, func(t TV) bool { return strings.EqualFold(t.Name, name) })
	if i < 0 {
		return -1, fmt.Errorf("no TV is named %q", name)
	}
	return i, nil
}

// Pasting is the TV the remote pastes go to, if any.
func (s State) Pasting() (TV, bool) {
	i := slices.IndexFunc(s.TVs, func(t TV) bool { return t.Pastes })
	if i < 0 {
		return TV{}, false
	}
	return s.TVs[i], true
}

// Put adds the TV, or replaces the one of the same name or address.
func (s *State) Put(t TV) error {
	i := slices.IndexFunc(s.TVs, func(o TV) bool {
		return strings.EqualFold(o.Name, t.Name) || (o.Host == t.Host && o.Kind == t.Kind)
	})
	if i >= 0 {
		t.Pastes = s.TVs[i].Pastes
		s.TVs[i] = t
		return nil
	}
	if len(s.TVs) >= MaxTVs {
		return fmt.Errorf("there are %d TVs already, the most a device keeps: remove one first", MaxTVs)
	}
	s.TVs = append(s.TVs, t)
	return nil
}

// ErrOutside is a TV whose address is not on the home network.
var ErrOutside = errors.New("the TV's address is not on the home network: a TV is reached only at home")

// CheckHost checks that host is an address or a name of the home network,
// and returns it trimmed. It may name a port, for tests.
func CheckHost(ctx context.Context, host string) (string, error) {
	host = strings.TrimSpace(host)
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	if name == "" {
		return "", errors.New("the TV's address is empty")
	}
	if a, err := netip.ParseAddr(name); err == nil {
		if !netguard.Home(a) {
			return "", ErrOutside
		}
		return host, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return "", fmt.Errorf("cannot find the TV %q: %w", name, err)
	}
	for _, a := range addrs {
		if !netguard.Home(a) {
			return "", ErrOutside
		}
	}
	return host, nil
}

// Dialer is how the remotes connect: to the home network only.
func Dialer() *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second, Control: netguard.ControlHome}
}

// Type types text on the TV, with Enter for each line break (an Apple TV
// takes the line break into the field's text); client is the identity
// paired with an Android TV.
func Type(ctx context.Context, t TV, client *androidtv.Client, text string) error {
	switch t.Kind {
	case AndroidTV:
		if client == nil {
			return errors.New("the TV is not paired: pair it again with cbb remote add")
		}
		r, err := androidtv.Dial(ctx, t.Host, *client, t.Pin)
		if err != nil {
			return err
		}
		defer r.Close()
		if err := r.WaitField(ctx, fieldWait); err != nil {
			return err
		}
		return r.Type(text)
	case AppleTV:
		if t.Apple == nil {
			return appletv.ErrNotPaired
		}
		r, err := appletv.Dial(ctx, t.Host, *t.Apple, RemoteName)
		if err != nil {
			return err
		}
		defer r.Close()
		return r.Type(text)
	case Roku:
		return roku.New(t.Host, Dialer().DialContext).Type(ctx, text)
	}
	return fmt.Errorf("the TV's kind %q is unknown", t.Kind)
}

// RemoteName is how an Apple TV knows the remote while it is connected.
const RemoteName = "CBB"

// fieldWait is how long Type waits for an Android TV to say a text field
// is open, which it does right after the remote starts.
const fieldWait = 2 * time.Second
