// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

// Group is the signed release that this device's service holds, which its
// group's members passed it (docs/protocol.md, section 16, "In the
// group"): the last source, for a device that reaches no update server.
// Held returns the three files; they are checked as any server's are.
// The archives come from the group through Updater.Group.
type Group struct {
	Held func(ctx context.Context) (keys, channel, rel release.File, err error)
}

func (g Group) String() string { return "the group" }

func (g Group) Fetch(ctx context.Context, name, version string, max int64) ([]byte, error) {
	keys, ch, rel, err := g.Held(ctx)
	if err != nil {
		return nil, err
	}
	var f release.File
	switch name {
	case "keys.json":
		f = keys
	case Channel + ".json":
		f = ch
	case "release.json":
		var c release.Channel
		if err := json.Unmarshal(ch.Body, &c); err != nil || c.Release != version {
			return nil, fmt.Errorf("the group holds no release.json of %s", version)
		}
		f = rel
	default:
		return nil, fmt.Errorf("the group holds no %s", name)
	}
	data, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return data, nil
}

func (g Group) Open(context.Context, string, string) (io.ReadCloser, error) {
	return nil, errors.New("the group passes the archives itself")
}

// MirrorThrough is the mirror on dl.cbb.tools reached by dial, such as
// over VLESS to the hub's forwarder, whose server the mirror is on: dial
// gets the connection, and the TLS with the mirror's name goes inside it,
// checked as on any other way.
func MirrorThrough(dial func(ctx context.Context) (net.Conn, error)) Source {
	s := newHTTP(Mirror, false)
	t := s.client.Transport.(*http.Transport)
	t.Proxy = nil
	t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }
	t.TLSHandshakeTimeout = 30 * time.Second
	return &through{s}
}

// through names the way in String, for the log.
type through struct{ *httpSource }

func (t *through) String() string { return t.base + " over VLESS" }

// EntriesName is the signed list of the project's entry points, beside
// keys.json in the channel (docs/protocol.md, section 16, "Entry points").
const EntriesName = "entries.json"

// FetchEntries fetches the signed entry points from src; the service
// checks them.
func FetchEntries(ctx context.Context, src Source) (release.File, error) {
	var f release.File
	data, err := src.Fetch(ctx, EntriesName, "", maxManifest)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, fmt.Errorf("%s: %w", EntriesName, err)
	}
	return f, nil
}
