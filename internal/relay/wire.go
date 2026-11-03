// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package relay is the blind relay: a meeting point for a group that has no
// computer to be its hub, on a server the user runs (docs/design.md, "Blind
// relay"). It holds none of the group's keys. Each member registers with
// its member certificate and proves its WireGuard key, and gets a tunnel to
// the relay; inside the tunnels the relay joins two members' connections
// end to end, so the member protocol's TLS runs between the two members
// and the relay passes only its ciphertext. It is still a star: members
// reach only the relay, and the relay decides which two connections to
// join, only within one group. The wire format is in docs/protocol.md,
// section 14.
package relay

import (
	"github.com/HunterEwok/cbb/internal/frame"
	"github.com/HunterEwok/cbb/internal/group"

	"net"
	"net/netip"
	"time"
)

// Protocol is the ALPN protocol of a member's registration.
const Protocol = "cbb-relay/2"

// proofLabel is the label of the key, from the registration's TLS, under
// which a member proves its WireGuard key.
const proofLabel = "cbb relay key"

// Addr is the relay's own address inside the tunnels; it gives each member
// another one.
var Addr = netip.MustParseAddr("fd00:cbb::1")

// The registration's messages, one JSON object a line, as the forwarder's
// (docs/protocol.md, section 14).
type (
	challenge struct {
		E []byte `json:"e"` // the relay's ephemeral X25519 key
		// Roots asks a device that registers with credentials for the
		// period credential and the group's roots: a relay that serves a
		// fixed list of groups knows them by their roots.
		Roots bool `json:"roots,omitempty"`
	}
	claim struct {
		Key   []byte `json:"key"`   // the member's WireGuard public key
		Proof []byte `json:"proof"` // HMAC-SHA256(X25519(member key, e), the TLS proof key)
		// Records are the group's authority records
		// (group.Records.AuthorityRecords): the relay keeps them for the
		// group and refuses, and drops, the devices they remove.
		Records []group.Record `json:"records,omitempty"`
		// Credentials are the period's hubs' and members' credentials, and
		// the period credential when the relay asks for the roots
		// (docs/protocol.md, section 18), in place of the records; Roots
		// are then the group's roots, the group CA first.
		Credentials []group.Credential `json:"credentials,omitempty"`
		Roots       [][]byte           `json:"roots,omitempty"`
	}
	welcome struct {
		Error string `json:"error,omitempty"` // why the relay refused it
		Key   []byte `json:"key,omitempty"`   // the relay's WireGuard public key
		PSK   []byte `json:"psk,omitempty"`   // this member's preshared key
		Addr  string `json:"addr,omitempty"`  // this member's tunnel address
	}
)

// The messages inside the tunnel, at the relay's member port: each
// connection starts with one request line; the relay answers with notes.
// A device's name is its device ID when it registered with its member
// certificate, or its pseudonym, the hash of its server key in hex, when
// it registered with the group's credentials.
type (
	request struct {
		Watch  bool   `json:"watch,omitempty"`  // keep this connection for the notes
		Dial   string `json:"dial,omitempty"`   // join this connection to that of the device of this name
		Answer string `json:"answer,omitempty"` // the ticket of a call this connection answers
	}
	note struct {
		Online *[]string `json:"online,omitempty"` // the other devices of the group on the relay now, by name
		Call   string    `json:"call,omitempty"`   // the name of a device that dials this one
		Ticket string    `json:"ticket,omitempty"` // to answer that call with
		OK     bool      `json:"ok,omitempty"`     // joined: the member protocol follows
		Error  string    `json:"error,omitempty"`
	}
)

// maxLine bounds a request or a note.
const maxLine = 64 << 10

// writeLine sends v as one frame (internal/frame), within d.
func writeLine(c net.Conn, v any, d time.Duration) error {
	c.SetWriteDeadline(time.Now().Add(d))
	err := frame.Write(c, v, maxLine)
	c.SetWriteDeadline(time.Time{})
	return err
}

// readLine reads one frame into v. A frame is read exactly, so nothing
// after it is taken from the connection: the member protocol follows an
// answer.
func readLine(c net.Conn, v any, d time.Duration) error {
	if d > 0 {
		c.SetReadDeadline(time.Now().Add(d))
		defer c.SetReadDeadline(time.Time{})
	}
	return frame.Read(c, v, maxLine)
}
