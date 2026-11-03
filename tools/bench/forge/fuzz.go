// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
)

// Fuzzed frames (S20): forge -state DIR -to DEVICE -addr HOST:PORT
// fuzz:SECONDS:SEED connects to the target as the member whose state DIR
// holds, again and again for SECONDS, and sends it frames made from valid
// ones with fields dropped, changed or of the wrong type, lengths that lie,
// and bytes at random; forge -addr HOST:PORT fuzz-raw:SECONDS:SEED sends
// random bytes and TLS records before any handshake, as a stranger can. It
// prints the connections and frames it sent, and how many connections the
// target took.
func fuzzCase(arg string) bool {
	return strings.HasPrefix(arg, "fuzz:") || strings.HasPrefix(arg, "fuzz-raw:") || strings.HasPrefix(arg, "fuzz-control:")
}

func runFuzz(state string, to group.DeviceID, addr, socket, arg string) error {
	if strings.HasPrefix(arg, "fuzz-control:") {
		if socket == "" {
			socket = control.SocketPath()
		}
		return runFuzzControl(socket, arg)
	}
	kind, rest, _ := strings.Cut(arg, ":")
	var secs int
	var seed uint64
	if _, err := fmt.Sscanf(strings.ReplaceAll(rest, ":", " "), "%d %d", &secs, &seed); err != nil {
		return fmt.Errorf("%s:SECONDS:SEED, not %q", kind, arg)
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	var cfg *tls.Config
	if kind == "fuzz" {
		id, err := group.Load(state)
		if err != nil {
			return err
		}
		cfg = id.ClientTLS(to, group.TLSOptions{})
	}
	end := time.Now().Add(time.Duration(secs) * time.Second)
	conns, taken, frames := 0, 0, 0
	for time.Now().Before(end) {
		conns++
		raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		var c net.Conn = raw
		if cfg != nil {
			tc := tls.Client(raw, cfg)
			if tc.Handshake() != nil {
				raw.Close()
				continue
			}
			taken++
			c = tc
		}
		n := 1 + rng.IntN(20)
		for i := 0; i < n; i++ {
			if _, err := c.Write(fuzzFrame(rng, cfg == nil, i == 0)); err != nil {
				break
			}
			frames++
		}
		// Read what comes back for a moment, so the target's writes
		// are not what stops it.
		c.SetReadDeadline(time.Now().Add(time.Duration(rng.IntN(300)) * time.Millisecond))
		buf := make([]byte, 64<<10)
		for {
			if _, err := c.Read(buf); err != nil {
				break
			}
		}
		c.Close()
	}
	fmt.Printf("fuzz: %d connections, %d taken, %d frames\n", conns, taken, frames)
	return nil
}

// seeds are valid frames of the member protocol (docs/protocol.md,
// section 4), which fuzzFrame changes.
var seeds = []map[string]any{
	{"t": "hello", "role": "full", "hello": map[string]any{"os": "linux", "wall_ms": 1761024000000, "name": "forge", "mode": "shared"}},
	{"t": "hello", "role": "phone", "hello": map[string]any{"current": map[string]any{"id": "9f0c", "origin": "3b1e", "time": "1761023990000.0", "age_ms": 10, "kind": "text", "text": "x"}}},
	{"t": "event", "event": map[string]any{"id": "77aa", "origin": "3b1e", "via": "phone", "time": "1761024001234.2", "age_ms": 15, "kind": "text", "text": "fuzz"}},
	{"t": "ping"}, {"t": "bye"}, {"t": "cert", "cert": "MIIB"},
	{"t": "records", "records": []any{map[string]any{"body": "e30", "sig": "AA"}}},
	{"t": "get", "get": map[string]any{"sha256": "AAAA", "offset": 0, "length": 1 << 20}},
	{"t": "command", "command": map[string]any{"body": "e30", "sig": "AA"}},
	{"t": "result", "result": map[string]any{"id": "x", "status": "done"}},
	{"t": "tunnel", "tunnel": map[string]any{"key": "AA"}},
	{"t": "credentials", "credentials": []any{"AA"}},
	{"t": "release", "release": map[string]any{"keys": "", "channel": "", "release": ""}},
	{"t": "evidence", "evidence": map[string]any{"kind": "tpm"}},
}

// junk is what replaces a field's value.
var junk = []any{nil, -1, 1 << 62, 1.5, "", strings.Repeat("A", 70000), []any{}, map[string]any{}, true, "\x00\xff", "-0", []any{[]any{[]any{}}}}

func fuzzFrame(rng *rand.Rand, raw, first bool) []byte {
	if raw {
		b := make([]byte, 1+rng.IntN(4096))
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		if rng.IntN(3) == 0 {
			// A TLS record header that promises more than comes.
			copy(b, []byte{0x16, 0x03, 0x01, 0xff, 0xff})
		}
		return b
	}
	seed := seeds[rng.IntN(len(seeds))]
	if first && rng.IntN(2) == 0 {
		seed = seeds[0]
	}
	m := mutate(rng, seed, 0).(map[string]any)
	body, _ := json.Marshal(m)
	switch rng.IntN(10) {
	case 0: // bytes changed in the JSON
		for i := 0; i < 1+rng.IntN(8) && len(body) > 0; i++ {
			body[rng.IntN(len(body))] = byte(rng.Uint32())
		}
	case 1: // cut short
		body = body[:rng.IntN(len(body)+1)]
	}
	n := uint32(len(body))
	switch rng.IntN(12) {
	case 0:
		n = 7<<20 + 1 // over the limit
	case 1:
		n = 0x80000000 | uint32(rng.IntN(300000)) // a chunk no one asked for
	case 2:
		n += uint32(rng.IntN(100)) // more than comes
	}
	out := binary.BigEndian.AppendUint32(nil, n)
	return append(out, body...)
}

// mutate copies v, dropping, replacing or adding fields at random.
func mutate(rng *rand.Rand, v any, depth int) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			switch rng.IntN(8) {
			case 0: // dropped
			case 1:
				out[k] = junk[rng.IntN(len(junk))]
			default:
				out[k] = mutate(rng, x, depth+1)
			}
		}
		if rng.IntN(6) == 0 {
			out[fmt.Sprintf("x%d", rng.IntN(100))] = junk[rng.IntN(len(junk))]
		}
		return out
	case []any:
		var out []any
		for _, x := range t {
			out = append(out, mutate(rng, x, depth+1))
		}
		if rng.IntN(5) == 0 {
			for i := 0; i < rng.IntN(2000); i++ {
				out = append(out, junk[rng.IntN(len(junk))])
			}
		}
		return out
	case string:
		if rng.IntN(5) == 0 {
			return junk[rng.IntN(len(junk))]
		}
		return t
	default:
		if rng.IntN(5) == 0 {
			return junk[rng.IntN(len(junk))]
		}
		return t
	}
}

// controlSeeds are headers of the control socket (docs/protocol.md,
// section 8) for everyone, which fuzz-control changes; none of them
// changes the group.
var controlSeeds = []map[string]any{
	{"op": "status"}, {"op": "devices"}, {"op": "paste"}, {"op": "watch"},
	{"op": "copy", "len": 5}, {"op": "copy_media", "len": 10, "type": "image/png"},
	{"op": "config"}, {"op": "clipboard"}, {"op": "frobnicate"},
}

// runFuzzControl is fuzz-control:SECONDS:SEED: headers changed as
// fuzzFrame changes frames, with payloads shorter or longer than they say,
// on the control socket at path.
func runFuzzControl(path, arg string) error {
	var secs int
	var seed uint64
	if _, err := fmt.Sscanf(strings.ReplaceAll(strings.TrimPrefix(arg, "fuzz-control:"), ":", " "), "%d %d", &secs, &seed); err != nil {
		return fmt.Errorf("fuzz-control:SECONDS:SEED, not %q", arg)
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	end := time.Now().Add(time.Duration(secs) * time.Second)
	conns := 0
	for time.Now().Before(end) {
		c, err := net.DialTimeout("unix", path, 5*time.Second)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		conns++
		c.SetDeadline(time.Now().Add(5 * time.Second))
		for i := 0; i < 1+rng.IntN(5); i++ {
			h, _ := json.Marshal(mutate(rng, controlSeeds[rng.IntN(len(controlSeeds))], 0))
			if rng.IntN(8) == 0 {
				h = h[:rng.IntN(len(h)+1)]
			}
			h = append(h, '\n')
			h = append(h, make([]byte, rng.IntN(64))...)
			if _, err := c.Write(h); err != nil {
				break
			}
		}
		c.SetReadDeadline(time.Now().Add(time.Duration(rng.IntN(200)) * time.Millisecond))
		buf := make([]byte, 16<<10)
		for {
			if _, err := c.Read(buf); err != nil {
				break
			}
		}
		c.Close()
	}
	fmt.Printf("fuzz-control: %d connections\n", conns)
	return nil
}
