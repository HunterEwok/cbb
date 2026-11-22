// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// Fuzzed bytes (S20): forge -addr HOST:PORT fuzz-raw:SECONDS:SEED connects
// to the target's member port again and again for SECONDS and sends random
// bytes and TLS records before any handshake, as a stranger can. It prints
// the connections and frames it sent.
func fuzzCase(arg string) bool {
	return strings.HasPrefix(arg, "fuzz-raw:") || strings.HasPrefix(arg, "fuzz-control:")
}

func runFuzz(addr, socket, arg string) error {
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
	end := time.Now().Add(time.Duration(secs) * time.Second)
	conns, frames := 0, 0
	for time.Now().Before(end) {
		conns++
		raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		c := raw
		n := 1 + rng.IntN(20)
		for i := 0; i < n; i++ {
			if _, err := c.Write(rawFrame(rng)); err != nil {
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
	fmt.Printf("fuzz: %d connections, %d frames\n", conns, frames)
	return nil
}

// junk is what replaces a field's value.
var junk = []any{nil, -1, 1 << 62, 1.5, "", strings.Repeat("A", 70000), []any{}, map[string]any{}, true, "\x00\xff", "-0", []any{[]any{[]any{}}}}

// rawFrame is random bytes, sometimes behind a TLS record header that
// promises more than comes.
func rawFrame(rng *rand.Rand) []byte {
	b := make([]byte, 1+rng.IntN(4096))
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	if rng.IntN(3) == 0 {
		copy(b, []byte{0x16, 0x03, 0x01, 0xff, 0xff})
	}
	return b
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
	{"op": "copy", "len": 5}, {"op": "copy_media", "len": 10, "args": map[string]any{"type": "image/png"}},
	{"op": "config"}, {"op": "clipboard"}, {"op": "frobnicate"},
}

// runFuzzControl is fuzz-control:SECONDS:SEED: headers changed as
// mutate changes them, with payloads shorter or longer than they say,
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
