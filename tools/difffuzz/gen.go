// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
)

// A Case is one line of the corpus.
type Case struct {
	Kind string `json:"kind"`
	Body []byte `json:"body,omitempty"`
}

// A vector is a body of strict-generated-*.json or strict-files.json.
type vector struct {
	Body  []byte `json:"body"`
	Pad   int    `json:"pad"`
	PadAt int    `json:"pad_at"`
	Kind  string `json:"kind"`
}

func (v vector) full() []byte {
	if v.Pad == 0 {
		return v.Body
	}
	b := append([]byte{}, v.Body[:v.PadAt]...)
	b = append(b, bytes.Repeat([]byte("a"), v.Pad)...)
	return append(b, v.Body[v.PadAt:]...)
}

// seeds reads the bodies the corpus starts from, by kind.
func seeds(dir string) ([]Case, error) {
	var out []Case
	load := func(file string) (map[string][]vector, error) {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return nil, err
		}
		var v map[string][]vector
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		return v, nil
	}
	take := func(file string, v map[string][]vector, sections map[string]string) error {
		names := make([]string, 0, len(sections))
		for s := range sections {
			names = append(names, s)
		}
		sort.Strings(names)
		for _, s := range names {
			if len(v[s]) == 0 {
				return fmt.Errorf("%s: no %s", file, s)
			}
			for _, c := range v[s] {
				kind := sections[s]
				if kind == "" {
					kind = c.Kind
				}
				out = append(out, Case{Kind: kind, Body: c.full()})
			}
		}
		return nil
	}
	read := func(file string, sections map[string]string) error {
		v, err := load(file)
		if err != nil {
			return err
		}
		return take(file, v, sections)
	}
	// The generated vectors, in as many files as they take.
	generated := map[string][]vector{}
	for i := 1; ; i++ {
		v, err := load(fmt.Sprintf("strict-generated-%d.json", i))
		if errors.Is(err, fs.ErrNotExist) && i > 1 {
			break
		}
		if err != nil {
			return nil, err
		}
		for s, l := range v {
			generated[s] = append(generated[s], l...)
		}
	}
	if err := take("strict-generated-*.json", generated, map[string]string{"manifests": "manifest"}); err != nil {
		return nil, err
	}
	if err := read("strict-files.json", map[string]string{"releases": ""}); err != nil {
		return nil, err
	}
	return out, nil
}

// maxSeed is the size of the largest body the corpus changes.
const maxSeed = 9 << 10

// generate returns the corpus: every seed body as it is and n changed
// bodies, from the seed.
func generate(dir string, seed uint64, n int) ([]Case, error) {
	base, err := seeds(dir)
	if err != nil {
		return nil, err
	}
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	m := mutator{r: r}
	out := append([]Case{}, base...)
	seen := map[string]bool{}
	for _, c := range base {
		seen[c.Kind+"\x00"+string(c.Body)] = true
	}
	// Each kind as often as the others, from its bodies of a few
	// kilobytes at most: the long ones are in the corpus as they are.
	byKind := map[string][]Case{}
	var kinds []string
	for _, c := range base {
		if len(c.Body) > maxSeed {
			continue
		}
		if byKind[c.Kind] == nil {
			kinds = append(kinds, c.Kind)
		}
		byKind[c.Kind] = append(byKind[c.Kind], c)
	}
	for tries := 0; len(out) < len(base)+n && tries < 4*n; tries++ {
		l := byKind[kinds[r.IntN(len(kinds))]]
		c := l[r.IntN(len(l))]
		body := c.Body
		for k := 1 + r.IntN(3); k > 0; k-- {
			body = m.mutate(body)
		}
		key := c.Kind + "\x00" + string(body)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Case{Kind: c.Kind, Body: body})
	}
	return out, nil
}

// writeCorpus writes the cases one to a line.
func writeCorpus(path string, cases []Case) error {
	f := os.Stdout
	if path != "" {
		var err error
		if f, err = os.Create(path); err != nil {
			return err
		}
		defer f.Close()
	}
	w := bufio.NewWriter(f)
	for _, c := range cases {
		line, err := json.Marshal(c)
		if err != nil {
			return err
		}
		w.Write(line)
		w.WriteByte('\n')
	}
	return w.Flush()
}

// readCorpus reads a corpus that writeCorpus wrote.
func readCorpus(path string) ([]Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Case
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var c Case
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		out = append(out, c)
	}
	return out, nil
}

var b64 = base64.StdEncoding

// fuzzTargets names the cargo fuzz target of each kind of body.
var fuzzTargets = map[string]string{
	"manifest": "wire",
	"keys":     "release", "release": "release", "channel": "release",
}

// writeSeeds writes every seed body to out/<target>/<n>.
func writeSeeds(dir, out string) error {
	base, err := seeds(dir)
	if err != nil {
		return err
	}
	n := map[string]int{}
	for _, c := range base {
		t := fuzzTargets[c.Kind]
		if t == "" || len(c.Body) > maxSeed {
			continue
		}
		if err := os.MkdirAll(filepath.Join(out, t), 0o755); err != nil {
			return err
		}
		n[t]++
		if err := os.WriteFile(filepath.Join(out, t, fmt.Sprint(n[t])), c.Body, 0o644); err != nil {
			return err
		}
	}
	if err := writeFormatSeeds(filepath.Join(filepath.Dir(dir), "format"), out); err != nil {
		return err
	}
	return writeAPISeeds(dir, filepath.Join(out, "api"), base)
}

// writeFormatSeeds writes the seeds of the 0.6 readers' targets from the
// vectors of testdata/format: sheet (each sheet's text and QR code, and the
// inputs read and refused), yubikey_object (the objects sealed and
// refused), command (the commands and orders of wave4.json), welcome_fields (the Welcome a good tag covers) and
// welcome_parts (that Welcome with its length in front, then the `records`
// frame of frames.json once for each part it announces, each with a step
// of one second and its length; the target tries them in both orders).
func writeFormatSeeds(dir string, out string) error {
	load := func(name string, v any) error {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		return json.Unmarshal(b, v)
	}
	var sheet struct {
		Take []struct {
			Text string `json:"text"`
			QR   string `json:"qr"`
		} `json:"take"`
		Read   []struct{ Input string } `json:"read"`
		Refuse []struct{ Input string } `json:"refuse"`
		Yubi   struct {
			Take   []struct{ Object string } `json:"take"`
			Refuse []struct{ Object string } `json:"refuse"`
		} `json:"yubikey"`
	}
	var msgs struct {
		Parts struct {
			Tag []struct{ Welcome string } `json:"tag"`
		} `json:"welcome_parts"`
	}
	var frames struct {
		Take []struct {
			Name  string `json:"name"`
			Frame string `json:"frame"`
		} `json:"take"`
	}
	var wave4 struct {
		Commands []struct{ Envelope string } `json:"commands"`
		Orders   []struct{ Orders string }   `json:"orders"`
	}
	for name, v := range map[string]any{"sheet.json": &sheet, "messages3.json": &msgs, "frames.json": &frames, "wave4.json": &wave4} {
		if err := load(name, v); err != nil {
			return err
		}
	}
	seeds := map[string][][]byte{}
	add := func(target string, b []byte) { seeds[target] = append(seeds[target], b) }
	for _, t := range sheet.Take {
		add("sheet", []byte(t.Text))
		add("sheet", []byte(t.QR))
	}
	for _, t := range sheet.Read {
		add("sheet", []byte(t.Input))
	}
	for _, t := range sheet.Refuse {
		add("sheet", []byte(t.Input))
	}
	for _, o := range append(sheet.Yubi.Take, sheet.Yubi.Refuse...) {
		b, err := hex.DecodeString(o.Object)
		if err != nil {
			return err
		}
		add("yubikey_object", b)
	}
	for _, c := range wave4.Commands {
		b, err := hex.DecodeString(c.Envelope)
		if err != nil {
			return err
		}
		add("command", b)
	}
	for _, o := range wave4.Orders {
		b, err := hex.DecodeString(o.Orders)
		if err != nil {
			return err
		}
		add("command", b)
	}
	var part []byte
	for _, f := range frames.Take {
		if f.Name == "records" {
			b, err := hex.DecodeString(f.Frame)
			if err != nil {
				return err
			}
			part = b
		}
	}
	if part == nil {
		return errors.New("frames.json has no records frame")
	}
	for _, t := range msgs.Parts.Tag {
		if t.Welcome == "" {
			continue
		}
		w, err := hex.DecodeString(t.Welcome)
		if err != nil {
			return err
		}
		add("welcome_fields", w)
		for n := 0; n <= 3; n++ {
			b := []byte{byte(len(w) >> 8), byte(len(w))}
			b = append(b, w...)
			for range n {
				b = append(b, 1, byte(len(part)>>16), byte(len(part)>>8), byte(len(part)))
				b = append(b, part...)
			}
			add("welcome_parts", b)
		}
	}
	for target, list := range seeds {
		if err := os.MkdirAll(filepath.Join(out, target), 0o755); err != nil {
			return err
		}
		for i, b := range list {
			if err := os.WriteFile(filepath.Join(out, target, fmt.Sprint(i+1)), b, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeAPISeeds writes the seeds of the cargo fuzz target api, requests to
// the core's entry point (docs/core-api.md): the version, each body of the
// corpus's seeds of a kind parse_body reads, and a few invitations'
// shapes for read_invite.
func writeAPISeeds(dir, out string, base []Case) error {
	var reqs [][]byte
	add := func(op string, args any) error {
		b, err := json.Marshal(map[string]any{"abi": 1, "op": op, "args": args})
		if err != nil {
			return err
		}
		reqs = append(reqs, b)
		return nil
	}
	if err := add("version", nil); err != nil {
		return err
	}
	bodies := map[string]int{}
	for _, c := range base {
		if len(c.Body) > maxSeed || bodies[c.Kind] >= 50 {
			continue
		}
		bodies[c.Kind]++
		if err := add("parse_body", map[string]any{"kind": c.Kind, "body": c.Body}); err != nil {
			return err
		}
	}
	// Invitations: a few shapes, the corpus's mutations do the rest.
	for _, text := range []string{"cbb://join#", "cbb://join#oA", "cbb://join#pAFQ", "cbb://invite#e30"} {
		if err := add("read_invite", map[string]string{"text": text}); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for i, r := range reqs {
		if err := os.WriteFile(filepath.Join(out, fmt.Sprint(i+1)), r, 0o644); err != nil {
			return err
		}
	}
	return nil
}
