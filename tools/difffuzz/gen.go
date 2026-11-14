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
	"slices"
	"sort"
	"strings"
)

// A Case is one line of the corpus.
type Case struct {
	Kind    string   `json:"kind"`
	Body    []byte   `json:"body,omitempty"`
	CA      []byte   `json:"ca,omitempty"`
	Records []Record `json:"records,omitempty"`
	Keys    [][]byte `json:"keys,omitempty"`
}

// A Record is a signed record as the interop vectors and the member
// protocol carry it.
type Record struct {
	Body  []byte   `json:"body"`
	Sig   []byte   `json:"sig"`
	Chain [][]byte `json:"chain,omitempty"`
}

// A vector is a body of strict-generated-*.json, strict-files.json or
// strict-mutants-*.json.
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

// A setSource is a record set of the interop vectors.
type setSource struct {
	name    string
	ca      []byte
	records []Record
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
	if err := take("strict-generated-*.json", generated, map[string]string{"records": "record", "commands": "command", "manifests": "manifest"}); err != nil {
		return nil, err
	}
	if err := read("strict-files.json", map[string]string{"credentials": "credential", "releases": ""}); err != nil {
		return nil, err
	}
	// More record bodies in the same form, as many files as there are.
	mutants, err := filepath.Glob(filepath.Join(dir, "strict-mutants-*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(mutants)
	for _, f := range mutants {
		if err := read(filepath.Base(f), map[string]string{"records": "record"}); err != nil {
			return nil, err
		}
	}
	// The bodies of records v2, which the others read, from the cases of
	// the state's vectors, when the directory has them.
	data, err := os.ReadFile(filepath.Join(dir, "v2-records.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	var v2 struct {
		Cases []struct {
			Records []Record `json:"records"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &v2); err != nil {
		return nil, fmt.Errorf("v2-records.json: %w", err)
	}
	for _, c := range v2.Cases {
		for _, r := range c.Records {
			out = append(out, Case{Kind: "record", Body: r.Body})
		}
	}
	return out, nil
}

// setSources reads every record set of the interop vectors: a file with a
// group_ca and records, or a list of such cases, alone or under "cases".
// The records of a set's "later" go with it, so the set holds both.
func setSources(dir string) ([]setSource, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	type raw struct {
		Name    string   `json:"name"`
		GroupCA []byte   `json:"group_ca"`
		Records []Record `json:"records"`
		Later   []Record `json:"later"`
	}
	var out []setSource
	add := func(name string, r raw) {
		if len(r.GroupCA) == 0 || len(r.Records) == 0 {
			return
		}
		out = append(out, setSource{name: name, ca: r.GroupCA, records: append(r.Records, r.Later...)})
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		base := strings.TrimSuffix(filepath.Base(f), ".json")
		var one raw
		if json.Unmarshal(data, &one) == nil {
			add(base, one)
		}
		var many struct {
			Cases []raw `json:"cases"`
		}
		if json.Unmarshal(data, &many) == nil {
			for _, c := range many.Cases {
				add(base+"/"+c.Name, c)
			}
		}
		var list []raw
		if json.Unmarshal(data, &list) == nil {
			for _, c := range list {
				add(base+"/"+c.Name, c)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no record sets", dir)
	}
	return out, nil
}

// keysOf returns every key hash the records' bodies name, sorted: the keys
// whose state a set's verdict reports.
func keysOf(rs []Record) [][]byte {
	seen := map[string]bool{}
	for _, r := range rs {
		var b struct {
			Key   []byte   `json:"key"`
			Admin []byte   `json:"admin"`
			Keys  [][]byte `json:"keys"`
			Keep  [][]byte `json:"keep"`
		}
		if json.Unmarshal(r.Body, &b) != nil {
			continue
		}
		for _, k := range append(append([][]byte{b.Key, b.Admin}, b.Keys...), b.Keep...) {
			if len(k) == 32 {
				seen[string(k)] = true
			}
		}
	}
	out := make([][]byte, 0, len(seen))
	for k := range seen {
		out = append(out, []byte(k))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

// maxSeed is the size of the largest body the corpus changes.
const maxSeed = 9 << 10

// generate returns the corpus: every seed body as it is, n changed bodies
// and sets record sets, from the seed.
func generate(dir string, seed uint64, n, sets int) ([]Case, error) {
	base, err := seeds(dir)
	if err != nil {
		return nil, err
	}
	srcs, err := setSources(dir)
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
	// Every set as it is, reversed and in two other orders: what a set
	// decides must not depend on the order its records come in.
	for _, s := range srcs {
		out = append(out, Case{Kind: "set", CA: s.ca, Records: s.records, Keys: keysOf(s.records)})
		reversed := slices.Clone(s.records)
		slices.Reverse(reversed)
		out = append(out, Case{Kind: "set", CA: s.ca, Records: reversed, Keys: keysOf(s.records)})
		for range 2 {
			rs := slices.Clone(s.records)
			r.Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
			out = append(out, Case{Kind: "set", CA: s.ca, Records: rs, Keys: keysOf(s.records)})
		}
	}
	for i := 0; i < sets; i++ {
		s := srcs[r.IntN(len(srcs))]
		out = append(out, m.set(s))
	}
	return out, nil
}

// set returns a changed copy of a record set: some of its records, in
// another order, some twice, some with their chain or signature changed.
func (m mutator) set(s setSource) Case {
	keep := []float64{1, 1, 0.9, 0.7, 0.5}[m.r.IntN(5)]
	var rs []Record
	for _, rec := range s.records {
		if m.r.Float64() < keep {
			rs = append(rs, rec)
		}
	}
	m.r.Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
	if len(rs) > 0 && m.r.IntN(4) == 0 {
		rs = append(rs, rs[m.r.IntN(len(rs))])
	}
	if len(rs) > 0 && m.r.IntN(6) == 0 {
		i := m.r.IntN(len(rs))
		c := rs[i]
		switch m.r.IntN(4) {
		case 0:
			c.Chain = nil
		case 1:
			c.Sig = flip(m.r, c.Sig)
		case 2:
			c.Body = flip(m.r, c.Body)
		default:
			// Another record's signature.
			c.Sig = rs[m.r.IntN(len(rs))].Sig
		}
		rs[i] = c
	}
	return Case{Kind: "set", CA: s.ca, Records: rs, Keys: keysOf(s.records)}
}

func flip(r *rand.Rand, b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	out := append([]byte{}, b...)
	out[r.IntN(len(out))] ^= byte(1 << r.IntN(8))
	return out
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
	"record": "record_body", "command": "command", "credential": "credential", "manifest": "wire",
	"keys": "release", "release": "release", "channel": "release",
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
// refused), welcome_fields (the Welcome a good tag covers) and
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
	for name, v := range map[string]any{"sheet.json": &sheet, "messages3.json": &msgs, "frames.json": &frames} {
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
// the core's entry point (docs/core-api.md): each case of v2-records.json
// as the arguments of evaluate, and of evaluate_saved with a secret, the
// version, and the first 100 record bodies for check_body and
// canonicalize, and each chain of member-chains.json for check_member.
func writeAPISeeds(dir, out string, base []Case) error {
	data, err := os.ReadFile(filepath.Join(dir, "v2-records.json"))
	if err != nil {
		return err
	}
	var v struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("v2-records.json: %w", err)
	}
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
	for _, c := range v.Cases {
		args := map[string]json.RawMessage{}
		for _, k := range []string{"group_ca", "group", "now_ms", "time_unknown", "first_seen", "records"} {
			if c[k] != nil {
				args[k] = c[k]
			}
		}
		if err := add("evaluate", args); err != nil {
			return err
		}
		args["secret"] = json.RawMessage(`"c2VjcmV0IG9mIHRoZSBtZW1iZXIhIQ=="`)
		if err := add("evaluate_saved", args); err != nil {
			return err
		}
	}
	bodies := 0
	for _, c := range base {
		if c.Kind != "record" || len(c.Body) > maxSeed || bodies >= 100 {
			continue
		}
		bodies++
		body := map[string][]byte{"body": c.Body}
		if err := add("check_body", body); err != nil {
			return err
		}
		if err := add("canonicalize", body); err != nil {
			return err
		}
	}
	chains, err := os.ReadFile(filepath.Join(dir, "member-chains.json"))
	if err != nil {
		return err
	}
	var mc struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(chains, &mc); err != nil {
		return fmt.Errorf("member-chains.json: %w", err)
	}
	for _, c := range mc.Cases {
		args := map[string]json.RawMessage{}
		for _, k := range []string{"chain", "trusted", "usage", "now_ms"} {
			args[k] = c[k]
		}
		if err := add("check_member", args); err != nil {
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
