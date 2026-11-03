// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/clip"
)

// TestVerdicts writes Go's verdict on each case of a corpus of
// tools/difffuzz (docs/differential.md): the records, commands, server
// credentials, manifests and record sets; internal/release writes the
// release files'. It runs when CBB_VERDICTS names the corpus and writes to
// CBB_VERDICTS_OUT; without them it reads a corpus of its own, so that the
// verdicts are always checked to be written.
func TestVerdicts(t *testing.T) {
	in, out := os.Getenv("CBB_VERDICTS"), os.Getenv("CBB_VERDICTS_OUT")
	if in == "" {
		in = writeVerdictCorpus(t)
		out = in + ".out"
	}
	data, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		v, err := goVerdict(line)
		if err != nil {
			t.Fatalf("case %d: %v", i+1, err)
		}
		b.WriteString(v)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(out, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("CBB_VERDICTS") == "" {
		got := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
		want := []string{"taken", "refused", "set", "skip"}
		for i, w := range want {
			if !strings.HasPrefix(got[i], w) {
				t.Errorf("case %d: %q, want %s", i+1, got[i], w)
			}
		}
	}
}

// writeVerdictCorpus writes a corpus of one valid record of version 2, one
// that the tables refuse, a record set and a release file.
func writeVerdictCorpus(t *testing.T) string {
	v := readStrictGenerated(t)
	var invalid []byte
	for _, c := range v.Records {
		if invalid == nil && !c.Valid {
			invalid = c.Full()
		}
	}
	data, err := os.ReadFile("../../testdata/interop/v2-records.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []v2Case `json:"cases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	set := struct {
		GroupCA []byte
		Records []Record
	}{f.Cases[0].GroupCA, f.Cases[0].Records}
	valid := set.Records[0].Body
	lines := []any{
		map[string]any{"kind": "record", "body": valid},
		map[string]any{"kind": "record", "body": invalid},
		map[string]any{"kind": "set", "ca": set.GroupCA, "records": set.Records, "keys": [][]byte{make([]byte, 32)}},
		map[string]any{"kind": "keys", "body": []byte("{}")},
	}
	var b bytes.Buffer
	for _, l := range lines {
		j, _ := json.Marshal(l)
		b.Write(j)
		b.WriteByte('\n')
	}
	path := t.TempDir() + "/corpus.jsonl"
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readStrictGenerated(t *testing.T) genVectors {
	v, err := readGenFiles("../../testdata/interop")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// verdictCase is a line of a corpus.
type verdictCase struct {
	Kind    string   `json:"kind"`
	Body    []byte   `json:"body"`
	CA      []byte   `json:"ca"`
	Records []Record `json:"records"`
	Keys    [][]byte `json:"keys"`
}

func goVerdict(line []byte) (string, error) {
	var c verdictCase
	if err := json.Unmarshal(line, &c); err != nil {
		return "", err
	}
	switch c.Kind {
	case "record":
		b, err := authority.ParseBody(c.Body)
		if err != nil {
			return "refused", nil
		}
		return verdictLine(
			"type", vStr(b.Type), "group", vStr(b.Group), "signer", vHashPtr(&b.Signer), "seq", vInt(b.Seq), "prev", vHashPtr(b.Prev),
			"time_ms", vInt(b.TimeMS), "device", vStr(b.Device), "name", vStr(b.Name), "role", vStr(b.Role), "os", vStr(b.OS),
			"store", vStr(b.Store), "key", vHashPtr(b.Key), "admin", vHashPtr(b.Admin), "powers", strings.Join(b.Powers, "."),
			"commands", strings.Join(b.Commands, "."), "holds_root", vBool(b.HoldsRoot), "keys", vHashes(b.Keys),
			"root", hex.EncodeToString(b.Root), "records", vHashes(b.Records)), nil
	case "command":
		b, err := parseCommandBody(c.Body)
		if err != nil {
			return "refused", nil
		}
		text := sha256.Sum256([]byte(b.Text))
		return verdictLine(
			"type", vStr(b.Type), "group", vStr(b.Group), "by", vStr(string(b.By)), "to", vStr(string(b.To)),
			"id", vStr(b.ID), "time_ms", vInt(b.TimeMS), "expires_ms", vInt(b.ExpiresMS), "mode", vStr(b.Mode),
			"enter", vBool(b.Enter), "kind", vStr(b.Kind), "text", hex.EncodeToString(text[:]), "action", vStr(b.Action)), nil
	case "credential":
		b, err := parseCredentialBody(c.Body)
		if err != nil {
			return "refused", nil
		}
		return verdictLine(
			"type", vStr(b.Type), "group", vStr(b.Group), "version", strconv.FormatUint(b.Version, 10),
			"expires_ms", vInt(b.ExpiresMS), "tag", vStr(b.Tag), "key", hex.EncodeToString(b.Key),
			"hubs", vHashes(b.Hubs), "admins", vHashes(b.Admins), "members", vHashes(b.Members)), nil
	case "manifest":
		var m clip.Manifest
		if json.Unmarshal(c.Body, &m) != nil || m.Validate() != nil {
			return "refused", nil
		}
		return "taken", nil
	case "set":
		return goSetVerdict(c)
	case "keys", "release", "channel", "attest-status":
		return "skip", nil
	}
	return "", fmt.Errorf("unknown kind %q", c.Kind)
}

func goSetVerdict(c verdictCase) (string, error) {
	ca, err := x509.ParseCertificate(c.CA)
	if err != nil {
		return "", err
	}
	s := NewRecords(ca)
	fresh, _ := s.AddAll(c.Records)
	var roots []string
	for _, r := range s.Roots() {
		h := sha256.Sum256(r.Raw)
		roots = append(roots, hex.EncodeToString(h[:]))
	}
	var devices []string
	for _, d := range s.Devices() {
		devices = append(devices, strings.Join([]string{
			vStr(string(d.ID)), vStr(d.Name), vStr(d.Role), vStr(d.Store), vBool(d.Admin), vHashPtr(d.AdminKey), vBool(d.Frozen),
		}, ":"))
	}
	var revoked, frozen strings.Builder
	for _, k := range c.Keys {
		var h KeyHash
		copy(h[:], k)
		revoked.WriteString(vBool(s.Revoked(h)))
		frozen.WriteString(vBool(s.Frozen(h)))
	}
	return fmt.Sprintf("set taken=%d roots=%s devices=%s revoked=%s frozen=%s digest=%s",
		len(fresh), strings.Join(roots, "."), strings.Join(devices, "."), revoked.String(), frozen.String(), s.Digest()), nil
}

// verdictLine writes "taken" and the pairs of names and values.
func verdictLine(pairs ...string) string {
	var b strings.Builder
	b.WriteString("taken")
	for i := 0; i < len(pairs); i += 2 {
		b.WriteString(" " + pairs[i] + "=" + pairs[i+1])
	}
	return b.String()
}

func vStr(s string) string { return hex.EncodeToString([]byte(s)) }
func vInt(n int64) string  { return strconv.FormatInt(n, 10) }
func vBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func vHashPtr(k *KeyHash) string {
	if k == nil {
		return ""
	}
	return hex.EncodeToString(k[:])
}

func vHashes(l []KeyHash) string {
	s := make([]string, len(l))
	for i, k := range l {
		s[i] = hex.EncodeToString(k[:])
	}
	return strings.Join(s, ".")
}
