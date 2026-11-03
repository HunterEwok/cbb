// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package core

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/HunterEwok/cbb/internal/authority"
)

// Linked reports whether this build calls the Rust core, as the release
// builds do. A build without it, as go test and go build are, evaluates
// with Go's own rules (internal/authority), which the tests keep the same
// as the core's.
func Linked() bool { return linked }

// Rules names the group rules this build runs, for cbb version and error
// reports: the core with its version, or Go's own.
func Rules() string {
	if !linked {
		return "Go's internal/authority (a development build, not the Rust core)"
	}
	v, err := CoreVersion()
	if err != nil {
		return fmt.Sprintf("the Rust core (%v)", err)
	}
	src := v.Source
	if src == "" {
		src = "unknown"
	}
	return fmt.Sprintf("the Rust core %s, abi %d, source %s (%s)", v.Core, v.ABI, src, how)
}

// Evaluate gives the state of a group's records (docs/records-v2.md): from
// the core when the build links it, from internal/authority otherwise.
func Evaluate(in authority.Input) (*authority.State, error) {
	if !linked {
		return authority.Evaluate(in)
	}
	type firstSeen struct {
		Record authority.Hash `json:"record"`
		MS     int64          `json:"ms"`
	}
	args := struct {
		GroupCA     []byte             `json:"group_ca"`
		Group       string             `json:"group"`
		NowMS       int64              `json:"now_ms"`
		TimeUnknown bool               `json:"time_unknown,omitempty"`
		FirstSeen   []firstSeen        `json:"first_seen,omitempty"`
		Records     []authority.Record `json:"records"`
	}{Group: in.Group, NowMS: in.NowMS, TimeUnknown: in.TimeUnknown}
	if in.GroupCA != nil {
		args.GroupCA = in.GroupCA.Raw
	}
	for id, ms := range in.FirstSeen {
		args.FirstSeen = append(args.FirstSeen, firstSeen{id, ms})
	}
	sort.Slice(args.FirstSeen, func(i, j int) bool { return args.FirstSeen[i].Record.String() < args.FirstSeen[j].Record.String() })
	// The core reads chain as an array, never null.
	args.Records = make([]authority.Record, len(in.Records))
	for i, r := range in.Records {
		if r.Chain == nil {
			r.Chain = [][]byte{}
		}
		args.Records[i] = r
	}
	var raw json.RawMessage
	if err := Do("evaluate", args, &raw); err != nil {
		return nil, err
	}
	var s authority.State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("core: read the state: %w", err)
	}
	return &s, nil
}
