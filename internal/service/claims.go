// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/benchtime"
)

// claimCheck is how often a member looks again at the claims to take the
// group over: a claim takes effect when its delay ends, without a new
// record (docs/protocol.md, section 10, "Handing the group over").
var claimCheck = max(benchtime.D(time.Minute), time.Second)

// claimLoop follows the claims until ctx is done: when one takes effect,
// the member trusts the new root, the claimant becomes the root, and the
// devices the new state refuses are cut off.
func (s *Service) claimLoop(ctx context.Context) {
	t := time.NewTicker(claimCheck)
	defer t.Stop()
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := s.claimStates()
		if now != last {
			last = now
			s.settleClaims()
		}
	}
}

// claimStates names every claim of the records with its state, and this
// admin's own claim: what changes when a claim takes effect.
func (s *Service) claimStates() string {
	var b strings.Builder
	s.mu.Lock()
	if s.id != nil && s.id.Claim != nil {
		b.WriteString("own ")
	}
	s.mu.Unlock()
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return b.String()
	}
	for _, c := range s.records.State().Claims {
		fmt.Fprintf(&b, "%s=%s ", c.Record, c.State)
	}
	return b.String()
}

// settleClaims applies what the claims say now, as settleRecords does after
// a record that changes the roots.
func (s *Service) settleClaims() {
	s.mu.Lock()
	err := s.adoptRootsLocked()
	s.mu.Unlock()
	if err != nil {
		s.logf("cbb: trusting the group's new root: %v", err)
	}
	s.afterRevocation()
	s.refreshCredential()
}
