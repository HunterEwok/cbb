// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority_test

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/cryptotest"
	"testing/synctest"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
)

var update = flag.Bool("update", false, "write testdata/interop/v2-records.json and v2-flood.json")

const (
	vectorsPath = "../../testdata/interop/v2-records.json"
	// floodPath holds the cases of sets at MaxRecords, apart so that
	// neither file passes the repository's limit on a file's size.
	floodPath = "../../testdata/interop/v2-flood.json"
)

// flooded are the scenarios whose cases go to floodPath.
var flooded = map[string]bool{"record limit": true}

// vectorFile is testdata/interop/v2-records.json: record sets of version 2
// with the state every implementation must give for them, byte for byte,
// in any order of the records (docs/records-v2.md, "Vectors and tests").
type vectorFile struct {
	Comment string       `json:"comment"`
	Cases   []vectorCase `json:"cases"`
}

type vectorCase struct {
	Test    string `json:"-"`
	Name    string `json:"name"`
	GroupCA []byte `json:"group_ca"`
	Group   string `json:"group"`
	NowMS   int64  `json:"now_ms"`
	// TimeUnknown is the member not knowing the time (Input.TimeUnknown).
	TimeUnknown bool               `json:"time_unknown,omitempty"`
	FirstSeen   []firstSeen        `json:"first_seen,omitempty"`
	Records     []authority.Record `json:"records"`
	// State is the canonical state, as a string so that its bytes stay
	// as they are.
	State string `json:"state"`
}

type firstSeen struct {
	Record authority.Hash `json:"record"`
	MS     int64          `json:"ms"`
}

// collecting holds the cases while TestV2Vectors -update runs the
// scenarios; nil otherwise.
var collecting *[]vectorCase

// collect keeps the evaluation evalAll just checked as a vector.
func (w *world) collect(fs map[authority.Hash]int64, state []byte) {
	if collecting == nil {
		return
	}
	n := 0
	for _, o := range *collecting {
		if o.Test == w.t.Name() {
			n++
		}
	}
	c := vectorCase{Test: w.t.Name(), Name: fmt.Sprintf("%s %d", strings.ReplaceAll(strings.TrimPrefix(w.t.Name(), "TestV2Vectors/"), "_", " "), n+1), GroupCA: w.roots["root"].Cert.Raw, Group: tag, NowMS: w.now, TimeUnknown: w.unknown,
		Records: append([]authority.Record(nil), w.recs...), State: string(state)}
	for id, ms := range fs {
		c.FirstSeen = append(c.FirstSeen, firstSeen{id, ms})
	}
	sort.Slice(c.FirstSeen, func(i, j int) bool { return c.FirstSeen[i].Record.String() < c.FirstSeen[j].Record.String() })
	*collecting = append(*collecting, c)
}

// scenarios are the tests whose evaluations make the vectors.
var scenarios = []struct {
	name string
	fn   func(*testing.T)
}{
	{"basic", TestEvaluateBasic},
	{"record of a later version", TestNewerVersion},
	{"ignored records", TestIgnoredReasons},
	{"root removal cuts an admin", TestRootRemovalCutsAdmin},
	{"admin removals in order", TestAdminRemovalsInOrder},
	{"admin removals crossed", TestAdminRemovalsCross},
	{"claim waits and takes effect", TestClaimWaitsAndTakesEffect},
	{"time unknown", TestTimeUnknown},
	{"settings delay", TestSettingsDelay},
	{"key level", TestKeyLevel},
	{"two claims", TestTwoClaimsStop},
	{"removed phone after a takeover", TestRemovedPhoneCannotTakeBack},
	{"claim disputed", TestClaimDisputed},
	{"claimed root signs early", TestClaimedRootSignsEarly},
	{"checkpoint", TestCheckpoint},
	{"checkpoint edges", TestCheckpointEdges},
	{"claim after removal", TestClaimAfterRemoval},
	{"claim while another waits", TestPendingClaimRace},
	{"removed admin's claim", TestRemovedAdminClaimVoid},
	{"chain of claims", TestChainOfClaims},
	{"removed admin's device", TestRemovedAdminDevice},
	{"one record under two admin CAs", TestSameRecordTwoCAs},
	{"two histories of an admin", TestTwoHistories},
	{"two histories of the root", TestRootTwoHistories},
	{"freeze and thaw", TestFreezeAndThaw},
	{"freezes crossed", TestFreezesCross},
	{"powers", TestPowers},
	{"stranger's claim", TestStrangersClaim},
	{"times at the ends", TestTimesAtTheEnds},
	{"device seal", TestDeviceSeal},
	{"device limit", TestDeviceLimit},
	{"admin limit", TestAdminLimit},
	{"path limit", TestPathLimit},
	{"record limit", TestRecordLimit},
	{"hubs table", TestHubsTable},
	{"recovery key", TestRecoveryKey},
	{"recovery delay", TestRecoveryDelay},
	{"recovery key removed", TestRecoveryRemoved},
	{"recovery key replaced", TestRecoveryReplaced},
	{"recovery by an admin", TestRecoveryByAdmin},
	{"recovery cert from another root", TestRecoveryCertFromAnotherRoot},
	{"handover", TestHandover},
	{"handover replaced", TestHandoverReplaced},
}

// TestV2Vectors writes (with -update) and checks
// testdata/interop/v2-records.json for the other implementations.
func TestV2Vectors(t *testing.T) {
	if *update {
		var cases, flood []vectorCase
		// A fixed random source and the bubble's fixed clock make the same
		// keys, certificates and signatures each time, so that a change of
		// the rules changes only the cases it touches.
		for _, s := range scenarios {
			collecting = &cases
			if flooded[s.name] {
				collecting = &flood
			}
			t.Run(s.name, func(t *testing.T) {
				cryptotest.SetGlobalRandom(t, 1)
				synctest.Test(t, s.fn)
			})
		}
		collecting = nil
		writeVectors(t, vectorsPath, cases)
		writeVectors(t, floodPath, flood)
	}
	var all []vectorCase
	for _, path := range []string{vectorsPath, floodPath} {
		data, err := os.ReadFile(filepath.FromSlash(path))
		if err != nil {
			t.Fatal(err)
		}
		var f vectorFile
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		all = append(all, f.Cases...)
	}
	if len(all) < len(scenarios) {
		t.Fatalf("%d cases, fewer than the %d scenarios", len(all), len(scenarios))
	}
	rng := rand.New(rand.NewPCG(3, 5))
	for _, c := range all {
		in := authority.Input{Group: c.Group, NowMS: c.NowMS, TimeUnknown: c.TimeUnknown, FirstSeen: map[authority.Hash]int64{}}
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		in.GroupCA = ca
		for _, s := range c.FirstSeen {
			in.FirstSeen[s.Record] = s.MS
		}
		for i := 0; i < 8; i++ {
			in.Records = append([]authority.Record(nil), c.Records...)
			if i > 0 {
				rng.Shuffle(len(in.Records), func(a, b int) { in.Records[a], in.Records[b] = in.Records[b], in.Records[a] })
			}
			s, err := authority.Evaluate(in)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			got, err := s.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.State {
				t.Fatalf("%s, order %d:\n got %s\nwant %s", c.Name, i, got, c.State)
			}
		}
	}
}

func writeVectors(t *testing.T, path string, cases []vectorCase) {
	data, err := json.MarshalIndent(vectorFile{
		Comment: "Written by internal/authority's TestV2Vectors -update. Each case's records, in any order, must evaluate to state, byte for byte (docs/records-v2.md).",
		Cases:   cases,
	}, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.FromSlash(path), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
