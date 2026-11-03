// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
)

// TestStopExchange checks Stopped and NoSecretsTo on the cases of
// v2-records.json that stop the exchange (docs/protocol.md, section 10,
// "Stopping the exchange"): a full stop stops every device and every
// secret, a stop of secrets every secret but no connection, and the
// devices the state names get nothing or no secrets.
func TestStopExchange(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "v2-records.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []v2Case `json:"cases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	other := DeviceID("00000000000000000000000000000000")
	seen := map[string]bool{}
	for _, c := range f.Cases {
		if c.TimeUnknown {
			continue
		}
		var want authority.State
		if err := json.Unmarshal([]byte(c.State), &want); err != nil {
			t.Fatal(err)
		}
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatal(err)
		}
		s := NewRecords(ca)
		s.tag = c.Group
		s.SetClock(func() time.Time { return time.UnixMilli(c.NowMS) })
		for _, r := range c.Records {
			s.Add(r)
		}
		clear(s.firstSeen)
		for _, fs := range c.FirstSeen {
			s.firstSeen[fs.Record] = fs.MS
		}
		s.st = nil
		if s.Stop() != want.Stop {
			continue // a record the set itself leaves out; checkV2Cases covers it
		}
		seen[want.Stop] = true
		devs := []DeviceID{other}
		for _, d := range append(append([]string{}, want.NothingTo...), want.NoSecretsTo...) {
			devs = append(devs, DeviceID(d))
		}
		for _, d := range want.Devices {
			devs = append(devs, DeviceID(d.Device))
		}
		for _, d := range devs {
			nothing := slices.Contains(want.NothingTo, string(d))
			noSecrets := slices.Contains(want.NoSecretsTo, string(d))
			if got, w := s.Stopped(d), want.Stop == authority.StopFull || nothing; got != w {
				t.Errorf("%s: Stopped(%s) = %v, want %v", c.Name, d, got, w)
			}
			if got, w := s.NoSecretsTo(d), want.Stop != authority.StopNone || nothing || noSecrets; got != w {
				t.Errorf("%s: NoSecretsTo(%s) = %v, want %v", c.Name, d, got, w)
			}
		}
	}
	for _, stop := range []string{authority.StopNone, authority.StopSecrets, authority.StopFull} {
		if !seen[stop] {
			t.Errorf("no case with stop %q", stop)
		}
	}
	if !errors.Is(ErrStopped, ErrRecordsOnly) || errors.Is(ErrStopped, ErrNotListed) {
		t.Error("ErrStopped must let records through and be no ErrNotListed")
	}
}
