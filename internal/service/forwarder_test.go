// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/forward"
)

// The project's forwarder: the command line sends its resolved address
// and "default", and the hub takes the first pin it accepts; a pin of it in
// a hub command marks it the same way, and another forwarder's does not.
func TestHubAddrsProjectForwarder(t *testing.T) {
	pins := []string{forward.ProjectPins(nil)[0], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	fw, eps, err := hubAddrs("198.51.100.20:8764", forward.ProjectKey, nil, pins)
	if err != nil {
		t.Fatal(err)
	}
	if fw == nil || !fw.Project || fw.Pin != pins[0] || fw.Endpoint.String() != "198.51.100.20:8764" || len(eps) != 0 {
		t.Errorf("hubAddrs(default) = %+v, %v", fw, eps)
	}
	if fw, _, err := hubAddrs("198.51.100.20:8764", pins[1], nil, pins); err != nil || !fw.Project || fw.Pin != pins[1] {
		t.Errorf("a pin of the project's forwarder: %+v, %v", fw, err)
	}
	other := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	if fw, _, err := hubAddrs("198.51.100.9:8764", other, nil, pins); err != nil || fw.Project {
		t.Errorf("another forwarder: %+v, %v", fw, err)
	}
	if _, _, err := hubAddrs("", forward.ProjectKey, nil, pins); err == nil {
		t.Error("the project's key without an address passed")
	}
}
