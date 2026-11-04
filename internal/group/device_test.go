// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"strings"
	"testing"
)

func TestDeviceInfoClean(t *testing.T) {
	good := DeviceInfo{Form: "laptop", OSVersion: "15.1", Version: "0.5.0", MAC: "a4:83:e7:01:02:0f", Archive: "cbb-linux-armv7.tar.gz"}
	if got := good.Clean(); got != good {
		t.Errorf("Clean(%+v) = %+v", good, got)
	}
	bad := DeviceInfo{Form: "toaster", OSVersion: strings.Repeat("9", 33), Version: "1\n2", MAC: "A4:83:E7:01:02:0F", Archive: "../cbb-linux-arm64.tar.gz"}
	if got := bad.Clean(); !got.IsZero() {
		t.Errorf("Clean(%+v) = %+v, want nothing", bad, got)
	}
}
