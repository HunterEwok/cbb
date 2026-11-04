// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package phone

import (
	"reflect"
	"strings"
	"testing"
)

func TestJoinQR(t *testing.T) {
	if got := JoinQR(JoinCode{Code: "012345"}); got != "cbb://join?code=012345" {
		t.Errorf("JoinQR = %q", got)
	}
	full := JoinCode{Code: "246802", Addrs: []string{"192.168.1.20:40123", "[fd00::5]:40123"}, Fingerprint: "q83vEjRWeJA"}
	if got := JoinQR(full); !strings.HasPrefix(got, "cbb://join?code=246802&") {
		t.Errorf("JoinQR = %q", got)
	}
	for in, want := range map[string]JoinCode{
		JoinQR(full):                               full,
		" cbb://join?code=135790\n":                {Code: "135790"},
		"CBB://JOIN?code=111111":                   {Code: "111111"},
		"cbb://join?code=222222&addr=10.0.0.2&x=1": {Code: "222222"}, // no port
		"cbb://join?code=3&addr=a:1&addr=b:1&addr=c:1&addr=d:1&addr=e:1": {Code: "3", Addrs: []string{"a:1", "b:1", "c:1", "d:1"}},
	} {
		if jc, ok := ParseJoinQR(in); !ok || !reflect.DeepEqual(jc, want) {
			t.Errorf("ParseJoinQR(%q) = %+v, %v", in, jc, ok)
		}
	}
	for _, in := range []string{"", "123456", "cbb-join:123456", "cbb://pair?code=1", "cbb://join", "https://join/?code=1"} {
		if jc, ok := ParseJoinQR(in); ok {
			t.Errorf("ParseJoinQR(%q) = %+v, true", in, jc)
		}
	}
}
