// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package appletv

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func answer(t *testing.T, ptr string, additional bool) []byte {
	t.Helper()
	r := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(service), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 120},
		Body:   &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(ptr)},
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true, Authoritative: true}}
	if additional {
		m.Additionals = []dnsmessage.Resource{r}
	} else {
		m.Answers = []dnsmessage.Resource{r}
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInstance(t *testing.T) {
	for _, c := range []struct {
		ptr        string
		additional bool
		want       string
	}{
		{"Living Room._companion-link._tcp.local.", false, "Living Room"},
		{"Den \u00e9t\u00e9._companion-link._tcp.local.", true, "Den \u00e9t\u00e9"},
		{"_companion-link._tcp.local.", false, ""},
		{"Kitchen._airplay._tcp.local.", false, ""},
	} {
		if got := instance(answer(t, c.ptr, c.additional)); got != c.want {
			t.Errorf("instance(%q) = %q, want %q", c.ptr, got, c.want)
		}
	}
	q, err := query()
	if err != nil {
		t.Fatal(err)
	}
	if got := instance(q); got != "" {
		t.Errorf("a query read as an answer: %q", got)
	}
	if got := instance([]byte{1, 2, 3}); got != "" {
		t.Errorf("garbage read as an answer: %q", got)
	}
}

func TestUnescape(t *testing.T) {
	for in, want := range map[string]string{`Den\032TV`: "Den TV", `a\.b`: "a.b", `back\\slash`: `back\slash`, " Plain ": "Plain"} {
		if got := unescape(in); got != want {
			t.Errorf("unescape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNameOutsideHome(t *testing.T) {
	if got := Name(t.Context(), "8.8.8.8"); got != "" {
		t.Errorf("Name asked outside the home network: %q", got)
	}
}
