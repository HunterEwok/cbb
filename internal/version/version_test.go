// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package version

import (
	"strings"
	"testing"
)

func TestDescribe(t *testing.T) {
	tests := []struct {
		name                                      string
		version, mainVersion, goos, goarch, goarm string
		want                                      string
	}{
		{
			name:    "release build",
			version: "v1.2.3", mainVersion: "(devel)", goos: "linux", goarch: "amd64",
			want: "cbb v1.2.3 linux/amd64",
		},
		{
			name:    "release version wins over the module version",
			version: "v1.2.3", mainVersion: "v1.2.4", goos: "linux", goarch: "amd64",
			want: "cbb v1.2.3 linux/amd64",
		},
		{
			name:    "installed module",
			version: "dev", mainVersion: "v1.2.3", goos: "darwin", goarch: "arm64",
			want: "cbb v1.2.3 darwin/arm64",
		},
		{
			name:    "checkout build",
			version: "dev", mainVersion: "v0.0.0-20261021051425-b7a0077e1f2a+dirty", goos: "linux", goarch: "arm64",
			want: "cbb v0.0.0-20261021051425-b7a0077e1f2a+dirty linux/arm64",
		},
		{
			name:    "no version information",
			version: "dev", mainVersion: "(devel)", goos: "linux", goarch: "amd64",
			want: "cbb dev linux/amd64",
		},
		{
			name:    "empty module version",
			version: "dev", goos: "linux", goarch: "amd64",
			want: "cbb dev linux/amd64",
		},
		{
			name:    "Raspberry Pi Zero W",
			version: "v1.0.0", goos: "linux", goarch: "arm", goarm: "6",
			want: "cbb v1.0.0 linux/arm/v6",
		},
		{
			name:    "ARM with a float mode",
			version: "v1.0.0", goos: "linux", goarch: "arm", goarm: "7,softfloat",
			want: "cbb v1.0.0 linux/arm/v7",
		},
		{
			name:    "GOARM is ignored on other architectures",
			version: "v1.0.0", goos: "linux", goarch: "arm64", goarm: "7",
			want: "cbb v1.0.0 linux/arm64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := describe(tt.version, tt.mainVersion, tt.goos, tt.goarch, tt.goarm)
			if got != tt.want {
				t.Errorf("describe() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestString(t *testing.T) {
	got := String()
	if !strings.HasPrefix(got, "cbb ") {
		t.Errorf("String() = %q, want the prefix %q", got, "cbb ")
	}
	if strings.Count(got, " ") != 2 {
		t.Errorf("String() = %q, want three words: name, version, platform", got)
	}
}
