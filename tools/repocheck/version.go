// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// androidVersion is the file with the Android apps' version, which their
// builds and F-Droid read (docs/apps.md, "F-Droid").
const androidVersion = "apps/android/version.properties"

// released matches a release's heading in CHANGELOG.md.
var released = regexp.MustCompile(`(?m)^## \[(\d+)\.(\d+)\.(\d+)\] - `)

// lastRelease returns the last release in CHANGELOG.md, as X.Y.Z, or "".
func lastRelease(changelog []byte) string {
	m := released.FindSubmatch(changelog)
	if m == nil {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s", m[1], m[2], m[3])
}

// specVersion matches an RPM spec's Version line.
var specVersion = regexp.MustCompile(`(?m)^Version:\s*(\S+)\s*$`)

// checkSpecVersions checks that the Aurora and Sailfish app's RPM specs
// (apps/silica/packaging/TARGET/*.spec) carry the last release in
// CHANGELOG.md, like the Android apps' version: the release pull request
// moves them on, and every build before it is the last release.
func checkSpecVersions(files map[string][]byte) []string {
	var specs []string
	for name := range files {
		if ok, _ := path.Match("apps/silica/packaging/*/*.spec", name); ok {
			specs = append(specs, name)
		}
	}
	if len(specs) == 0 {
		return nil
	}
	sort.Strings(specs)
	want := lastRelease(files["CHANGELOG.md"])
	if want == "" {
		return []string{"CHANGELOG.md: no released version for the RPM specs to follow"}
	}
	var problems []string
	for _, name := range specs {
		m := specVersion.FindSubmatch(files[name])
		if m == nil {
			problems = append(problems, name+": no Version line")
		} else if string(m[1]) != want {
			problems = append(problems, fmt.Sprintf("%s: Version is %q, the last release in CHANGELOG.md is %s", name, m[1], want))
		}
	}
	return problems
}

// checkAndroidVersion checks that the Android apps' version is the last
// release in CHANGELOG.md and that its versionCode is X*10000 + Y*100 + Z,
// so that the pull request that moves the changes under a new version also
// moves the apps on, and the tag's build is that version.
func checkAndroidVersion(files map[string][]byte) []string {
	data, ok := files[androidVersion]
	if !ok {
		return nil
	}
	props := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			props[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	m := released.FindSubmatch(files["CHANGELOG.md"])
	if m == nil {
		return []string{"CHANGELOG.md: no released version for " + androidVersion + " to follow"}
	}
	var problems []string
	if want := fmt.Sprintf("%s.%s.%s", m[1], m[2], m[3]); props["versionName"] != want {
		problems = append(problems, fmt.Sprintf("%s: versionName is %q, the last release in CHANGELOG.md is %s", androidVersion, props["versionName"], want))
	}
	var n [3]int
	for i := range n {
		n[i], _ = strconv.Atoi(string(m[i+1]))
	}
	if want := strconv.Itoa(n[0]*10000 + n[1]*100 + n[2]); props["versionCode"] != want {
		problems = append(problems, fmt.Sprintf("%s: versionCode is %q, want %s for the last release", androidVersion, props["versionCode"], want))
	}
	return problems
}
