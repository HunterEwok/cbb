// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"regexp"
	"strings"
)

// releaseWorkflows are the workflows that read the release's secrets: the
// signing keys, the notarization key, the tap's and the feed's keys.
var releaseWorkflows = []string{".github/workflows/release.yml", ".github/workflows/published.yml"}

var (
	jobHeading = regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*(#.*)?$`)
	secretUse  = regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`)
	releaseEnv = regexp.MustCompile(`^    environment:\s*release\s*(#.*)?$`)
)

// checkReleaseSecrets checks that every job of the release workflows that
// reads a secret (other than GITHUB_TOKEN, which GitHub gives each run)
// runs in the deployment environment release, whose protection rules
// guard those secrets (docs/maintainers/maintaining.md, "Release secrets").
func checkReleaseSecrets(files map[string][]byte) []string {
	var problems []string
	for _, name := range releaseWorkflows {
		data, ok := files[name]
		if !ok {
			continue
		}
		problems = append(problems, jobsReadingSecrets(name, string(data))...)
	}
	return problems
}

func jobsReadingSecrets(name, text string) []string {
	var problems []string
	inJobs := false
	job, line, secret, env := "", 0, "", false
	flush := func() {
		if job != "" && secret != "" && !env {
			problems = append(problems, fmt.Sprintf("%s:%d: the job %s reads secrets.%s outside the environment release", name, line, job, secret))
		}
	}
	for i, l := range strings.Split(text, "\n") {
		if !strings.HasPrefix(l, " ") && strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "#") {
			flush()
			inJobs, job = strings.HasPrefix(l, "jobs:"), ""
			continue
		}
		if !inJobs {
			continue
		}
		if m := jobHeading.FindStringSubmatch(l); m != nil {
			flush()
			job, line, secret, env = m[1], i+1, "", false
			continue
		}
		if releaseEnv.MatchString(l) {
			env = true
		}
		for _, m := range secretUse.FindAllStringSubmatch(l, -1) {
			if m[1] != "GITHUB_TOKEN" && secret == "" {
				secret = m[1]
			}
		}
	}
	flush()
	return problems
}
