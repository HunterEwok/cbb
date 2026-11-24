#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Fetches the branch channel's keys.json, and stable.json unless PINNED is set
# (a pre-release, which no channel names), into the directory $1, once
# release-sign publish has written them for the tag GITHUB_REF_NAME: stable.json
# names that release, or for a pre-release keys.json is there. published.yml
# runs it after the release is published, which comes before publish commits
# the channel. A file GitHub does not serve is left out, never written as the
# error it answers.
set -eu
dir=$1
files="keys.json"
[ -n "${PINNED:-}" ] || files="keys.json stable.json"
for _ in $(seq 30); do
  for f in $files; do
    if gh api -H "Accept: application/vnd.github.raw" "repos/$GITHUB_REPOSITORY/contents/$f?ref=channel" >"$dir/$f.part" 2>/dev/null; then
      mv "$dir/$f.part" "$dir/$f"
    else
      rm -f "$dir/$f.part"
    fi
  done
  if [ -n "${PINNED:-}" ]; then
    [ -f "$dir/keys.json" ] && exit 0
  else
    named=$(jq -r .body "$dir/stable.json" 2>/dev/null | base64 -d 2>/dev/null | jq -r .release 2>/dev/null || true)
    [ "v$named" = "$GITHUB_REF_NAME" ] && exit 0
  fi
  sleep 20
done
echo "::error::the branch channel does not name $GITHUB_REF_NAME" >&2
exit 1
