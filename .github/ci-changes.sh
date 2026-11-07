#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Which parts of the repository a pull request changes, so CI runs only the
# jobs that build or test them. Usage: ci-changes.sh BASE HEAD, with BASE the
# commit of main the pull request was compared with; it prints name=true or
# name=false for each part, for $GITHUB_OUTPUT.
#
# A pull request is up to date with main before it merges, so a job that does
# not run has nothing new to test: every file it reads is main's, which ran it
# when they changed. A part therefore lists every path its jobs read. A path
# that no part names runs everything, as do this script, the workflow and the
# files every part reads.
set -eu

base=$1
head=$2

core=false     # the Go service: cmd, internal, mobile, packaging, the e2e scripts
tools=false    # Go tools under tools/, tested by the test job
lite=false     # the lite member and its firmware
ios=false      # the Swift kit, the iPhone and Watch apps
macos=false    # the Mac app, which shares the iPhone app's theme
desktop=false  # the tray app
android=false  # the Kotlin kit, the Android and Wear OS apps, the F-Droid build
zxnext=false   # the ZX Spectrum Next dot command
silica=false   # the app for Aurora OS and Sailfish OS
design=false   # the design tokens and the icon, which every app and the site use
site=false     # the website and the documentation it publishes
all=false

files=$(git diff --name-only "$base...$head")
for f in $files; do
	case $f in
	.github/workflows/ci.yml | .github/ci-changes.sh | .github/differential.sh | go.mod | go.sum | testdata/*) all=true ;;
	packaging/zxnext/*) zxnext=true ;; # the Next's files for the site, not the members' packages
	packaging/macos/*) core=true; macos=true ;; # the Mac app's job tests the .pkg
	cmd/* | internal/* | mobile/* | packaging/* | tools/e2e/*) core=true ;;
	tools/tokens/* | tools/icon/* | apps/design/*) design=true; tools=true ;;
	tools/site/*) site=true; tools=true ;;
	tools/sbom/*) core=true; tools=true ;; # the packaging job and the Android job run it
	tools/*) tools=true ;;
	# The Rust core's rules, which the phone kits and the Aurora app link.
	core/* | ffi/* | Cargo.toml | Cargo.lock) lite=true; ios=true; android=true; silica=true ;;
	member/* | embassy/* | esp32/* | ring-shim/* | wasm/* | .cargo/* | deny.toml | rustfmt.toml) lite=true ;;
	apps/ios/*) ios=true; macos=true ;;
	apps/macos/*) macos=true ;;
	apps/desktop/*) desktop=true ;;
	apps/android/*) android=true ;;
	apps/zxnext/*) zxnext=true ;;
	apps/silica/*) silica=true ;;
	site/* | docs/* | *.md | LICENSE) site=true ;;
	.github/*) ;; # other workflows, templates and settings: no job of ci.yml reads them
	*) all=true ;;
	esac
done

# The jobs of one part that also read another's files.
[ "$core" = false ] || { ios=true; desktop=true; android=true; lite=true; }
[ "$lite" = false ] || zxnext=true
[ "$design" = false ] || { ios=true; macos=true; desktop=true; android=true; silica=true; site=true; }

if [ "$all" = true ]; then
	core=true tools=true lite=true ios=true macos=true desktop=true android=true zxnext=true silica=true design=true site=true
fi
printf 'core=%s\ntools=%s\nlite=%s\nios=%s\nmacos=%s\ndesktop=%s\nandroid=%s\nzxnext=%s\nsilica=%s\ndesign=%s\nsite=%s\n' \
	"$core" "$tools" "$lite" "$ios" "$macos" "$desktop" "$android" "$zxnext" "$silica" "$design" "$site"
