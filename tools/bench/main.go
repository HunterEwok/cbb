// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command bench runs the hardware test bench of docs/testbench.md: it drives
// real devices over SSH from the bench's controller and reports what passed.
//
//	go run ./tools/bench [-inventory FILE] [-report DIR] [-only a,b] check|smoke|full|away|relay
//	go run ./tools/bench [-only a,b] -build DIR reset
//	go run ./tools/bench [-only a,b] -quick reset
//
// check only reaches every device and prints what it finds; reset (R1)
// installs the build under test on every device at once, in no group, or
// with -quick only wipes the devices' state; smoke makes a
// group of the devices and sends one text from each device to all the
// others; full runs the sync matrix and the failure, mode and security
// cases on top; away adds the devices away from home by invitation through
// the hub and its forwarder (with -stop-forwarder also F7, which stops the
// forwarder); relay meets the group at the blind relay. The inventory lives on the controller, never in the repository
// (docs/testbench.md, section 13). Devices must be in no group before smoke;
// the bench never removes a group it did not make.
//
// CBB_DEBUG=1 adds each command's output to the messages of failed steps;
// the report always has it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	home, _ := os.UserHomeDir()
	invPath := fs.String("inventory", filepath.Join(home, ".config", "cbb-bench", "inventory.toml"), "the bench's inventory")
	reportDir := fs.String("report", "", "write report.xml (JUnit) and report.txt here")
	only := fs.String("only", "", "comma-separated devices to use instead of all of them")
	timeout := fs.Duration("timeout", 20*time.Second, "how long a text may take to arrive")
	stopForwarder := fs.Bool("stop-forwarder", false, "away: also stop and start the forwarder (F7), which other groups may use")
	buildDir := fs.String("build", "", "reset: the directory with the release archives (and SHA256SUMS) to install")
	quick := fs.Bool("quick", false, "reset: keep each device's install and only remove its state")
	cbb := fs.String("cbb", "", "fleet, phone, all: a static Linux cbb of the build under test for this computer's CPU, which the fleet's containers run")
	fs.StringVar(&fleetLite, "cbb-lite", "", "fleet, all: the lite member's cbb for Linux (cargo build --release in lite/), for the fleet's cases with a lite member")
	cbbTime := fs.String("cbb-time", "", "time, all: the same cbb built with -tags benchtime, whose long times run 100000 times faster")
	fleetSize := fs.Int("fleet-size", 16, "fleet: the members of the many-members case (E3)")
	scenarioList := fs.String("scenario", "", "fleet, time: comma-separated scenarios to run instead of all, such as T2-tmux or K6-clock")
	docs := fs.String("docs", "docs", "coverage, all: the directory with testbench-catalogue.md and testbench-functions.md")
	fs.DurationVar(&fuzzFor, "fuzz-for", fuzzFor, "fleet: how long the fuzzing case (S20) sends each kind of frame; a release's full run takes 1h")
	fs.BoolVar(&disruptive, "disruptive", false, "desktop: also lock, put to sleep and restart the computers (Q3, I18, H7, H8); only on the owner's word")
	fs.DurationVar(&soakFor, "soak-for", 0, "fleet: how long the soak (E10) runs, 24h for a release; 0 leaves it out")
	android := fs.String("android", "apps/android", "phone: the Android project, whose instrumented tests run on the emulator adb sees")
	coverDir := fs.String("coverdir", "", "fleet, time, all: with a cbb built with -cover, the directory where every container writes its coverage (docs/testbench.md, \"Code coverage\")")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: bench [flags] check|reset|smoke|full|faults|desktop|away|relay|fleet|time|phone|all|coverage")
		return 2
	}
	if *coverDir != "" {
		abs, err := filepath.Abs(*coverDir)
		if err == nil {
			err = os.MkdirAll(abs, 0o755)
		}
		if err != nil {
			fmt.Fprintf(stderr, "bench: -coverdir: %v\n", err)
			return 2
		}
		fleetCoverDir = abs
	}
	for _, n := range splitList(*scenarioList) {
		if scenarios == nil {
			scenarios = map[string]bool{}
		}
		scenarios[n] = true
	}
	if fs.Arg(0) == "phone" {
		// The emulator and the fleet run on this computer alone.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		r := NewReport("phone", stdout, debugMode())
		Phone(ctx, r, *cbb, *android, *timeout)
		return finish(r, *reportDir, stderr)
	}
	if fs.Arg(0) == "fleet" || fs.Arg(0) == "time" {
		// The fleet runs on this computer alone and needs no inventory.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		r := NewReport(fs.Arg(0), stdout, debugMode())
		if fs.Arg(0) == "time" {
			TimeSuite(ctx, r, *cbbTime, *timeout)
		} else {
			FleetSuite(ctx, r, *cbb, *fleetSize, *timeout)
		}
		return finish(r, *reportDir, stderr)
	}
	if fs.Arg(0) == "coverage" {
		if err := Coverage(stdout, *docs); err != nil {
			fmt.Fprintf(stderr, "bench: %v\n", err)
			return 1
		}
		return 0
	}
	inv, err := LoadInventory(*invPath)
	if err != nil {
		fmt.Fprintf(stderr, "bench: %v\n", err)
		return 1
	}
	devices, err := inv.Select(*only)
	if err != nil {
		fmt.Fprintf(stderr, "bench: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	r := NewReport(fs.Arg(0), stdout, debugMode())
	switch fs.Arg(0) {
	case "check":
		Check(ctx, r, devices)
	case "smoke":
		Smoke(ctx, r, inv, devices, *timeout)
	case "full":
		Full(ctx, r, devices, *timeout)
	case "away":
		Away(ctx, r, inv, devices, *timeout, *stopForwarder)
	case "relay":
		Relay(ctx, r, inv, devices, *timeout)
	case "faults":
		Faults(ctx, r, devices, *timeout)
	case "desktop":
		Desktop(ctx, r, devices, *timeout)
	case "all":
		All(ctx, r, inv, devices, *timeout, *stopForwarder, *cbb, *cbbTime, *fleetSize)
	case "reset":
		var b *Build
		if *buildDir != "" {
			if b, err = LoadBuild(*buildDir); err != nil {
				fmt.Fprintf(stderr, "bench: %v\n", err)
				return 1
			}
		}
		Reset(ctx, r, devices, b, *quick)
	default:
		fmt.Fprintf(stderr, "bench: unknown suite %q\n", fs.Arg(0))
		return 2
	}
	code := finish(r, *reportDir, stderr)
	if fs.Arg(0) == "all" {
		allCoverage(stdout, stderr, *docs, *reportDir)
	}
	return code
}

// finish writes the report where -report asks and gives the exit status.
func finish(r *Report, reportDir string, stderr io.Writer) int {
	if reportDir != "" {
		if err := r.Write(reportDir); err != nil {
			fmt.Fprintf(stderr, "bench: %v\n", err)
			return 1
		}
	}
	if r.Failed() > 0 {
		return 1
	}
	return 0
}

// debugMode follows CBB_DEBUG like cbb itself: details under each failure
// with 1, none with 0; a development run shows them by default.
func debugMode() bool {
	v := strings.TrimSpace(os.Getenv("CBB_DEBUG"))
	return v != "0"
}
