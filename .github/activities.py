#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

"""Keeps the activities of the failed UI tests: every step XCTest took (the
launches, taps, waits, queries and the tests' own activities, each with its
time and attachments), which the attachments alone do not show.

Usage: activities.py <output folder> <result bundle>...

For each failed test of each .xcresult, `xcrun xcresulttool get
test-results activities` is written to
<output folder>/<bundle>/<test>.json, and as indented text, with each step's
seconds from the test's start and a mark on the steps the failure belongs
to, to <test>.txt and into the job's log in a group of its own.
"""

import json
import os
import re
import subprocess
import sys


def xcresulttool(*args: str) -> dict:
    out = subprocess.run(["xcrun", "xcresulttool", "get", "test-results", *args, "--format", "json"],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def failed_tests(node: dict) -> list[str]:
    """The identifiers of the failed test cases under node."""
    found = []
    if node.get("nodeType") == "Test Case" and node.get("result") == "Failed" and node.get("nodeIdentifier"):
        found.append(node["nodeIdentifier"])
    for child in node.get("children", []):
        found += failed_tests(child)
    return found


def lines(activities: list, start: float, depth: int) -> list[str]:
    out = []
    for a in activities:
        t = a.get("startTime")
        when = f"{t - start:8.2f}s" if isinstance(t, (int, float)) else " " * 9
        mark = "✗" if a.get("isAssociatedWithFailure") else " "
        out.append(f"{when} {mark} {'  ' * depth}{a.get('title', '')}")
        for att in a.get("attachments", []):
            out.append(f"{' ' * 11}{'  ' * (depth + 1)}[attachment] {att.get('name', '')}")
        out += lines(a.get("childActivities", []), start, depth + 1)
    return out


def text(result: dict) -> str:
    out = [result.get("testIdentifier", "")]
    for run in result.get("testRuns", []):
        device = run.get("device", {})
        out.append(f"-- {device.get('deviceName', '')} {device.get('osVersion', '')}".rstrip())
        acts = run.get("activities", [])
        times = [a["startTime"] for a in acts if isinstance(a.get("startTime"), (int, float))]
        out += lines(acts, min(times) if times else 0.0, 0)
    return "\n".join(out) + "\n"


def main() -> None:
    root, bundles = sys.argv[1], sys.argv[2:]
    for bundle in bundles:
        if not os.path.isdir(bundle):
            continue
        name = os.path.basename(bundle.rstrip("/")).removesuffix(".xcresult")
        try:
            tests = xcresulttool("tests", "--path", bundle)
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            print(f"::warning::no test results in {bundle}: {e}")
            continue
        for test in sorted(set(t for n in tests.get("testNodes", []) for t in failed_tests(n))):
            try:
                result = xcresulttool("activities", "--path", bundle, "--test-id", test)
            except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
                print(f"::warning::no activities for {test} in {bundle}: {e}")
                continue
            folder = os.path.join(root, name)
            os.makedirs(folder, exist_ok=True)
            base = os.path.join(folder, re.sub(r"[^A-Za-z0-9_.-]+", "_", test).strip("_"))
            with open(base + ".json", "w") as f:
                json.dump(result, f, indent=1, ensure_ascii=False)
            t = text(result)
            with open(base + ".txt", "w") as f:
                f.write(t)
            print(f"::group::the activities of {test} on {name}")
            print(t, end="")
            print("::endgroup::")


if __name__ == "__main__":
    main()
