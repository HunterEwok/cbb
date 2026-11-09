#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

"""Prints the UI tests' pictures whose names contain a marker (as -en) into
the job's log as small base64 JPEGs, so that a failed accessibility audit
can be looked at from the log alone.

Usage: pictures.py <folder of exported attachments> <marker>

The folder holds what `xcrun xcresulttool export attachments` wrote, one
folder for each result bundle, each with its manifest.json. A picture is
printed between "picture <name> begin" and "picture <name> end"; decode it
with `base64 -d`.
"""

import json
import os
import subprocess
import sys
import tempfile


def main() -> None:
    root, marker = sys.argv[1], sys.argv[2]
    for folder, _, files in os.walk(root):
        if "manifest.json" not in files:
            continue
        with open(os.path.join(folder, "manifest.json")) as f:
            manifest = json.load(f)
        for test in manifest:
            for a in test.get("attachments", []):
                name = a.get("suggestedHumanReadableName", "")
                if marker not in name:
                    continue
                path = os.path.join(folder, a["exportedFileName"])
                with tempfile.TemporaryDirectory() as tmp:
                    small = os.path.join(tmp, "small.jpg")
                    subprocess.run(["sips", "-Z", "800", "-s", "format", "jpeg", "-s", "formatOptions", "60",
                                    path, "--out", small], check=True, capture_output=True)
                    data = subprocess.run(["base64", "-i", small], check=True, capture_output=True, text=True).stdout
                print(f"picture {name} begin")
                print(data.replace("\n", ""))
                print(f"picture {name} end")


if __name__ == "__main__":
    main()
