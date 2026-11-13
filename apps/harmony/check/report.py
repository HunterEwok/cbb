# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
"""Reads what check.sh's run of the ArkTS compiler said: its errors and the
linter's, and fails when there is any.

  report.py WORK LOADER

The compiler's webpack mode does not read the custom components of
@ComponentV2 that a page imports, which hvigor's build does, and calls each
use of one "does not meet UI component syntax"; those of the app's own
@ComponentV2 structs are left out, every other error counts.
"""
import json
import os
import re
import sys

work, loader = sys.argv[1], sys.argv[2]
ets = os.path.join(work, "main", "ets")
v2 = set()
for root, _, files in os.walk(ets):
    for f in files:
        if f.endswith(".ets"):
            text = open(os.path.join(root, f), encoding="utf-8").read()
            v2.update(re.findall(r"@ComponentV2\s+export\s+struct\s+(\w+)", text))

log = re.sub(r"\x1b\[[0-9;]*m", "", open(os.path.join(work, "log.txt"), encoding="utf-8").read())
errors = []
for block in re.split(r"(?=ArkTS:(?:ERROR|WARN))", log):
    if not block.startswith("ArkTS:ERROR"):
        continue
    m = re.search(r"'(\w+)\(.*?does not meet UI component syntax", block, re.S)
    if m and m.group(1) in v2:
        continue
    errors.append(block.strip())
if "COMPILE RESULT" not in log:
    errors.append("the compiler did not finish:\n" + log[-3000:])

lint = os.path.join(loader, "node_modules", ".cache", "ArkTS", "ArkTSLinter_output.json")
for e in json.load(open(lint, encoding="utf-8")) if os.path.exists(lint) else []:
    if e.get("categoryInfo") != "Error":
        continue
    name = e["fileName"].replace(ets + os.sep, "")
    errors.append(f"ArkTS:LINT {name}:{e['line']}:{e['character']}\n {e['messageText']}")

for e in errors:
    print(e)
print(f"check.sh: {len(errors)} errors")
sys.exit(1 if errors else 0)
