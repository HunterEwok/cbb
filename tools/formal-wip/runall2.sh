#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
# runall2.sh <dir> <theory> <seconds> [lemma...]: every lemma (or the given ones) in file order
d=$1; f=$2; to=$3; shift 3
ls=${@:-$(grep -o '^lemma [A-Za-z0-9_]*' $d/$f | awk '{print $2}')}
for l in $ls; do /home/user/work/run2.sh $d $f $l $to; done
echo "$(date -u +%H:%MZ) $f ALL DONE" >> $d/out/runs.sum
