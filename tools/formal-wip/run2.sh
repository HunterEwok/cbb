#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
# run2.sh <dir> <theory> <lemma> <seconds> [extra args]: one lemma, result + peak memory in <dir>/out/runs.sum
cd "$1"; shift; export PATH=/opt/tools/bin:$PATH LANG=C.UTF-8; mkdir -p out
f=$1; l=$2; to=$3; shift 3; tag=$(basename $f .spthy)
s=$(date +%s)
timeout $to tamarin-prover -c=30 --derivcheck-timeout=0 --prove=$l "$@" $f +RTS -M${HEAP:-4g} -N1 -RTS > out/${tag}__$l.txt 2>&1 &
tp=$!; peak=0
while kill -0 $tp 2>/dev/null; do
  for p in $(pgrep -P $tp) $(pgrep -f "prove=$l .*$f" ); do r=$(awk '/VmRSS/{print $2}' /proc/$p/status 2>/dev/null); [ -n "$r" ] && [ $r -gt $peak ] && peak=$r; done
  sleep 5
done
wait $tp; rc=$?
res=$(grep -E "^\s+$l \(" out/${tag}__$l.txt | sed 's/^ *//')
[ $rc -eq 124 ] && res="$l: TIMEOUT ${to}s"
[ -z "$res" ] && res="$l: rc=$rc $(tail -1 out/${tag}__$l.txt | cut -c1-120)"
echo "$(date -u +%H:%MZ) $tag $* | $res | $(( $(date +%s)-s ))s | peak $((peak/1024)) MB" >> out/runs.sum
