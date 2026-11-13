#!/bin/bash
# watch.sh <container>: on the Mac host, every 10 minutes: free memory and
# swap; pause the container when free memory is under 3 GB or swap grew
# by more than 256 MB since the start. Writes watch.log next to itself.
c=$1; L=$(dirname "$0")/watch.log
swap() { sysctl -n vm.swapusage | sed -E 's/.*used = ([0-9.]+)M.*/\1/' | cut -d. -f1; }
free_mb() { vm_stat | awk -v ps="$(pagesize)" '/Pages free|Pages inactive|Pages speculative|Pages purgeable/{gsub("\\.","",$NF); s+=$NF} END{print int(s*ps/1048576)}'; }
s0=$(swap)
while docker inspect "$c" >/dev/null 2>&1; do
  f=$(free_mb); s=$(swap); st=$(docker inspect -f '{{.State.Status}}' "$c")
  echo "$(date -u +%FT%TZ) free=${f}M swap=${s}M (start ${s0}M) $st $(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' "$c")" >> "$L"
  if [ "$st" = running ] && { [ "$f" -lt 3072 ] || [ $((s - s0)) -gt 256 ]; }; then
    docker pause "$c" >/dev/null && echo "$(date -u +%FT%TZ) PAUSED: low memory or swap grew" >> "$L"
  fi
  sleep 600
done
