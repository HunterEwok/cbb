#!/bin/bash
# watch.sh <container>: on the Mac host. Every 30 s: while another
# thread's xcodebuild or a booted simulator runs, the container is paused,
# and resumed after. A trip pauses it: free memory under 3 GB or swap over
# 7 GB (other threads' builds move swap, so growth alone is no trip). After
# a trip it resumes only once all three are clear again, checked every
# 10 minutes; two trips within an hour keep it paused for good (STOPPED
# beside this script). Logs to watch.log every 10 minutes and on changes.
c=$1; D=$(dirname "$0"); L=$D/watch.log
swap() { sysctl -n vm.swapusage | sed -E 's/.*used = ([0-9.]+)M.*/\1/' | cut -d. -f1; }
free_mb() { vm_stat | awk -v ps="$(pagesize)" '/Pages free|Pages inactive|Pages speculative|Pages purgeable/{gsub("\\.","",$NF); s+=$NF} END{print int(s*ps/1048576)}'; }
apple() { pgrep -x xcodebuild >/dev/null || xcrun simctl list devices 2>/dev/null | grep -q '(Booted)'; }
log() { echo "$(date -u +%FT%TZ) $*" >> "$L"; }
s0=$(swap); last_trip=0; tripped=0; byapple=0; n=0
log "watch start swap=${s0}M"
while docker inspect "$c" >/dev/null 2>&1; do
  f=$(free_mb); s=$(swap); st=$(docker inspect -f '{{.State.Status}}' "$c"); now=$(date +%s)
  bad=0; { [ "$f" -lt 3072 ] || [ "$s" -gt 7000 ]; } && bad=1
  if [ $((n % 20)) -eq 0 ]; then
    log "free=${f}M swap=${s}M (start ${s0}M) $st $(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' "$c")"
  fi
  n=$((n + 1))
  if [ "$bad" = 1 ] && [ "$tripped" = 0 ]; then
    [ "$st" = running ] && docker pause "$c" >/dev/null
    if [ $((now - last_trip)) -lt 3600 ] && [ "$last_trip" -gt 0 ]; then
      log "TRIP again within an hour: free=${f}M swap=${s}M; paused for good"; touch "$D/STOPPED"; exit 0
    fi
    log "TRIP: free=${f}M swap=${s}M (start ${s0}M); paused"; last_trip=$now; tripped=1
  elif [ "$tripped" = 1 ]; then
    if [ "$bad" = 0 ] && [ $((now - last_trip)) -ge 600 ] && ! apple; then
      docker unpause "$c" >/dev/null && log "clear again: resumed"; tripped=0
    fi
  elif apple; then
    [ "$st" = running ] && docker pause "$c" >/dev/null && log "xcodebuild or a simulator runs: paused" && byapple=1
  elif [ "$byapple" = 1 ]; then
    docker unpause "$c" >/dev/null && log "xcodebuild and simulators gone: resumed"; byapple=0
  fi
  sleep 30
done
