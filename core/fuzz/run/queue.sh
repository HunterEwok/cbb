#!/bin/bash
# queue.sh: long cargo-fuzz runs, one phase after another, in the container.
# /work is a checkout with this core/fuzz; /out keeps corpus/, art/, logs/
# across restarts, so every run resumes from its corpus. Touch /out/STOP to
# end after the current phase. A build in 3 GB runs out of memory: build
# once in a container with 5 GB and CARGO_BUILD_JOBS=1, then run here.
set -u
cd /work/core/fuzz
mkdir -p /out/logs
log() { echo "$(date -u +%FT%TZ) $*" >> /out/logs/queue.log; }
ALL="records_set records_group grant_seq grant_stored join records_decode pq_verify format format_guarded msg content commands beacon record_body command credential release wire api vless"
log "build"
cargo +nightly fuzz build -O >> /out/logs/build.log 2>&1 || { log "build failed"; exit 1; }
BIN=$(cd "$(dirname "$(ls target/*/release/records_set)")" && pwd)
[ -x "$BIN/records_set" ] || { log "no binaries in $BIN"; exit 1; }

# run <target> <seconds> <workers> [timeout]
run() {
  local t=$1 secs=$2 jobs=$3 to=${4:-10}
  mkdir -p /out/corpus/$t /out/art/$t
  [ -d corpus/$t ] && cp -n corpus/$t/* /out/corpus/$t/ 2>/dev/null
  # Caps: stop a target's run when its corpus passes 400 MB or it has 200
  # artifacts; stop the queue when /out has under 5 GB free.
  if [ "$(du -sm /out/corpus/$t | cut -f1)" -gt 400 ]; then log "$t corpus over cap, skipped"; return; fi
  if [ "$(ls /out/art/$t | wc -l)" -ge 200 ]; then log "$t artifacts over cap, skipped"; return; fi
  log "start $t ${secs}s x$jobs"
  (cd /out/art/$t && nice -n 10 "$BIN/$t" /out/corpus/$t -fork=$jobs \
    -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1 -max_total_time=$secs \
    -max_len=131072 -malloc_limit_mb=128 -rss_limit_mb=1536 -timeout=$to \
    -artifact_prefix=/out/art/$t/ -print_final_stats=1 >> /out/logs/$t.log 2>&1)
  rc=$?
  [ -x "$BIN/$t" ] || { log "no binary for $t"; exit 1; }
  log "end $t exit $rc crashes=$(ls /out/art/$t | grep -c crash) timeouts=$(ls /out/art/$t | grep -c timeout)"
}
disk_ok() { [ "$(df -Pm /out | awk 'NR==2{print $4}')" -gt 5120 ]; }

# PHASE=B starts the first round at phase B.
first=${PHASE:-A}
while [ ! -e /out/STOP ] && disk_ok; do
  # Phase A, 4 h: the records targets, two workers each.
  if [ "$first" = A ]; then
    run records_set 14400 2 & run records_group 14400 2 120 & wait
  fi
  first=A
  [ -e /out/STOP ] || ! disk_ok && break
  # Phase B, 2 h: the readers next to the records.
  # Three at a time, to stay inside the container's memory.
  run join 3600 1 & run records_decode 3600 1 & run grant_seq 3600 1 & wait
  run pq_verify 3600 1 & run format_guarded 3600 1 & run grant_stored 3600 1 & wait
  [ -e /out/STOP ] || ! disk_ok && break
  # Phase C, 2 h: the rest, two at a time.
  for pair in "msg content" "commands beacon" "record_body command" "credential release" "wire api" "vless format"; do
    set -- $pair
    run $1 2400 2 & run $2 2400 2 & wait
    [ -e /out/STOP ] && break
  done
done
log "queue ended"
