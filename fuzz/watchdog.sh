#!/usr/bin/env bash
# Hang detection for fuzz/run-24h.sh (D-115). libFuzzer's own timeout reads
# the wall clock, which WSL steps; the runs turn it off and this script
# watches progress instead. A target's fork-mode log gains a line at least
# every 5 minutes; when one stays the same for STALE_MINUTES (default 15)
# while its job runs, the job gets SIGSEGV, so AddressSanitizer prints where
# it was and libFuzzer saves the input to fuzz/artifacts/<target>/crash-*.
# It counts its own sleeps, which run on the monotonic clock.
#
#   bash fuzz/watchdog.sh <hours> <targets...>
set -u
HOURS=$1
shift
CORPUS=${CORPUS:-$HOME/fuzz-corpus/tls-net}
STALE=${STALE_MINUTES:-15}
: "${CORPUS:?}"
declare -A LINES QUIET
for t in "$@"; do LINES[$t]=0; QUIET[$t]=0; done
for ((m = 0; m < HOURS * 60 + 60; m++)); do
  sleep 60
  for t in "$@"; do
    jobs=$(pgrep -f "^[^ ]*/release/$t .*-seed_inputs" || true)
    [ -n "$jobs" ] || { QUIET[$t]=0; continue; }
    n=$(wc -l <"$CORPUS/$t.log")
    if [ "$n" -ne "${LINES[$t]}" ]; then
      LINES[$t]=$n
      QUIET[$t]=0
      continue
    fi
    QUIET[$t]=$((QUIET[$t] + 1))
    if [ "${QUIET[$t]}" -ge "$STALE" ]; then
      echo "$(date) $t: no progress for $STALE minutes; SIGSEGV to $jobs" >>"$CORPUS/watchdog.log"
      kill -SEGV $jobs 2>/dev/null || true
      QUIET[$t]=0
    fi
  done
done
