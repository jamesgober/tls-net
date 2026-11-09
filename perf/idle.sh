#!/usr/bin/env bash
# Memory per idle TLS connection (docs/PERFORMANCE.md): server RSS with N
# established, idle connections minus its RSS before them, divided by N.
#
#   bash perf/idle.sh [connections] [stacks...]
#
# WARM=1: each connection first fetches a 32 KiB page, so the numbers show
# what an idle connection keeps after it has carried traffic.
set -eu
cd "$(dirname "$0")"
N=${1:-9000}
shift || true
STACKS=${*:-tls-net tokio-rustls tokio-openssl}
cargo build --release -q
BIN=${CARGO_TARGET_DIR:-target}/release/tls-net-perf
OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT
rss() { awk '/VmRSS/ {print $2}' "/proc/$1/status"; }
for s in $STACKS; do
  taskset -c "${SERVER_CPUS:-0,2,4,6,8,10,12,14}" "$BIN" server "$s" 127.0.0.1:9480 8 2>/dev/null &
  PID=$!
  # On a loaded machine a server can take seconds to listen.
  until (exec 3<>/dev/tcp/127.0.0.1/9480) 2>/dev/null; do sleep 0.2; done
  # One connection first, so lazily built state is not counted per connection.
  "$BIN" idle 127.0.0.1:9480 1 0 ${WARM:+warm} >/dev/null
  before=$(rss "$PID")
  "$BIN" idle 127.0.0.1:9480 "$N" 6 ${WARM:+warm} >"$OUT" &
  CLIENT=$!
  until grep -q open "$OUT" 2>/dev/null || ! kill -0 "$CLIENT" 2>/dev/null; do sleep 0.5; done
  sleep 2
  after=$(rss "$PID")
  open=$(awk '/open/ {print $2}' "$OUT")
  if [ -z "$open" ] || [ "$open" -eq 0 ]; then
    echo "$s: the client opened no connections" >&2
    kill "$PID"; wait "$PID" 2>/dev/null || true
    continue
  fi
  printf '%-14s %s idle connections: %.0f bytes each (RSS %s -> %s KiB)\n' "$s" "$open" \
    "$(echo "($after - $before) * 1024 / $open" | bc -l)" "$before" "$after"
  wait "$CLIENT" || true
  kill "$PID"; wait "$PID" 2>/dev/null || true
  sleep 1
done
