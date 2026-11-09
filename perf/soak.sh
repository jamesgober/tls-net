#!/usr/bin/env bash
# Soak (PLAN NFR-21, D-108): tls-net on net-io's reactor under mixed full
# and resumed handshakes, with a certificate reload every 60 seconds and a
# ticket key rotation every 10 minutes (ephemeral ring, 10-minute epochs).
# The server's resident memory and tls-net's counters are logged every
# minute; the summary compares memory after the first 10 minutes with the
# end, and counts failed handshakes, refused reloads, and client errors.
#
#   bash perf/soak.sh [minutes]
set -eu
cd "$(dirname "$0")"
MINUTES=${1:-360}
DIR=${SOAK_DIR:-$HOME/soak/tls-net}
: "${DIR:?}"
mkdir -p "$DIR"
cargo build --release -q
BIN=${CARGO_TARGET_DIR:-target}/release/tls-net-perf
ADDR=127.0.0.1:9490
STAMP=$(date +%Y%m%d-%H%M)
SLOG="$DIR/server-$STAMP.log"
CLOG="$DIR/load-$STAMP.log"
PERF_RELOAD_SECS=60 PERF_TICKET_MINUTES=10 PERF_RSS_SECS=60 \
  taskset -c "${SERVER_CPUS:-0,2,4,6,8,10,12,14}" "$BIN" server tls-net "$ADDR" 8 2>"$SLOG" &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT
sleep 1
taskset -c "${CLIENT_CPUS:-16-31}" "$BIN" load mixed "$ADDR" "${THREADS:-32}" $((MINUTES * 60)) >"$CLOG" 2>&1
sleep 61
awk -v m="$MINUTES" '
  /^rss_kib/ { n++; rss[n] = $2; if ($2 > max) max = $2; failed = $8 }
  /reload failed/ { reloads++ }
  END {
    warm = (n >= 10) ? rss[10] : rss[1]
    printf "minutes %d, samples %d: RSS after 10 min %d KiB, at the end %d KiB, peak %d KiB (%+.1f%%)\n",
      m, n, warm, rss[n], max, (rss[n] - warm) * 100 / warm
    printf "handshakes failed by the server: %d, refused reloads: %d\n", failed, reloads + 0
  }' "$SLOG"
tail -1 "$CLOG"
grep -q "^rss_kib" "$SLOG" || echo "no samples: see $SLOG"
grep "^rss_kib" "$SLOG" | tail -1 | sed 's/^/last sample: /'
