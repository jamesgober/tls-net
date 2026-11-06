#!/usr/bin/env bash
# Interleaved loopback comparison (docs/PERFORMANCE.md): every server runs at
# once on SERVER_CPUS (an idle server costs nothing), and the load generator
# visits them in turn, ROUNDS times, WINDOW seconds each. Load from other
# processes that drifts over the run then hits every stack alike. Prints, per
# stack, the median rate and the median server CPU time per operation.
#
#   bash perf/ab.sh <handshakes|bulk> [rounds] [window] [stacks...]
set -eu
cd "$(dirname "$0")"
MODE=$1
ROUNDS=${2:-10}
WINDOW=${3:-3}
shift 3 || shift $#
STACKS=${*:-tls-net tokio-rustls tokio-openssl}
SERVER_CPUS=${SERVER_CPUS:-0,2,4,6,8,10,12,14}
CLIENT_CPUS=${CLIENT_CPUS:-16-31}
THREADS=${THREADS:-64}
[ "$MODE" = bulk ] && THREADS=${BULK_THREADS:-8}
cargo build --release -q
BIN=${CARGO_TARGET_DIR:-target}/release/tls-net-perf
TCK=$(getconf CLK_TCK)
OUT=$(mktemp -d)
cpu() { awk '{print $14 + $15}' "/proc/$1/stat"; }
declare -A PID PORT
port=9460
for s in $STACKS; do
  PORT[$s]=$port
  taskset -c "$SERVER_CPUS" "$BIN" server "$s" "127.0.0.1:$port" 8 2>/dev/null &
  PID[$s]=$!
  port=$((port + 1))
done
trap 'for s in $STACKS; do kill ${PID[$s]} 2>/dev/null || true; done; rm -rf "$OUT"' EXIT
sleep 1
for r in $(seq 1 "$ROUNDS"); do
  for s in $STACKS; do
    b=$(cpu "${PID[$s]}")
    line=$(taskset -c "$CLIENT_CPUS" "$BIN" load "$MODE" "127.0.0.1:${PORT[$s]}" "$THREADS" "$WINDOW" x25519)
    a=$(cpu "${PID[$s]}")
    rate=$(echo "$line" | awk '{print $2}')
    # The load generator runs one warm-up second at the same rate.
    echo "$rate $(echo "($a - $b) / $TCK" | bc -l)" >>"$OUT/$s"
  done
  # Rotate the order so no stack always follows the same one.
  STACKS="$(echo $STACKS | cut -d' ' -f2-) $(echo $STACKS | cut -d' ' -f1)"
done
unit=handshakes/s; per="µs per handshake"; scale=1000000
[ "$MODE" = bulk ] && { unit=MB/s; per="ms per GB"; }
for s in $(ls "$OUT"); do
  awk -v w="$WINDOW" -v sc="$scale" -v s="$s" -v unit="$unit" -v per="$per" '
    { rate[NR] = $1; cost[NR] = $2 / ($1 * (w + 1)) * sc }
    END {
      n = asort(rate); asort(cost)
      printf "%-14s %s median %.0f (min %.0f, max %.0f)  server cpu (%s) median %.1f\n",
        s, unit, rate[int((n + 1) / 2)], rate[1], rate[n], per, cost[int((n + 1) / 2)]
    }' "$OUT/$s"
done
