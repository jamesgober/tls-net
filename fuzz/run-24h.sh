#!/usr/bin/env bash
# Long fuzz runs (ROADMAP 0.7, D-060, D-108): seeds every target's corpus
# from fuzz/seeds and the system's certificates, then runs each target for
# HOURS (default 24) at low priority, detached. Corpora and logs go to
# CORPUS (default ~/fuzz-corpus/tls-net), artifacts to fuzz/artifacts/.
#
#   bash fuzz/run-24h.sh [hours]
#
# A finding stops its target and leaves the input in fuzz/artifacts/<target>/.
# On WSL a clock step can report a false timeout: replay the input with
# `cargo fuzz run <target> <file>`, and restart the target if it passes.
set -eu
cd "$(dirname "$0")"
HOURS=${1:-24}
CORPUS=${CORPUS:-$HOME/fuzz-corpus/tls-net}
TD=${FUZZ_TARGET_DIR:-$HOME/tgt/tls-net-fuzz}
: "${CORPUS:?}" "${TD:?}"
TARGETS="hello_parse session_step_server session_step_client der_fields pem_intake ticket_open"
mkdir -p "$CORPUS"
for t in $TARGETS; do mkdir -p "$CORPUS/$t"; done
# Real ClientHellos, raw for the parser and behind a chunk-size byte (whole,
# 5-byte, and 64-byte chunks) for the server session.
for f in seeds/client_hello/*.bin; do
  n=$(basename "$f" .bin)
  cp "$f" "$CORPUS/hello_parse/seed-$n"
  for c in ff 05 40; do
    { printf "\x$c"; cat "$f"; } >"$CORPUS/session_step_server/seed-$c-$n"
  done
done
for f in seeds/server_flight/*.bin; do cp "$f" "$CORPUS/session_step_client/seed-$(basename "$f" .bin)"; done
# Certificates: the test fixtures and up to 64 of the system's roots.
for f in ../tests/data/*.der; do cp "$f" "$CORPUS/der_fields/seed-$(basename "$f")"; done
for f in ../tests/data/*.pem; do cp "$f" "$CORPUS/pem_intake/seed-$(basename "$f")"; done
i=0
for f in /etc/ssl/certs/*.pem; do
  [ $i -ge 64 ] && break
  openssl x509 -in "$f" -outform der -out "$CORPUS/der_fields/seed-sys-$i.der" 2>/dev/null && cp "$f" "$CORPUS/pem_intake/seed-sys-$i.pem"
  i=$((i + 1))
done
cargo +nightly fuzz build --target x86_64-unknown-linux-gnu --target-dir "$TD"
SECS=$((HOURS * 3600))
for t in $TARGETS; do
  setsid nohup nice -n 10 cargo +nightly fuzz run --target x86_64-unknown-linux-gnu --target-dir "$TD" "$t" "$CORPUS/$t" -- \
    -max_total_time="$SECS" -timeout=20 -rss_limit_mb=2048 -print_final_stats=1 \
    >"$CORPUS/$t.log" 2>&1 </dev/null &
  echo "$t: pid $!"
done
