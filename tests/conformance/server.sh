#!/usr/bin/env bash
# Builds and starts examples/https_server_blocking twice, default policy:
# 127.0.0.1:4433 with the ECDSA P-256 test certificate and 127.0.0.1:4434
# with the RSA-2048 one (tlsfuzzer assumes RSA unless told otherwise).
set -eu
cd "$(dirname "$0")/../.."
cargo build --release --example https_server_blocking
chmod 600 tests/data/site.key tests/data/site-rsa.key
LOG=${RUNNER_TEMP:-/tmp}
nohup target/release/examples/https_server_blocking 127.0.0.1:4433 tests/data/site.pem tests/data/site.key \
  >"$LOG/server.log" 2>&1 &
nohup target/release/examples/https_server_blocking 127.0.0.1:4434 tests/data/site-rsa.pem tests/data/site-rsa.key \
  >"$LOG/server-rsa.log" 2>&1 &
for port in 4433 4434; do
  up=0
  for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then up=1; break; fi
    sleep 0.2
  done
  if [ $up = 0 ]; then
    echo "server on $port did not start"
    cat "$LOG"/server*.log
    exit 1
  fi
done
echo "servers up on 4433 (ECDSA) and 4434 (RSA)"
