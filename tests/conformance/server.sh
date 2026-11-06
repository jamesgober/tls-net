#!/usr/bin/env bash
# Builds and starts examples/https_server_blocking on 127.0.0.1:4433 with the
# test certificate (ECDSA P-256 under the test CA), default policy.
set -eu
cd "$(dirname "$0")/../.."
cargo build --release --example https_server_blocking
chmod 600 tests/data/site.key
nohup target/release/examples/https_server_blocking 127.0.0.1:4433 tests/data/site.pem tests/data/site.key \
  >"${RUNNER_TEMP:-/tmp}/server.log" 2>&1 &
for _ in $(seq 1 50); do
  if (exec 3<>/dev/tcp/127.0.0.1/4433) 2>/dev/null; then echo "server up"; exit 0; fi
  sleep 0.2
done
echo "server did not start"; cat "${RUNNER_TEMP:-/tmp}/server.log"; exit 1
