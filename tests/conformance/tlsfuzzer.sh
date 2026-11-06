#!/usr/bin/env bash
# Runs the tlsfuzzer scripts listed in tlsfuzzer.txt. Each line:
# <expect> <server> <script> [args...]; <expect> is `pass` (a failure fails
# the job) or `report` (run and log only, the reason in the file); <server>
# is `ecdsa` (127.0.0.1:4433) or `rsa` (127.0.0.1:4434).
#
#   bash tests/conformance/tlsfuzzer.sh <tlsfuzzer checkout>
set -u
TF=$1
: "${TF:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
LOGS=${RUNNER_TEMP:-/tmp}/tlsfuzzer-logs
mkdir -p "$LOGS"
failed=0
while read -r expect server script args; do
  case "$expect" in ''|'#'*) continue ;; esac
  case "$server" in ecdsa) port=4433 ;; rsa) port=4434 ;; *) echo "bad server $server"; exit 1 ;; esac
  log="$LOGS/$server-$script.log"
  # shellcheck disable=SC2086
  if (cd "$TF" && PYTHONPATH=. timeout 900 python3 "scripts/$script" -h localhost -p "$port" $args) >"$log" 2>&1; then
    result=pass
  else
    result=fail
  fi
  summary=$(grep -E "^(TOTAL|SKIP|PASS|FAIL|XFAIL|XPASS):" "$log" | tr '\n' ' ')
  printf '%-6s %-6s %-5s %-50s %s\n' "$expect" "$result" "$server" "$script" "$summary"
  if [ "$expect" = pass ] && [ "$result" = fail ]; then
    failed=1
    grep -E "^(FAIL|Error|Traceback)|AssertionError" "$log" | head -20
  fi
done <"$HERE/tlsfuzzer.txt"
exit $failed
