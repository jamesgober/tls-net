#!/usr/bin/env bash
# Runs the tlsfuzzer scripts listed in tlsfuzzer.txt against 127.0.0.1:4433.
# Each line: <expect> <script> [args...], where <expect> is `pass` (a failure
# fails the job) or `report` (run and log only, with the reason in the file).
#
#   bash tests/conformance/tlsfuzzer.sh <tlsfuzzer checkout>
set -u
TF=$1
: "${TF:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
LOGS=${RUNNER_TEMP:-/tmp}/tlsfuzzer-logs
mkdir -p "$LOGS"
failed=0
while read -r expect script args; do
  case "$expect" in ''|'#'*) continue ;; esac
  log="$LOGS/$script.log"
  # shellcheck disable=SC2086
  if (cd "$TF" && PYTHONPATH=. timeout 900 python3 "scripts/$script" -h localhost -p 4433 $args) >"$log" 2>&1; then
    result=pass
  else
    result=fail
  fi
  summary=$(grep -E "^(TOTAL|SKIP|PASS|FAIL|XFAIL|XPASS):" "$log" | tr '\n' ' ')
  printf '%-6s %-6s %-52s %s\n' "$expect" "$result" "$script" "$summary"
  if [ "$expect" = pass ] && [ "$result" = fail ]; then
    failed=1
    grep -E "^(FAIL|Error|Traceback)|AssertionError" "$log" | head -20
  fi
done <"$HERE/tlsfuzzer.txt"
exit $failed
