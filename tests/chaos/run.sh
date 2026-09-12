#!/usr/bin/env bash
# Chaos / failure experiments for the scanner itself.
#
# Each experiment injects a fault the tool will meet in the field and asserts
# the *graceful* behaviour: an error is reported, nothing hangs, nothing
# panics, the exit code is honest. Expectations are written before the
# experiment runs; an experiment without an expectation is not a test.
#
#   tests/chaos/run.sh [path-to-truent-binary]
set -uo pipefail

BIN="${1:-./target/release/truent}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; kill $(jobs -p) 2>/dev/null' EXIT
FAILS=0
ok()  { echo "  ✓ $1"; }
bad() { echo "  ✗ $1"; FAILS=$((FAILS+1)); }
json_assert() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert $2, d" "$1" 2>/dev/null; }

echo "▶ 1. probe against a server that accepts and never answers (network hang)"
python3 - "$WORK" <<'PY' &
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 8097)); s.listen(5)
while True:
    c, _ = s.accept()
    time.sleep(120)  # hold the connection open, send nothing
PY
sleep 0.5
START=$(date +%s)
"$BIN" probe http://127.0.0.1:8097 --authorized --ports none --no-paths --timeout 3 --format json > "$WORK/probe.json" 2>"$WORK/probe.err"; RC=$?
ELAPSED=$(( $(date +%s) - START ))
if [ "$ELAPSED" -le 8 ]; then ok "returns within 2× timeout (took ${ELAPSED}s)"; else bad "returns within 2× timeout (took ${ELAPSED}s)"; fi
if json_assert "$WORK/probe.json" 'd["errors"]'; then ok "reports the failure in errors[] instead of hanging"; else bad "reports the failure in errors[] instead of hanging"; fi
if ! grep -qi panicked "$WORK/probe.err"; then ok "no panic"; else bad "no panic"; fi

echo "▶ 2. probe against a closed port (connection refused)"
"$BIN" probe http://127.0.0.1:8098 --authorized --ports none --no-paths --timeout 2 --format json > "$WORK/probe2.json" 2>"$WORK/probe2.err"
if json_assert "$WORK/probe2.json" 'd["errors"] and not d["findings"]'; then ok "refused connection is an error, not a finding"; else bad "refused connection is an error, not a finding"; fi

echo "▶ 3. dependency analysis on corrupted lockfiles"
mkdir -p "$WORK/deps"; printf '{"lockfileVersion": 3, "packages": {' > "$WORK/deps/package-lock.json"; head -c 4096 /dev/urandom > "$WORK/deps/Cargo.lock"; printf '[[package]]\nname = "a"\n' > "$WORK/deps/poetry.lock"
"$BIN" deps "$WORK/deps" --format json > "$WORK/deps.json" 2>"$WORK/deps.err"; RC=$?
if [ "$RC" -ne 101 ] && ! grep -qi panicked "$WORK/deps.err"; then ok "corrupt lockfiles do not crash (exit $RC)"; else bad "corrupt lockfiles do not crash (exit $RC)"; fi
if json_assert "$WORK/deps.json" 'True'; then ok "still produces a JSON report"; else bad "still produces a JSON report"; fi

echo "▶ 4. scan of unreadable, binary and empty inputs"
mkdir -p "$WORK/scan"; head -c 100000 /dev/urandom > "$WORK/scan/blob.py"; : > "$WORK/scan/empty.sol"; printf '\xff\xfe' > "$WORK/scan/bad.js"
mkdir "$WORK/scan/noperm"; printf 'x = 1\n' > "$WORK/scan/noperm/a.py"; chmod 000 "$WORK/scan/noperm/a.py"
"$BIN" scan "$WORK/scan" --chain auto --output json > "$WORK/scan.json" 2>"$WORK/scan.err"; RC=$?
chmod 644 "$WORK/scan/noperm/a.py"
if ! grep -qi panicked "$WORK/scan.err" && json_assert "$WORK/scan.json" 'True'; then ok "binary/empty/unreadable files are skipped, not fatal"; else bad "binary/empty/unreadable files are skipped, not fatal"; fi

echo "▶ 5. symbolic execution with no executor on PATH"
PATH=/nonexistent "$BIN" symbolic examples/foundry --format json > "$WORK/sym.json" 2>"$WORK/sym.err"; RC=$?
if json_assert "$WORK/sym.json" 'not d["ran"] and d["errors"]'; then ok "missing tool is reported as an error, never as a pass"; else bad "missing tool is reported as an error, never as a pass"; fi

echo "▶ 6. release-check with a malformed acceptance file"
mkdir -p "$WORK/acc"; printf 'x = 1\n' > "$WORK/acc/a.py"; printf '[[accept]]\nid = "gen_x"\nreason = "no"\n' > "$WORK/acc/.truent.toml"
"$BIN" release-check "$WORK/acc" > "$WORK/rc.out" 2>"$WORK/rc.err"; RC=$?
if [ "$RC" -ne 0 ] && grep -qi "truent.toml" "$WORK/rc.err"; then ok "a malformed .truent.toml fails loudly instead of silently un-accepting (exit $RC)"; else bad "a malformed .truent.toml fails loudly instead of silently un-accepting (exit $RC)"; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "✓ all chaos experiments behaved as expected"; else echo "✗ $FAILS experiment(s) misbehaved"; exit 1; fi
