#!/usr/bin/env bash
# gate.sh — the Truent CI security gate.
#
# Runs the deterministic scan, writes a JSON report and a SARIF file (for
# GitHub code scanning), prints a one-line summary, and exits with the
# scan's own code so the PR check fails when findings at/above the fail-on
# threshold exist. Zero LLM cost, identical result every run.
#
# Env / args:
#   TRUENT_BIN   path to the truent binary        (default: truent)
#   SCAN_PATH    file/dir to scan                 (default: .)
#   SCAN_CHAIN   evm|solana|move|soroban          (default: evm)
#   FAIL_ON      low|medium|high|critical         (default: critical)
#   OUT_JSON     report path                      (default: truent-report.json)
#   OUT_SARIF    sarif path                        (default: truent.sarif)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUENT_BIN="${TRUENT_BIN:-truent}"
SCAN_PATH="${SCAN_PATH:-.}"
SCAN_CHAIN="${SCAN_CHAIN:-evm}"
FAIL_ON="${FAIL_ON:-critical}"
OUT_JSON="${OUT_JSON:-truent-report.json}"
OUT_SARIF="${OUT_SARIF:-truent.sarif}"

if ! command -v "$TRUENT_BIN" >/dev/null 2>&1 && [ ! -x "$TRUENT_BIN" ]; then
  echo "::error::truent binary not found ('$TRUENT_BIN'). Build it first (cargo build --release --bin truent) or set TRUENT_BIN." >&2
  exit 127
fi

# Prefer the engine's own SARIF writer. It emits a real CWE taxonomy component
# with per-rule relationships and security-severity, which is what lets GitHub
# code scanning group, filter and rank Truent findings by weakness class. The
# Python converter can only attach CWE as an opaque property string.
#
# The action may run against a binary older than the --sarif flag, so probe for
# it rather than assume.
native_sarif=0
if "$TRUENT_BIN" scan --help 2>/dev/null | grep -q -- '--sarif'; then
  native_sarif=1
fi

# Run the scan. --fail-on makes the exit code the gate signal; capture it
# without aborting so we still emit SARIF for the Security tab.
scan_rc=0
if [ "$native_sarif" -eq 1 ]; then
  "$TRUENT_BIN" scan "$SCAN_PATH" --chain "$SCAN_CHAIN" --output json \
    --fail-on "$FAIL_ON" --sarif "$OUT_SARIF" \
    > "$OUT_JSON" 2>/dev/null || scan_rc=$?
else
  echo "::warning::truent has no --sarif flag; falling back to the converter. \
Upgrade to get CWE taxonomy in code scanning." >&2
  "$TRUENT_BIN" scan "$SCAN_PATH" --chain "$SCAN_CHAIN" --output json \
    --fail-on "$FAIL_ON" \
    > "$OUT_JSON" 2>/dev/null || scan_rc=$?
fi

# Fallback conversion, also used if the native write produced nothing (e.g. the
# scan aborted before reaching the writer). An empty Security tab is a worse
# failure than a taxonomy-less one.
if [ ! -s "$OUT_SARIF" ]; then
  python3 "$HERE/to_sarif.py" "$OUT_JSON" "$OUT_SARIF" || true
fi

# One-line summary from the report.
python3 - "$OUT_JSON" <<'PY' || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    s = d.get("summary", {})
    print("::notice::Truent scan — %d violations (critical %d, high %d, medium %d, low %d) on %s"
          % (s.get("violations", 0), s.get("critical", 0), s.get("high", 0),
             s.get("medium", 0), s.get("low", 0), d.get("chain", "?")))
except Exception:
    print("::notice::Truent scan — no parseable report (target may have no in-scope files)")
PY

if [ "$scan_rc" -ne 0 ]; then
  echo "::error::Truent gate FAILED — findings at or above '$FAIL_ON'. See the Security tab / $OUT_SARIF." >&2
fi
exit "$scan_rc"
