#!/usr/bin/env bash
# engine.sh — run Truent's deterministic engine. This is the ground-truth layer
# of a truent-audit scan: every finding here is produced by a compiled analyzer,
# not by a model, so it is reproducible and free of hallucination.
#
# Usage:
#   engine.sh <path> [chain] [--render] [--out FILE] [--sarif FILE]
#   engine.sh --files LIST [chain] [--render] [--out FILE]
#     <path>     file or directory to scan
#     --files L  a file holding one in-scope path per line (SKILL.md Turn 2-engine
#                writes one per chain). Each path is scanned on its own and the
#                results are merged into one document, so the engine sees exactly
#                the audit's scope and nothing under lib/, test/ or target/.
#     [chain]    evm | solana | move | soroban | general | auto
#                Omitted, or `auto`: detect from the files under <path>. One
#                kind of source gives that chain; a mix gives the engine's own
#                `--chain auto`, which picks an analyzer per file.
#     --render   instead of JSON, print engine-findings.md: one finding block
#                per violation in the run-file shape assemble.sh reads
#                (marker, title, location, Engine line, Description, Fix,
#                Verify). Every block carries its tier: VERIFIED-PROVEN when
#                the engine's `evidence` is "proven", VERIFIED-STATIC when it
#                is "lead".
#     --out F    write the raw JSON to F as well (useful with --render, so the
#                JSON is kept next to the rendered blocks).
#     --sarif F  also write a SARIF 2.1.0 report (passed through to the engine).
#
# Output (stdout): the JSON object from `truent scan --output json`
#   {chain, duration_ms, summary{critical,high,medium,low,violations}, target,
#    version, violations[]} — or, with --render, the markdown blocks.
#
# Exit code mirrors `truent scan --fail-on critical`: the engine exits 1 only
# when a PROVEN finding at or above critical exists (static detector matches
# are evidence "lead" and never fail the gate). 127 when no binary was found.
# So in an audit the exit code is information, not a stop condition: SKILL.md
# Turn 2-engine records it and carries on.
set -uo pipefail

PATH_ARG=""
FILES=""
if [ "${1:-}" = "--files" ]; then
  FILES="${2:?--files needs a list file}"; shift 2
  [ -f "$FILES" ] || { echo "engine.sh: no such list file $FILES" >&2; exit 2; }
else
  PATH_ARG="${1:?usage: engine.sh <path>|--files LIST [chain] [--render] [--out FILE] [--sarif FILE]}"
  shift
fi
CHAIN=""
RENDER=0
OUT=""
SARIF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --render) RENDER=1; shift ;;
    --out)    OUT="${2:?--out needs a file}"; shift 2 ;;
    --sarif)  SARIF="${2:?--sarif needs a file}"; shift 2 ;;
    evm|solana|move|soroban|general|auto) CHAIN="$1"; shift ;;
    *) echo "engine.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

# ── Locate the truent binary ─────────────────────────────────────────────
# Prefer an installed `truent`; fall back to a build in this repo.
find_truent() {
  if command -v truent >/dev/null 2>&1; then command -v truent; return; fi
  local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # Walk up looking for a cargo target dir (skill may live inside the repo,
  # or be installed alongside it).
  local d="$here"
  for _ in 1 2 3 4 5 6; do
    for cand in "$d/target/release/truent" "$d/target/debug/truent"; do
      [ -x "$cand" ] && { echo "$cand"; return; }
    done
    d="$(dirname "$d")"
  done
  # Also try the current working directory's target.
  for cand in "./target/release/truent" "./target/debug/truent"; do
    [ -x "$cand" ] && { echo "$cand"; return; }
  done
  return 1
}

TRUENT="$(find_truent)" || {
  echo '{"_truent":{"error":"truent binary not found. Install it (cargo install --path crates/cli) or build it (cargo build --release --bin truent)."}}' >&2
  exit 127
}

# ── Chain detection ──────────────────────────────────────────────────────
# By file content and extension, never by directory name. A `.rs` file is a
# Solana program when it has a `use anchor_lang` / `use solana_program` line,
# a Soroban contract when it has `use soroban_sdk`, and out of scope otherwise
# (a file that only mentions a crate name in a string is not a program).
detect_chain() {
  local p="$1" sol=0 mv=0 sol_rs=0 sor_rs=0 f
  if [ -f "$p" ]; then
    case "$p" in
      *.sol)  echo evm; return ;;
      *.move) echo move; return ;;
      *.rs)
        if /usr/bin/grep -qE '^[[:space:]]*use soroban_sdk' "$p" 2>/dev/null; then echo soroban; return; fi
        if /usr/bin/grep -qE '^[[:space:]]*use (anchor_lang|solana_program)' "$p" 2>/dev/null; then echo solana; return; fi
        echo general; return ;;
      *) echo general; return ;;
    esac
  fi
  while IFS= read -r f; do
    case "$f" in
      *.sol)  sol=1 ;;
      *.move) mv=1 ;;
      *.rs)
        if /usr/bin/grep -qE '^[[:space:]]*use soroban_sdk' "$f" 2>/dev/null; then sor_rs=1
        elif /usr/bin/grep -qE '^[[:space:]]*use (anchor_lang|solana_program)' "$f" 2>/dev/null; then sol_rs=1
        fi ;;
    esac
  done < <(find "$p" -type f \( -name '*.sol' -o -name '*.move' -o -name '*.rs' \) \
             -not -path '*/node_modules/*' -not -path '*/lib/*' -not -path '*/target/*' \
             -not -path '*/build/*' -not -path '*/out/*' -not -path '*/artifacts/*' 2>/dev/null)
  local n=$((sol + mv + sol_rs + sor_rs))
  if [ "$n" -eq 0 ]; then echo general
  elif [ "$n" -gt 1 ]; then echo auto
  elif [ "$sol" = 1 ]; then echo evm
  elif [ "$mv" = 1 ]; then echo move
  elif [ "$sol_rs" = 1 ]; then echo solana
  else echo soroban
  fi
}

if [ -z "$CHAIN" ] || [ "$CHAIN" = auto ]; then
  if [ -n "$FILES" ]; then
    # Detect from the first listed file; a list Turn 2-engine wrote is one chain by construction.
    first="$(head -n 1 "$FILES")"
    CHAIN="$(detect_chain "$first")"
  else
    CHAIN="$(detect_chain "$PATH_ARG")"
  fi
fi

# ── Run the deterministic scan ───────────────────────────────────────────
# --output json is stable, machine-parseable, and identical run-to-run.
# --fail-on critical makes the exit code a usable CI gate signal.
# The engine prints its progress lines on stderr; stdout is the JSON alone.
workdir="$(mktemp -d -t truent-engine.XXXXXX)"
trap 'rm -rf "$workdir"' EXIT
work="$workdir/all.jsonl"   # one JSON object per line: one per scanned path
: > "$work"
status=0
if [ -n "$FILES" ]; then
  # One scan per listed path. The exit code is the worst one seen. --sarif is not
  # supported in list mode (one SARIF per file would need one --sarif per file).
  [ -n "$SARIF" ] && echo "engine.sh: --sarif is ignored with --files" >&2
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    "$TRUENT" scan "$f" --chain "$CHAIN" --output json --fail-on critical > "$workdir/one.json"
    st=$?
    [ "$st" -gt "$status" ] && status=$st
    tr -d '\n' < "$workdir/one.json" >> "$work"; printf '\n' >> "$work"
  done < "$FILES"
else
  set -- scan "$PATH_ARG" --chain "$CHAIN" --output json --fail-on critical
  [ -n "$SARIF" ] && set -- "$@" --sarif "$SARIF"
  "$TRUENT" "$@" > "$workdir/one.json"
  status=$?
  tr -d '\n' < "$workdir/one.json" >> "$work"; printf '\n' >> "$work"
fi

[ -n "$OUT" ] && cp "$work" "$OUT"

if [ "$RENDER" = 0 ]; then
  if [ -n "$FILES" ]; then cat "$work"; else cat "$workdir/one.json"; fi
  exit "$status"
fi

# ── Render engine-findings.md ────────────────────────────────────────────
# One block per violation, in the exact geometry assemble.sh indexes:
#   +0 marker · +1 blank · +2 title · +3 blank · +4 location · +5 blank · +6.. body
# Confidence is set from the engine's own fields, never by a model:
#   evidence "proven"                       → tier VERIFIED-PROVEN, conf 100
#   evidence "lead", exploitability likely  → tier VERIFIED-STATIC, conf 95
#                                  possible → 90 · unlikely → 85 · theoretical → 80
# All of these clear the 75 threshold, so every engine block carries the
# engine's own Fix and Verify text.
# The key is <file-stem>|engine-L<line>|<invariant_id>: the second segment is
# what the memory prune recognises (see SKILL.md Turn 2 step 2b) and the line
# keeps two matches of one detector in one file as two records.
if ! command -v python3 >/dev/null 2>&1; then
  echo "engine.sh: --render needs python3 to read the engine's JSON" >&2
  cat "$work"
  exit "$status"
fi

python3 - "$work" "$CHAIN" "$status" <<'PY'
import json, re, sys, os

path, chain_arg, status = sys.argv[1], sys.argv[2], sys.argv[3]
docs, bad = [], 0
with open(path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            docs.append(json.loads(line))
        except Exception:
            bad += 1
if not docs:
    print("<!--ENGINE chain=%s status=%s violations=? error=unreadable-json-->" % (chain_arg, status))
    print()
    print("**Engine output could not be read** — %d scan(s) printed something that is not JSON. The raw output is kept next to this file." % max(bad, 1))
    sys.exit(0)

summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
viols = []
targets = []
for d in docs:
    for k in summary:
        summary[k] += (d.get("summary") or {}).get(k, 0) or 0
    viols.extend(d.get("violations") or [])
    targets.append(str(d.get("target", "?")))
version = docs[0].get("version", "?")
doc = {"target": targets[0] if len(targets) == 1 else "%d files" % len(targets), "chain": docs[0].get("chain", chain_arg)}
if bad:
    print("<!--ENGINE-WARNING %d scan(s) printed unreadable output and are missing below-->" % bad)
print("<!--ENGINE chain=%s version=%s status=%s violations=%d critical=%s high=%s medium=%s low=%s-->" % (
    chain_arg, version, status, len(viols),
    summary.get("critical", 0), summary.get("high", 0), summary.get("medium", 0), summary.get("low", 0)))
print()
print("# Engine findings — what the compiled detectors already proved or matched")
print()
print("Target `%s` · chain `%s` · truent %s · %d violation(s): %s critical, %s high, %s medium, %s low."
      % (doc.get("target", "?"), doc.get("chain", chain_arg), version, len(viols),
         summary.get("critical", 0), summary.get("high", 0), summary.get("medium", 0), summary.get("low", 0)))
print()
print("Every block below came from the engine, not from a model. `VERIFIED-PROVEN` means the engine")
print("executed it. `VERIFIED-STATIC` means a compiled detector matched real code. Agents: these are")
print("found. Hunt what the detectors cannot encode, and report a listed bug again only when you")
print("reach it by a different mechanism or with a wider impact.")
print()

CONF = {"likely": 95, "possible": 90, "unlikely": 85, "theoretical": 80}
LANG = {".sol": "solidity", ".rs": "rust", ".move": "move", ".vy": "vyper"}

def norm(s):
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-") or "x"

def oneline(s):
    return re.sub(r"\s+", " ", str(s or "")).strip()

for v in viols:
    evidence = (v.get("evidence") or "lead").lower()
    tier = "VERIFIED-PROVEN" if evidence == "proven" else "VERIFIED-STATIC"
    conf = 100 if tier == "VERIFIED-PROVEN" else CONF.get((v.get("exploitability") or "").lower(), 85)
    sev = (v.get("severity") or "info").lower()
    inv = v.get("invariant_id") or "unknown"
    file_ = v.get("file") or "?"
    line = v.get("line") or 0
    stem, ext = os.path.splitext(os.path.basename(file_))
    key = "%s|engine-L%s|%s" % (norm(stem), line, norm(inv))
    title = oneline(v.get("title") or inv)
    loc = v.get("location") or "%s:%s" % (file_, line)
    vchain = v.get("chain") or chain_arg

    print("<!--F key=%s conf=%d kind=FINDING tier=%s sev=%s agents=engine id=%s evidence=%s-->" % (
        key, conf, tier, sev, inv, evidence))
    print()
    print("[%d] **%s**" % (conf, title))
    print()
    print("`%s` · %s · %s · Confidence: %d" % (loc, sev.upper(), tier, conf))
    print()
    tax = []
    if v.get("cwe"):
        tax.append(oneline(v["cwe"]))
    for k, label in (("swc", ""), ("owasp_sc", "OWASP "), ("dasp", "")):
        for item in v.get(k) or []:
            tax.append(label + oneline(item))
    eng = "**Engine** `%s` · chain: %s · evidence: %s" % (inv, vchain, evidence)
    if v.get("exploitability"):
        eng += " · exploitability: %s" % v["exploitability"]
    if tax:
        eng += " · " + " · ".join(tax)
    print(eng)
    for r in v.get("exploit_reasons") or []:
        print("- %s" % oneline(r))
    print()
    print("**Description**")
    print(oneline(v.get("message") or title))
    print()
    snippet = (v.get("code_snippet") or "").rstrip()
    if snippet:
        print("```%s" % LANG.get(ext, ""))
        print(snippet)
        print("```")
        print()
    fix = oneline(v.get("fix") or v.get("recommendation") or "")
    if fix:
        print("**Fix**")
        print(fix)
        print()
    ver = oneline(v.get("verify") or "")
    if ver:
        print("**Verify**")
        print(ver)
        print()
    ref = v.get("reference")
    if ref:
        print("Reference: %s" % ref)
        print()
    print("<!--/F-->")
    print()
PY

exit "$status"
