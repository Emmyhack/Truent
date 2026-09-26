#!/usr/bin/env bash
# Adapted from pashov/skills x-ray/scripts/enumerate.sh (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine integration, multi-chain.
#
# Step 1 of truent-recon: enumerate source files, line counts, nSLOC, doc
# comments, test signals per toolchain, docs, commit, and git history stats.
#
# Usage: enumerate.sh <project-root> [src-dir]
#   src-dir omitted or "auto" → first of src/ contracts/ programs/ sources/ that exists
#
# Output: labeled "=== section ===" blocks consumed by SKILL.md Step 1.
#
# Portability: POSIX ERE only (no `grep -P`, no `\s`/`\w`/`\b`), so it runs
# identically on macOS /usr/bin/grep (BSD), GNU grep and busybox. `wc -l`
# output is stripped of BSD's leading spaces. `--include`/`--exclude-dir`
# are supported by BSD and GNU grep.

set -u
ROOT="${1:-.}"
SRC="${2:-auto}"

cd "$ROOT" || { echo "cannot cd to $ROOT" >&2; exit 1; }

if [ "$SRC" = "auto" ] || [ -z "$SRC" ]; then
  SRC=""
  for d in src contracts programs sources; do
    if [ -d "$d" ]; then SRC="$d"; break; fi
  done
  [ -z "$SRC" ] && SRC="."
fi

# Directories never treated as protocol source or tests.
EXCL_PATHS='-not -path */node_modules/* -not -path */lib/* -not -path */forge-std/* -not -path */out/* -not -path */broadcast/* -not -path */artifacts/* -not -path */cache/* -not -path */target/* -not -path */build/* -not -path */dist/* -not -path */coverage/* -not -path */typechain*/* -not -path */.git/* -not -path */recon/*'
EXCL_DIRS='--exclude-dir=node_modules --exclude-dir=lib --exclude-dir=forge-std --exclude-dir=out --exclude-dir=broadcast --exclude-dir=artifacts --exclude-dir=cache --exclude-dir=target --exclude-dir=build --exclude-dir=dist --exclude-dir=coverage --exclude-dir=typechain --exclude-dir=typechain-types --exclude-dir=.git --exclude-dir=recon'

count() { tr -d ' \n' ; }                         # strip BSD wc padding
sumcol() { awk -F: '{s+=$NF} END{print s+0}'; }    # sum grep -c output

# ─── Toolchain ────────────────────────────────────────────────────────────────

echo "=== Toolchain ==="
TC=""
[ -f foundry.toml ] && TC="$TC foundry"
{ [ -f hardhat.config.js ] || [ -f hardhat.config.ts ] || [ -f hardhat.config.cjs ] || [ -f hardhat.config.mjs ]; } && TC="$TC hardhat"
[ -f Anchor.toml ] && TC="$TC anchor"
if [ -f Move.toml ] || find . -maxdepth 3 -name Move.toml $EXCL_PATHS 2>/dev/null | grep -q .; then
  MT=$(find . -maxdepth 3 -name Move.toml $EXCL_PATHS 2>/dev/null | head -5)
  if echo "$MT" | xargs grep -lE 'AptosFramework|aptos-core|AptosStdlib' 2>/dev/null | grep -q .; then TC="$TC move-aptos"
  elif echo "$MT" | xargs grep -lE '^\s*Sui\b|sui-framework|MoveStdlib.*sui' 2>/dev/null | grep -q .; then TC="$TC move-sui"
  else TC="$TC move-unknown"; fi
fi
if find . -maxdepth 3 -name Cargo.toml $EXCL_PATHS 2>/dev/null | xargs grep -l 'soroban-sdk' 2>/dev/null | grep -q .; then TC="$TC soroban"; fi
if [ -z "$TC" ] && find . -maxdepth 3 -name Cargo.toml $EXCL_PATHS 2>/dev/null | xargs grep -lE 'anchor-lang|solana-program' 2>/dev/null | grep -q .; then TC="$TC solana-native"; fi
[ -z "$TC" ] && TC=" unknown"
echo "${TC# }"

echo "=== Source dir ==="
echo "$SRC"

# ─── Source files with line counts ────────────────────────────────────────────

src_find() {
  # shellcheck disable=SC2086
  find "$SRC" \( -name '*.sol' -o -name '*.rs' -o -name '*.move' -o -name '*.vy' \) \
    -not -path '*/test/*' -not -path '*/tests/*' -not -path '*/script/*' \
    -not -path '*/mocks/*' -not -path '*/mock/*' \
    $EXCL_PATHS 2>/dev/null | sort
}

echo "=== Source (with line counts) ==="
src_find | xargs wc -l 2>/dev/null | sed 's/^ *//'

# ─── Chains present ───────────────────────────────────────────────────────────

echo "=== Chains ==="
CH=""
src_find | grep -q '\.sol$' && CH="$CH evm"
src_find | grep -q '\.vy$'  && CH="$CH evm(vyper)"
if src_find | grep '\.rs$' | xargs grep -lE '#\[program\]|anchor_lang|solana_program|entrypoint!' 2>/dev/null | grep -q .; then CH="$CH solana"; fi
if src_find | grep '\.rs$' | xargs grep -l 'soroban_sdk' 2>/dev/null | grep -q .; then CH="$CH soroban"; fi
src_find | grep -q '\.move$' && CH="$CH move"
[ -z "$CH" ] && CH=" none-detected"
echo "${CH# }"

# ─── nSLOC (non-blank, non-comment lines) per file ───────────────────────────
# Same comment grammar for Solidity, Rust, Move and Vyper-with-// : a line is a
# comment line if it starts with //, ///, //!, /*, * or */ (Vyper `#` too).

echo "=== nSLOC ==="
sum=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  t=$(grep -c '[^[:space:]]' "$f" 2>/dev/null || true)
  c=$(grep -cE '^[[:space:]]*(//|/\*|\*|\*/|#)' "$f" 2>/dev/null || true)
  n=$(( ${t:-0} - ${c:-0} ))
  printf "%s: %d\n" "$f" "$n"
  sum=$((sum + n))
done < <(src_find)
echo "TOTAL: $sum"

# ─── Doc comments (NatSpec / rustdoc / Move doc comments) ─────────────────────

echo "=== NatSpec ==="
# Solidity NatSpec tags — count of tagged lines.
# shellcheck disable=SC2086
grep -rE '@notice|@dev|@param|@return|@inheritdoc|@custom' "$SRC" --include='*.sol' $EXCL_DIRS 2>/dev/null | wc -l | count; echo

echo "=== doc_comments_rust_move ==="
# `///` and `//!` doc lines in .rs and .move (Anchor, Soroban, Move modules).
# shellcheck disable=SC2086
grep -rE '^[[:space:]]*//[/!]' "$SRC" --include='*.rs' --include='*.move' $EXCL_DIRS 2>/dev/null | wc -l | count; echo

# ─── Tests ────────────────────────────────────────────────────────────────────

echo "=== test_files ==="
# Anything test-shaped: files under a test dir (Foundry/Hardhat/Anchor/cargo),
# *.t.sol, *_test.move / *_tests.move, and .rs files containing #[cfg(test)].
{
  # shellcheck disable=SC2086
  find . \( -name '*.sol' -o -name '*.js' -o -name '*.ts' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.rs' -o -name '*.move' -o -name '*.py' \) \
    \( -path '*/test/*' -o -path '*/tests/*' -o -name '*.t.sol' -o -name '*_test.move' -o -name '*_tests.move' \) \
    $EXCL_PATHS 2>/dev/null
  # shellcheck disable=SC2086
  grep -rlE '#\[cfg\(test\)\]|#\[test\]|#\[tokio::test\]' . --include='*.rs' --include='*.move' $EXCL_DIRS 2>/dev/null
} | sort -u | wc -l | count; echo

echo "=== test_functions ==="
# Foundry `function test…` in test dirs; JS/TS `it(`; Rust/Move `#[test]`.
# shellcheck disable=SC2086
SOL_TESTS=$(grep -rcE 'function[[:space:]]+test' . --include='*.sol' $EXCL_DIRS 2>/dev/null | grep -iE '/(test|tests|invariant|echidna|medusa|halmos|fuzz)/|\.t\.sol:' | sumcol)
# shellcheck disable=SC2086
JS_TESTS=$(grep -rcE '^[[:space:]]*it(\.(only|skip))?[[:space:]]*\(' . --include='*.js' --include='*.ts' --include='*.mjs' --include='*.cjs' $EXCL_DIRS 2>/dev/null | grep -iE '/(test|tests|spec|specs)/' | sumcol)
# shellcheck disable=SC2086
RS_TESTS=$(grep -rcE '#\[(test|tokio::test|async_std::test)\]' . --include='*.rs' $EXCL_DIRS 2>/dev/null | sumcol)
# shellcheck disable=SC2086
MV_TESTS=$(grep -rcE '#\[test' . --include='*.move' $EXCL_DIRS 2>/dev/null | sumcol)
echo $((SOL_TESTS + JS_TESTS + RS_TESTS + MV_TESTS))

echo "=== test_functions_by_kind ==="
echo "foundry_sol:${SOL_TESTS} js_ts_it:${JS_TESTS} rust_test:${RS_TESTS} move_test:${MV_TESTS}"

# ── Stateless Fuzz (Foundry) ──
echo "=== stateless_fuzz ==="
# shellcheck disable=SC2086
grep -rcE 'function[[:space:]]+testFuzz' . --include='*.sol' $EXCL_DIRS 2>/dev/null | sumcol

# ── Stateful Fuzz: Foundry invariant tests ──
echo "=== foundry_invariant ==="
# shellcheck disable=SC2086
grep -rcE 'function[[:space:]]+invariant_' . --include='*.sol' $EXCL_DIRS 2>/dev/null | sumcol

# ── Stateful Fuzz: Echidna ──
echo "=== echidna ==="
# shellcheck disable=SC2086
ECHIDNA_FUNCS=$(grep -rcE 'function[[:space:]]+echidna_' . --include='*.sol' $EXCL_DIRS 2>/dev/null | sumcol)
ECHIDNA_CONFIGS=$(find . -maxdepth 3 \( -name 'echidna.yaml' -o -name 'echidna_config.yaml' -o -name 'echidna.config.yaml' \) 2>/dev/null | wc -l | count)
echo "${ECHIDNA_FUNCS}:${ECHIDNA_CONFIGS}"

# ── Stateful Fuzz: Medusa ──
echo "=== medusa ==="
# shellcheck disable=SC2086
MEDUSA_FUNCS=$(grep -rcE 'function[[:space:]]+(property_|fuzz_)' . --include='*.sol' $EXCL_DIRS 2>/dev/null | sumcol)
MEDUSA_CONFIGS=$(find . -maxdepth 3 -name 'medusa.json' 2>/dev/null | wc -l | count)
echo "${MEDUSA_FUNCS}:${MEDUSA_CONFIGS}"

# ── Hardhat Fuzz ──
echo "=== hardhat_fuzz ==="
if [ -f package.json ]; then
  grep -cE '"@chainlink/hardhat-fuzz"|"hardhat-fuzz"|"@openzeppelin/hardhat-fuzz"' package.json 2>/dev/null || echo "0"
else
  echo "0"
fi

# ── Fork Tests ──
echo "=== fork ==="
# shellcheck disable=SC2086
grep -rcE 'vm\.createFork|createSelectFork|hardhat_reset|FORKING_URL|forking.*url' . --include='*.sol' --include='*.ts' --include='*.js' $EXCL_DIRS 2>/dev/null | sumcol

# ── Formal Verification: Certora ──
echo "=== certora ==="
CERTORA_SPECS=$(find . \( -name '*.spec' -o -name '*.cvl' \) 2>/dev/null | grep -v node_modules | grep -v '/lib/' | wc -l | count)
CERTORA_CONF=$(find . -maxdepth 3 \( -name '*.conf' -path '*/certora/*' -o -name 'certora.conf' \) 2>/dev/null | wc -l | count)
echo "${CERTORA_SPECS}:${CERTORA_CONF}"

# ── Formal Verification: Halmos ──
echo "=== halmos ==="
# shellcheck disable=SC2086
HALMOS_FUNCS=$(grep -rcE 'function[[:space:]]+check_' . --include='*.sol' $EXCL_DIRS 2>/dev/null | sumcol)
HALMOS_CONF=$(find . -maxdepth 3 -name 'halmos.toml' 2>/dev/null | wc -l | count)
echo "${HALMOS_FUNCS}:${HALMOS_CONF}"

# ── Formal Verification: HEVM ──
echo "=== hevm ==="
# shellcheck disable=SC2086
grep -rcE 'function[[:space:]]+prove_' . --include='*.sol' $EXCL_DIRS 2>/dev/null | sumcol

# ── Solana: Anchor TS tests, cargo tests, Trident/property fuzzing ──
echo "=== anchor_ts_tests ==="
# shellcheck disable=SC2086
grep -rcE '^[[:space:]]*it(\.(only|skip))?[[:space:]]*\(' tests 2>/dev/null --include='*.ts' --include='*.js' $EXCL_DIRS | sumcol

echo "=== solana_fuzz ==="
# Trident (Anchor fuzzing) config/deps + Rust proptest/quickcheck harnesses.
TRIDENT=$(find . -maxdepth 3 \( -name 'Trident.toml' -o -path '*/trident-tests/*' \) 2>/dev/null | wc -l | count)
# shellcheck disable=SC2086
PROPTEST=$(grep -rcE 'proptest!|#\[quickcheck\]|arbitrary::' . --include='*.rs' $EXCL_DIRS 2>/dev/null | sumcol)
echo "${PROPTEST}:${TRIDENT}"

# ── Move: unit tests and Move Prover specs ──
echo "=== move_prover ==="
# `spec` blocks and .spec.move files are Move Prover input (aptos move prove / sui prover).
# shellcheck disable=SC2086
SPEC_BLOCKS=$(grep -rcE '^[[:space:]]*spec[[:space:]]+[[:alnum:]_]+' . --include='*.move' $EXCL_DIRS 2>/dev/null | sumcol)
SPEC_FILES=$(find . -name '*.spec.move' $EXCL_PATHS 2>/dev/null | wc -l | count)
echo "${SPEC_BLOCKS}:${SPEC_FILES}"

echo "=== move_expected_failure ==="
# shellcheck disable=SC2086
grep -rcE '#\[expected_failure' . --include='*.move' $EXCL_DIRS 2>/dev/null | sumcol

# ── Soroban: testutils-based tests ──
echo "=== soroban_tests ==="
# shellcheck disable=SC2086
grep -rlE 'soroban_sdk::testutils|testutils::' . --include='*.rs' $EXCL_DIRS 2>/dev/null | wc -l | count; echo

# ─── Docs ─────────────────────────────────────────────────────────────────────

echo "=== docs ==="
ls -d README* docs/ doc/ whitepapers/ whitepaper/ spec/ specs/ paper/ papers/ 2>/dev/null | sort -u || true

# ─── Git ──────────────────────────────────────────────────────────────────────

echo "=== commit ==="
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git rev-parse --short HEAD 2>/dev/null || echo "unknown"
else
  echo "not-a-git-repository"
fi

echo "=== branch ==="
git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "=== git_unique_authors ==="
  git log --format='%aN' 2>/dev/null | sort -u | wc -l | count; echo

  echo "=== git_contributors ==="
  git log --format='%aN' 2>/dev/null | sort | uniq -c | sort -rn | sed 's/^ *//'

  echo "=== git_source_contributors ==="
  git log --numstat --format='COMMIT_BY:%aN' -- "$SRC" 2>/dev/null | \
    awk '/^COMMIT_BY:/{a=substr($0,11);next} NF==3 && $1~/[0-9]/{add[a]+=$1;del[a]+=$2} END{for(a in add)printf "%d\t%d\t%s\n",add[a],del[a],a}' | sort -rn

  echo "=== git_repo_age ==="
  git log --reverse --format='%aI' 2>/dev/null | head -1
  git log -1 --format='%aI' 2>/dev/null

  echo "=== git_total_commits ==="
  git rev-list --count HEAD 2>/dev/null

  echo "=== git_merge_count ==="
  git log --merges --oneline 2>/dev/null | wc -l | count; echo

  echo "=== git_shallow ==="
  git rev-parse --is-shallow-repository 2>/dev/null || echo "false"

  echo "=== git_hotspots ==="
  git log --name-only --format='' -- "$SRC" 2>/dev/null | grep -E '\.(sol|rs|move|vy)$' | sort | uniq -c | sort -rn | head -15 | sed 's/^ *//'

  echo "=== git_recent_30d ==="
  git log --since='30 days ago' --oneline -- "$SRC" 2>/dev/null | head -20

  echo "=== git_large_diffs ==="
  git log --format='COMMIT:%h %aN %s' --numstat -- "$SRC" 2>/dev/null | \
    awk '/^COMMIT:/{if(c && s>0)print s,c;c=$0;s=0;next} NF>=2 && $1~/[0-9]/{s+=$1+$2} END{if(c && s>0)print s,c}' | sort -rn | head -10
fi
