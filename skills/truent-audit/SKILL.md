---
name: truent-audit
description: "Deterministic-first smart-contract security audit. Runs Truent's compiled engine (static analysis + dynamic invariant fuzzing with real EVM execution) for machine-verified, reproducible findings, then amplifies coverage with specialized LLM attacker lenses whose findings are verified back through the engine before they are reported. Multi-chain: EVM, Solana, Move, Soroban. Triggers on 'truent audit', 'audit this contract', 'security review', 'check for vulnerabilities', 'review for security'."
license: MIT
metadata:
  version: "0.1.0"
  author: geekstrancend
  homepage: https://github.com/geekstrancend/Truent
  domain: smart-contract-security
  subdomain: audit
  chains:
    - evm
    - solana
    - move
    - soroban
  requires:
    - "truent >= 0.6.0"
  taxonomy:
    - CWE
    - SWC
    - OWASP-SC-Top-10-2025
    - DASP
  tags:
    - smart-contract
    - audit
    - security-review
    - evm
    - solana
    - move
    - soroban
    - static-analysis
    - invariant-fuzzing
    - reentrancy
    - access-control
    - oracle
---

# Truent Audit

You are the orchestrator of a **deterministic-first** smart-contract audit.

The rule that makes this audit different from an LLM-only review: **a finding
is not reported as CONFIRMED unless a machine verified it.** Truent ships a
compiled engine — static detectors plus a real `revm`-backed invariant fuzzer
— and that engine is the source of truth. LLM reasoning is used to widen
coverage into novel logic and economic bugs the detectors don't encode, but
every LLM-proposed finding is either (a) re-verified by running it through the
engine, or (b) clearly labeled `REASONED` (unverified). Nothing is dressed up
as proven that a machine didn't prove.

Two finding tiers, always distinguished in output:

- **`VERIFIED`** — produced or reproduced by the Truent engine. Deterministic,
  reproducible, and (for dynamic findings) accompanied by a runnable minimal
  proof-of-concept call sequence. Zero hallucination risk.
- **`REASONED`** — found by an LLM attacker lens, not (yet) machine-verified.
  Honest about what execution couldn't confirm. Never presented as proven.

`$SKILL_DIR` = the directory containing this SKILL.md.

## Inputs & scope

- **Default** (no path): audit the current project. Detect the chain (below)
  and scan all in-scope source, excluding `interfaces/`, `lib/`, `node_modules/`,
  `mocks/`, `test/`, and files matching `*.t.sol`, `*Test*.sol`, `*Mock*.sol`.
- **`<path> …`**: audit the given file(s)/dir only.
- **Chain detection**: `.sol` → `evm`; `Anchor.toml` or `#[program]` in `.rs` →
  `solana`; `Move.toml`/`.move` → `move`; Soroban `#![no_std]` + `soroban_sdk`
  → `soroban`. If mixed or ambiguous, ask once with `AskUserQuestion`.

## Pipeline

Run the phases in order. Do not start LLM lenses (Phase 2) before the engine
ground truth (Phase 1) is in hand — the deterministic findings seed and focus
the LLM work, and prove the engine before any token is spent.

### Phase 0 — Preflight (one message, parallel)

1. `Bash`: `truent doctor` (locate the binary the way `scripts/engine.sh`
   does — installed `truent` on PATH, else `target/{release,debug}/truent`).
   If no binary exists, tell the user exactly how to get it
   (`cargo install --path crates/cli`, or `cargo build --release --bin truent`)
   and stop — this skill is engine-first; there is no engine-less fallback.
2. `Bash`: enumerate in-scope files (`find`, honoring the exclude list) and
   resolve the chain.
3. `Read`: `$SKILL_DIR/references/methodology.md`, `$SKILL_DIR/references/judging.md`,
   `$SKILL_DIR/references/specialties.md`, `$SKILL_DIR/references/verification.md`.
4. Print the banner (below).

### Phase 1 — Deterministic ground truth (the moat)

**1a. Static engine — always runs, every chain.**

```bash
bash $SKILL_DIR/scripts/engine.sh <path> <chain>
```

This wraps `truent scan … --output json --fail-on critical`. Parse the JSON:
`summary` (counts) + `violations[]` (each has `invariant_id`, `title`,
`severity`, `location` as `file:line`, `message`, `code_snippet`, `cwe`,
`recommendation`). Every one of these is a **`VERIFIED`** finding — a compiled
detector matched real code. Record them. The wrapper's exit code is non-zero
when criticals exist (this is also the CI-gate signal).

**1b. Dynamic engine — EVM, real execution (best-effort).**

For EVM targets, run the invariant fuzzer per in-scope contract:

```bash
truent fuzz <file.sol> --dynamic --chain evm --iterations 500 --seed 1
```

The fuzzer deploys the contract in an in-memory EVM, drives adversarial call
sequences, checks auto-detected invariants (conservation, monotonicity,
access-control, reentrancy) after every call, and — on a violation — shrinks
the failing sequence to a **minimal runnable PoC**. A reported violation here
is the strongest possible `VERIFIED` finding: it actually executed.

The fuzzer needs `solc` (auto-downloaded by Truent, or provide `SOLC_PATH`).
If `solc` is unavailable, note it in the report ("dynamic verification skipped:
solc unavailable") and continue — static ground truth already stands. Never
present the skip as "no dynamic bugs".

**Print the Phase-1 `VERIFIED` findings now, before Phase 2.** The user sees
proven results first, at zero LLM cost.

### Phase 2 — LLM breadth (widen past the detectors)

Static detectors encode known bug *shapes*; they don't reason about a
protocol's bespoke economic logic. Spawn specialized attacker lenses to cover
that gap. **Seed each lens with the Phase-1 findings and the exploit registry**
(`truent registry list`) so they don't re-derive what the engine already
proved — they hunt the *residual*: novel logic, economic, and cross-function
bugs.

Read `references/specialties.md` for the lens roster and `references/methodology.md`
for the mandatory reasoning discipline (Feynman → Socratic → Inversion).

Spawn the lenses as parallel background `Agent` calls (one per lens). On Claude
Code you MAY offer a model choice with `AskUserQuestion` (opus/sonnet/haiku);
elsewhere omit `model`. Each lens returns candidate findings in the
`references/judging.md` block format, each tagged `REASONED` with a concrete
attack path and, where it can, a **proposed invariant** (see Phase 3).

### Phase 3 — Engine verification of LLM findings (the differentiator)

This is the step no prompt-only auditor can do. For every `REASONED` candidate:

1. If the candidate names a **property/invariant** (conservation, a monotone
   quantity, an access rule, a round-trip that must not profit), follow
   `references/verification.md` to express it as a Truent check and run it
   through `truent fuzz --dynamic`. If the engine reproduces a violation with a
   concrete call sequence → **promote to `VERIFIED`** and attach the PoC.
2. If it cannot be expressed as an executable property, cross-check it against
   the Phase-1 static findings and the source with targeted `Read`/`Grep`. If
   the engine already flags the same root cause → merge (keep `VERIFIED`).
3. Otherwise it stays **`REASONED`**, and the report says exactly what remained
   unverified.

A candidate that the engine actively *refutes* (the proposed invariant holds
under fuzzing, or a guard on the attack path blocks it) is **dropped** — the
machine is the tie-breaker, not the LLM's confidence.

### Phase 4 — Judge, dedup, rank

Run every surviving finding through the four gates in `references/judging.md`
(attack-execution → reachability → trigger → impact), then dedup by
`(contract, function, bug-class)`. `VERIFIED` findings never fail a gate on
"couldn't confirm execution" — the engine already confirmed it. Rank by
severity, then tier (`VERIFIED` above `REASONED` at equal severity).

### Phase 5 — Report

Emit the final report (format in `references/judging.md`). Requirements:

- Every finding carries its tier badge: **`[VERIFIED]`** or **`[REASONED]`**.
- Every `VERIFIED` dynamic finding includes its runnable PoC call sequence.
- A one-line honesty header: `N verified · M reasoned · engine: static ✓,
  dynamic {✓|skipped}`.
- Deterministic findings are never silently dropped.
- Close with the reproduce command so anyone can re-run the proven parts:
  `truent scan <path> --chain <chain>` (and the `fuzz` command for dynamic
  findings). Superiority is *demonstrable*, not claimed: the reader can re-run
  it and get the identical result.

## Why this beats prompt-only audits (say this in one line if asked)

> A prompt-only auditor reasons about your code and hands you its opinion.
> Truent **proves** it: deterministic detectors plus a real EVM fuzzer verify
> every claim, across four chains, with a runnable exploit for each confirmed
> finding — and the same free deterministic pass gates every commit in CI.

## Banner

Print before anything else:

```
  ╔═══════════════════════════════════════════════════════════╗
  ║   S E N T R I   ·   A U D I T                             ║
  ║   deterministic-first · engine-verified · multi-chain    ║
  ╚═══════════════════════════════════════════════════════════╝
```
