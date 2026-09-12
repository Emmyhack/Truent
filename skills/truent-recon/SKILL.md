---
name: truent-recon
description: "Pre-audit reconnaissance for a smart-contract codebase. Produces a recon report (overview, threat model, entry points, synthesized invariants, git-history risk map, test/coverage gaps, and a prioritized audit plan) — and, unlike a report-only recon, feeds the synthesized invariants straight into Truent's engine to auto-check them. Multi-chain. Triggers on 'truent recon', 'pre-audit', 'audit readiness', 'readiness report', 'prep this protocol', 'map this codebase', 'where should I audit'."
license: MIT
metadata:
  version: "0.1.0"
  author: geekstrancend
  homepage: https://github.com/geekstrancend/Truent
  domain: smart-contract-security
  subdomain: reconnaissance
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
    - pre-audit
    - threat-model
    - recon
    - invariants
    - git-history
    - attack-surface
    - evm
    - solana
    - move
    - soroban
---

# Truent Recon

Map the codebase before auditing it — and prove part of the map with the
engine. A report-only recon tells a human where to look. Truent's recon does
that *and* turns the invariants it synthesizes into executable checks the
engine runs, so some of the "you should verify X" items come back already
verified (or already broken).

`$SKILL_DIR` = the directory containing this SKILL.md.

## Pipeline (3 phases)

### Phase 1 — Enumerate & mine history (one message, parallel)

1. `Bash`: detect project root, source dir, and chain (`.sol`→evm,
   Anchor/`#[program]`→solana, `Move.toml`→move, soroban_sdk→soroban).
   Enumerate in-scope source (exclude `test/`, `lib/`, `node_modules/`, mocks).
2. `Bash`: **git-history security mining** — the signal a fresh read misses:
   ```bash
   python3 $SKILL_DIR/scripts/git_security.py --repo <root> --src-dir <src> --json <root>/recon/git-security.json
   ```
   Sections: `fix_candidates` (files historically fixed for bugs/security),
   `churn_hotspots` (high change = high defect density), `late_changes`
   (recently touched, least reviewed), `forked_deps` (drift from upstream),
   `tech_debt` (self-flagged risk). **This ranks where audit attention pays.**
3. `Read`: `$SKILL_DIR/references/report-template.md`.
4. `Read` any spec/whitepaper/README for stated invariants, actors, trust
   assumptions, and economic properties.

### Phase 2 — Engine pass, prioritized by risk

1. Run the deterministic scanner over the **priority set first** (the
   `fix_candidates` + `churn_hotspots` files), then the rest:
   ```bash
   truent scan <path> --chain <chain> --output json
   ```
   Record findings — these are the engine's opening position on the codebase.
2. **Classify entry points.** For every externally-callable function: who can
   call it, what state it mutates, what value moves. Mark the ones on the
   git-risk hotspots as priority.
3. **Synthesize invariants.** From the ABI, the docs, and the entry points,
   write down what must always hold: conservation laws, monotone quantities,
   access rules, no-profit round-trips. Tag each with whether Truent's fuzzer
   can auto-check its shape (conservation / monotonic / access-control /
   reentrancy — see the truent-audit `verification.md`).
4. **Verify the checkable ones now** (EVM):
   ```bash
   truent fuzz <contract.sol> --dynamic --chain evm --iterations 500
   ```
   Any invariant the fuzzer breaks is not a "to-verify" item — it's already a
   confirmed finding, with a PoC, before the audit even starts.

### Phase 3 — Write the recon report

Write `recon/recon.md` per `references/report-template.md`, containing:

- **Overview** — what the protocol does, in plain language.
- **Threat model** — assets, actors & trust levels, attack surfaces (weighted
  by the git-risk map), external dependencies, temporal/upgrade risks.
- **Entry points** — the classified table, priority-ordered.
- **Invariants** — the synthesized list, each marked
  `engine-checkable | doc-stated | manual`, and for checkable ones the fuzzer
  result (`held` / `BROKEN + PoC`).
- **Git-history risk map** — the ranked hotspots, fix-candidates, late changes,
  forked deps, tech-debt, straight from `git-security.json`.
- **Test & coverage gaps** — what exists, what's missing on the hot files.
- **Prioritized audit plan** — the ordered file/function list to audit first,
  justified by the combined engine + history signal. Hand this list to the
  `truent-audit` skill.

## Why this beats a report-only recon

A prompt-only recon hands you a to-do list of things to check. Truent's recon
hands you a to-do list where the machine-checkable items are **already
checked** — and prioritizes the rest by where your own git history says bugs
have always lived. Less guessing, more proof, before the audit starts.
