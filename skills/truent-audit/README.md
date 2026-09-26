# truent-audit

A parallelized smart-contract audit whose ground truth is a compiled engine, not a model.

**What it does.** The Truent engine runs first — static detectors on every in-scope file
(EVM, Solana, Move, Soroban) and, on the EVM, a real `revm`-backed invariant fuzzer. Twelve
attacker-lens agents then hunt the residual: the bespoke logic, economics and seams a detector
cannot encode. Every property an agent states is pushed back through the engine; only an engine
reproduction promotes a claim. One shell script assembles the report from the run files, so the
report can never claim more than the scan found.

**Three evidence tiers, never blurred:**

| Tier | Meaning |
|---|---|
| `VERIFIED-PROVEN` | the engine executed it: dynamic fuzz PoC, symbolic counterexample, or `evidence:"proven"` |
| `VERIFIED-STATIC` | a compiled detector matched real code (`evidence:"lead"`); deterministic, reproducible, not executed |
| `REASONED` | a model proposed it; the engine could not verify it — reported, labelled, with what remained unverified |

Findings are ranked by severity, then `PROVEN > STATIC > REASONED`. In truent 0.6.0 the only
`VERIFIED-PROVEN` path is the EVM; the Solana plan path validates and stops (execution
deferred), and Move / Soroban verification beyond the static detectors is external and
labelled so.

**How to run.** Install the engine (`cargo install --path crates/cli` or `cargo build --release
--bin truent`), then in a repository:

```
run truent audit on the codebase
run truent audit on src/Vault.sol
run truent audit in loop mode          # 3 passes, each told what the earlier ones found
run 3 passes
```

Flags: `--file-output` copies the report into the working directory; `--memory` remembers
findings between scans in `.truent-audit/memory.tsv`; `--loop [N]` runs N passes. Every scan
writes `.truent-audit/runs/{stamp}/` (engine.md, run-K.md, scope.tsv, full-report.md).

**Layout.** `SKILL.md` orchestrates. `references/` holds the auditor SOP, the four gates, the
verification procedure, the report contract, the STE language rules, four chain primers and
the twelve agent specialties. `scripts/engine.sh` runs the engine and renders its findings;
`scripts/assemble.sh` is the only report producer.

**Attribution.** The orchestration, agent specialties, judging gates, report contract and
assembler are adapted from [pashov/skills](https://github.com/pashov/skills) `solidity-auditor`
(MIT). Each adapted file carries an attribution line; the licence is reproduced in
[`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
