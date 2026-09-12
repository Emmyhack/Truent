# Truent Skills

Deterministic-first security skills for AI coding agents (Claude Code, Cursor,
Codex, Copilot, Windsurf). Unlike prompt-only audit skills, these are backed by
[Truent](https://github.com/geekstrancend/Truent)'s **compiled engine** — static
analyzers plus a real `revm`-backed invariant fuzzer — so findings are
machine-verified and reproducible, not an LLM's opinion.

Every skill distinguishes two tiers and never blurs them: **`VERIFIED`** (the
engine produced or reproduced it) and **`REASONED`** (an LLM lens proposed it,
and nothing executed it).

| Skill | What it does |
|-------|--------------|
| [truent-audit](truent-audit/) | Deterministic-first, engine-verified smart-contract audit across EVM · Solana · Move · Soroban. Runs the compiled engine first, then amplifies with LLM attacker lenses whose findings are verified back through the engine before being reported. |
| [truent-recon](truent-recon/) | Pre-audit recon: git-history risk mining + threat model + entry points + synthesized invariants — with the checkable invariants run through the engine, not just listed. |
| [truent-fuzz](truent-fuzz/) | Stateful invariant fuzzing. Native revm-backed fuzzer (auto-detected invariants + minimal-PoC shrinking, no external toolchain) by default; emits an equivalent Echidna/Medusa harness on demand. |
| [truent-deps](truent-deps/) | Dependency supply-chain review. Finds forked/drifted libraries and unpinned versions, then runs the engine over the dependency code actually compiled into your contracts — the code every "exclude `lib/`" scanner misses. Also reviews CI for leaked deploy keys. |
| [truent-keys](truent-keys/) | Key custody and deploy safety. Secrets in source, scripts and git history, paired with the engine's answer to the on-chain half — single-EOA admins, weak multisig thresholds, unprotected initializers and upgrade paths. |
| [truent-ir](truent-ir/) | On-chain incident response. Scopes an exploit from its transaction, reproduces it against deployed bytecode with the fuzzer to establish the broken invariant, and keeps confirmed mechanism separate from hypothesis in the post-mortem. |

## Taxonomy

Findings from these skills carry industry identifiers, not just Truent's
internal rule names — **CWE**, **SWC Registry**, **OWASP Smart Contract Top 10
(2025)**, and **DASP Top 10** — so they map into an existing triage process
without a translation step.

```bash
truent taxonomy                       # the full matrix
truent taxonomy --chain solana        # one chain
truent taxonomy --id SWC-107          # everything mapped to a weakness class
```

The committed matrix lives in [`docs/COVERAGE.md`](../docs/COVERAGE.md) and is
regenerated from the engine, so it cannot drift from what actually ships.

## Prerequisite

The skills call the `truent` binary. Install it once:

```bash
# from a clone of the Truent repo
cargo install --path crates/cli
# or build in-place
cargo build --release --bin truent
```

Verify: `truent doctor` should report all components healthy.

## Install

**As a Claude Code plugin** (recommended — installs all six skills):

```
/plugin marketplace add geekstrancend/Truent
/plugin install truent
```

**Or point an agent at the repo:**

```
Install https://github.com/geekstrancend/Truent and run truent-audit on the codebase
```

**Or copy a single skill** into your agent's skills directory, e.g.
`skills/truent-audit/`.

## Contributing a skill

Skills follow the [agentskills.io](https://agentskills.io) standard: `name` and
`description` are the standard top-level keys, and everything else
(version, author, domain, chains, tags) lives under `metadata`.

Before opening a PR:

```bash
pip install pyyaml
python3 tools/validate_skills.py          # frontmatter, naming, descriptions
python3 tools/validate_skills.py --write  # regenerate skills/index.json
```

CI runs both. The validator enforces that `name` matches the directory, that a
description says *when* to use the skill (not just what it does), that
`metadata.version` agrees with the sidecar `VERSION` file, and that every
`$SKILL_DIR/...` path referenced in the body actually exists.
