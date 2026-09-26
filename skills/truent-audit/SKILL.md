---
name: truent-audit
description: "Engine-first smart-contract security audit across EVM, Solana, Move and Soroban. Truent's compiled engine runs first (static detectors on every chain, a real revm invariant fuzzer on the EVM) and is the ground truth; twelve LLM attacker lenses then hunt the residual, and every property they state is pushed back through the engine. Findings carry one of three evidence tiers, never blurred: VERIFIED-PROVEN (the engine executed it), VERIFIED-STATIC (a compiled detector matched real code), REASONED (a model proposed it, nothing executed it). Modes - default (full repo) or a specific filename. Loop mode runs several passes in one scan, each pass told what the earlier ones found, and ends in one combined report; it remembers findings between scans in a ledger. Triggers on 'truent audit', 'audit', 'audit this contract', 'check this contract', 'security review', 'check for vulnerabilities', 'review for security', 'solidity auditor', 'run the auditor', 'run the auditor in loop mode', 'loop mode', 'run 3 passes'."
license: MIT
metadata:
  version: "0.2.0"
  author: Emmyhack
  homepage: https://github.com/Emmyhack/Truent
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

<!-- Adapted from pashov/skills solidity-auditor/SKILL.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine ground truth, three evidence tiers, multi-chain. -->

# Truent Audit — engine-first smart contract security audit

You are the orchestrator of a parallelized smart contract security audit whose ground truth is a compiled engine.

**The rule that makes this audit different:** the Truent engine runs **first**, on every scan, and its findings are the floor. Twelve LLM attacker agents then hunt what the detectors cannot encode. Every property an agent states is handed back to the engine, and **only an engine reproduction promotes a claim**. Three evidence tiers, never blurred, on every finding:

- **`VERIFIED-PROVEN`** — the engine executed it: a dynamic fuzz PoC, a symbolic counterexample, or an engine violation with `evidence:"proven"`.
- **`VERIFIED-STATIC`** — a compiled detector matched real code (`evidence:"lead"`). Deterministic and reproducible; nothing executed it.
- **`REASONED`** — a model proposed it and the engine could not verify it. Reported, labelled, with what remained unverified.

Rank: severity, then `PROVEN > STATIC > REASONED`. `$SKILL_DIR` is the directory holding this file; `{resolved_path}` is `$SKILL_DIR/references`.

## Mode Selection

**Exclude pattern:** skip **dependency and build directories** — `node_modules/`, `lib/`, `artifacts/`, `cache/`, `out/`, `broadcast/`, `coverage/`, `typechain*/`, `target/`, `build/` — and **non-production code** — `interfaces/`, `mocks/`, `test/`, `tests/` and files matching `*.t.sol`, `*Test*.sol`, `*Mock*.sol`, `*_test.move`, `*_tests.move`.

**Deploy scripts stay in scope.** `script/`, `deploy/`, `*.s.sol`, an Anchor `migrations/deploy.ts` is not source but a Solidity or Move deploy script is: it sets constructor arguments, hands over ownership and seeds state, and it carries real bugs. Excluding a dependency is an argument about code you did not write; a deploy script is code you did write.

- **Default** (no arguments): scan all `.sol`, `.move` and chain-program `.rs` files using the exclude pattern. Use Bash `find` (not Glob), exactly this command:

  ```bash
  find . -type f \( -name '*.sol' -o -name '*.rs' -o -name '*.move' \) \
    -not -path '*/node_modules/*' -not -path '*/lib/*' -not -path '*/artifacts/*' \
    -not -path '*/cache/*' -not -path '*/out/*' -not -path '*/broadcast/*' \
    -not -path '*/coverage/*' -not -path '*/typechain*/*' -not -path '*/target/*' \
    -not -path '*/build/*' -not -path '*/interfaces/*' -not -path '*/mocks/*' \
    -not -path '*/test/*' -not -path '*/tests/*' \
    -not -name '*.t.sol' -not -name '*Test*.sol' -not -name '*Mock*.sol' \
    -not -name '*_test.move' -not -name '*_tests.move' \
  | while IFS= read -r f; do
      case "$f" in
        *.rs) grep -qE '^[[:space:]]*use (anchor_lang|solana_program|soroban_sdk)' "$f" && printf '%s\n' "$f" ;;
        *)    printf '%s\n' "$f" ;;
      esac
    done
  ```

  `-type f` is **required, not tidiness**: Hardhat writes each build artifact into a *directory* named `GatewayCrossChain.sol/`, so a `find` without it matches directories as if they were source files and hands them to `cat`. The `.rs` filter is required for the same reason in the other direction: a Rust workspace holds CLI crates, tests and build scripts, and only a file with a `use` of a chain SDK is a program — a file that merely mentions `anchor_lang` in a string (an analyzer, a linter) is not. Do not drop either, and do not re-derive this command — paste it.

- **`$filename ...`**: scan the specified file(s) only. **The exclude pattern does not apply here.** A file named on the command line is always scanned, wherever it lives — naming `node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol` scans that file. The pattern chooses what a *default* scan discovers; it never overrides an explicit request.

**Chain detection, per file:** `.sol` → `evm`; `.move` → `move`; `.rs` with `use soroban_sdk` → `soroban`; any other `.rs` that passed the filter (`use anchor_lang` / `use solana_program`) → `solana`. `{chains}` is the set of distinct chains among the in-scope files, space separated, in first-seen order. A repository can hold more than one (a bridge with an EVM side and a Solana side); every chain in `{chains}` gets its own engine run and its own primer in the bundles. Never ask the runner which chain it is — the files say.

**Flags:**

- `--file-output` (off by default): **copy** the assembled report into the working directory (name per `{resolved_path}/report-formatting.md`). The flag never causes a report to be produced — every scan assembles `.truent-audit/runs/{stamp}/full-report.md` whether it is passed or not. It only decides whether a copy lands where the runner can see it.

  > **This flag used to mean "never write a report file unless explicitly passed", and that is now false.** The rule was written to protect the runner's **working directory**, and that protection is unchanged: without the flag, nothing is written outside `.truent-audit/`. What changed is that the report is assembled by shell on every scan, so the flag can no longer collapse the report — nothing regenerates, it copies. A later editor must not read this as a mistake and revert it.

- `--memory` (off by default): remember findings between scans in a ledger at `.truent-audit/memory.tsv` in the audited repo. Any pass count above 1 turns memory on by itself, whether or not the flag was passed.
- `--loop [N]` (off by default): run N passes in one scan, each pass told what the earlier ones found, ending in one combined report. `--loop` with no number is **3** passes. `--loop 1` is a 1-pass scan. The flag exists for runners who prefer flags; when it is passed the picker in Turn 1b does not ask, it obeys.

**Vocabulary (used throughout this file):**

- **run** — one pass of the 12 agents.
- **scan** — one invocation of this skill. A scan holds 1 or more runs, and exactly one engine pass.

The ledger's `scans` column counts scans. The report's `seen in k/N runs` counts runs inside one scan and is never written to the ledger. Two numbers, two names — do not mix them.

The pass count the scan runs is `{passes}` — settled in Turn 1b, 1 or more. The **loop body** is Turn 2 step 2c, Turn 2 step 3, Turn 3a, Turn 3b and Turn 4, and it runs once per pass. Everything before it — including **Turn 2-engine** — runs once per scan, and Turn 5 closes the scan once, whatever `{passes}` is. The engine is deterministic: running it once per pass would produce the same blocks N times.

> **HARD RULE — the plain path must stay plain.** A 1-pass scan with no flags reaches **none** of the memory steps: not Turn 1c, not Turn 2 step 2, not Turn 4 step 4, not Turn 4 step 6. It reads no ledger, writes no file outside `.truent-audit/`, and prints exactly the report it printed before memory existed. Memory is on only when `--memory` was passed or the pass count is above 1. A later editor who is tempted to make any memory step unconditional is breaking this on purpose, not tidying up.

> **A 1-pass answer reaches none of the loop or memory machinery.** No ledger is read or written. No `Passes` or `Memory` row in the Scope table. No `seen in k/N runs`. No `KNOWN` / `NEW` tag. No per-pass summary lines. The only trace of the picker is the question itself.
>
> **What it does write.** Every scan writes `.truent-audit/runs/{stamp}/` — one `engine.md`, one `run-1.md`, one `scope.tsv`, one `full-report.md` — because the report is assembled from those files at every pass count, and `name`, `mode`, `files`, `chains` and the engine keys are needed by every report.
>
> **What the rule protects, stated exactly:** on the plain path the scan reads no ledger, writes no `mem_` key, and prints a Scope table of exactly **four** rows — `Mode`, `Files reviewed`, `Engine`, `Confidence threshold (1-100)` — and no `Passes` row, no `Memory` row. The `Engine` row is the one row this skill adds to the upstream's three, and it is unconditional: the engine runs on every scan and a report that does not say so cannot say what its tiers mean. Disk is not printed output. A later editor who makes a **memory** step unconditional is breaking this on purpose; writing the runs directory is not one of those steps, and neither is the engine.
>
> `--memory` on a 1-pass run is the single exception: memory turns on, the loop machinery stays off.

> **The engine is not optional and has no fallback.** If Turn 1 finds no `truent` binary, print exactly how to get one (`cargo install --path crates/cli`, or `cargo build --release --bin truent`) and **stop**. This skill is engine-first; twelve agents with no engine produce a REASONED-only report that this skill must never print under its banner. A later editor must not add "if the engine is missing, continue with the agents".

## Orchestration

**Turn 1 — Discover.** Print the banner, then make these parallel tool calls in one message:

a. Bash `find` for in-scope files per mode selection
b. Glob for `**/references/hacking-agents/shared-rules.md` — extract the `references/` directory (two levels up) as `{resolved_path}`
c. ToolSearch `select:Agent`
d. Read the local `VERSION` file from the same directory as this skill
e. Bash `curl -sf https://raw.githubusercontent.com/Emmyhack/Truent/main/skills/truent-audit/VERSION`
f. Bash `mktemp -d ./.audit-XXXXXX` → store as `{bundle_dir}`
g. Bash `date +%Y%m%d-%H%M%S` → store as `{stamp}`, the scan-time stamp. **One stamp per scan, computed once, here.** The runs directory, the run files and any `--file-output` copy all carry it, so a report and the runs that produced it are tied together by eye.
h. Bash `bash $SKILL_DIR/scripts/engine.sh --help >/dev/null 2>&1; command -v truent || ls target/release/truent target/debug/truent 2>/dev/null` — the binary check. `scripts/engine.sh` locates the binary the same way (installed `truent` on PATH, else `target/{release,debug}/truent` walking up from the skill directory and in the current directory); if nothing is found, stop per the rule above.

**Turn 1a — Open the scan directory.** After the `find` returns, in one Bash command:

```bash
mkdir -p .truent-audit/runs/{stamp}
: > .truent-audit/runs/{stamp}/scope.tsv
```

Then write the four scope keys this turn knows. **A scope key is written with one `printf` and never any other way:**

```bash
printf '%s\t%s\n' name   "{project-name}" >> .truent-audit/runs/{stamp}/scope.tsv
printf '%s\t%s\n' mode   "{mode}"         >> .truent-audit/runs/{stamp}/scope.tsv
printf '%s\t%s\n' files  "{file list}"    >> .truent-audit/runs/{stamp}/scope.tsv
printf '%s\t%s\n' chains "{chains}"       >> .truent-audit/runs/{stamp}/scope.tsv
```

- `{project-name}` — the repo root basename, the same one `report-formatting.md` names.
- `{mode}` — `default` or `filename`, as Mode Selection settled it.
- `{file list}` — every in-scope path the `find` returned, **space separated on one line**, in `find` order. The assembler wraps them 3 per row; the order it prints is the order written here.
- `{chains}` — the chain set, space separated. The assembler reads one static and one dynamic key per chain named here.

Also write one list file per chain into the bundle directory, for Turn 2-engine: `{bundle_dir}/files-{chain}.txt`, one in-scope path per line, the paths of that chain only.

> **`scope.tsv` is `key<TAB>value`, append-only, last line per key wins.** An absent key gives an absent table row — that is what keeps the plain scan's Scope table at four rows with no special case. A tab or a newline in a value breaks the row, so values are **stripped**, not escaped: no key here has any use for either character. Seven writers across five turns append to this one file, and none of them ever rewrites or deletes a line.
>
> `name`, `mode` and `chains` are the **only three keys a model types**. Everything else is either shell knowledge or read by the assembler for itself: the threshold from the constant, `N` in `seen in k/N runs` from counting run files, the stamp from the directory's own name, the engine version from the engine's own marker.

If the remote VERSION fetch succeeds, compare the two as **version numbers** (split on `.`, compare each part numerically) and warn **only when the local one is lower**: print `⚠️ You are not using the latest version of truent-audit. Please upgrade for best security coverage. See https://github.com/Emmyhack/Truent`. If it fails, skip silently.

> **Lower, not different.** A plain "differs" test warns the wrong person: somebody working on an unreleased version has a local `VERSION` **above** the published one, and gets told to upgrade to the version they are writing. Local equal to remote, or local above it, prints nothing.

**Turn 1b — Model and pass count.** This turn asks **two questions in one `AskUserQuestion` call**: which model the 12 agents use, and how many passes the scan runs. The runner is interrupted once, before any work starts.

> **The two questions do not fail the same way.** On a runtime without `AskUserQuestion` and an `Agent` tool that takes a `model` parameter — Codex, Gemini, Cursor's native agent — the **model** question is skipped silently, `{agent_model}` is left unset, and no prose replaces it. The **pass** question is not skipped: it falls through to the printed block in Turn 1b-ii, which stops and waits. This turn as a whole is never skipped. A later editor must not restore a blanket "SKIP this turn entirely" rule: it was true when this turn asked one question, and it is false now.

**Turn 1b-i — the `AskUserQuestion` call (Claude Code).** Ask both questions in one call. Where the `Agent` tool takes no `model` parameter, ask the pass question alone.

Question 1 — model:

1. Read your system prompt to detect your own model **family** (Opus, Sonnet, or Haiku). Ignore the version digits — the Agent tool's `model` parameter takes the family name (`"opus"` / `"sonnet"` / `"haiku"`), and the runtime resolves to the latest version in that family.
2. Put this question in the call:
   - Question: `"Which Claude model should the 12 audit agents use?"`
   - Three single-select options. Mark the orchestrator's own family as `(Recommended)` and place it first.
   - On each option, set the `description` field to `latest`.
   - On each option, set the `preview` field verbatim (preserve all whitespace exactly — the box widths must stay equal across all three):

   Opus preview:

   ```
   ┌──────────────────────────────────────────────────────────┐
   │  opus  ·  highest reasoning  ·  most expensive           │
   └──────────────────────────────────────────────────────────┘
   ```

   Sonnet preview:

   ```
   ┌──────────────────────────────────────────────────────────┐
   │  sonnet  ·  balanced reasoning  ·  mid cost              │
   └──────────────────────────────────────────────────────────┘
   ```

   Haiku preview:

   ```
   ┌──────────────────────────────────────────────────────────┐
   │  haiku  ·  lowest reasoning  ·  cheapest                 │
   └──────────────────────────────────────────────────────────┘
   ```
3. Store the runner's choice as `{agent_model}`. If no answer, default to the orchestrator's own model.

Question 2 — pass count. It goes in the **same call**, second:

4. Question: `"How many passes should this audit run? The engine runs once either way. Each pass is a full 12-agent audit, and every pass after the first is told what the earlier ones found, so it hunts new ground. You get one combined report at the end."`

   Three single-select options, `3 passes` first and marked `(Recommended)`. Each carries a `preview` box in this turn's style — the boxes are **60 characters wide, equal to the model picker's**, so two questions in one prompt look like one thing. Set `preview` verbatim, whitespace preserved:

   | Label | `description` |
   | --- | --- |
   | `3 passes (Recommended)` | `~45 min` |
   | `1 pass` | `~15 min` |
   | `5 passes` | `~75 min` |

   3 passes preview:

   ```
   ┌──────────────────────────────────────────────────────────┐
   │  3 passes  ·  each pass hunts new ground  ·  ~45 min     │
   └──────────────────────────────────────────────────────────┘
   ```

   1 pass preview:

   ```
   ┌──────────────────────────────────────────────────────────┐
   │  1 pass  ·  today's audit  ·  ~15 min, nothing written   │
   └──────────────────────────────────────────────────────────┘
   ```

   5 passes preview:

   ```
   ┌──────────────────────────────────────────────────────────┐
   │  5 passes  ·  deepest sweep  ·  ~75 min                  │
   └──────────────────────────────────────────────────────────┘
   ```

   > **These are measured, not guessed — and they are a floor.** They were measured on the
   > upstream Solidity-only skill this one is adapted from: a real 3-pass scan of 2,228 lines
   > across 10 files, 12 agents per pass on Opus, took **43 minutes** wall clock: 11 minutes
   > for pass 1 and about 16 for each of passes 2 and 3, which run slower because the growing
   > `known-findings.md` is appended to all twelve bundles. Individual agents ran 3.5–11
   > minutes. This skill adds the engine on top: seconds for the static pass, and up to a few
   > minutes per EVM file for the dynamic fuzzer in Turn 2-engine and again in Turn 4 for
   > every property an agent states. A larger codebase takes longer; a smaller model is
   > faster. Quote minutes rather than multipliers — "~3x time" told the runner nothing about
   > whether to wait or come back after lunch. If these numbers are ever re-measured on this
   > skill, correct them here rather than adding a second estimate somewhere else.

5. **Any other number needs no option of its own.** `AskUserQuestion` always adds an **Other** choice with a free-text box, and the runner types their number there. Do NOT add a fourth option reading "your own number" — options are fixed choices, so it could not collect the number and would dead-end.

   Parse the Other answer for the first integer. Below 1 or above 10 → ask once more. A second unusable answer → **1 pass**.

6. Store the answer as `{passes}`. No answer at all → 1 pass.

**Turn 1b-ii — the printed fallback (every runtime without `AskUserQuestion`).** Print this exactly:

```
How many passes should this audit run?

The engine runs once either way. Each pass is a full 12-agent audit. Every pass after
the first is told what the earlier passes found, so it hunts new ground. You get one
combined report at the end.

  1) 1 pass    — today's audit, about 15 minutes. Nothing is written outside .truent-audit/.
  2) 3 passes  — recommended. About 45 minutes.
  3) 5 passes  — deepest sweep. About 75 minutes.

Answer with 1, 2, 3, or any pass count you want.
```

> **STOP here and wait for the runner's answer.** Do NOT choose for them. Do NOT continue to Turn 2 with an assumed pass count. Do NOT start the scan and ask later.
>
> This is the one place in this skill where a question is emitted as prose. Turn 1b forbids prose questions because the model picker has a safe default — the orchestrator's own model. A pass count has no safe default: 1 and 5 differ by 5x in time and in cost, and that is the runner's money. A later editor must not "fix" this by deleting the prose block or by picking a default. If you are reading this and it looks like an inconsistency, it is deliberate.

Answers `1`, `2` and `3` are the three listed choices; any other integer is that many passes. Apply the same bounds as Turn 1b-i step 5 — below 1 or above 10, ask once more, then 1 pass.

**Turn 1b-iii — when the runner already said.** Ask nothing that has already been answered:

| What arrived | What the picker does |
| --- | --- |
| `--loop 5` | Skip the pass question, silently. 5 passes. |
| `--loop` with no number | Skip the pass question, silently. 3 passes. |
| "run 4 passes", "audit this four times" | Skip the pass question, silently. 4 passes. |
| "loop mode", "run it a few times" — a request with no number | **Ask.** They asked for the feature, not for a count. |
| Nothing | Ask. |

Skipping is silent in the first three rows — printing `using 5 passes` back at somebody who just typed `--loop 5` is noise. Skipping the pass question never skips the model question, and the reverse holds too.

**Turn 1b-iv — record the pass count.** However `{passes}` was settled — asked, typed in the prose fallback, or read off a flag — write it once, here:

```bash
printf '%s\t%s\n' passes_planned "{passes}" >> .truent-audit/runs/{stamp}/scope.tsv
```

This is the `P` in the Scope table's `Passes` row. The `R` — how many passes actually produced a run file — is counted by the assembler from the run files themselves, so a pass that dies before it can record anything still lowers the count. The row is printed only when `P` is above 1, so writing the key on a 1-pass scan is harmless: `passes_planned` `1` prints no row.

**Turn 1c — Memory read.** **SKIP this turn entirely when memory is off.** It is a turn of its own, and not a step of Turn 2, because two of its outcomes stop or downgrade the whole scan — they have to be reached before any expensive work starts.

1. **Shell check.** Memory is merged by `awk`. Run `command -v awk >/dev/null` once. If it fails, print `memory needs a bash shell — on Windows install Git for Windows`, turn memory **off** for this scan, scan as a plain 1-run scan, and touch no file. There is no second implementation of the merge; the rule that must never break lives in one language only.

2. **Stale temporary file.** If `.truent-audit/memory.tsv.tmp` exists, a previous scan did not finish. Print `warning: .truent-audit/memory.tsv.tmp left by an unfinished scan — overwriting`, then carry on. It is overwritten by this scan's merge.

3. **Read the ledger.** If `.truent-audit/memory.tsv` does not exist, this is a first-ever scan: memory is empty, every finding is `NEW`, the file is written at the end. Otherwise read it and **validate it before using it**:
   - the first line's first tab-separated field is exactly `#truent-audit-memory v1`
   - every later line has exactly **6** tab-separated fields

   On any failure print the path and the problem and **STOP the scan**. No agents, no report, no write. The user fixes or deletes the file. Do NOT start fresh and do NOT continue with a warning — a single bad row must never destroy real memory.

4. **Photocopy it.** `mkdir -p {bundle_dir}` is already done; copy the ledger as it was **before this scan started**:

   ```bash
   cp .truent-audit/memory.tsv {bundle_dir}/memory-before.tsv 2>/dev/null || : > {bundle_dir}/memory-before.tsv
   ```

   Every merge this scan performs reads this photocopy, never the live file. Create it empty when no ledger exists, so the merge command below needs no special case.

5. **Create the scan's row file**, empty: `: > {bundle_dir}/scan-rows.tsv`. Each run appends its gated rows to it.

6. **Hold the key list** — column 1 of every row of the photocopy (after the prune in Turn 2, if one runs).

   The **per-function bug-class vocabulary** — for each `contract|function` prefix, the bug-class labels the ledger already holds — is not held in the orchestrator's head. Turn 2 step 2c writes it to `{bundle_dir}/known-findings.md`, where the agents read it inside their bundles and Turn 4 reads it back from disk. It is a file and not a memory because the two readers are a long scan apart, and because the same labels must reach both.

   The vocabulary is what keeps exact key matching honest: a bug class is a label written in words, so the same bug re-labelled is a second record and memory fails silently. Handing the existing labels back is how the same bug keeps the same key.

**Turn 2 — Prepare.** In one message, make parallel tool calls: (a) Read `{resolved_path}/report-formatting.md`, (b) Read `{resolved_path}/judging.md`, (c) Read `{resolved_path}/agent-prompts.md`, (d) Read `{resolved_path}/report-language.md`, (e) Read `{resolved_path}/verification.md`.

> **Why `report-formatting.md` is still read, now that nothing here composes a report.** It is the shape Turn 4 step 5a writes each finding in — title line, location line, Description, diff Fix block — and the assembler pastes those bytes straight through. Read it as the contract the finding blocks meet, not as a template to imitate at the end.

> **`report-language.md` is read for the same reason, one level down.** `report-formatting.md` settles the **shape** of a finding block; `report-language.md` settles the **words inside it**. Turn 4 step 5a writes the title and the Description, the assembler pastes them through unchanged, so those bytes are the last chance to write a sentence a developer can act on. It is Simplified Technical English (ASD-STE100), and it is not optional styling: a finding the developer cannot read is a finding they do not fix. The same file is in every agent bundle, so the sentence the pass writes and the sentence the agent handed it obey one rule.

> **`verification.md` is read here and used in Turn 4.** It is what turns a REASONED claim into a VERIFIED-PROVEN finding, or into nothing. Reading it now, before any agent runs, is what keeps Turn 4 from improvising a verification step with a flag the engine does not have.

Then build `source.md`, run the engine, run the memory step, and only then cat the bundles — in that order, because the bundles carry files the engine and the memory step write:

> **Turn 2 is split across the loop.** Step 1 and Turn 2-engine run **once per scan**: `source.md` provably cannot change between passes — one git SHA for the whole loop, no pruning between them — and the engine is deterministic on that frozen source. Step 2c and step 3 run **once per pass**, because only they carry the knowns, and re-catting twelve bundles from files already on disk is one Bash command. Steps 2a and 2b run once per scan with step 1, since both read that frozen source.
>
> **One `{bundle_dir}`, reused, everything overwritten.** `source.md` and `engine-findings.md` are written once and never touched again; `known-findings.md` and the twelve `agent-N-bundle.md` files are overwritten each pass. Disk stays flat whether the runner picked 1 pass or 10 — a directory per pass would hold 12 × N copies of the whole repo. This is safe because Turn 3b is a hard barrier: no pass-K agent is still reading a bundle when pass K+1 overwrites it. The cost, accepted: after the loop you cannot see what pass 2 told its agents. The durable record is `engine.md`, the run files and the ledger.

1. **Once per scan.** `{bundle_dir}/source.md` — ALL in-scope files, each with a `### path` header and fenced code block (`solidity`, `rust` or `move`).

**Turn 2-engine — Ground truth. Once per scan, after step 1 and before step 2.** This is the turn that makes the skill engine-first, and it runs on every scan at every pass count.

a. **Static, per chain.** For every chain `c` in `{chains}`, one Bash command:

```bash
bash $SKILL_DIR/scripts/engine.sh --files {bundle_dir}/files-{c}.txt {c} --render \
  --out {bundle_dir}/engine-{c}.jsonl > {bundle_dir}/engine-findings-{c}.md
```

`--render` turns the engine's JSON into finding blocks in the run-file shape — marker, title, location, an **Engine** line (`invariant_id`, evidence, exploitability, CWE / SWC / OWASP / DASP), the engine's message, snippet, fix and verify step — one block per violation, each tagged `VERIFIED-STATIC` (evidence `lead`) or `VERIFIED-PROVEN` (evidence `proven`), with a confidence derived from the engine's own exploitability. The exit code mirrors `truent scan --fail-on critical` and is **information, not a stop**: 1 means a proven critical exists, 127 means no binary (Turn 1 already stopped for that), anything else is a scan that ran. Record the outcome:

```bash
printf '%s\t%s\n' engine_static_{c} "✓" >> .truent-audit/runs/{stamp}/scope.tsv          # rendered
printf '%s\t%s\n' engine_static_{c} "✗ (exit N: <first stderr line>)" >> …/scope.tsv     # did not render
```

Then, once, for the whole scan:

```bash
cat {bundle_dir}/engine-findings-*.md > {bundle_dir}/engine-findings.md
cp {bundle_dir}/engine-findings.md .truent-audit/runs/{stamp}/engine.md
printf '%s\t%s\n' engine_version "$(awk '/^<!--ENGINE / { if (match($0, /version=[^ ]+/)) { print substr($0, RSTART+8, RLENGTH-8); exit } }' {bundle_dir}/engine-findings.md)" \
  >> .truent-audit/runs/{stamp}/scope.tsv
```

`engine.md` is the durable copy the assembler reads; `engine-findings.md` is the copy every agent bundle carries. Same bytes. **The orchestrator never edits either**: they are shell output from the engine's JSON, and a model that "tidies" an engine block has turned ground truth into opinion.

**Write the static reproduce keys**, one per chain, numbered from 1 in `{chains}` order. With six or fewer files on the chain, one key per file; above six, one key naming the repository root with a scope note:

```bash
printf '%s\t%s\n' repro_1 "truent scan src/Vault.sol --chain evm --output json" >> .truent-audit/runs/{stamp}/scope.tsv
printf '%s\t%s\n' repro_2 "truent scan . --chain solana --output json   # scope: the Files reviewed row; the engine itself does not apply the exclude pattern" >> …/scope.tsv
```

b. **Dynamic — EVM only, best effort, per in-scope `.sol` file.** For each path in `{bundle_dir}/files-evm.txt`:

```bash
truent fuzz <file.sol> --dynamic --chain evm --iterations 500 --seed 1
```

Read the printed result and act on exactly three outcomes:

- **`✗ [PROVEN]` with an `Invariant violated` block and a `Reproduction`** → append a block to **both** `{bundle_dir}/engine-findings.md` and `.truent-audit/runs/{stamp}/engine.md` (same bytes, `cat >>` to each), in the run-file shape, with the engine's text pasted verbatim under **Proof (engine)**:

  ````markdown
  <!--F key={file-stem}|engine-fuzz|{invariant-slug} conf=100 kind=FINDING tier=VERIFIED-PROVEN sev={sev} agents=engine id=dynamic-{invariant-slug} evidence=proven-->

  [100] **{the invariant's name, as the engine printed it}**

  `{file.sol}` · Confidence: 100

  **Engine** dynamic fuzz · revm · seed 1 · 500 iterations · evidence: proven

  **Description**
  {one STE sentence: who does what and what they get, from the reproduction}

  **Proof (engine)**
  ```
  {from "Invariant violated" through "Failing step", verbatim}
  ```

  <!--/F-->
  ````

  `{invariant-slug}` is the invariant's name normalised (lower case, runs of non-alphanumerics to one hyphen: `erc20-conservation`). `{sev}` is fixed by the invariant shape, not by judgment: conservation and access control → `critical`; monotonicity and reentrancy → `high`. This transcription is the **only** place the orchestrator writes into an engine file, and the only model-written line in it is the Description; everything else is the engine's text or a fixed shape. Append a `repro_N` key with the exact command.
- **A clean run to completion** (no violation printed, no "not analysed") → nothing to write. It is not evidence of anything and no block says "held".
- **"not analysed" / "could not be analysed"** (no auto-detectable invariant on the ABI, `solc` failed, a constructor that takes arguments, a relative import) → nothing to write; keep the engine's one-line reason for the key below. `verification.md` lists the observed limits; the orchestrator **never edits the contract** to get past one.

Then record the dynamic outcome per chain, once:

```bash
printf '%s\t%s\n' engine_dynamic_evm "✓" >> …/scope.tsv                                    # at least one file ran to completion
printf '%s\t%s\n' engine_dynamic_evm "skipped (<the engine's reason>)" >> …/scope.tsv      # no file could run
printf '%s\t%s\n' engine_dynamic_solana "n/a (execution deferred in truent 0.6.0)" >> …/scope.tsv
printf '%s\t%s\n' engine_dynamic_move "n/a" >> …/scope.tsv
printf '%s\t%s\n' engine_dynamic_soroban "n/a" >> …/scope.tsv
```

`✓` means the fuzzer executed at least once on that chain. It never means "and found nothing". A Solana, Move or Soroban chain in scope gets its `n/a` key here so the Engine row never has a blank cell; `--dynamic` on those chains is an error (Move, Soroban) or a validate-and-stop (Solana) in this engine release, and the skill does not pretend otherwise.

**Print the engine summary now, before any agent runs**: one line per chain, from the `<!--ENGINE` marker — `engine: evm · truent 0.6.0 · 7 violations (1 critical, 3 high, 2 medium, 1 low) · dynamic: 2 files fuzzed, 1 proven`. The runner sees proven results first, at zero model cost, and the rest of the scan is visibly *additional*.

2. **Turn 2 step 2 — Name map, prune and known findings** (below). SKIPPED whole when memory is off. Parts a and b run once per scan; part c runs **every pass**, because the ledger it reads grows as the loop learns.
3. **Every pass.** Agent bundles, in a single Bash command using `cat` (not shell variables or heredocs) = `source.md` + engine findings + chain primers + agent-specific files:

| Bundle                | Appended files (relative to `{resolved_path}`, after `{bundle_dir}/source.md` and `{bundle_dir}/engine-findings.md`)                          |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `agent-1-bundle.md`   | `chains/{c}.md` for each `c` in `{chains}` + `senior-auditor-sop.md` + `hacking-agents/math-precision-agent.md` + `hacking-agents/shared-rules.md`    |
| `agent-2-bundle.md`   | same primers + `senior-auditor-sop.md` + `hacking-agents/access-control-agent.md` + `hacking-agents/shared-rules.md`                          |
| `agent-3-bundle.md`   | same primers + `senior-auditor-sop.md` + `hacking-agents/economic-security-agent.md` + `hacking-agents/shared-rules.md`                       |
| `agent-4-bundle.md`   | same primers + `senior-auditor-sop.md` + `hacking-agents/execution-trace-agent.md` + `hacking-agents/shared-rules.md`                         |
| `agent-5-bundle.md`   | same primers + `senior-auditor-sop.md` + `hacking-agents/invariant-agent.md` + `hacking-agents/shared-rules.md`                               |
| `agent-6-bundle.md`   | same primers + `senior-auditor-sop.md` + `hacking-agents/periphery-agent.md` + `hacking-agents/shared-rules.md`                               |
| `agent-7-bundle.md`   | same primers + `senior-auditor-sop.md` + `hacking-agents/first-principles-agent.md` + `hacking-agents/shared-rules.md`                        |
| `agent-8-bundle.md`   | same primers + `senior-auditor-sop.md` + `hacking-agents/asymmetry-agent.md` + `hacking-agents/shared-rules.md`                               |
| `agent-9-bundle.md`   | same primers + `senior-auditor-sop.md` + `hacking-agents/boundary-agent.md` + `hacking-agents/shared-rules.md`                                |
| `agent-10-bundle.md`  | same primers + `senior-auditor-sop.md` + `hacking-agents/numerical-gap-agent.md` + `hacking-agents/shared-rules.md`                           |
| `agent-11-bundle.md`  | same primers + `senior-auditor-sop.md` + `hacking-agents/trust-gap-agent.md` + `hacking-agents/shared-rules.md`                               |
| `agent-12-bundle.md`  | same primers + `senior-auditor-sop.md` + `hacking-agents/flow-gap-agent.md` + `hacking-agents/shared-rules.md`                                |
| **every one of the 12** | **`{bundle_dir}/engine-findings.md`, appended right after `source.md`** — unconditional, every mode, every pass. The engine already found these; the agents hunt the residual, and an agent that cannot see the engine's blocks re-derives them. |
| **every one of the 12** | **`chains/{c}.md` for every chain in `{chains}`**, appended after the engine findings — the execution model, trust boundaries, per-specialty hunting grounds and detector ids for that chain. One primer per chain in scope, none for a chain that is not. |
| **every one of the 12** | **+ `report-language.md`, appended after `shared-rules.md`** — unconditional, every mode, every pass. The agent's `description:` is the seed of the report's Description, so the language rule has to reach the writer and not only the editor. |
| **every one of the 12** | **+ `{bundle_dir}/known-findings.md`, appended last** — only when memory is on **and** step 2 wrote that file. Never appended on a plain scan, and never appended when the ledger holds no record. |

Each bundle = source.md + engine findings + chain primer(s) + SOP + specialty + shared-rules + report-language (+ known findings, when there are any). Agents read the bundle; no Read/Grep needed for the initial scan. Targeted Read/Grep allowed for cross-file investigation.

**Turn 2 step 2 — Name map, prune and known findings.** **SKIP this step entirely when memory is off.** It lives in Turn 2 and not in a turn of its own because all three parts read `source.md`, which Turn 2 has just built — a separate turn would only carry that file across a boundary. It is numbered **2**, ahead of the bundle cat, because part c writes a file every bundle carries; a pruned record must never reach an agent.

a. **Build the name map, always** — once per scan, with step 1 (both the prune and the report need it, and the source it reads is frozen for the whole scan):

```bash
{
  grep -ohE '(contract|library|interface|module|mod|struct|impl)[[:space:]]+[A-Za-z0-9_]+|(function|fn|fun)[[:space:]]+[A-Za-z0-9_]+' {bundle_dir}/source.md \
    | awk '{ n=$2; k=tolower(n); gsub(/[^a-z0-9]+/, "-", k); print k "\t" n }'
  grep -E '^### ' {bundle_dir}/source.md \
    | awk '{ p=$2; sub(/.*\//, "", p); sub(/\.[A-Za-z0-9]+$/, "", p); k=tolower(p); gsub(/[^a-z0-9]+/, "-", k); print k "\t" p }'
} | sort -u > {bundle_dir}/source-names.tsv
```

Column 1 is the identifier normalised the same way a key segment is (lower case, every run of non-alphanumeric characters to one hyphen); column 2 is how it is spelled in the source. The regex covers Solidity (`contract` / `function`), Rust (`mod` / `struct` / `impl` / `fn`) and Move (`module` / `struct` / `fun`, which also matches `public fun` and `entry fun` because the match starts at `fun`). The second `grep` adds every in-scope file's stem, because engine keys use the stem as their first segment. Normalising **both sides the same way** is what makes the comparison exact — a key segment can never be matched against raw source text, because `withdrawAll` is stored as `withdrawall`.

b. **Prune — once per scan, and only after a whole-repo scan.** Run it **only** in default mode. Never on a named-file scan (a file that was not scanned proves nothing about the records it holds), and never a second time inside one scan — the loop's later passes read the same frozen source, so there is nothing new for a second prune to learn.

The prune edits the **photocopy**, not the live ledger. The live file inherits the prune when the first merge writes it. Pruning the live file instead would be undone by the next rebuild.

```bash
awk -F'\t' -v OFS='\t' '
FILENAME==ARGV[1] { names[$1]=1; next }
FNR==1 { print; next }
{
  split($1, p, "|")
  keep = (p[1] in names) && (p[2] in names)
  if (p[2]=="constructor" || p[2]=="receive" || p[2]=="fallback" || p[2]=="init" || p[2]=="init-module" || p[2] ~ /^engine-/) keep = (p[1] in names)
  if (keep) print; else print "pruned: " $6 "\t" $1 "\t" $5 > "/dev/stderr"
}
' {bundle_dir}/source-names.tsv {bundle_dir}/memory-before.tsv > {bundle_dir}/memory-before.tsv.tmp \
  && mv {bundle_dir}/memory-before.tsv.tmp {bundle_dir}/memory-before.tsv
```

A record is dropped when its contract or its function can no longer be found in the assembled source. `constructor`, `receive`, `fallback`, `init` and `init_module` are never written as `function <name>` in a way the map catches, so a record on one of them is kept whenever its contract survives. An **engine record** (`<stem>|engine-L42|<id>`, or `engine-fuzz`) has a file stem, not a contract, as its first segment and a location, not a function, as its second: it is kept whenever the file is still in scope. A line-shifted engine record is not pruned here — it stays until the file leaves scope, and shows under "Known from earlier scans" until then; `report-formatting.md` states that limitation.

**The prune deletes Leads as well as findings.** A Lead is a full ledger record, so the same rule reaches it — and a pruned Lead leaves no trace anywhere else in the output. That is why the command prints every dropped row to the runner: `kind`, key and title, one line each. Print them under `Pruned N records (contract or function no longer in scope):`. Never drop a record silently.

After the prune, re-read the photocopy for the key list of Turn 1c step 6. A pruned record must not reach the agents, the merge, or the "Known from earlier scans" section.

c. **Write `mem_before`, then build `{bundle_dir}/known-findings.md`.**

**`mem_before` first** — the row count of the photocopy **as the merge will read it**, which is the count *after* the prune. It is written here and nowhere else, and it is written in every mode memory is on, whether or not part b's prune ran (it does not run on a named-file scan):

```bash
printf '%s\t%s\n' mem_before "$(( $(wc -l < {bundle_dir}/memory-before.tsv) - 1 ))" \
  >> .truent-audit/runs/{stamp}/scope.tsv
```

The `- 1` drops the header line. An empty photocopy has no header and would give `-1`; write `0` instead. The **pre**-prune number would make the `Memory` row's own arithmetic wrong — `12 records before this scan · 14 after` has to describe the same set the merge worked on.

**This key is the memory flag the assembler reads.** Its presence is what makes the `Memory` row appear and the "Known from earlier scans" section exist — the presence of `memory-before.tsv` is not. Nothing writes a `mem_` key when memory is off, and this whole step is skipped when it is, so the flag cannot get out of step with the scan.

It is written before the early exit below, so an empty ledger still gets a `Memory` row reading `0 records before this scan`.

**Then `{bundle_dir}/known-findings.md`** — the ledger as the agents and Turn 4 read it. It is built from the **pruned** photocopy and from `source-names.tsv`, so it never names a record the prune has just dropped and never prints a normalised key at a human.

```bash
awk -F'\t' '
FILENAME==ARGV[1] { nm[$1]=$2; next }
FNR==1 { next }
{
  split($1, p, "|")
  c = (p[1] in nm) ? nm[p[1]] : p[1]
  f = (p[2] in nm) ? nm[p[2]] : p[2]
  h = c "." f
  if (!(h in seen)) { seen[h]=1; ord[++n]=h }
  body[h] = body[h] "- `" p[3] "` — " $6 ", seen in " $3 ($3==1 ? " scan" : " scans") " — " $5 "\n"
}
END { for (i=1; i<=n; i++) printf "## %s\n\n%s\n", ord[i], body[ord[i]] }
' {bundle_dir}/source-names.tsv {bundle_dir}/memory-before.tsv > {bundle_dir}/known-findings.body.md
```

**If that file is empty, stop here** — delete it, write no `known-findings.md`, and append nothing to the bundles. An empty ledger (a first-ever scan, or a scan whose every record the prune removed) must not hand twelve agents an empty heading.

Otherwise write `{bundle_dir}/known-findings.md` as this exact prose followed by the body, unchanged:

````markdown
# Known findings — ground already walked

Earlier scans of this repository recorded the findings below, grouped by the contract and
function they sit in. Each line is `bug class` — kind, scans, title. A section whose function
reads `engine-L42` is an engine record: the compiled detector named in the label matched that
line on an earlier scan.

**They are not false positives, and they are not off limits.** Put your **effort** into new
ground: functions, flows and mechanisms this list does not name. That is a rule about where
your reading time goes. It is **not** a rule about what you report.

**Report every bug you find in full, listed or not.** A listed bug you reach again is a bug
that is still there, and the report has to say so. Write it up exactly as you would write up
anything new — the same path, proof and fix — whether you reached it by the mechanism it is
listed with or by a different one. Silence is read as "nobody found this": a finding no agent
raises drops out of the report into a table of records nobody re-checked, so a repository
scanned twice would show fewer bugs than the same repository scanned once. The one exception
is an engine record: the engine re-checks its own records on every scan, so you do not need
to.

**Reuse the bug-class label.** The backticked label on each line is the word this repository
already uses for that class of bug in that function. When you report a finding or a lead
whose bug class is one of the classes listed for that same contract and function, write
**that exact label**. Invent a new label only when none of them is the same class of bug.
Memory matches these labels as plain text, so the same bug under a new word is remembered
twice and recognised never.

<body — one `## Contract.function` section per function, as generated above>
````

The label-reuse rule is written here, once, for **both** readers of this file: the 12 agents,
who write the bug class in a finding, and Turn 4 step 4, which writes it into a key.

**The builder takes any 6-column ledger file.** On a single-run scan that file is the pruned
photocopy, as above. A multi-pass scan rebuilds `known-findings.md` from the freshly merged
`.truent-audit/memory.tsv` after every pass, before it re-cats the bundles, so the agents
of pass K+1 read what pass K found as ground already walked. That is the whole point of
passing memory down a loop; the command does not change, only the file it is pointed at.

Print line counts for every bundle, `source.md` and `engine-findings.md`. Do NOT inline source code into the Agent call prompt itself.

**Turn 3a — Spawn all 12 agents.** Runs **every pass**. In one message, spawn all 12 agents as **parallel BACKGROUND Agent calls** (`run_in_background=true`). If Turn 1b set `{agent_model}`, pass `model={agent_model}` on every Agent call. If `{agent_model}` is unset (Turn 1b skipped — Codex, Gemini, others), omit the `model` parameter entirely — do NOT substitute any default. The orchestrator will receive a notification when each agent completes — do NOT poll or sleep. Single phase, no later spawns. Proceed to Turn 3b only after all 12 have notified completion.

Agents 1–9 use the **single-specialty prompt** (Turn 3a-i). Agents 10–12 use the **gap-hunter prompt** (Turn 3a-ii).

**Turn 3a-i — Single-specialty prompt (agents 1–9).** Use the template under "Single-specialty prompt" in `{resolved_path}/agent-prompts.md`, substituting `{bundle_dir}`, the agent number, the bundle line count and `{chains}`.

**Turn 3a-ii — Gap-hunter prompt (agents 10–12).** Use the template under "Gap-hunter prompt" in the same file.

Three rules that file carries, repeated here because they are conditions and not text:

- The **"Known findings"** paragraph is included **only when memory is on and `known-findings.md` was appended**. On a plain scan the prompt is byte-identical to the one it has always been — a paragraph about a section that is not there would send agents hunting for it.
- The **"Engine findings"** paragraph is **unconditional** — the engine runs on every scan, so the section is in every bundle, and an empty engine list is the boundary of what the detectors encode, not a clean bill.
- The **READ-ONLY** paragraph is **unconditional** — every agent, every mode, every pass, every chain. A real scan proved it necessary: an agent built Foundry proof-of-concept files inside the audited repository and deleted them afterwards. It left the tree clean and the stored SHA honest, and it was still wrong. On Solana and Move a test module is the natural way to try an idea, and the rule is the same. Agents do not run the engine either; the orchestrator does, on the property they state. A later editor must not make it conditional, and must not soften it into a preference.

**Turn 3b — Wait for all 12 agents to complete.** Runs **every pass**. Once every one of the 12 spawned agents has notified completion, proceed to Turn 4. Do NOT proceed to dedup until every agent has finished — let them run to natural completion. Do NOT poll or sleep; act only on completion notifications.

**While you wait, on the first pass only, Read `{resolved_path}/dedup-and-assembly.md`.** It holds the whole of Turn 4 and Turn 5. This turn is the one point in the scan where the orchestrator has nothing else to do, so the read costs no wall-clock; and having it in hand before Turn 4 starts is what keeps Turn 4 from improvising. Later passes already hold it.

**When an agent dies.** Continue the pass with the eleven that came back. **Never respawn it, in any mode.** A retry costs an unbounded wait for one twelfth of the coverage, and a loop covers it for free — the next pass runs the same twelve specialties again, knowing what this one found. Record the loss in all three places, or it is a silent coverage loss: the pass summary line (Turn 4 step 5), the `run-K.md` header, and the report's `Passes` row.

**When a whole pass produces nothing** — the bundle build failed, or all twelve died:

**Record the failure before doing either.** A pass that produces nothing writes no run file, so nothing else on disk knows it was ever planned:

```bash
printf '%s\t%s\n' pass_{K}_failed 1 >> .truent-audit/runs/{stamp}/scope.tsv
```

- **Pass 1 produces nothing:** this is not a loop failure, it is today's failure. No ledger write. Go to Turn 5, which assembles a report holding the engine's findings and no agent findings — rather than printing nothing at all. The `Passes` row is suppressed on a 1-pass scan, so the assembler says it in a **Run files** row instead — `⚠️ No pass produced a run file. The agents reviewed nothing; only the engine's findings are below.` The runs directory stays; it holds `engine.md` and the `scope.tsv` that says what was attempted.
- **A later pass produces nothing:** stop the loop and go straight to Turn 5. The report is assembled from the passes that finished and its `Passes` row says which one failed. Nothing is lost — the ledger was rebuilt after every pass. Grinding on to the next pass after the machinery has broken burns the runner's money.

**Turn 4 — Deduplicate, validate, verify & record.** Runs **every pass**, and it is the end of the loop body: deduplicate this pass's agent results against each other and against the engine's blocks, gate-evaluate, **hand every stated property to the engine**, tag, record the pass, write the ledger. **It prints no report** — there is exactly one report per scan and Turn 5 prints it. Do NOT print an intermediate dedup list.

**Steps 4 and 6 are SKIPPED entirely when memory is off.** Every other step runs at any pass count.

Follow `{resolved_path}/dedup-and-assembly.md`, section **"Turn 4"**, step by step. Its step 3b is this skill's differentiator and runs at every pass count: for every gated FINDING and LEAD whose `property:` is not `none`, `{resolved_path}/verification.md` says which engine command to run — EVM → `truent fuzz --dynamic` (and `truent symbolic` where a Foundry project has proof tests); Solana → a plan the engine validates (execution is deferred in truent 0.6.0); Move and Soroban → external tools, labelled EXTERNAL. An engine reproduction promotes the item to `VERIFIED-PROVEN` with the engine's output pasted as proof; a property the engine held across seeds demotes or drops it; an engine that could not run leaves the tier alone and the clause says why. **The machine is the arbiter.** Model confidence never changes a tier.

Then, after the loop body has run `{passes}` times (or stopped early), go to Turn 5 once.

**Turn 5 — Assemble, print, clean.** Runs **once per scan**, at any pass count, including a 1-pass scan and including a loop that stopped early. There is no path where a scan ends without this turn.

**This turn holds no model judgment.** It copies two files, runs `scripts/assemble.sh`, counts with `awk`, and prints. `$SKILL_DIR/scripts/assemble.sh` is the only producer of a report in this skill: do not re-word its output, do not re-order it, do not add to it and do not summarise it in your own words. If this turn looks too thin to be a reporting step — that is the point, and `dedup-and-assembly.md` records why.

Follow `{resolved_path}/dedup-and-assembly.md`, section **"Turn 5"**, step by step. Its step 1 is SKIPPED when memory is off; its step 4 runs only when `--file-output` was passed.

The assembled report ends with a **Reproduce** section holding every `repro_N` command this scan ran, so a reader can re-run the engine and get every `VERIFIED` finding again, identically. REASONED findings are not in it, because nothing reproduces them.

## Banner

Before doing anything else, print this exactly:

```
  ╔═══════════════════════════════════════════════════════════╗
  ║   T R U E N T   ·   A U D I T                             ║
  ║   engine first · three evidence tiers · multi-chain       ║
  ╚═══════════════════════════════════════════════════════════╝
```
