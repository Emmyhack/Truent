---
name: truent-fuzz
description: "Stateful invariant fuzzing for smart contracts on EVM, Solana, Move and Soroban. Default path runs Truent's native revm-backed fuzzer — auto-detected invariants, user-written .invar properties, adversarial call sequences, and minimal-PoC shrinking in one binary, no external toolchain. On demand it generates a full fizz-grade Echidna/Medusa suite (setup, handlers, ghost/snapshot properties, coverage loop, campaigns, Foundry repros, report, convert/sync sub-commands) as a strict superset, never lock-in, plus Solana fuzz plans and Move Prover / Soroban test harnesses. Triggers on 'truent fuzz', 'fuzz this', 'fizz', 'invariant fuzzing', 'stateful fuzzing', 'generate fuzz suite', 'build fuzz harness', 'build a fuzz harness', 'fuzzing harness', 'property testing', 'invariant suite'."
license: MIT
metadata:
  version: "0.2.0"
  author: Emmyhack
  homepage: https://github.com/Emmyhack/Truent
  domain: smart-contract-security
  subdomain: fuzzing
  chains:
    - evm
    - solana
    - move
    - soroban
  requires:
    - "truent >= 0.6.0"
    - "foundry (Section B only)"
    - "medusa (Section B only)"
    - "echidna (Section B, optional)"
    - "node >= 18 (Section B only)"
  taxonomy:
    - CWE
    - SWC
    - OWASP-SC-Top-10-2025
    - DASP
  tags:
    - smart-contract
    - fuzzing
    - invariant-testing
    - property-testing
    - echidna
    - medusa
    - foundry
    - revm
    - evm
    - solana
    - move
    - soroban
    - proof-of-concept
---
<!-- Adapted from pashov/skills fizz/SKILL.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent native path first, multi-chain. -->

# Truent Fuzz

Fuzz a contract for broken invariants. The **default** path (Section A) needs
no Echidna, no Medusa, no Foundry setup and no hand-written handlers: Truent's
native fuzzer deploys the contract in an in-memory EVM, drives adversarial call
sequences, checks auto-detected and user-written invariants after every call,
and shrinks any violation to a minimal, runnable proof-of-concept. One binary,
one command.

For teams standardised on Echidna/Medusa, Section B generates a **full
fizz-grade suite** (scaffold, setup wiring, handlers, coverage loop, five
invariant-discovery agents, implementers, campaigns, Foundry repros, report,
drift sync). It is a strict superset of the native path, never a lock-in: the
synthesizer also emits every DSL-expressible property as a Truent `.invar`
file so the native fuzzer checks the same properties with no harness at all.

Section C adds the `convert` and `sync` sub-commands. Section D covers
Solana (native plan-driven fuzzing), Move and Soroban (harness generation;
Truent verifies those two chains statically only).

`$SKILL_DIR` = the directory containing this SKILL.md. Every path below that
starts with `$SKILL_DIR/` exists in this directory.

## Evidence vocabulary (never blur these)

| Tag | Meaning |
|---|---|
| `VERIFIED-PROVEN` | Truent's engine executed it: a native fuzz PoC (`truent fuzz --dynamic`) or a symbolic counterexample (`truent symbolic`). |
| `VERIFIED-STATIC` | A Truent detector matched (`truent scan`). |
| `EXTERNAL` | A real result from Echidna, Medusa, Foundry, Move Prover, `aptos`/`sui move test` or `cargo test` — real, but not Truent's engine. |
| `REASONED` | An LLM proposed it and nothing executed it. |

Properties additionally keep fizz's generation-time guarantee tag:
**`SHOULD-HOLD`** (documented / standard-mandated / exact identity, evidence
cited) or **`EXPLORATORY`** (inferred). A violated SHOULD-HOLD property is a
confirmed bug; a violated EXPLORATORY property is a lead for human review.
Guarantee says *why the property should hold*; the evidence tag says *what
executed the check*. Report both.

## Step 0 (all sections): banner and version check

Print this banner once, before any other output:

```text
████████╗██████╗ ██╗   ██╗███████╗███╗   ██╗████████╗    ███████╗██╗   ██╗███████╗███████╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝████╗  ██║╚══██╔══╝    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝
   ██║   ██████╔╝██║   ██║█████╗  ██╔██╗ ██║   ██║       █████╗  ██║   ██║  ███╔╝   ███╔╝
   ██║   ██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║   ██║       ██╔══╝  ██║   ██║ ███╔╝   ███╔╝
   ██║   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║       ██║     ╚██████╔╝███████╗███████╗
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝       ╚═╝      ╚═════╝ ╚══════╝╚══════╝
```

Then run the version check. Warn **only** when the local version is lower than
the published one; say nothing on a network failure or when equal/newer:

```bash
LOCAL=$(cat "$SKILL_DIR/VERSION")
REMOTE=$(curl -fsSL --max-time 5 https://raw.githubusercontent.com/Emmyhack/Truent/main/skills/truent-fuzz/VERSION 2>/dev/null || true)
if [ -n "$REMOTE" ] && [ "$(printf '%s\n%s\n' "$LOCAL" "$REMOTE" | sort -V | head -1)" = "$LOCAL" ] && [ "$LOCAL" != "$REMOTE" ]; then
  echo "truent-fuzz $LOCAL is behind published $REMOTE — update the skill."
fi
```

Preflight: locate the `truent` binary (`which truent`, else
`target/release/truent` from a repo clone); run `truent doctor` if unsure.

---

# Section A — Native fuzzing (default, recommended)

## A1. Run per in-scope EVM contract

```bash
truent fuzz <contract.sol> --dynamic --chain evm --iterations 1000 --seed 1
```

Truent auto-detects invariant shapes from the ABI and needs no property
authoring for them:

| Shape | Detected from | A violation proves |
|---|---|---|
| Conservation | `totalSupply()` + `balanceOf(address)` | value credited with no matching supply change |
| Monotonicity | a no-arg accumulator getter (`totalSupply`, `totalAssets`, `exchangeRate`, `sharePrice`, `cumulative*`, `checkpoint*`) | a never-decreasing quantity went down |
| Access control | `owner()` + `transferOwnership(address)` | ownership changed from a non-owner call |
| Reentrancy | execution trace (call-stack inspector) | state written after an external call re-entered |

Useful flags: `--depth D` (max call-sequence length, default 10),
`--iterations N`, `--seed S`, `--output json --file F` (machine-readable
result), `--verbose`.

## A2. Read the result

On a violation the engine prints the invariant, the message and a **minimal
reproduction**. That sequence IS the PoC — report it verbatim as
`VERIFIED-PROVEN`. Real engine output (truent 0.6.0, a 1000-token ERC20 with a
`burn`, checked against the DSL file in A3):

```
▶ Loaded 2 properties from fizz_data/properties.invar
▶ Dynamically fuzzing Token1.sol (revm, 200 runs, depth 10)...

✗ [PROVEN] Token1.sol
Invariant violated: SupplyIsConstant
violated with total_supply = 999999999999578235281

Reproduction (1 call):
  1. burn(0000000000000000000000000000000000000000000000000000000019239e6f)  [caller=0x0101010101010101010101010101010101010101]

Failing step: #1 (burn)
```

A clean run prints `✓ no violation found in N runs`. Before concluding an
invariant holds, vary `--seed` (2, 3) and raise `--iterations`. A contract the
engine **could not analyse** is reported as such and is *not* a pass:

```
✗ 1 of 1 contract(s) could not be analysed — this is not a pass:
    Vault.sol: no auto-detectable invariant on this ABI (looked for ERC20-shaped totalSupply/balanceOf, or monotonic accumulator getters) and no --invariants file supplied — nothing to check
```

When you see that, write properties (A3). Never report "no findings" for a
contract that was not analysed.

## A3. Author properties in the Truent DSL (`--invariants`)

Auto-detection only recognises shapes it already knows. The properties that
decide whether *this* protocol is correct — solvent, exitable, bounded — must be
stated. Write them in a `.invar` file and pass `--invariants`:

```bash
truent fuzz <contract.sol> --dynamic --chain evm --iterations 1000 --seed 1 \
  --invariants fizz_data/properties.invar
```

Grammar that the engine accepts (read `$SKILL_DIR/references/dsl.md` before
writing one; the pest grammar in `crates/dsl_parser/src/grammar.rs` is the
truth):

- `invariant Name { expr }` — one or more per file; `//` line comments allowed.
- Operators: `&& || !`, `== != < > <= >=`, `+ - * /`, parentheses. **No `%`,
  no `sum()`, no `forAll()`, no `exists()` at runtime** — whatever older docs
  show, the engine binds identifiers, not quantifiers.
- An identifier binds to a **zero-argument view function** on the contract,
  case- and underscore-insensitively (`total_supply` binds `totalSupply()`).
- A call with **integer/boolean literal arguments** (`balanceOf(0)`,
  `shareOf(1, 2)`) binds to a getter of matching name and arity — this is how
  a property reaches into a mapping.
- An identifier that cannot be bound is an **error, never a skipped check**.
  Real engine output:
  ```
  invariant 'Unbound' references a variable with no matching zero-argument view on the contract.
    unbound: balance_of
    available getters: decimals, name, owner, symbol, totalSupply
  ```
- Values are compared as unsigned 128-bit integers. A getter above 2^128, a
  reverting getter, or an overflow/division-by-zero makes that check
  *undecidable* for that state (not a violation, not a pass).

Real DSL examples (from `examples/invariants.invar`, the ones the runtime can
bind when the named getters exist):

```
invariant TokenConservation {
    (balance_alice + balance_bob + balance_charlie) == total_supply
}
invariant MultipleConditions {
    (total_supply >= 0) && (total_supply <= max_supply)
}
invariant LiquidityPreservation {
    (reserve_a > 0) && (reserve_b > 0) && ((reserve_a * reserve_b) >= constant_product)
}
```

Authoring rules (the same rules the Section B synthesizer applies):

1. One `.invar` file per target contract — every identifier in the file must
   bind on the contract it is run against.
2. Prefer exact identities (`==`) for SHOULD-HOLD accounting properties and
   bounds (`<=`, `>=`) for EXPLORATORY ones.
3. Sum-over-actors properties cannot be written (no `sum()`): either expose an
   aggregate getter on a thin harness contract, or leave them to the
   auto-detected conservation check / the Section B Solidity suite.
4. Before/after (delta) properties, liveness ("can always withdraw") and
   round-trips are not expressible — `dsl: null` in the property plan; they
   live in the Solidity suite only.

## A4. Observed limits of the native path (truent 0.6.0)

State these instead of working around them silently:

- **Constructor arguments are not supplied.** A contract whose constructor
  takes parameters stops with `could not deploy the contract in the in-memory
  EVM: constructor reverted … The constructor takes N argument(s) and the
  fuzzer deploys with none`. Add a no-argument
  wrapper contract in the *same file* (`contract TokenFuzz is Token { constructor() Token(1000) {} }`)
  and fuzz that file.
- **Imports are not resolved.** The engine compiles a temporary copy of the
  file, so `import "./X.sol"` fails with `Source ... not found`. Fuzz
  single-file sources, or flatten first (`forge flatten`).
- **`--dynamic` is EVM and Solana only.** `--chain move` and `--chain soroban`
  return the engine error `--dynamic fuzzing currently only supports --chain evm (Move/Soroban need their own execution backends, not yet built)`.
  See Section D.

## A5. Deployed / unverified targets (no source)

```bash
truent fuzz --dynamic --chain evm --address 0x<contract> --rpc-url <https-endpoint>
```

Truent fetches the runtime bytecode, probes it against known ERC20/Ownable
selectors and fuzzes the confirmed surface. It does **not** fork on-chain
storage — it exercises the contract's own accounting logic from a fresh
state. Say so in the report. `--invariants` works here too when the bound
getters are among the probed selectors.

## A6. Quick harness for one contract (no agents)

When the team wants an Echidna/Medusa harness for the *auto-detected* shapes
only, skip Section B and run:

```bash
python3 $SKILL_DIR/scripts/emit_harness.py \
  --contract <ContractName> --path <path/to/Contract.sol> \
  --props conservation,supply-monotonic,owner-stable --actors 3 \
  --suite-dir test/fizz --meta-dir fizz_data
```

It writes `test/fizz/TruentHarness.sol` plus `echidna.yaml` / `medusa.json`
at the project root (same layout Section B uses) with one marked `TODO` for
deployment. Results from those runners are `EXTERNAL`.

---

# Section B — Suite generation (fizz-grade Echidna/Medusa suite)

Generate a stateful Solidity fuzz suite under `{SUITE_DIR}` (default
`test/fizz/`) with metadata and runtime files under `{META_DIR}` (default
`fizz_data/`). Echidna and Medusa run the campaigns; Foundry compiles, smoke
tests and reproduces. Their results are `EXTERNAL`; the native cross-check in
Step 9f upgrades DSL-expressible violations to `VERIFIED-PROVEN`.

## Workflow rules

- Follow the steps in order. Do not skip forward if a required artifact for
  the current step does not exist yet.
- If a step fails, stop there and report the blocker. If tooling is missing,
  say exactly what was attempted and what is missing.
- Keep the generated Solidity under `test/fizz/` and metadata under
  `fizz_data/` unless the user asks for different paths.
- Reuse existing project setup and test logic; never invent a deployment
  flow the repo already has.
- Never clone external repositories to obtain analysis inputs.

## Parameters

- `PROJECT_ROOT`: user-provided path, else the current working directory.
- `SUITE_DIR`: `test/fizz` (pass `--suite-dir` to suite scripts).
- `META_DIR`: `fizz_data` (pass `--meta-dir` to metadata scripts).
- Optional contract arguments narrow handler generation to specific contracts.
- `--no-invariants` skips Step 9 only.
- `--guided` / `--automatic` selects `{MODE}`; `--max` / `--opus` /
  `--sonnet` selects `{AGENT_MODEL}`.

## Run mode `{MODE}`

- `guided` — pause at: Step 3 (extra docs), Step 4 (browser picker), Step 4.5
  (cost confirm), Step 6 (Setup Review), Step 8 (per-cycle coverage decision),
  Step 9c (property review), Step 10 (fuzzer choice).
- `automatic` — never pause: Step 4 runs `--auto`, Step 8 caps at 3 cycles,
  Step 10 defaults to Medusa, the cost estimate is printed but not gated.

Resolve once from the invocation (`--guided` / "walk me through" / "let me
review" → guided; `--automatic` / `--auto` / "run the whole thing" / "no
prompts" → automatic). If unresolved, ask after the banner. Never switch
modes mid-run.

## Subagent model `{AGENT_MODEL}`

All spawned subagents (Step 3 fallback Protocol Analyzer, the 5 discovery
agents, the Synthesizer, the 2 Implementers, the Report Writer) default to
**sonnet**; `--max` / `--opus` / "max quality" → **opus**. Resolve once; never
mix tiers within a run. The parent agent is whatever the session runs.

**Selection prompt (only for values still unresolved).** After the banner,
with **no intervening text**, ask via a single `AskUserQuestion` call:

- `header: "Run mode"` — "Automatic (Recommended): run end-to-end with no
  prompts" / "Guided: pause at 7 checkpoints".
- `header: "Subagent model"` — "Sonnet (Recommended)" / "Opus (~10× cost,
  same as --max)".

Then print `Mode: <guided|automatic>` and `Subagent model: <sonnet|opus>`.

## Step 1: Verify tooling

1. Read `$SKILL_DIR/references/template-map.md`.
2. `forge --version` — if it fails, Foundry is missing: point at
   `https://www.getfoundry.sh/introduction/installation` and **stop**.
3. `bash $SKILL_DIR/scripts/ensure_foundry.sh {PROJECT_ROOT}` — creates a
   `foundry.toml` (Hardhat-aware) and installs `forge-std` if missing. Stop on
   error.
4. `medusa --version` — required; if missing point at the Medusa install docs
   (`https://secure-contracts.com/program-analysis/medusa/docs/src/getting_started/installation.html`) and **stop**.
5. `echidna --version` — optional; if missing continue but keep the
   recommendation in the final summary.
6. `node --version` — must be 18+. The scripts have no npm dependencies.

## Step 2: Compile and extract

1. Read `{PROJECT_ROOT}/foundry.toml`.
2. `cd {PROJECT_ROOT} && forge build`.
3. `node $SKILL_DIR/scripts/extract_abis.js {PROJECT_ROOT} --meta-dir {META_DIR}`
   → `{META_DIR}/contracts.json` (the contract/function inventory).

## Step 3: Understand the protocol

If `{MODE} = guided`, first ask: *"Any additional docs, links, whitepapers,
spec files, or prior-audit notes I should consider? (paths or URLs, or
'none')"*. Write anything given to `{META_DIR}/additional-context.md`, one
entry per line, URLs verbatim. Later sub-steps and Step 9a fold it in.

Acquire the protocol-understanding source in this order — record each attempt
and its outcome in `{META_DIR}/understanding-attempts.md`:

1. **`{PROJECT_ROOT}/recon/recon.md` exists** (written by `truent-recon`) →
   read it as the primary source. Its §3 entry-point table feeds Step 4, its
   §4 invariant table (with `held` / `BROKEN + PoC` engine results) feeds Step
   9. A `BROKEN` row there is already `VERIFIED-PROVEN`; carry it forward as a
   confirmed finding, not a candidate.
2. Otherwise **invoke the skill**: `Skill('truent-recon', args="{PROJECT_ROOT}")`.
   Only a runtime "skill not found" / "unknown skill" counts as unavailable.
   If it runs and writes `recon/recon.md` → SUCCESS.
3. Otherwise, in guided mode ask: *"Could not obtain recon/recon.md. (a) paste
   a path, (b) authorise the Protocol Analyzer fallback, (c) abort."* In
   automatic mode record `SKIPPED: automatic mode` and continue.
4. **Protocol Analyzer fallback.** Read `$SKILL_DIR/agents/protocol-analyzer.md`,
   substitute `{SKILL_DIR}`, `{PROJECT_ROOT}`, `{META_DIR}`, spawn as a
   `general-purpose` agent with `model: "{AGENT_MODEL}"`. It writes
   `{META_DIR}/protocol-understanding.md`.

Do **not** clone any repository to obtain a recon skill.

From the source obtained, summarise: deployment order; constructor parameter
meaning; required post-deploy initialisation; actor roles and permissioned
actions; approvals/liquidity/state needed before handlers are useful; real
entry points vs internal plumbing; candidate invariants for Step 9. Keep
ambiguity as a targeted TODO, not a broad guess. Do not plan ghost layouts or
snapshot structs here.

## Step 4: Select entry points

Read `$SKILL_DIR/references/selection-policy.md`. Build the preselection from
Step 3 (recon entry-point table first, then source-level access control).
Use `contracts.json` only as the structural template. Then:

- automatic: `node $SKILL_DIR/scripts/select_functions.js {PROJECT_ROOT} --contracts {PROJECT_ROOT}/{META_DIR}/contracts.json --selection {PROJECT_ROOT}/{META_DIR}/entry-point-selection.json --meta-dir {META_DIR} --auto`
- guided: same command without `--auto` — it opens a local browser picker
  with the inferred selection pre-checked.

Read back `{META_DIR}/entry-point-selection.json`; stop if it was not written.
Print selected contracts, selected functions per contract, notable exclusions.

**Dispatcher tiers.** Classify each selected function as `"tier": "primary"`
(deposit/withdraw/mint/redeem/borrow/repay/swap/stake/unstake/claim/liquidate)
or `"tier": "secondary"` (admin setters, pause/unpause, role grants, parameter
tuning) and write the field into `entry-point-selection.json`. Step 7 wraps
secondary functions behind one enum-selector dispatcher so they are exercised
but do not dominate sequences. The selection limits handler generation only,
not the setup dependency graph.

## Step 4.5: Cost estimate

`node $SKILL_DIR/scripts/estimate_cost.js {PROJECT_ROOT} --meta-dir {META_DIR} --model {AGENT_MODEL} --mode {MODE}`
writes `{META_DIR}/cost-estimate.md` (list-price ballparks per stage). Print
it. Guided: ask *"Proceed with this estimate, or abort?"*. Automatic: continue.

## Step 5: Generate scaffold

`node $SKILL_DIR/scripts/generate_suite.js {PROJECT_ROOT} --suite-dir {SUITE_DIR} --meta-dir {META_DIR}`

Copies `$SKILL_DIR/templates/evm/` into `{SUITE_DIR}/` (core harness files,
`utils/` including `MockERC20.sol`), writes `echidna.yaml` and `medusa.json`
at `{PROJECT_ROOT}/`, and generates one stub `handlers/<Contract>Handler.sol`
per selected contract plus the `Handlers.sol` aggregator. The copied files are
a starting point only.

## Step 6: Modify core files and wire setup

Read `$SKILL_DIR/references/setup-playbook.md` and
`$SKILL_DIR/references/template-map.md`. Wire `Base.sol::setup()` (deployment
order, constructor args, proxies, mocks vs real dependencies, actors, seeded
balances, roles, approvals). Prefer `utils/MockERC20.sol` for simple external
tokens unless the project has a more faithful mock.

Guided: before `forge build`, print a **Setup Review** block — contracts
deployed (name, address variable, constructor-arg source); proxies and their
implementations; mocks vs real with reasons; actors and roles; seeded
balances; role grants; approvals — then ask *"Setup looks right? Reply
'proceed' to build, or tell me what to adjust."* Loop until approved.

Run `cd {PROJECT_ROOT} && forge build`.

## Step 7: Generate handlers

Read `$SKILL_DIR/references/handler-patterns.md`. Run
`node $SKILL_DIR/scripts/generate_handlers.js {PROJECT_ROOT} --suite-dir {SUITE_DIR} --meta-dir {META_DIR}`
to pre-populate signatures and type mappings, then read `Handlers.sol`, every
`<Contract>Handler.sol` and every selected source in parallel and refine:
clamped vs unclamped layers, caller context (`asActor` / `asAdmin` / role
modifiers), semantic clamping via `utils/Clamp.sol`, donation handlers,
boundary-value stress variants (near-zero, full-amount, type-boundary), the
secondary-tier dispatcher. Update `Handlers.sol` to inherit all handlers.
`forge build` and fix.

## Step 8: Reach coverage with Medusa

**8.0 via-IR handling.** If `foundry.toml` sets `via_ir = true`, run
`bash $SKILL_DIR/scripts/setup_fuzz_profile.sh {PROJECT_ROOT}`. It appends a
`[profile.fuzz]`; last line is `FUZZ_PROFILE=no-ir` (accurate coverage),
`FUZZ_PROFILE=ir-no-opt` (lower targets ~10%) or exit 1 (default profile,
lower targets 15–20%). Record the mode at the top of
`{META_DIR}/coverage-targets.md` and set `{FUZZ_BUILD_CMD}` to
`FOUNDRY_PROFILE=fuzz forge build` (or plain `forge build`).

**Runs.** Every Medusa run in this step goes through the wrapper, launched
asynchronously with the agent's command runner (no `&`, no `sleep`+`tail`):

```
node $SKILL_DIR/scripts/run_medusa.js {PROJECT_ROOT} --meta-dir {META_DIR} --coverage-mode
```

`--coverage-mode` runs `medusa fuzz --timeout 300`, allows ≥60 s, stops when
`branches hit` plateaus for 5 status lines, and prints the coverage report
path. The wrapper prints a local log-viewer URL (add `--logs` only if the user
wants the browser opened).

**Targets** (use the column for the via-IR mode):

| Contract role | no-ir | ir-no-opt | ir fallback |
|---|---|---|---|
| Core protocol logic | 80%+ | 70%+ | 65%+ |
| Access control / roles | 60%+ | 50%+ | 45%+ |
| Peripheral helpers | 50%+ | 40%+ | 35%+ |
| Libraries / math | inherited | inherited | inherited |

Write per-contract targets and skip justifications (fork-only branches,
contract-only guards, timelocks, unmocked externals) to `coverage-targets.md`.
One cycle = run wrapper → inspect → adjust handlers/setup/clamps → rebuild.
After each cycle append a `## Cycle N` table (`Contract | Role | Target | Hit
| Status`). Automatic: loop to 3 cycles then proceed with gaps logged. Guided:
ask *"iterate / adjust targets / proceed"* after every cycle. Use
`FoundryTester.sol` to PoC why a handler misses a path. Do not proceed to
invariants with clearly insufficient coverage unless told to.

## Step 9: Generate invariants (5 discovery agents → synthesizer → 2 implementers)

Skip only with `--no-invariants`.

### 9a. Build `INVARIANT_CONTEXT`

Read `$SKILL_DIR/references/property-generation.md` (it carries the Truent
DSL mapping rules). Assemble: Step 3 invariant notes (`recon/recon.md` §4 or
`protocol-understanding.md`), `additional-context.md`, all in-scope sources,
`Base.sol`, `Snapshots.sol`, `Properties.sol`, all handlers. Extract
`AGGREGATE_VARIABLES` (`total*`, `sum*`, `accumulated*`), `PAIRED_OPERATIONS`,
`CONVERSION_FUNCTIONS` (`convertTo*`, `preview*`), `ACCESS_CONTROL`
(`onlyOwner`, `onlyRole`, `require(msg.sender`), and `ZERO_ARG_GETTERS` (the
public no-arg views per contract — the DSL can bind only these).

### 9b. Spawn 5 discovery agents in ONE message

| Agent | File | Approach |
|---|---|---|
| Conservation Auditor | `$SKILL_DIR/agents/invariant-discovery/conservation-auditor.md` | sum-of-parts = tracked whole |
| Round-Trip & Rounding Analyst | `$SKILL_DIR/agents/invariant-discovery/roundtrip-rounding-analyst.md` | forward+inverse, directional rounding |
| State Transition Mapper | `$SKILL_DIR/agents/invariant-discovery/state-transition-mapper.md` | postconditions, monotonicity, state machine |
| Adversarial Profit Maximizer | `$SKILL_DIR/agents/invariant-discovery/adversarial-profit-maximizer.md` | DoS, extraction, edge states |
| Protocol-Type Specialist | `$SKILL_DIR/agents/invariant-discovery/protocol-type-specialist.md` | vault/lending/AMM/… templates |

Substitute `{INVARIANT_CONTEXT}`, `{FILE_PATHS}` and `{CHAIN}` (`evm` here),
spawn each as `general-purpose` with `model: "{AGENT_MODEL}"`. Each property
they emit carries `CHAIN`, `DSL` (a Truent `.invar` expression when
expressible, else `null`), `GUARANTEE` and `PRIORITY`.

### 9c. Synthesize

Read `$SKILL_DIR/agents/invariant-discovery/synthesizer.md`, substitute
`{AGENT_OUTPUTS}`, `{META_DIR}`, `{PROJECT_ROOT}`, `{SUITE_DIR}`, `{CHAIN}`,
spawn with `model: "{AGENT_MODEL}"`. It writes:

- `{META_DIR}/property-plan.md` — implementation tables with stable Spec IDs
  (`GL-NN`, `SP-NN`), ghost/snapshot/wiring plans, a `DSL` column;
- `{META_DIR}/property-plan.json` — the same plan, chain-neutral and
  machine-readable: one object per property with `id`, `name`, `chain`,
  `scope`, `category`, `guarantee`, `evidence`, `priority`, `english`, `dsl`
  (string or `null`), `contract`, `after`. Section D's
  `emit_solana_plan.py` reads this file;
- `{PROJECT_ROOT}/PROPERTIES.md` — the English spec with `[ ]` checkboxes,
  category, guarantee (+evidence), priority, scope, sources, and `DSL:` line;
- `{META_DIR}/properties.invar` — every property whose `dsl` is non-null,
  as `invariant GL_NN_<name> { expr }`, for the primary target contract (and
  `{META_DIR}/properties.<Contract>.invar` per additional contract, because a
  file may only reference getters that bind on the contract it runs against).

Print "Generated X properties (N HIGH/MEDIUM/LOW; P SHOULD-HOLD, Q
EXPLORATORY; D expressible in the Truent DSL)". Guided: pause — *"Review
`PROPERTIES.md`, edit freely, keep Spec IDs, leave `[ ]` unchanged. Reply
'proceed' or 'regenerate'."* Re-spawn the synthesizer on `regenerate`.

### 9d. Implement (2 agents in parallel)

| Agent | File | Scope |
|---|---|---|
| Global Property Implementer | `$SKILL_DIR/agents/implementers/global-property-implementer.md` | ghosts in `Base.sol`, `State` in `Snapshots.sol`, `property_*` public functions |
| Specific Property Implementer | `$SKILL_DIR/agents/implementers/specific-property-implementer.md` | internal `property_*` functions + handler wiring |

Substitute `{META_DIR}`, `{SKILL_DIR}`, `{PROJECT_ROOT}`, `{SUITE_DIR}`,
`{CHAIN}`; spawn both with `model: "{AGENT_MODEL}"`. Both flip `[ ]` → `[x]`
in `PROPERTIES.md` for what they implement and `[ ]` → `[-]` for what they
skip; every property function carries the `/// @notice GL-NN:` / `SP-NN:`
doctag.

### 9e. Validate

`{FUZZ_BUILD_CMD}`; fix compile errors. Prefer a commented TODO over a brittle
assertion for low-confidence properties.

### 9f. Native cross-check (upgrades evidence)

Run the DSL file(s) through the native fuzzer against each target contract
(flattened single file, no-arg constructor — see A4):

```bash
truent fuzz <Contract.sol> --dynamic --chain evm --iterations 1000 --seed 1 \
  --invariants {META_DIR}/properties.invar
```

- A **bind error** names the identifier; fix the `.invar` (wrong getter name)
  or set that property's `DSL:` to `null` in `PROPERTIES.md` and re-emit. Do
  not delete the Solidity property.
- A **violation** here is `VERIFIED-PROVEN` with a minimal reproduction —
  record it in `{META_DIR}/native-findings.md` now; Step 11 reports it ahead
  of any campaign result.
- `no violation found` is not proof; it is one more seed of evidence.

## Step 10: Run campaigns

Fuzzer: automatic → **Medusa**; guided → ask *"Medusa (default, parallel
workers) or Echidna?"*. Never run both simultaneously. Launch asynchronously:

```
node $SKILL_DIR/scripts/run_medusa.js  {PROJECT_ROOT} --meta-dir {META_DIR} --timeout 600
node $SKILL_DIR/scripts/run_echidna.js {PROJECT_ROOT} --meta-dir {META_DIR} --timeout 600
```

If Echidna reports `unlinked libraries detected in bytecode`, add to
`echidna.yaml`: `deployContracts: [["0xf1", "Lib1"]]` and
`cryticArgs: ["--compile-libraries=(Lib1,0xf1)"]`.

**Interpret.** For each violation: extract the call sequence; rule out a
harness/property bug first (fix and rerun); then triage by guarantee tag —
SHOULD-HOLD violated = confirmed bug; EXPLORATORY violated = human-review
lead. Every campaign result is `EXTERNAL`. If the violated property has a
non-null `DSL`, re-run Step 9f on that contract: a native reproduction
upgrades it to `VERIFIED-PROVEN`. Document property name, guarantee, evidence
tag, sequence, state at failure. No violations → report clean with coverage
achieved. Afterwards offer the other fuzzer, a longer timeout, or handler
reshaping.

## Step 11: Validate and report

1. `{FUZZ_BUILD_CMD}`; 2. `cd {PROJECT_ROOT} && FOUNDRY_PROFILE=fuzz forge test --match-contract FoundryTester`
(drop the profile variable if none). Fix specific files; max 3 repair cycles.

**Violation repros.** Only when `{META_DIR}/corpus_medusa/test_results/`
holds violation JSON or the Echidna log has `failed!` sequences. For each
distinct violated property (shortest sequence): add
`test_repro_<propertyName>()` to `FoundryTester.sol`, replay handler calls
from `methodSignature`/`inputValues`, advance with `vm.roll`/`vm.warp` by the
per-call delays, map senders `0x10000/0x20000/0x30000` → `actors[0..2]`.
Global (`property_*` returning bool): replay then
`assertFalse(property_x(), "should be violated")`. Inline assertions
(`assert()`/`t()` inside handlers): wrap the violating call in
`try this._repro_helperN() { revert("assertion should have fired"); } catch {}`.
Run `forge test --match-contract FoundryTester -vvv`; max 2 fix attempts,
then comment the body with `// TODO: manual repro needed`. A passing repro is
`EXTERNAL` (Foundry executed it); the native 9f reproduction, when it exists,
is the `VERIFIED-PROVEN` line and is listed first.

**Report.** Read `$SKILL_DIR/agents/report-writer.md`, substitute
`{SKILL_DIR}`, `{PROJECT_ROOT}`, `{META_DIR}`, `{SUITE_DIR}`, spawn with
`model: "{AGENT_MODEL}"`. It writes `{META_DIR}/report.md`, prints it inline,
and reminds the user of the manual commands (`medusa fuzz`,
`echidna . --contract FuzzTester --config echidna.yaml`,
`truent fuzz <Contract.sol> --dynamic --chain evm --invariants fizz_data/properties.invar`).

**Snapshot.** `node $SKILL_DIR/scripts/fizz_sync.js {PROJECT_ROOT} --init --meta-dir {META_DIR} --suite-dir {SUITE_DIR}`
(or `--refresh-snapshot` if `last-run.json` exists) so `truent fuzz sync` can
detect drift later.

---

# Section C — Sub-commands

## `truent fuzz convert [GL-01 SP-03 …]`

Turn `[ ]` entries of `PROPERTIES.md` into Solidity in the existing harness
and flip their checkboxes, honouring the checkbox × doctag action matrix
(implement / regenerate / drop / drift-warn / skip). Also refresh the `.invar`
file for any converted property with a non-null `DSL:` line. Follow
`$SKILL_DIR/references/convert.md` exactly.

## `truent fuzz sync [--init|--apply|--only C|--no-property-quarantine]`

Reconcile a generated suite with a changed source tree without re-running
the pipeline: refresh ABIs, diff against `{META_DIR}/last-run.json`,
regenerate only drifted handler stubs (with `.pre-sync.bak` backups),
quarantine stale properties (`[x]` → `[~]`), rebuild, refresh the snapshot.
Follow `$SKILL_DIR/references/sync.md` exactly; the script is
`$SKILL_DIR/scripts/fizz_sync.js`.

---

# Section D — Other chains

Run the Step 9 discovery agents and synthesizer for these chains too, with
`{CHAIN}` set accordingly; the property plan is chain-neutral (each property
carries `chain`, `dsl`, `guarantee`, `priority`). What changes is the target
the implementers write to. Read the chain guide before implementing.

## Solana — plan-driven fuzzing (validated today, executed when the backend ships) + Anchor tests (`EXTERNAL`)

Guide: `$SKILL_DIR/references/chains/solana.md`. Truent's only Solana dynamic
path is:

```bash
truent fuzz <anchor-idl.json> --dynamic --chain solana --plan plan.json
```

The IDL describes instructions; `plan.json` describes the world — genesis
accounts, signer/writable/readonly pools, pins, and the invariants (schema in
`crates/dynamic/solana/src/config.rs`). Without `--plan` the engine errors:
`--dynamic --chain solana requires --plan <plan.json>`. A plan with no
invariants is rejected. Two invariant types exist:

- `token_conservation` — `sum(token account amounts) == mint supply`
  (`mint`, `token_accounts[]`, `amount_offset`, `supply_offset`; SPL Token
  layout: amount at byte 64 of a token account, supply at byte 36 of a mint);
- `account_owner` — an account's owner program never changes.

**Release status (truent 0.6.0, observed — not a claim).** The engine parses
the IDL and the plan, reports the fuzzable instruction count, then stops:

```
Error: IDL and plan are valid (2 fuzzable instruction(s)), but this release cannot execute them.

Running real Solana bytecode needs an in-process Solana VM, whose dependencies currently carry unpatched security advisories. Truent will not ship known-vulnerable crypto, so the dynamic Solana backend is deferred to a later version.
```

So today a Solana plan is **validated, not run**: there is no
`VERIFIED-PROVEN` Solana evidence yet. Available evidence is `truent scan
--chain solana` (`VERIFIED-STATIC`) plus the Anchor harness (`EXTERNAL`).
Still build the plan — it is exactly the input the backend takes when it
ships, and the validation step already catches bad pubkeys, bad hex, unknown
invariant types and empty invariant lists.

Build the plan from the IDL and the synthesized properties:

```bash
python3 $SKILL_DIR/scripts/emit_solana_plan.py \
  --idl target/idl/<program>.json --properties fizz_data/property-plan.json \
  --accounts fizz_data/solana-accounts.json --out fizz_data/plan.json
```

The script maps conservation properties → `token_conservation` and
authority-stability properties → `account_owner`; every other property is
reported as `unmapped` and becomes an Anchor `#[test]` /
`solana-program-test` harness (`EXTERNAL`, see the guide's skeleton). Real
pubkeys come from `--accounts` (the IDL has none); the script refuses to
write a plan with zero invariants, matching the engine. Example plan:
`$SKILL_DIR/templates/solana/plan.example.json`.

## Move (Aptos, Sui) — Truent verifies statically only

Guide: `$SKILL_DIR/references/chains/move.md`. There is **no** Truent dynamic
backend for Move (`--dynamic --chain move` is an engine error). Truent's
contribution is `truent scan --chain move` (`VERIFIED-STATIC`). The
synthesized properties become:

- **Aptos**: Move Prover `spec` blocks (`invariant`, `aborts_if`, `ensures`)
  and `#[test]` / `#[expected_failure]` unit tests — `aptos move prove`,
  `aptos move test`. A prover result is `EXTERNAL` (a proof, but not Truent's).
- **Sui**: `#[test]` / `#[expected_failure]` with `sui::test_scenario` —
  `sui move test`. `EXTERNAL`.

Skeletons: `$SKILL_DIR/templates/move/aptos_invariants.move`,
`$SKILL_DIR/templates/move/sui_invariants.move`.

## Soroban — Truent verifies statically only

Guide: `$SKILL_DIR/references/chains/soroban.md`. No Truent dynamic backend
(`--dynamic --chain soroban` is an engine error); `truent scan --chain
soroban` is `VERIFIED-STATIC`. Properties become a Rust `#[cfg(test)]` module
using `soroban_sdk::testutils` (`Env::default()`, `mock_all_auths`,
`Address::generate`, `Ledger` manipulation) and `proptest` strategies for
input-shaped properties — `cargo test`, `EXTERNAL`. Skeleton:
`$SKILL_DIR/templates/soroban/invariants_test.rs`.

## Where a chain has no analogue

Say so instead of pretending. Specifically: Medusa/Echidna coverage loops,
`FoundryTester` repros, `via_ir` handling and `fizz_sync.js` drift detection
are EVM-only; the `.invar` DSL binds to EVM getters only (Solana properties go
into the plan, Move into `spec`, Soroban into Rust tests); `--address/--rpc-url`
bytecode fuzzing is EVM-only; Solana has no user-DSL — only the two plan
invariant types — and in 0.6.0 the plan is validated but not executed; Move
and Soroban have no Truent dynamic verification at all.

---

## Why native-first

A harness generator's output is only as correct as the handlers and ghost
accounting an LLM wrote for it, and it still needs Echidna/Medusa/Foundry
installed and configured. Truent's native fuzzer removes all of that from the
default path — invariants detected or stated in a five-line DSL, sequences
generated, the counterexample shrunk, deterministically, in one binary — and
you still get the full suite on demand, with the same properties checked both
ways.
