---
name: truent-recon
description: "Pre-audit reconnaissance for a smart-contract codebase, engine-verified. Produces a recon/ folder (recon.md readiness report with threat model, entry-point map, full invariant map, architecture diagram, git-history risk mining, test and doc gaps, verdict) and, unlike a report-only recon, feeds the synthesized invariants into Truent's compiled engine so checkable items come back already checked and the engine's own findings, STRIDE model and exposure chains are part of the map. Multi-chain: EVM, Solana, Move (Aptos, Sui), Soroban. Triggers on 'truent recon', 'recon', 'x-ray', 'pre-audit', 'pre-audit report', 'audit readiness', 'readiness report', 'prep this protocol', 'protocol prep', 'summarize this protocol', 'map this codebase', 'where should I audit'."
license: MIT
metadata:
  version: "0.2.0"
  author: Emmyhack
  homepage: https://github.com/Emmyhack/Truent
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
    - x-ray
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

<!-- Adapted from pashov/skills x-ray/SKILL.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine integration, multi-chain. -->

# Truent Recon

Generate a `recon/` folder at the project root containing all output files. Pipeline: 3 phases, always sequential, with the engine woven into phases 1 and 2.

The idea that makes this different from a report-only recon: **every invariant you synthesize is handed to the engine before it is written down**. Machine-checkable items come back `held` or `BROKEN` with a PoC; the engine's own detector findings, STRIDE model and exposure chains are part of the map, not an appendix. Nothing is dressed up as proven that a machine did not prove.

`$SKILL_DIR` = the directory containing this SKILL.md file. Resolve it from the path you loaded this skill from.

## Evidence vocabulary (use in every output file, every table, every bullet)

| Tag | Meaning | Where it comes from |
|-----|---------|---------------------|
| `VERIFIED-PROVEN` | the engine **executed** it | `truent fuzz --dynamic` PoC (`✗ [PROVEN]`), `truent symbolic` counterexample, `truent probe` hit |
| `VERIFIED-STATIC` | a compiled detector matched; deterministic, not executed | `truent scan` violation (`evidence: "lead"` or `"proven"`) |
| `REASONED` | your inference from reading code | anything with no engine line to cite |
| `EXTERNAL` | a non-Truent tool's result | forge coverage, Move Prover, `cargo test`, Certora … |
| `(per spec)` | stated in a whitepaper/README, not confirmed in code | Step 1 spec extraction |

A claim without an engine line to cite is `REASONED`. Absence of a tag on a surface bullet means `REASONED`. A `held` fuzz result is `VERIFIED-PROVEN (negative)` for *that seed and iteration count* — say so. In truent 0.6.0 only EVM contracts can produce `VERIFIED-PROVEN` from `fuzz`; Solana plans validate but do not execute, Move/Soroban have no dynamic backend.

## Progress tracking (MANDATORY)

Before doing anything else, call TodoWrite with these 3 todos (all `pending`):

1. `Phase 1: Enumerate, measure, run engine ground truth`
2. `Phase 2: Read sources, classify entry points, synthesize + engine-check invariants`
3. `Phase 3: Write recon report files`

Transitions (update via TodoWrite — never batch):
- Mark Phase 1 `in_progress` immediately, before running `enumerate.sh`.
- When Step 1's parallel batch (including Step 1-engine) returns, in ONE TodoWrite call mark Phase 1 `completed` and Phase 2 `in_progress`.
- When Step 2 (including 2b–2h) finishes, in ONE TodoWrite call mark Phase 2 `completed` and Phase 3 `in_progress`.
- After all Step 3 output files are written and cleanup is done, mark Phase 3 `completed`.

Rule: exactly one todo is `in_progress` at any time.

## Step 0: Preflight (one message, parallel)

1. **Locate the engine** (Bash): prefer `truent` on PATH, else `target/release/truent`, else `target/debug/truent` walking up from `$SKILL_DIR` and from cwd. Run `truent doctor` and `truent --version`. If no binary exists, tell the user how to get it (`cargo install --path crates/cli` or `cargo build --release --bin truent`) and **continue without the engine** — every engine section of the report is then written as "engine did not run" and every claim is `REASONED`. Never fabricate engine output.
2. **Version check** (Bash): read `$SKILL_DIR/VERSION`, then `curl -sf https://raw.githubusercontent.com/Emmyhack/Truent/main/skills/truent-recon/VERSION`. If the fetch succeeds and the remote version is **greater** than local (compare as dotted integers), print `⚠ truent-recon <local> is older than <remote>; upgrade from https://github.com/Emmyhack/Truent for the latest detectors and templates.` If remote is equal or lower, or the fetch fails, say nothing.
3. **Print the banner** (below).

## Step 1: Enumerate & Measure

If the user specifies a path, use it as project root. Otherwise use cwd. If nothing chain-shaped is found at root, check one level deep.

**Chain and scope detection** (mixed repos are allowed — record every chain found):

| Signal | Chain | Source dir (first that exists) |
|--------|-------|-------------------------------|
| `foundry.toml` (`src = "…"`), `hardhat.config.*`, any `.sol` | `evm` | foundry `src`, else `src/`, `contracts/` |
| `Anchor.toml`, `#[program]` / `anchor_lang` / `solana_program` in `.rs` | `solana` | `programs/`, `src/` |
| `Move.toml`, any `.move` — `AptosFramework` dep → Aptos; `Sui` dep → Sui | `move` | `sources/` |
| `soroban_sdk` in `.rs` / `soroban-sdk` in `Cargo.toml` | `soroban` | `contracts/`, `src/` |

The `general` analyzer (secrets, CI, containers, app code) always applies — `truent scan --chain auto` picks every applicable engine per file, so you never choose.

**Run enumeration** (single Bash call — includes output directory creation):
```bash
mkdir -p [project-root]/recon && bash $SKILL_DIR/scripts/enumerate.sh [project-root] [src-dir-or-auto]
```
Sections: `Toolchain`, `Source dir`, `Source (with line counts)`, `Chains`, `nSLOC` (+ `TOTAL`), `NatSpec`, `doc_comments_rust_move`, `test_files`, `test_functions`, `test_functions_by_kind`, `stateless_fuzz`, `foundry_invariant`, `echidna`, `medusa`, `hardhat_fuzz`, `fork`, `certora`, `halmos`, `hevm`, `anchor_ts_tests`, `solana_fuzz`, `move_prover`, `move_expected_failure`, `soroban_tests`, `docs`, `commit`, `branch`, git stats. Multi-signal sections print `functions:configs`.

**Immediately after**, launch ALL of the following in a single message (parallel):

**1. Coverage** (`run_in_background: true`, one per toolchain present):
```bash
cd [root] && forge coverage 2>&1 || (echo "RETRYING_WITH_IR_MINIMUM" && forge coverage --ir-minimum 2>&1)   # foundry
cd [root] && npx hardhat coverage 2>&1                                                                      # hardhat
cd [root] && anchor test 2>&1                                                                               # anchor (no coverage %; pass/fail only)
cd [root] && cargo test 2>&1                                                                                # soroban / native solana
cd [root] && aptos move test --coverage 2>&1     # or: sui move test --coverage 2>&1                        # move
```
If the toolchain is not installed, this fails. Expected — test *existence* is already captured by enumeration. Coverage failure does NOT mean tests are absent. All of these are `EXTERNAL`.

**2. Git security analysis + JSON read** (foreground, single Bash call):
```bash
cd [root] && python3 $SKILL_DIR/scripts/git_security.py --repo . --src-dir [src-dir] --json recon/git-security.json 2>&1 && cat recon/git-security.json
```
Keys (documented at the top of the script): `meta` (incl. `git_branch`, `git_head`, `chains_detected`, `is_git_repo`), `repo_shape`, `fix_candidates` (commit-level, scored), `fix_prone_files`, `churn_hotspots`, `dangerous_area_changes`, `late_changes`, `forked_deps`, `tech_debt`, `dev_patterns`, `notes`. If the script fails, fall back to the bash git stats already in the enumerate output. Never block on a missing script.

**3. Preload reference files** (2 parallel Read calls — must be in context before Step 2d/3a):
- `$SKILL_DIR/references/threats.md` — protocol-type profiles, temporal threats, composability threats, **chain-specific threat dimensions** (Solana / Move-Aptos / Move-Sui / Soroban) with the engine detector ids that cover each pattern
- `$SKILL_DIR/references/templates.md` — recon.md template (with §4 Engine findings and §5 Exposure), entry-points template, invariant-map template, architecture guide

**4. Spec/whitepaper detection** (1 Glob: `**/{whitepaper,spec,design,protocol,architecture,overview,README}*.{pdf,md}` excluding `node_modules/`, `lib/`, `recon/`, `test/`, `target/`). Skip user-facing docs (tutorials, API refs, changelogs, contribution guides). Then apply size-aware handling:

- **Path A (≤5 docs, each ≤300 lines):** Include them as Read calls in Step 2's parallel message.
- **Path B (>5 docs OR any doc >300 lines):** Launch a single subagent (`model: "sonnet"`) that reads ALL doc files and returns a structured extraction (max 200 lines). Subagent prompt:
  ```
  Read each doc file listed below. Extract ONLY security-relevant information into this format:
  Files: [list of doc file paths]

  Return this exact structure:
  ### Doc-Stated Global Invariants
  [Bullet list of every invariant, constraint, or guarantee the docs claim must hold globally across calls. Routed by Step 2g to §2 / §3 / §4 of invariants.md by shape, NOT into §1.]
  ### Actor Definitions
  [Each actor/role with stated permissions and trust level — include upgrade authority / UpgradeCap / admin address if stated]
  ### Trust Assumptions
  [What the protocol assumes about external systems, oracles, admins, users]
  ### Cross-System Flows
  [How value/data moves between contracts/programs or external systems]
  ### Economic Properties
  [Fee structures, reward mechanisms, tokenomics, bounded parameters]
  ### Key Design Decisions
  [Explicit "we chose X over Y because Z" statements]

  Rules: Quote the source doc for each claim. Omit sections with no relevant content. Max 200 lines total.
  ```
  Include this subagent in Step 1's parallel message. Its output feeds Step 3.

For both paths, tag every spec-derived claim `(per spec)`. Doc-stated global invariants feed Step 2g's routing step — §2 / §3 / §4 of `invariants.md`, never §1.

### Step 1-engine: Engine ground truth (same parallel message, each best-effort)

Run these in the SAME message as coverage/git/reads. Each is independent; a failure of one does not block the others. Capture stderr — the exact error line is what you report.

```bash
cd [root] && truent scan . --chain auto --output json --file recon/engine-findings.json 2>&1; cat recon/engine-findings.json
cd [root] && truent threat-model . --format json --out recon/engine-threat-model.json 2>&1; cat recon/engine-threat-model.json
cd [root] && truent exposure . --format json 2>/dev/null > recon/engine-exposure.json; cat recon/engine-exposure.json
cd [root] && truent deps . --format json 2>/dev/null > recon/engine-deps.json; cat recon/engine-deps.json
cd [root] && truent registry list 2>&1
```

What each returns and what it is worth:
- **`scan`** → `{chain, duration_ms, summary{critical,high,medium,low,violations}, target, version, violations[]}`; each violation: `invariant_id, title, severity, chain, file, line, location, message, code_snippet, evidence("lead"|"proven"), exploitability, exploit_reasons[], fix, verify, cwe, swc[], owasp_sc[], dasp[], attack[], nist_csf[]`. Every row is `VERIFIED-STATIC`. `--chain auto` runs every applicable analyzer per file; scan a subdirectory only if the root scan is unusably slow, and say which paths were covered. If the user pointed you at a single file, scan that file.
- **`threat-model`** → STRIDE model from discovered routes, data stores, outbound calls, secret sources and auth markers (`entry_points, data_stores, outbound_calls, secret_sources, has_auth, has_authz, has_rate_limit, has_logging, has_validation, threats[]`). Repository-level — it complements your contract-level threat model (Step 3) and does not replace it. On a pure-contracts repo it is often empty; report that as a fact, not a finding.
- **`exposure`** → per-finding `exploitability` (`likely|possible|unlikely|theoretical`), `chains[]` (**completed** attack chains), `known_chains[]` (the 12 chain definitions the engine can recognise), `accepted[]`. Only `chains` is a result; `known_chains` is a capability list — never present one as the other.
- **`deps`** → `{advisory_count, advisory_source, findings[], lockfiles[], packages}` for Cargo / npm / pip / Go lockfiles; pass `--advisory-db DIR` if the user has one, `--sbom FILE` if they want an SBOM. Empty `lockfiles` on a Foundry-only repo is normal.
- **`registry list`** → 21 historical exploits each mapped to invariant ids. Use it in Step 3 to annotate scan rows whose `invariant_id` has a precedent (e.g. `evm_oracle_spot_price` → euler-finance-2023, gmx-2024).

If the binary is missing or a command errors, write the exact stderr line into the relevant report section and continue. Do not retry with flags that do not exist in `truent <cmd> --help`.

ALL calls (coverage, git analysis, reference reads, spec glob, engine batch) MUST appear in the same message. Proceed to Step 2 without waiting for coverage.

## Step 2: Read Source Files + Entry Point Scan (SINGLE message, ALL tool calls parallel)

CRITICAL: Every tool call — Bash, Agent, Read, Grep — MUST be issued in ONE message so they run concurrently. This includes source file reads, the entry point grep scans, and any spec doc detected in Step 1.

### Scope Filtering
- Skip interfaces: `interfaces/` dirs or filenames `I` + uppercase letter; Rust `trait`-only files; Move files that only declare `struct`s with no `fun`
- Skip vendored libs: Uniswap FullMath/TickMath, OZ copies, copied `anchor-spl` helpers, copied Move framework modules
- Skip generated code: Anchor IDL JSON, TypeScript clients, `target/`
- When uncertain, include it but exclude from scope table

### Path A: ≤20 source files (direct reads)
One Read call per file. Do NOT read README, docs, or toolchain config (already read in Step 1).

**Extract per file:** contract/program/module type & inheritance (or `use` deps), roles & access control, value-holding state, external calls (EVM calls, Solana CPIs, Move cross-module calls, Soroban `invoke_contract`/clients), fund flows, invariant comments, guards, backwards-compatibility indicators (see 2c), **delta writes** (per function: storage variables and the symbolic delta applied — e.g. `Δ(totalSupply) = +shares, Δ(balanceOf[msg.sender]) = +shares` — same-basic-block only, no cross-function inference; inherited/framework helpers like OZ `_mint`/`_burn`, `token::transfer`, `coin::deposit`, `balance::join` may be resolved only when their effect is semantically unambiguous), **guard predicates** (every `require`/`assert`/`if-revert`/`require!`/`assert!`/`abort`/`require_auth`/`panic!`-under-`if` that references persistent state, quoted verbatim with line number; skip guards that reference only function parameters), **enum/one-shot transitions** (every `require(state == X); …; state = Y` pair, recorded as `X@Lx → Y@Ly` — include one-shot latches like `require(addr == address(0)); addr = concrete`, Anchor `init`, Soroban `instance().has(&Admin)`, Aptos `pending_admin → admin`).

**Chain-specific extraction (in addition):**
- **Solana/Anchor:** for every `#[derive(Accounts)]` struct, each field's type (`Signer` / `Account<T>` / `AccountInfo` / `UncheckedAccount` / `Program` / `Sysvar`) and constraints (`has_one`, `constraint`, `seeds`, `bump`, `address`, `owner`, `init`, `init_if_needed`, `close`); every `invoke`/`invoke_signed`/`CpiContext` target; every `lamports` write; every sysvar read (`Clock::get()` vs `from_account_info`).
- **Move/Aptos:** every `borrow_global_mut<T>(@addr)` site and its signer check; every `move_to`; every function returning `signer` or a `*Cap`/`*Ref`; capability struct abilities; `#[randomness]` function visibility.
- **Move/Sui:** every `transfer::share_object` type; every `public fun` taking `&mut SharedType`; every capability struct's abilities (`key`/`store`); every struct returned from a `public fun` without `drop` (hot potato) or with it; every generic `<T>` on a value-moving function and how `T` is constrained; `UpgradeCap` handling.
- **Soroban:** for every `pub fn` in `#[contractimpl]`, which `Address` params get `require_auth()`/`require_auth_for_args` before the first storage write; each `DataKey` and its storage tier (`instance`/`persistent`/`temporary`); `extend_ttl` presence per persistent key; `update_current_contract_wasm` gate; `i128` ops checked or not.

### Path B: >20 source files (parallel subagents)

**Tier 1 — Small files (≤120 lines):** Batch into single Bash `cat` call.

**Tier 2 — Large files (>120 lines):** Group by subsystem. Launch **one subagent per subsystem** (`model: "sonnet"`, up to 5, max ~10 files each). Subagent prompt:
```
Read each file listed below and return a structured summary. Do NOT analyze — just extract facts.
Files: [list of file paths]
Chain: [evm | solana | move-aptos | move-sui | soroban]
For EACH file, return this exact format:
### [filename]
- **Type**: contract | library | abstract | program | module | soroban-contract
- **Inherits / uses**: [parent contracts, or `use` dependencies]
- **Roles/Access**: [onlyOwner, role constants, modifiers | Signer fields + has_one/constraint | signer checks / capability params / friend | require_auth targets]
- **State (value-holding)**: [mappings/vars/accounts/resources/objects/DataKeys that hold balances, collateral, etc. — for Soroban note the storage tier]
- **External calls**: [calls to other contracts, ERC20 transfers, CPIs, cross-module calls, invoke_contract]
- **Fund flows**: [deposit/withdraw/mint/burn/transfer paths]
- **Invariants**: [require/assert/require!/assert!/abort statements, doc-comment invariant claims]
- **Delta writes**: For EACH state-mutating function, list storage that changes and the symbolic delta. Format `Δ(var) = +expr` / `Δ(var) = -expr`. Only pairs where BOTH writes are in the same function body with no intervening unknown external call/CPI. Do NOT chase writes through inherited/imported functions unless the effect is unambiguous (OZ `_mint` → `balanceOf` + `_totalSupply`; `balance::join` → the Balance's value; custom helpers are NOT — list those in the helper's own entry). Example:
  - `deposit()`: `Δ(totalSupply) = +shares`, `Δ(balanceOf[msg.sender]) = +shares`
- **Guard predicates**: Every guard that references persistent state. Quote verbatim with line number. Skip guards that reference only parameters.
  - `Vault.sol:206`: `require(_fee <= 10, "fee is capped at 0.1%")`
- **Enum/one-shot transitions**: Every `require(var == X); ...; var = Y` pattern. Record as `X@Lx → Y@Ly`. Include one-shot latches.
- **Chain-specific**: [Solana: per Accounts struct, each field type + constraints; CPI targets; lamport writes. Move: borrow_global_mut sites + signer check; move_to targets; capability abilities; shared-object &mut params; hot potatoes; unconstrained <T>. Soroban: per pub fn, which Address gets require_auth; DataKey storage tiers; extend_ttl; upgrade gate.]
- **Key logic**: [1-2 sentences on what it does]
- **Function-level access map** (REQUIRED for contracts/programs/modules, skip for libraries):
  List every entry point (see chain rule) that mutates state with its access control:
  - `functionName()` — [gate, e.g. `onlyRole(OCT_KEEPER)` | `Signer authority + has_one` | `&AdminCap` | `admin.require_auth()`] or [NONE — permissionless]
  For functions with NO gate, also list which external calls/CPIs they make:
  - `functionName()` — NONE — calls `ContractName.method()`
Entry point rule: EVM external/public non-view; Anchor every pub fn in #[program]; Move public entry fun / entry fun / public fun; Soroban every pub fn in #[contractimpl].
```

### Entry Point Grep Scan (INCLUDED in the same parallel message as source reads)

Launch the relevant **Bash** calls for every chain present, in the SAME message as the source reads. Commands use **only POSIX ERE + POSIX character classes** (no `-P`, no `\s` `\w` `\b`), so they work identically on GNU grep, BSD grep (macOS `/usr/bin/grep`) and ripgrep.

**Solidity** (two greps, combine results):
```bash
# 1. Single-line signatures: function name and visibility on same line
grep -rnE 'function[[:space:]]+[[:alnum:]_]+[[:space:]]*\([^)]*\)[[:space:]]+(external|public)' [src-dir]/ --include='*.sol' \
  | grep -v '/interfaces/' | grep -v '/mock/' \
  | grep -Ev '(^|[^[:alnum:]_])(view|pure)([^[:alnum:]_]|$)'
```
```bash
# 2. Multiline signatures: visibility keyword on the closing-paren line (covers 90%+ of multiline cases)
grep -rnE '^[[:space:]]*\)[[:space:]]+(external|public)' [src-dir]/ --include='*.sol' -B5 \
  | grep -v '/interfaces/' | grep -v '/mock/' \
  | grep -Ev '(^|[^[:alnum:]_])(view|pure)([^[:alnum:]_]|$)'
```
The trailing `grep -Ev '(^|[^[:alnum:]_])(view|pure)([^[:alnum:]_]|$)'` is the POSIX-portable substitute for `\b(view|pure)\b`.

**Anchor / Solana** (instructions are `pub fn` taking `Context<…>` inside the `#[program]` module; the second grep catches multiline signatures where `ctx:` is on its own line):
```bash
grep -rnE 'pub[[:space:]]+fn[[:space:]]+[[:alnum:]_]+[[:space:]]*(<[^>]*>)?[[:space:]]*\([^)]*Context[[:space:]]*<' [src-dir]/ --include='*.rs' \
  | grep -v '/tests/' | grep -v '/target/'
grep -rnE '^[[:space:]]*(mut[[:space:]]+)?ctx[[:space:]]*:[[:space:]]*Context[[:space:]]*<' [src-dir]/ --include='*.rs' -B3 \
  | grep -E 'pub[[:space:]]+fn' | grep -v '/tests/'
# native (non-Anchor): the dispatch arms
grep -rnE 'entrypoint!|fn[[:space:]]+process_instruction|Instruction::[[:alnum:]_]+[[:space:]]*(\{|\(|=>)' [src-dir]/ --include='*.rs' | grep -v '/tests/'
```
Also grep the account structs — they carry the access control: `grep -rnE '#\[derive\(Accounts\)\]|Signer<|has_one[[:space:]]*=|constraint[[:space:]]*=|AccountInfo<|UncheckedAccount<|init_if_needed' [src-dir]/ --include='*.rs'`.

**Soroban** (every `pub fn` inside a `#[contractimpl]` block; then which of them call `require_auth`):
```bash
grep -rnE '#\[contractimpl\]' [src-dir]/ --include='*.rs' -A400 \
  | grep -E '^[^:]+-[0-9]+-[[:space:]]*pub[[:space:]]+fn[[:space:]]+[[:alnum:]_]+' \
  | sed -E 's/^([^-]+)-([0-9]+)-/\1:\2:/' | grep -v '/test'
grep -rnE 'require_auth(_for_args)?[[:space:]]*\(' [src-dir]/ --include='*.rs' | grep -v '/test'
```
(`-A400` is a window, not a guarantee — if an impl block is longer, read the file.) Exclude `#[cfg(test)]` modules and `fn`s that take only `env: Env` and return without a storage `set` — those are views.

**Move** (transaction entry points and composable public functions; `public(friend)` / `public(package)` and private `fun` are downstream):
```bash
grep -rnE '^[[:space:]]*(public[[:space:]]+entry[[:space:]]+fun|entry[[:space:]]+fun|public[[:space:]]+fun)[[:space:]]+[[:alnum:]_]+' [src-dir]/ --include='*.move' \
  | grep -v '/tests/' | grep -Ev '#\[(view|test|test_only)\]'
grep -rnE '#\[view\]' [src-dir]/ --include='*.move' -A2 | grep -E 'fun[[:space:]]+[[:alnum:]_]+'   # views to exclude
```
Sui: also `grep -rnE 'share_object|public_share_object|freeze_object|has[[:space:]]+key(,[[:space:]]*store)?' [src-dir]/ --include='*.move'` — shared types and capability abilities are the access model.

**Portability guarantees:** `-E -v -r -n -A -B`, `[[:space:]]`, `[[:alnum:]_]` → POSIX. `--include` → GNU + BSD + ripgrep (not busybox; substitute `$(find [src] -name '*.ext')` there).

ALL tool calls (source reads/Bash/subagents, ALL grep scans) MUST be in ONE message. Do NOT read test files or documentation files here.

### Step 2b: Entry Point Classification

Using the grep results already returned, classify ALL entry points. Do NOT rely solely on subagent summaries — subagents extract facts at the file level and can misattribute which function makes which call or has which gate.

**Exclude** from entry points: view/pure functions (`#[view]`, Soroban env-only readers, read-only Anchor instructions), interface/trait-only declarations, library internal functions, mocks, test-only code.

**For each result, classify into one of three categories.** You MUST verify the function body before classifying as permissionless — for Path A the bodies are in context; for Path B batch all candidate body reads into a SINGLE parallel message.

1. **Permissionless** — no gate AND no internal caller restriction. Chain semantics of "a gate":
   - **EVM:** a modifier, `require(msg.sender == X)`, `if (msg.sender != X) revert`, compound conditions, or an internal function that checks `msg.sender`. `nonReentrant` alone is NOT access control; `initializer`/`reinitializer` are one-time — track separately.
   - **Anchor:** the privileged account is `Signer<'info>` **and** bound to state via `has_one = …`, `constraint = … == …key()`, or `seeds` that include its key. A bare `Signer` with no binding means "any signer" → **permissionless (signature required)**; an `AccountInfo`/`UncheckedAccount` authority with no `is_signer` check → permissionless, and note it (this is the `sol_missing_signer` shape).
   - **Move/Aptos:** `assert!(signer::address_of(account) == stored_admin)`, a capability-typed parameter the caller must hold, or `friend` visibility. A `&signer` parameter by itself is NOT a gate — it just names the caller.
   - **Move/Sui:** a capability object parameter (`_: &AdminCap`), or `ctx.sender()` compared to stored state. A `public fun` taking `&mut SharedObject` with neither → permissionless (the `move_access_control_missing` shape). `&mut OwnedObject` is gated by ownership — record as role-gated (owner).
   - **Soroban:** `X.require_auth()` where `X` is read from storage (admin) or is the `Address` whose funds move (owner). A `pub fn` with no `require_auth` → permissionless (the `sor_missing_require_auth` shape).
2. **Role-gated** — has a role gate as defined above. Record which role/account/capability/address is required.
3. **Admin-only** — gated by `DEFAULT_ADMIN_ROLE`/`onlyOwner` pointing to the protocol admin; the stored admin or upgrade authority (Solana, Soroban); the `@module_addr` admin (Aptos); an `AdminCap`/`UpgradeCap` holder (Sui).

**For each entry point, record:**
- Contract/program/module name and function name
- Access level (permissionless / role name / admin) and the gate mechanism
- Caller (User, Keeper, Admin, LP, etc.)
- Parameters with trust level: `(user-controlled)`, `(user-signed)`, `(keeper-provided)`, `(protocol-derived)`
- Non-EVM: accounts / objects / Address params with their type, constraint and auth status
- Call chain: `→ Contract.fn() → Contract.fn()` (CPIs and cross-module calls included)
- State modified: which storage / accounts / resources / DataKeys change
- Value flow: `in`, `out`, `none`
- Reentrancy guard: yes / no / n.a. (runtime-blocked on Solana and Move; host-blocked by default on Soroban)

This data feeds the **permissionless entry points** in recon.md §2 (via pointer) and the full **entry-points.md** (Step 3).

### Step 2b-flow: Protocol Flow Path Construction

Using the entry point data already collected, construct flow paths for entry-points.md. Not a separate analysis pass — it reorganizes data you already have.

**For each major user-facing entry point** (permissionless and role-gated functions that move value):
1. Identify its guards and state checks
2. For each check, find which function WRITES that state (known from other entry points' "State modified")
3. Chain backwards: destination ← writer of its precondition ← … ← deployment/initialization
4. Note non-function preconditions (time passage, market conditions, an account/PDA existing, a TTL still live, an object being shared) with `◄──` annotations

**Output**: arrow chains grouped by actor flow, 15-30 lines. See the entry-points.md template.

The grep scan is a **hard gate**: the permissionless entry points in the report must match the grep-verified list. If there is a conflict, grep + code reading wins.

### Step 2c: Backwards-Compatibility Code Detection

While reading source, watch for remnants of a removed mechanism kept so the remaining codebase does not break: empty or trivial bodies, state declared but never meaningfully read or written, comments containing "deprecated" / "legacy" / "backwards compat" / "no longer used", functions implementing an interface/trait that always return a default, storage preserved solely for proxy layout / account layout compatibility, Anchor instructions kept for old clients, Soroban `DataKey` variants never read.

After reading ALL source files, cross-reference candidates against these **mandatory verification checks**. **Batch ALL caller-check Grep calls for all candidates into a SINGLE parallel message**:

1. **Caller check (REQUIRED)**: Grep to confirm NO active callers. If called from active code, it is the current design — not backwards-compat.
2. **Doc-comment check (REQUIRED)**: if NatSpec / `///` / inline comments explain WHY ("simplified for X mode", "by design", "intentionally zero"), it is documented intentional design. Do not override developer documentation with pattern matching.
3. **Interface obligation check**: a default-returning function that an interface/trait requires AND is actively called is current architecture.

Only classify as backwards-compatibility when ALL of: (a) no active callers, (b) no doc comments marking it intentional, (c) git history shows the mechanism it belonged to was removed. Note survivors in recon.md §1; omit the subsection if none survive.

### Step 2d: Centralization & Pause Coverage Analysis

Feeds the Actors table, Trust Boundaries, and Key Attack Surfaces (§2). NOT standalone sections.

**Centralization analysis** — for each privileged role (admin, owner, operator, keeper, upgrade authority, `UpgradeCap` holder, Soroban admin, `@module_addr` admin):
1. List every operational action the role can take (from the function-level access map)
2. For each, note whether a timelock, multisig, or delay exists. Distinguish role *transfer* delays from operational *action* delays — a transfer delay does not protect against a compromised holder using instant functions. Chain notes: Solana upgrade authority and Soroban `update_current_contract_wasm` are instant, whole-program replacements unless a governance contract or multisig holds them — whether one does is a **deployment** fact; write `could not determine` unless a deploy script, `Anchor.toml`, or README states it. Aptos `pending_*` + `effective_at` patterns are the timelock shape (`move_admin_no_timelock` fires when absent).
3. Identify which actions can extract or redirect user funds (`emergencyWithdraw`, `setTreasury`, `transferFee`, Solana `payout` from a treasury signed by a single keypair — `sol_treasury_single_authority`)

Cross-check against `recon/engine-findings.json`: `evm_single_eoa_admin`, `evm_insufficient_multisig_threshold`, `evm_missing_pause_mechanism`, `sol_admin_no_timelock`, `sol_treasury_single_authority`, `move_admin_no_timelock`, `move_admin_transfer_single_step`, `move_capability_transferred_to_caller`, `move_capability_with_store`, `sor_unprotected_upgrade`. Where a detector fired, the Actors-table cell says `(VERIFIED-STATIC: <id> @ file:line)`; where the code has the shape and the detector did not fire, say `(engine: no <id> match)` and keep your claim `REASONED`.

Integrate into: **Actors table** (instant vs timelocked), **Trust Boundaries** (what each boundary actually protects vs what bypasses it), **Key Attack Surfaces** ("Admin operational powers" / "[Role] compromise" — the surface is the role compromise, not individual functions).

**Pause coverage analysis** — for each critical state-changing function: is `whenNotPaused` (or a `paused` flag check / Sui `assert!(!pool.paused)` / Soroban `Paused` key) applied? Which are pausable vs not? A function that should logically be pausable but is not worsens the relevant role's compromise scenario — fold it into that surface. **Do NOT create a standalone "Centralization Risks" subsection.**

### Step 2e: Protocol Classification

Classify the protocol following `references/threats.md` (type detection + hybrid classification, phase detection, external call classification) **and** pick the chain dimension(s) from its Chain-Specific Threat Dimensions section for every chain in scope.

### Step 2f: nSLOC

Use the exact nSLOC `TOTAL` from the Step 1 enumerate output (no `~` prefix) in the report header and scope table. For mixed-chain repos, report per-chain sums from the per-file lines.

### Step 2g: Invariant Synthesis

Using the delta writes, guard predicates, transitions and invariant comments extracted in Step 2, systematically walk the taxonomy to produce invariant candidates. Reasoning pass — no new tool calls except the Grep batch in step 2 Pass B.

**Terminology**: A *guard* is a per-call precondition at a single callsite (`require(amount >= MIN)`, `require_auth()`, `assert!(fee <= MAX)`). Not a falsifiable invariant — the code guarantees it at that callsite. An *invariant* must hold globally across any sequence of calls ("every active position ≥ MIN"). Guards feed §1 of `invariants.md` only. Invariants *lifted* from guards or stated in doc comments feed §2 / §3 / §4.

**Doc-comment routing** (before the structural walk): for each NatSpec `@invariant`, `///` doc line, or inline comment asserting a global property, route DIRECTLY to §2 (or §3/§4 if it spans contracts or derives from multiple primitives) by shape (Conservation / Bound / Ratio / StateMachine / Temporal). Source tag `NatSpec: Contract.sol:LN` or `doc: file:LN`. Never into §1. Still run the structural scans — they confirm (On-chain=Yes) or contradict (On-chain=No) the claim.

**Walk order** (each step uses the raw extraction data, not prior-step conclusions):

1. **Conservation scan**: for each function, find delta-write pairs `Δ(A) = +expr` and `Δ(B) = -expr` (or `Δ(B) = +expr` for a mapping counterpart) in the same function body. Each pair is a conservation candidate: `A + B = const` or `A == Σ B[key]`.
   - Mapping writes paired with a scalar (`mapping[key] += e` with `scalar += e`) → infer `scalar == Σ mapping[key]`. Verify across ALL functions that write either variable — if ANY writes one without the other, note "partial conservation" and split into Yes/No rows. Chain forms: Anchor `vault.balance` vs the vault's lamports / token-account amount; Move `Balance<T>` joins/takes vs a tracked `total`; Soroban per-address `persistent()` entries vs a `TotalSupply` key.
   - Transfer patterns (`mapping[from] -= e`, `mapping[to] += e`, no scalar change) → mapping sum is self-conserving.
   - **Negative conservation**: a function that *ought* to track a flow (flashloan pull/push, receive/forward, a CPI that moves tokens with no local accounting) with zero storage Δ is itself a Conservation-negative finding.
2. **Guard extraction and lift** (two passes over each guard):
   **Pass A — Extract verbatim (§1)**: every guard becomes a `G-N` row with the predicate verbatim (in the source language) and location. Skip guards that only reference parameters with no storage tie-back AND no global implication.
   **Pass B — Lift, then check all write sites**: does the guard imply a property that must hold across any sequence of calls? If NO → §1 only. If YES → rewrite as a global property, then Grep ALL write sites of the constrained storage variable across scope files — **batch every write-site Grep for all lifted guards into ONE parallel message**:
   - ALL write sites enforce an equivalent guard → §2 Bound, On-chain=**Yes**.
   - ANY write site lacks it → §2 Bound, On-chain=**No**, cite the unguarded write site(s). **This is the high-signal output** — the gap is simultaneously an invariant and a potential bug.
   Include setter-level bounds. Auth guards lift too: `require_auth()` / `Signer` / `assert!(addr == admin)` on *some* writers of a resource but not all → On-chain=No (this is exactly the `sor_missing_require_auth` / `sol_missing_signer` / `move_access_control_missing` shape — cross-check the scan JSON and cite the id if it fired).
3. **Ratio scan**: each storage write of form `A = B * C / D` over storage or function-scoped snapshots of storage → record the ratio and snapshot ordering (before/after other writes). Note divide-before-multiply (`(a / b) * c`) — the `move_divide_before_multiply` / `evm_precision_loss` shape.
4. **State machine / one-shot scan**: each `require(var == X); … var = Y` → record the transition. Distinguish **one-shot latch** (no path back), **togglable flag** (another function flips it back — skip), **cyclic state** (timing-driven cycle — record).
5. **Temporal scan**: each `block.timestamp`/`block.number`/`Clock`/`timestamp::now_seconds()`/`env.ledger().timestamp()`/TTL comparison involving storage → extract the constraint; note checked-then-updated (safe) vs updated-then-checked (stale read). Soroban: a `persistent()` key read on a path with no `extend_ttl` is a temporal invariant "entry is live" with On-chain=No.
6. **Cross-contract scan**: each external call / CPI / cross-module call whose return is used in arithmetic or a storage write → record the caller's assumption, then find the callee's write sites for that state. If the callee can change it independently, the assumption is unvalidated → §3 with On-chain=No. ONLY rows where BOTH sides are in scope. Also include **setter-vs-invariant mismatches** (admin setter writes a value without checking existing invariants still hold).
7. **Economic derivation**: check whether combinations of §2 + §3 invariants imply a higher-order property. Each economic invariant cites the I-N / X-N it derives from; a gap (any source On-chain=No) makes it On-chain=No.

**Verification gate** (MANDATORY before including any inferred invariant):
- Conservation: confirm the Δ-pair exists at the cited lines (same function body).
- Guard (§1 row): confirm the predicate is verbatim from code.
- Guard lift (§2 row): confirm the lifted property references persistent storage; confirm all write sites were enumerated via Grep; confirm the On-chain verdict matches the enumeration — a row claiming Yes with an unguarded write site is invalid.
- Doc-comment: confirm the tag/comment exists verbatim at the cited location AND asserts a global property; per-call notes are dropped.
- Ratio: confirm the formula is exact and the snapshot ordering noted.
- StateMachine: confirm both sides of the edge exist AND no reverse path.
- Temporal: confirm the comparison involves storage, not only parameters.
- Cross-contract: confirm both caller usage AND callee write site exist in scope.
- Economic: confirm all referenced I-N / X-N are themselves verified.
- If you cannot verify → drop the row. "Could not verify" is not a valid row.

**Output**: candidates feed `invariants.md` (Step 3) — after Step 2h has stamped each with its engine verdict.

### Step 2h: Engine Invariant Checking (Truent addition — MANDATORY when the engine exists)

For every I-N / X-N / E-N that survived the gate, decide whether the engine can check its shape, run it, and record the result on the block. Batch all fuzz commands into ONE parallel message (one Bash call per contract file; `run_in_background: true` for more than ~5).

**EVM — auto-detected shapes.** `truent fuzz` deploys the contract in-memory (revm), drives call sequences, and auto-detects: ERC20 **conservation** (`sum(balanceOf) == totalSupply()` — needs ERC20-shaped `totalSupply()`/`balanceOf()` on the ABI), **monotonic accumulator** getters, **access control** (only the owner can change the owner), and **reentrancy**. If an I-N is one of those shapes:
```bash
truent fuzz <file.sol> --dynamic --chain evm --iterations 500 --seed 1
```
Interpret the output literally — these are the exact lines the engine prints:
- `✓ no violation found in N runs` → the block's Engine field is `held (engine, seed 1, N iters)`. `VERIFIED-PROVEN (negative)` for that seed/N only. It is valid **only if the auto-detected invariant is the same property as the block** — a `✓` for reentrancy does not make a conservation block `held`.
- `✗ [PROVEN] <file>` followed by `Invariant violated: …`, `Reproduction (N calls):` and `Failing step:` → Engine field `BROKEN — VERIFIED-PROVEN`. Paste the whole block verbatim into recon.md §4. This is a confirmed bug with a PoC before the audit starts; the matching attack surface in §2 points to it and does not re-describe it.
- `⚠ not analysed: no auto-detectable invariant on this ABI (looked for ERC20-shaped totalSupply/balanceOf, or monotonic accumulator getters) and no --invariants file supplied — nothing to check` → `not checkable by engine`, quote the reason. Then, if the property can be written as an expression over zero-argument views of the contract, write a `.invar` file (`invariant Name { total == sum_of_balances }` — each free variable binds to a zero-argument view of the same name; an unbindable variable is an error, never a silent skip) and re-run with `--invariants <file.invar>`. Record the second result the same way.
- `⚠ not analysed: solc failed …` → `not checkable by engine: solc failed (<first error line>)`. Try `SOLC_PATH` / `TRUENT_SOLC_VERSION` once if the error is a version mismatch; otherwise stop.
- an error `could not deploy the contract in the in-memory EVM … The constructor takes N argument(s) and the fuzzer deploys with none` → `engine could not deploy: constructor takes arguments`. Do not write a wrapper contract to work around it — that would be fuzzing your code, not theirs.
- a solc error about an import it cannot find → the fuzzer compiles a **temp copy** of the single file, so relative imports (`import "./Lib.sol"`) do not resolve → `engine could not deploy: relative imports`. Flattening is the user's call, not yours; note it as the actionable step.
- The fuzzer's own footer says it: *"when it cannot run, nothing was verified."* Never present a skip as a pass, and never write `held` for a contract that did not deploy.

**Solana — plan-based.** `--dynamic --chain solana` takes the program's Anchor IDL as `path` and **requires** `--plan plan.json` (the engine errors otherwise: `--dynamic --chain solana requires --plan <plan.json>`). The plan states genesis `accounts`, `signers`, `writable`, `readonly`, `pin`, optional `program_id`/`program_so`/`seed`/`runs`/`depth`, and `invariants`, of exactly two types:
```json
{ "invariants": [
  { "type": "token_conservation", "mint": "<pubkey>", "token_accounts": ["<pubkey>", "…"], "amount_offset": 64, "supply_offset": 36 },
  { "type": "account_owner", "account": "<pubkey>" }
] }
```
Write a plan only when an I-N is one of those two shapes (`Σ token-account amounts == mint supply`; "this account's owner never changes") and the genesis accounts are derivable from the tests or IDL. Then:
```bash
truent fuzz <target/idl/<program>.json> --dynamic --chain solana --plan recon/plan.json --iterations 500 --seed 1
```
**In truent 0.6.0 this validates and stops.** The engine prints `IDL and plan are valid (N fuzzable instruction(s)), but this release cannot execute them … the dynamic Solana backend is deferred to a later version.` So a Solana block's Engine field is `validated plan (execution deferred)` when that line appears, or `not checkable by engine` (plan rejected, or shape not one of the two) — **never `held` and never `BROKEN`**. A validated plan is worth keeping: it is the exact input a later release (or the `truent-fuzz` skill) runs. Every other Solana invariant is `not checkable by engine` (state the shape it would need). Delete `recon/plan.json` in cleanup unless a plan validated — then keep it and say so.

**Move and Soroban — no execution backend.** `truent fuzz --dynamic` **errors** for `--chain move` and `--chain soroban` (`--dynamic fuzzing currently only supports --chain evm (Move/Soroban need their own execution backends, not yet built)`). Say so once in recon.md §4, mark every Move/Soroban block `not checkable by engine`, and route: Aptos → Move Prover (`aptos move prove`) / `aptos move test`; Sui → `sui move test` (+ Sui prover if configured); Soroban → `cargo test` with `soroban_sdk::testutils`. If the toolchain is installed, run the protocol's own suite in the Step 1 coverage batch and fold pass/fail in as `EXTERNAL`; do not write new prover specs during recon.

**Static detectors as invariant evidence.** For every block whose *shape* a detector encodes (auth-lift gaps → `sol_missing_signer` / `sor_missing_require_auth` / `move_access_control_missing` / `evm_access_control`; conservation-negative → `evm_conservation_check_absent` / `move_liquidity_conservation`; ratio → `evm_precision_loss` / `move_divide_before_multiply`; temporal-TTL → `sor_storage_ttl_not_extended`; initializer latch → `evm_unprotected_initializer` / `sor_init_guard`), check `recon/engine-findings.json` for a violation at the block's location. A hit is cited in the block's `Engine check` line as `VERIFIED-STATIC: <id> @ file:line`; it does not change the Engine field (that is reserved for execution) but it upgrades the evidence on the matching §2 surface.

**Record on every block:** `Engine: held (engine, seed s, N iters)` | `BROKEN — VERIFIED-PROVEN` | `engine could not deploy: <reason>` | `validated plan (execution deferred)` (Solana only) | `not checkable by engine` | `EXTERNAL: <tool> <result>` | `not run` (engine missing), plus the `Engine check` line with the exact command or reason. In this release only EVM blocks can be `held` or `BROKEN`. Count them — the counts go in recon.md §3, §4 and the verdict's "Engine ground truth" line.

## Step 3: Write Output

### Test existence vs. coverage execution (CRITICAL)

**Test presence** comes from Step 1 enumeration (`test_files`, `test_functions`, `test_functions_by_kind`, `stateless_fuzz`, `foundry_invariant`, `echidna`, `medusa`, `hardhat_fuzz`, `fork`, `certora`, `halmos`, `hevm`, `anchor_ts_tests`, `solana_fuzz`, `move_prover`, `move_expected_failure`, `soroban_tests`). File-scan results — ALWAYS reliable. Multi-signal categories print `functions:configs`.

**Coverage metrics** come from `forge coverage` / `hardhat coverage` / `aptos|sui move test --coverage` / `cargo test` and require installed deps, successful compilation, passing tests. They fail for many reasons unrelated to test quality.

**Rules:**
1. Use enumeration counts for ALL test-existence claims. Never infer "no tests" from coverage failure.
2. If coverage fails but tests exist: `"[N] test files with [M] test functions detected; coverage metrics unavailable — [failure reason]"`.
3. In "Gaps", only flag missing categories, prioritized by audit impact (missing stateful fuzz / formal verification for math-heavy logic > missing fork tests). Invariants Step 2h marked `not checkable by engine` are concrete gaps — say what an `.invar` file or Solana plan would need to state.
4. Never claim "commits without tests" from coverage failure. `test_co_change_rate` measures file co-modification, not coverage.
5. Coverage failure must not cascade into threat model or risk assessments.

Check coverage status: include results if done, failure reason if failed, "pending" if still running. Do NOT wait.

### 3a. Write ALL output files (4 parallel Write calls in ONE message)

All output files go into `recon/`. Write ALL FOUR in a SINGLE message (the fifth output, `engine-findings.json`, already exists from Step 1-engine):

**1. `recon/architecture.json`** — per the architecture guide in `references/templates.md`.

**2. `recon/recon.md`** — per the output template in `references/templates.md`. Under 500 lines. No fabrication. Sections: 1 Overview · 2 Threat & Trust Model · 3 Invariants (**pointer only** — one blockquote with counts including the engine tally; the catalog lives in invariants.md) · **4 Engine Findings** (scan table from `engine-findings.json` verbatim fields, registry precedents, the Step 2h execution table, every BROKEN PoC verbatim) · **5 Exposure & Attack Chains** (`chains` vs `known_chains` kept apart; STRIDE model summary; secret sources verbatim) · 6 Documentation Quality · 7 Test Analysis · 8 Developer & Git History · Recon Verdict with the **Engine ground truth** line (counts by tier).

**Key Attack Surfaces cross-link requirement**: cross-reference each surface against the `invariants.md` blocks. If the surface's cited `file:line` falls within the `Location` / `Derivation` / `Caller side` / `Callee side` window of any G-N / I-N / X-N / E-N block, append the IDs as lowercase-slug links: `- **Surface** &nbsp;&#91;[X-4](invariants.md#x-4), [I-17](invariants.md#i-17)&#93; — …`. Separate surface bullets with a blank line. If an engine finding sits on the surface, end the bullet with `(VERIFIED-STATIC: <id>)` or `(VERIFIED-PROVEN: fuzz PoC, §4)`; otherwise nothing.

**3. `recon/entry-points.md`** — per the entry-points template. Protocol Flow Paths first, then Permissionless (full detail blocks), Role-Gated, Admin-Only (compact table with Gate and Delay columns), Initialization. Chain-aware rows (Accounts / objects / Address auth) for non-EVM. Factual only. >30 entry points → compact tables for role-gated and admin sections.

**4. `recon/invariants.md`** — per the invariant-map template. `#### G-N` / `#### I-N` / `#### X-N` / `#### E-N` heading blocks, NOT tables. Every I/X/E block carries the `Engine:` field and an `Engine check` line from Step 2h. Every inferred block cites a concrete Δ-pair, guard-lift + write-sites, edge, temporal predicate, or doc-comment claim — drop blocks that cannot. No cap on block count.

**5. `recon/engine-findings.json`** — already written by Step 1-engine; do not rewrite it. (If the scan did not run, write `{"_truent": {"error": "<exact stderr>"}}` so downstream tooling sees why.)

**Writing Section 2 (Threat & Trust Model)** — follow the template. Use `references/threats.md` for profiles, temporal and composability content, and the chain dimension(s). For hybrids merge: primary adversaries first, then unique secondary, then chain-specific — de-duplicated.

**Verification rules** (apply during Section 2 writing):
- **Permissionless entry points**: only the grep-verified list from Step 2b.
- **Security claims**: before writing that a check is missing, incomplete, or bypassable, trace the data flow by reading the code: (1) Grep all write sites, (2) confirm the claim against them. If you cannot, write "could not confirm". If a detector covers the shape and did NOT fire, say so — do not let a `REASONED` claim read as stronger than the engine's silence.
- **Engine sections (§4, §5)**: fields verbatim from the JSON. No paraphrased messages, no rows the JSON does not contain, no `known_chains` presented as findings.

**Section 8 (Git History)**: integrate `recon/git-security.json` into Contributors, Review Signals, Hotspots (merge `churn_hotspots` + `fix_prone_files`), Security-Relevant Commits (score ≥ 5), Dangerous Area Evolution, Forked Dependencies (incl. `locally_modified_vendor_files`), Tech Debt, Cross-Reference Synthesis (2-4 bullets connecting git signals to §2-§5 — a detector hit inside a fix-prone file is the strongest cross-reference).

### Branch scoping (CRITICAL)

The git analysis is scoped to **HEAD only**. `meta.git_branch` says which branch. All git signals reflect only commits reachable from HEAD.

1. State the branch in the report header and §8: "Analyzed branch: `[branch]` at `[commit]`".
2. Describe fix commits as what the **current branch code** does — never a before/after you cannot see on this branch.
3. Never describe code state from other branches.
4. If `repo_shape.classification` is `squashed_import`, say so and skip fix/hotspot analysis.

### 3b. Generate & Validate Architecture SVG

```bash
python3 $SKILL_DIR/scripts/generate_svg.py recon/architecture.json recon/architecture.svg
```

Then follow the rendering, audit checklist, and fix loop in the architecture guide. Max 3 iterations. Cleanup temp files after:
```bash
rm -f recon/architecture.json recon/git-security.json recon/engine-threat-model.json recon/engine-exposure.json recon/engine-deps.json recon/plan.json /tmp/architecture-preview.png
```
Keep `recon/engine-findings.json` — the `truent-audit` skill seeds from it.

### 3c. Terminal Verdict

After all files are written and cleanup is done, read the `## Recon Verdict` section from `recon/recon.md` and print it verbatim to the terminal — tier, justification, **Engine ground truth** line, structural facts. Do NOT paraphrase.

## Constraints

- Under 500 lines for recon.md. Protect threat model, invariants pointer, engine findings, test gaps, git analysis, verdict — compress other sections if needed.
- No fabrication. Say "could not determine" when uncertain. Engine output is pasted, never reconstructed from memory. Only flags that appear in `truent <cmd> --help` are ever used.
- Steps 0-3 fully autonomous. No user interaction required.
- Always group contracts by subsystem (and chain) in the scope table.
- Single pass. No partial outputs.
- Never reference audit platforms, contest rules, or bounty program framing — keep the report vendor-neutral.
- If the git security script fails, fall back to bash-only git stats. If the engine is missing, write the report anyway with engine sections marked not run. Never block on a missing script or binary.
- **DO-NOT-EXPLOIT report language**: attack surfaces name the concern area, not the exploit ("worth checking / tracing / confirming"). The single exception is an engine `VERIFIED-PROVEN` PoC, which is pasted verbatim in §4 because it is a fact, not a hypothesis.

---

## Banner

Print before anything else:

```
  ╔═══════════════════════════════════════════════════════════╗
  ║   T R U E N T   ·   R E C O N                             ║
  ║   map it · prove what the engine can · label the rest    ║
  ╚═══════════════════════════════════════════════════════════╝
```
