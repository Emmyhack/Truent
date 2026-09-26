<!-- Adapted from pashov/skills x-ray/references/templates.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine integration, multi-chain. -->
# Output Template

Write `recon/recon.md` using this exact structure. Every line should tell an auditor something useful — write for someone who has 5 minutes to decide where to look first.

**Evidence vocabulary (use everywhere in every output file):**
- `VERIFIED-PROVEN` — the engine *executed* it: `truent fuzz --dynamic` PoC, `truent symbolic` counterexample, or a `truent probe` hit.
- `VERIFIED-STATIC` — a compiled detector matched (`truent scan` violation with `evidence: "lead"` or `"proven"`); deterministic, reproducible, not executed.
- `REASONED` — your inference from reading code; nothing executed or matched it.
- `EXTERNAL` — a non-Truent tool's result (forge coverage, Move Prover, `cargo test`, Certora …).
- `(per spec)` — stated in a whitepaper/README, not confirmed in code.

Never blur tiers. A `REASONED` claim never becomes `VERIFIED-*` by restating it.

```markdown
# Truent Recon

> [Protocol Name] | [total in-scope nSLOC] nSLOC | [short-hash] (`[branch]`) | [framework(s)] | [chain(s)] | [DD/MM/YY] | engine `truent [version]`

---

## 1. Protocol Overview

**What it does:** [One sentence — the core mechanism.]

- **Users**: [Who interacts and why]
- **Core flow**: [The main user-facing operation in one bullet]
- **Key mechanism**: [AMM type, vault model, oracle design, etc.]
- **Token model**: [What tokens exist and their roles — for Solana name the mints / Token-2022 extensions; for Move the `Coin<T>`/`FungibleAsset` types; for Soroban the SAC vs custom token contracts]
- **Admin model**: [Who controls what — owner, multisig, governance; on Solana also the program upgrade authority; on Sui the `UpgradeCap` holder; on Soroban the upgrade entrypoint's gate]

[No paragraphs. No fluff. Keep vendor-neutral — no audit platform or bounty program framing.]

For a visual overview of the protocol's architecture, see the [architecture diagram](architecture.svg).

### Contracts in Scope

[Group by subsystem — one row per subsystem, not one row per file. List key contracts/programs/modules in the row.]

| Subsystem | Key Contracts | Chain | nSLOC | Role |
|-----------|--------------|-------|------:|------|
| [Subsystem] | [Contract1, Contract2, ...] | [evm/solana/move-aptos/move-sui/soroban] | [total] | [One-line role of this subsystem] |

[Only protocol-authored code. No interfaces, no vendored libs, no generated IDL/clients. Mixed-chain repos get one row per subsystem per chain.]

### Backwards-Compatibility Code

[Include this subsection ONLY if backwards-compatibility remnants were identified in Step 2c. Omit entirely if none found.]

[Some protocols remove a mechanism but leave parts of it in the codebase so the remaining code does not break. List any such code here for clarity, so auditors know these are not active features.]

- `[contract:function/variable]` — [what it was part of, why it's retained, and that it is not active functionality]

[Keep entries short. The goal is clarity — preventing auditors from investigating dead code as if it were live.]

### How It Fits Together

[Start with "The core trick:" — one sentence explaining the protocol's fundamental mechanism.]

[Then show 3-5 key flows as annotated code-block diagrams. Each flow gets:]
[1. A ### subheading (no numbering — order is self-evident)]
[2. A code block showing the call chain with tree-style branching (├─ └─)]
[3. Italic annotations on critical steps (where state changes, where callbacks/CPIs fire, where auth is checked, where payment is verified)]
[Keep it to the 3-5 MOST IMPORTANT flows. Skip governance/admin/oracle flows — those are covered in Section 2. This section is about the core user-facing mechanics only.]

[IMPORTANT: Use concrete contract/program/module names in call chains, NOT interface or trait names. Write `FuturesManager.addCollateral()`, not `ICollateralManager.addCollateral()`. On Solana write `vault::withdraw` → `token::transfer` (CPI); on Move `vault::withdraw` → `coin::extract`; on Soroban `Token.transfer` → `token::Client.transfer`. The only exception is calls to genuinely external contracts (e.g. `IERC20.safeTransfer()`, `spl_token`, `pyth::`) where the concrete code is outside the protocol's codebase.]

[Focus on flows that span multiple contracts — these are where integration bugs hide.]

[No inheritance lists. No import lists. Those details are in the scope table and the diagram. This section answers: "how does the system actually work, end to end?"]
[No bridge/transition sentences at end of section. No filler lines like "This is the flow an auditor traces..."]

---

## 2. Threat & Trust Model

> **Bullet brevity rule (applies to every bullet-heavy subsection in Sections 2, 3, 6):** one tight sentence per bullet — ideally one line, max two. Don't restate what the `file:line` reference already shows. Example of the pattern to follow:
>
> ✅ `**Historical snapshot mutability (balanceOfAt)** — LockManager.getVotingPowerAtBlock:830-842 caps decay by points[low+1].ts - p.ts; any later user checkpoint shifts reconstructed past VP → moving numerator against frozen denominator in _updateReward:663.`
>
> ❌ Not: *"`LockManager.getVotingPowerAtBlock:830-842` caps the decay window by `points[low+1].ts - p.ts`; any subsequent checkpoint written by the same user (via lock / increase / extend / ragequit) changes the cap and therefore the reconstructed voting power for blocks between `p.blk` and `points[low+1].blk`. `_updateReward:663` reads this value to set per-user share against a frozen denominator. Scoring: this is the #1 surface for reward manipulation."*
>
> The bad version repeats what the code reference already shows. The good version says the mechanism once, points to the code, and stops. **Cut words that restate the file's contents. Code refs carry the evidence — prose must not duplicate them.**

### Protocol Threat Profile

> Protocol classified as: **[Primary type]** with **[Secondary type(s)]** characteristics · chain dimension(s): **[Solana / Move-Aptos / Move-Sui / Soroban / none (EVM)]**

[1-2 sentences explaining why this classification, based on code signals detected. For hybrids, merge adversary lists: primary first, then unique secondary threats — de-duplicate overlapping ones. Then merge the chain-specific adversaries from `threats.md` §Chain-Specific Threat Dimensions.]

### Actors & Adversary Model

| Actor | Trust Level | Capabilities |
|-------|-------------|-------------|
| [Role] | [Trusted / Bounded (reason)] | [What they can do] |

[Only named roles from code. No "Anyone". Never use "Semi-trusted" — use "Bounded (reason)" instead. Chain notes: on Solana the program **upgrade authority** is always a row (state "could not determine holder" if no deploy config shows it); on Sui the **`UpgradeCap` holder** and every **capability object** type is a row; on Soroban the **stored admin** and the **upgrade entrypoint gate** are rows; on Aptos the **`@module_addr` publisher** is a row.]

[CENTRALIZATION INTEGRATION: The Capabilities column must be specific about what is instant vs timelocked/delayed. If a role has a transfer delay (e.g., AccessControlDefaultAdminRules) but instant operational functions, state both — "1-day transfer delay, but all operational functions instant." If a role's functions are not subject to pausability, note it in the Trust Level or Capabilities column — e.g., "Bounded (can only complete CREATED swaps with constraints). Not subject to whenNotPaused — can operate during pause." This replaces any standalone "Centralization Risks" section — centralization details belong here, in Trust Boundaries, and in Key Attack Surfaces.]

[CELL BREVITY: Capabilities cells are a scannable reference, NOT a capability paragraph. For roles with many powers, summarise as e.g. "11 instant setters + pause (incl. setTimePerBlock which retroactively shifts every balanceOfAt, setTreasuryAddress, reward-token lifecycle). pause does NOT gate withdraw." — enumerate the dangerous ones inline, don't list every setter name. Aim ≤2 lines per cell.]

[ENGINE TIE-IN: where a detector speaks to a row — `evm_single_eoa_admin`, `sol_treasury_single_authority`, `sol_admin_no_timelock`, `move_admin_no_timelock`, `move_admin_transfer_single_step`, `sor_unprotected_upgrade` — append `(VERIFIED-STATIC: <id> @ file:line)` or `(engine: no <id> match)` to the cell.]

**Adversary Ranking** (ordered by threat level for this protocol type, adjusted by git evidence):

1. **[Adversary type]** — [1 sentence: WHO they are and WHY they are relevant to this protocol type.]
2. **[Adversary type]** — [...]
3. [...]

[Include only adversary types relevant to this protocol. Typically 3-5. Keep each entry to ONE sentence — the adversary ranking identifies WHO threatens the protocol. The HOW and WHERE details belong in Key Attack Surfaces below. Do NOT describe attack mechanics or cite specific functions here.]

[Do NOT include a "Permissionless Entry Points" list here — that information lives in entry-points.md. Instead, reference: "See [entry-points.md](entry-points.md) for the full permissionless entry point map."]

### Trust Boundaries

[Where trust transitions happen. For each boundary: what's trusted, what damage if compromised, whether timelock/multisig exists.]
[For admin/privileged boundaries, distinguish what the delay mechanism actually protects. E.g., if AccessControlDefaultAdminRules protects role transfer but operational functions are instant, state: "1-day delay protects the admin seat itself, but all operational actions (emergencyWithdraw, setFee, etc.) execute instantly with no delay."]
[If git analysis shows trust boundary code was frequently modified or has fix-scored commits, note: "*Git signal: N modifications, M fix-scored commits — elevated risk.*"]

[**Per-bullet format** (apply brevity rule above): `**Boundary** — protection status + the single worst instant action it leaves open + code ref; max 2 lines. Don't enumerate every function an admin holds — name the most dangerous one and reference the code.`]

### Key Attack Surfaces

[This is the SINGLE authoritative location for attack surface details. Adversary Ranking above identifies WHO; this section describes WHERE to investigate. Do NOT repeat the same risk in both places.]

[Sorted by priority score (protocol-type relevance + engine finding on the surface + git hotspot + fix history + late changes + dangerous area churn). NOT alphabetical. A surface with a `VERIFIED-*` engine finding on it sorts above an equally-weighted surface without one.]
[These are **investigation pointers**, not exploit writeups. The auditor decides whether the concern is real, what the severity is, and how to exploit it. Your job is to name the area worth looking at and give enough context for the auditor to know where to start reading.]
[No RISK labels (HIGH/MEDIUM/LOW). No mitigation analysis. No git evidence per surface.]

- **[Surface name]** &nbsp;&#91;[X-N](invariants.md#x-n), [I-N](invariants.md#i-n)&#93; — [one tight sentence: code ref + the concern (what's unusual, fragile, or worth double-checking) + what an auditor should trace to confirm or dismiss it. Aim for 1 line, max 2.] [If an engine finding sits on this surface, end with `(VERIFIED-STATIC: evm_xxx)` or `(VERIFIED-PROVEN: fuzz PoC, see §4)`. Otherwise nothing — absence of a tag means REASONED.]

[Repeat for each surface, **separating bullets with a blank line** for readability. **Hard cap: 2 lines per surface.** Do not write paragraphs. Do not restate what the file:line already shows.]

[**INVARIANT CROSS-LINK RULE**: If the surface's cited code location falls within the derivation window of any guard/invariant in `invariants.md` (the `Location` or `Derivation` field of G-N / I-N / X-N / E-N blocks), append the matching IDs as bracketed markdown links immediately after the surface title. Use lowercase slugs (`invariants.md#x-4`, not `#X-4`) since VS Code and GitHub normalize heading IDs to lowercase. Example: `**`withdrawFromInvestment` unchecked subtraction** &nbsp;&#91;[X-4](invariants.md#x-4)&#93; — ...`. Surfaces that are purely access-control or upgrade-ability concerns (no state-invariant touched) may be left unlinked — that is a healthy signal, not a gap.]

[**DO-NOT-EXPLOIT RULE (critical):** Attack surfaces must describe the *concern area*, not the specific exploit. The auditor's value is building the attack path; yours is finding the area fast. If your bullet contains phrases like "→ attacker drains X", "→ user trapped", "→ inflated share", "reverts with Y trapping Z", "double-counts W", "leads to understated N" — cut them. Replace with "Worth checking...", "Worth tracing...", "Worth confirming...". Name the asymmetry, the divergence, the unusual pattern, the cross-path bookkeeping — then stop. Let the auditor finish the sentence. **The one exception is an engine `VERIFIED-PROVEN` result: a fuzzer PoC is a fact, not a hypothesis — it lives in §4 verbatim, and the surface bullet only points to it.**]

[Example of the pattern to follow:]

[✅ `- **Epoch-end bookkeeping has two removal paths** — _addToEpochEndLocked:102 and _subtractFromEpochEndLocked:117-138 manage the globalEpochEnds arrays vs. the totalLockedAtEpochEnd mapping; _checkpointExpiredLocksCumulative:140 walks only the arrays. Worth checking that array membership stays in sync with mapping contents across all mutation paths.`]

[❌ Not: `- **globalEpochEnds desynced from totalLockedAtEpochEnd** — _subtractFromEpochEndLocked:117-138 pops the array unconditionally; expired mass at shared epochs never lands in accExpiredLocks → understated decay → inflated global bias.` (This spells out the exploit chain — "never lands in", "understated", "inflated" — leaving the auditor nothing to discover.)]

[FRAMING RULE: Attack surfaces should be named after the root threat area, not individual symptoms or specific exploits. E.g., "SERVICE_ROLE compromise" is a surface — missing pausability on completeSwap is a detail that sits inside it. "Admin operational powers without timelock" is a surface — individual setters are evidence within the description. "Reward accounting crosses user/global symmetry" is a surface — specific numerator/denominator manipulations belong to the auditor. Frame surfaces as the actor/capability/pattern that deserves scrutiny, list the relevant functions inside the description, and stop before naming the exploit.]

### Upgrade Architecture Concerns

[Include if any upgradeable code exists: EVM UUPS/transparent/beacon proxy; Solana program with a live upgrade authority; Sui package with an `UpgradeCap`; Aptos package with a non-immutable upgrade policy; Soroban contract exposing `update_current_contract_wasm`. Concrete concerns tied to this codebase's upgrade patterns.]

- **[Concern]** — [one tight sentence: code ref + risk + affected contracts. Max 2 lines.]

[Typical concerns: uninitialized implementations, storage gap consistency, missing timelock on upgrades, blast radius of upgrading shared contracts, placeholder proxy windows; Solana account-layout migration; Soroban `DataKey` ordering across upgrades; Sui struct-layout compatibility rules.]

### Protocol-Type Concerns

[Based on the protocol classification from Section 2a. ONLY include concerns that are NOT already covered in Key Attack Surfaces above. This section adds protocol-type-specific technical details (math precision, curve invariants, share accounting, etc.) — not the same risks restated from a type perspective.]

**As a [Primary type]:**
- [One tight line: code ref + the technical concern (math precision, curve edge case, share rounding direction). Max 2 lines.]

**As a [Secondary type]** *(if applicable)*:
- [Same format]

**On [chain]** *(if non-EVM — from threats.md chain dimension; only concerns not already surfaces above)*:
- [Same format — e.g. an unconstrained `AccountInfo`, a `Coin<T>` with free `T`, a `temporary()` entry, a `has store` capability]

[2-3 bullets per type. If a concern is already an attack surface above, skip it here. No generic protocol-type advice — every bullet must cite a specific contract/function. Do NOT restate what the file:line already shows.]

### Temporal Risk Profile

[ONLY include phases that add NEW information not already in Actors, Attack Surfaces, or Upgrade Architecture. Skip any phase whose risks are already fully covered above. Typical: Deployment & Initialization adds value (empty-state, front-running init); Governance & Upgrade usually does NOT (already covered in Actors + Upgrade Architecture). 1-3 bullets per phase, each citing specific code locations.]

**Deployment & Initialization:**
- [One tight line: code ref + risk + mitigation status. Max 2 lines.]

**Market Stress** *(include only if adding new info beyond Attack Surfaces)*:
- [Same format]

**Deprecation** *(include only if V2/migration evidence exists)*:
- [Same format]

[Per-bullet: single sentence. No multi-sentence paragraphs. No "because the code does X, therefore Y, therefore Z" — the code ref carries the evidence.]

### Composability & Dependency Risks

**Dependency Risk Map:**

[Use blockquote format per dependency — one block each, easy to scan:]

> **[External Name]** — via `[contract:function]` [(CPI / cross-module / invoke_contract)]
> - Assumes: [key assumptions about return value / behavior]
> - Validates: [what checks exist] or [NONE]
> - Mutability: [Immutable / Upgradeable by X / Governed by X / upgrade authority Y]
> - On failure: [what happens — revert / fallback / fail-open]

[Repeat for each significant external dependency. Well-mitigated ones can be shorter.]

**Token Assumptions** *(unvalidated only)*:
- [Token type]: assumes [assumption not validated in code] — impact if violated: [consequence]

**Shared State Exposure** *(if applicable)*:
- [Which shared resources (pools, oracles, shared objects), what other protocols share them, whether this protocol's actions could affect others]

**Build-time dependencies** *(from `truent deps`, if it ran)*:
- [One line: `N packages, M lockfiles, K findings (ids)` — or "no lockfile found for <ecosystem>" — this is VERIFIED-STATIC at the repository level.]

[Do NOT add an "Integration Summary" table — the Dependency Risk Map blockquotes above already cover every external dependency. A summary table would duplicate them.]

---

## 3. Invariants

> ### 📋 Full invariant map: **[invariants.md](invariants.md)**
>
> A dedicated reference file contains the complete invariant analysis — do not look here for the catalog.
>
> - **[N] Enforced Guards** (`G-1` … `G-N`) — per-call preconditions with `Check` / `Location` / `Purpose`
> - **[N] Single-Contract Invariants** (`I-1` … `I-N`) — Conservation, Bound, Ratio, StateMachine, Temporal
> - **[N] Cross-Contract Invariants** (`X-1` … `X-N`) — caller/callee pairs that cross scope boundaries
> - **[N] Economic Invariants** (`E-1` … `E-N`) — higher-order properties deriving from `I-N` + `X-N`
> - **Engine check:** [N] checkable by `truent fuzz` → [N] held · [N] **BROKEN (VERIFIED-PROVEN)** · [N] engine could not deploy · [N] Solana plans validated (execution deferred) · [N] not checkable by engine · [N] routed EXTERNAL (Move Prover / cargo test)
>
> Every inferred block cites a concrete Δ-pair, guard-lift + write-sites, state edge, temporal predicate, or NatSpec quote. The **On-chain=No** blocks are the high-signal ones — each is simultaneously an invariant and a potential bug. Any **BROKEN** block is no longer a hypothesis: its PoC is in §4. Attack-surface bullets above cross-link directly into the relevant blocks (e.g. `[X-4]`, `[I-17]`).

[Section 3 is a POINTER, not a catalog. Do NOT duplicate guards or invariants here — they belong exclusively in `invariants.md`. Fill the bracketed counts from the actual invariants.md output.]

---

## 4. Engine Findings

> Source: `recon/engine-findings.json` (`truent scan --chain auto --output json`), plus Step 2h fuzz runs. Everything in this section is machine-produced. `VERIFIED-STATIC` rows are detector matches; `VERIFIED-PROVEN` rows executed.

**Summary:** [critical] critical · [high] high · [medium] medium · [low] low — [N] violations in [duration_ms] ms across [chains scanned]. [If the scan failed or the binary was missing: "engine unavailable — <exact error>; this section is empty and nothing below is VERIFIED".]

| # | Detector | Sev | Location | Evidence | Exploitability | Tier |
|--:|----------|-----|----------|----------|----------------|------|
| 1 | `[invariant_id]` | [severity] | `[file:line]` | [lead / proven] | [likely / possible / unlikely / theoretical] | VERIFIED-STATIC |

[One row per violation, sorted by severity then exploitability. Use the `invariant_id`, `severity`, `location`, `evidence`, `exploitability` fields verbatim. Cap the table at 25 rows; if longer, keep the top 25 and add "… and N more in engine-findings.json". Do not paraphrase `message`; do not add rows the JSON does not contain.]

**Registry precedents:** [For each distinct `invariant_id` above that appears in `truent registry list`, one line: `evm_oracle_spot_price` → euler-finance-2023 ($196M), gmx-2024 ($50M). Omit the subsection if none match.]

### Invariants the engine executed (Step 2h)

| Invariant | Command | Result | Tier |
|-----------|---------|--------|------|
| [I-N] | `truent fuzz <file> --dynamic --chain evm --iterations N --seed S` | held (engine, seed S, N iters) | VERIFIED-PROVEN (negative) |
| [I-M] | `…` | **BROKEN** — see PoC below | VERIFIED-PROVEN |
| [I-K] | — | not checkable by engine: [reason verbatim — e.g. "no auto-detectable invariant on this ABI"] | — |
| [I-L] | `truent fuzz … --dynamic --chain evm …` | engine could not deploy: [constructor takes arguments / relative imports] | — |
| [I-S] | `truent fuzz <idl.json> --dynamic --chain solana --plan recon/plan.json` | validated plan (execution deferred) — `IDL and plan are valid (N fuzzable instruction(s))…` | — (plan kept) |
| [I-J] | `aptos move prove` / `sui move test` / `cargo test` | [result or "not run"] | EXTERNAL |

[A `held` result means N random sequences of depth D found no violation with that seed. It is evidence, not proof — say so in the row if the auditor could misread it.]

**PoC (verbatim engine output)** — one block per BROKEN row:

```
[paste the fuzzer's `Invariant violated:` line, the `Reproduction (N calls):` list and `Failing step:` line exactly as printed]
```

[FORMAT reference — this is what a real run looks like, produced by `truent fuzz BrokenToken.sol --dynamic --chain evm --iterations 300 --seed 7` on a token whose `mint` credits `balanceOf` without touching `totalSupply`:]

```
✗ [PROVEN] BrokenToken.sol
Invariant violated: ERC20 conservation: sum(balanceOf) == totalSupply()
ERC20 conservation: sum(balanceOf) == totalSupply(): sum(balanceOf) = 98861774990095078751955108432288833117878002115940341017090003132597792335537 != totalSupply() = 1000

Reproduction (1 call):
  1. mint(0000000000000000000000000303030303030303030303030303030303030303da91c81e9c8273a4eb95f94d6c62b44900d38de199803e57a3764a3b796ae2c9)  [caller=0x0101010101010101010101010101010101010101]

Failing step: #1 (mint)
```

---

## 5. Exposure & Attack Chains

> Source: `recon/engine-exposure.json` (`truent exposure --format json`) and `recon/engine-threat-model.json` (`truent threat-model --format json`). Repository-level: the engine's STRIDE model is built from discovered routes, stores, outbound calls, secrets and auth markers; it complements the contract-level model in §2 and does not replace it.

**Exploitability distribution:** [N] likely · [N] possible · [N] unlikely · [N] theoretical (from `findings[].exploitability`).

**Completed attack chains** (`chains[]` — findings that compose into a known chain):
- **[chain name]** (`[chain id]`) — steps: [role → detector id matched] … — [one sentence on what the chain reaches]. [If `chains` is empty: "No completed attack chains — none of the 12 known chain definitions (`known_chains`) had every step matched."]

**Engine STRIDE model** (`threats[]`): [If empty: "No STRIDE threats emitted — the repository exposes no discovered routes/stores/secret sources (`entry_points: [], data_stores: [], outbound_calls: []`)." Otherwise one line per threat category with count and the top item.] Secret sources flagged: [list `secret_sources` verbatim or "none"].

[Do not narrate hypothetical chains here. `known_chains` describes what the engine *can* recognise; only `chains` describes what it *did* find. Mixing them is fabrication.]

---

## 6. Documentation Quality

| Aspect | Status | Notes |
|--------|--------|-------|
| README | [Present/Missing] | [Filename/path if present] |
| Doc comments | [~N NatSpec tags / ~N `///` lines] | [Coverage notes — from enumerate `NatSpec` and `doc_comments_rust_move`] |
| Spec/Whitepaper | [Present/Missing] | [Filename/path if present] |
| Inline Comments | [Sparse/Adequate/Thorough] | [Notable gaps] |
| Anchor IDL / Soroban spec / Move interface docs | [Present/Missing/n.a.] | [path] |

[Skip user-facing docs (tutorials, API refs, marketing). If a spec/whitepaper was ingested in Step 1, tag derived claims with `(per spec)` vs `(per code)` so auditors know what is code-verified vs spec-stated.]

---

## 7. Test Analysis

| Metric | Value | Source |
|--------|-------|--------|
| Test files | [N] | File scan (always reliable) |
| Test functions | [N] ([breakdown from test_functions_by_kind]) | File scan (always reliable) |
| Line coverage | [N% or "Pending" or "Unavailable — [reason]"] | Coverage tool (EXTERNAL; requires compilation) |
| Branch coverage | [N% or "Pending" or "Unavailable — [reason]"] | Coverage tool (EXTERNAL; requires compilation) |

[IMPORTANT: Test file/function counts come from file scanning and are always accurate. Coverage metrics require the toolchain to compile and run — if coverage fails (missing deps, compiler error, stack-too-deep), this does NOT mean tests are absent. State this clearly when coverage is unavailable.]

### Test Depth

| Category | Count | Contracts Covered |
|----------|------:|-------------------|
| Unit | [N] | [List or "broad"] |
| Integration | [N] | [List or "none"] |
| Fork | [N] | [List or "none"] |
| Stateless Fuzz (Foundry / proptest) | [N] | [List or "none"] |
| Stateful Fuzz (Foundry invariant) | [N] | [List or "none"] |
| Stateful Fuzz (Echidna) | [N] | [List or "none"] |
| Stateful Fuzz (Medusa) | [N] | [List or "none"] |
| Stateful Fuzz (Truent engine, Step 2h) | [N checkable / N ran] | [contracts fuzzed] |
| Solana fuzz (Trident / plan-based) | [N] | [List or "none"] |
| Move Prover specs | [N spec blocks : N spec files] | [List or "none"] |
| Soroban testutils suites | [N] | [List or "none"] |
| Formal Verification (Certora) | [N] | [List or "none"] |
| Formal Verification (Halmos) | [N] | [List or "none"] |
| Formal Verification (HEVM) | [N] | [List or "none"] |

[Only include rows where the count > 0 or where the absence is notable. For categories with 0, consolidate into the Gaps section instead of showing empty rows. Always include Unit, Stateless Fuzz, Stateful Fuzz (at least one tool), and Formal Verification (at least one tool) — even if 0 — since their absence is audit-relevant. Omit rows for chains not present. Omit Hardhat Fuzz row unless the package.json dependency was detected.]

[Enumeration output format for multi-signal categories: `echidna`, `medusa`, `certora`, `halmos`, `solana_fuzz`, `move_prover` output as `functions:configs` (e.g., `5:1` = 5 functions + 1 config file). Report the function/spec count in the table. If configs exist but no functions, note: "[tool] config present but no test functions found".]

### Gaps

[Notable testing gaps. Only flag missing test categories — never claim "no tests" when enumeration found test files. Prioritize gaps by audit impact: missing stateful fuzz and formal verification for math-heavy/financial logic is higher priority than missing fork tests. If Step 2h found invariants "not checkable by engine", say what an `.invar` file or a Solana plan would need to state to make them checkable — that is a concrete, actionable gap.]

---

## 8. Developer & Git History

> Repo shape: [normal_dev / squashed_import] — [one sentence: e.g., "All source arrived in 1 commit (9fb17ba); no development history visible" or "Normal development history with N source-touching commits over N months"]. Analyzed branch: `[branch]` at `[commit]`.

### Contributors

| Author | Commits | Source Lines (+/-) | % of Source Changes |
|--------|--------:|--------------------|--------------------:|
| [Name] | [N]     | +[N] / -[N]       | [N%]                |

[Compute % from source line additions. Flag single-developer dominance (>90%), ghost contributors (1 commit), or uneven distribution.]

### Review & Process Signals

| Signal | Value | Assessment |
|--------|-------|------------|
| Unique contributors | [N] | [Single-dev / Small team / Larger team] |
| Merge commits | [N] of [total] ([%]) | [Formal review process / No merge commits — likely no peer review] |
| Repo age | [first] → [last] | [Duration] |
| Recent source activity (30d) | [N] commits | [Active / Quiet / Late burst before audit] |
| Test co-change rate | [N%] | [% of source-changing commits that also modify test files — measures co-modification, NOT coverage] |

### File Hotspots

| File | Modifications | Fix commits | Note |
|------|-------------:|-----------:|------|
| [path] | [N] | [N] | [High churn — prioritize review] |

[Top 5-10 from `churn_hotspots` merged with `fix_prone_files`. High modification count correlates with higher defect density; a high fix ratio says the churn was corrective.]

### Security-Relevant Commits

[Include ONLY if fix_candidates from git security analysis has entries with score >= 5. For squashed-import repos, skip this subsection and note "No development history — fix detection not applicable."]

**Score** = weighted sum of fix-like signals in a commit: message keywords (fix, bug, reentrancy, overflow...), diff patterns (deletes code, changes `require`/`assert`/`require!`/`require_auth`, touches access control or accounting), and change shape (focused = higher). **10+ warrants a manual diff.**

| SHA | Date | Subject | Score | Key Signal |
|-----|------|---------|------:|------------|
| [hash] | [date] | [subject] | [N] | [top reason from scoring] |

### Dangerous Area Evolution

[Include if the repo has normal development history. Shows which security-sensitive code areas changed most.]

| Security Area | Commits | Key Files |
|--------------|--------:|-----------|
| [fund_flows / access_control / oracle_price / liquidation / signatures / state_machines / upgrade_paths] | [N] | [top 2-3 files] |

[Areas with high commit counts warrant deeper review — frequent changes to security-critical code correlate with higher defect density.]

### Forked Dependencies

[Include if forked_deps.detected_libs contains internalized libraries or locally_modified_vendor_files is non-empty. Skip if all libs are standard submodules.]

| Library | Path | Upstream | Status | Notes |
|---------|------|----------|--------|-------|
| [name] | [lib/path] | [Uniswap V2 / OpenZeppelin / Anchor / Soroban SDK / etc.] | [Submodule / Internalized / Locally modified] | [Pragma mismatch, modifications from upstream, etc.] |

[Internalized libraries with pragma or logic changes from upstream are hidden attack surface — the team may have introduced bugs while adapting code, and upstream security fixes won't auto-propagate.]

### Technical Debt Markers

[Include if tech_debt.total_count > 0. Skip otherwise.]

| File:Line | Type | Text | Author | Date |
|-----------|------|------|--------|------|
| [path:N] | [TODO/FIXME/HACK/XXX/UNSAFE/@audit] | [comment text] | [blame author] | [date] |

[TODO/FIXME/HACK comments represent known-but-unresolved issues. These are areas where the developer acknowledged incomplete work.]

### Security Observations

[4-8 bullets — each ONE line: `**Lead-in** — short fact + file/commit ref.` No multi-sentence explanations. The signal is the fact + the ref; skip the "why this matters" gloss unless it's genuinely non-obvious.]
- [Single-developer risk if applicable]
- [Missing code review signals if no merge commits]
- [High-churn files that warrant deeper review]
- [Recent rapid changes / last-minute additions before audit]
- [Large unreviewed commits if detected]
- [Fix commits without corresponding test file changes — residual risk (note: this measures file co-modification, not coverage)]
- [Forked dependencies with divergent pragmas or logic]
- [Technical debt in security-critical paths]

Example good line: `**Two-dev concentration** — 0xKaizendev (47 %) + Rozales (29 %) = 76 % of commits.`
Example bad line (too wordy): `**Single-developer dominance**: 0xKaizendev authored 47 % of all commits; combined with Rozales (29 %), 76 % of development came from two people. Review ergonomics for the veRAAC subsystem depend heavily on these two reviewers understanding each other's intent.`

### Cross-Reference Synthesis

[2-4 bullets connecting git history signals to findings from Sections 2-5. One line each: `**Cross-reference** — signal A + signal B → conclusion.` Use arrows (→) to compress cause-and-effect. Don't restate the findings.]
- [e.g., "**VeRAACToken.sol is #1 in BOTH churn AND attack-surface priority** — all top-4 surfaces route through it → highest-leverage review: `_updateReward`, `_getClaimableAmount`, `distributeRewards`, ragequit functions."]
- [e.g., "**`_lockBiasAt:1087` TODO aligns with I-17** — `amount/maxTime` then multiply loses precision; `//bug same as M-09` tag suggests prior-audit carryover."]
- [e.g., "**`evm_stale_oracle_price` @ Oracle.sol:88 sits in the file with 3 fix-scored commits** — the detector match is on code that has already been patched twice → read the diffs of d5ee685 and e108753 first."]

---

## Recon Verdict

**[TIER]** — [one sentence justification]

[Tier calculation: take the lowest level across Tests, Docs, Access Control (evidence is in Sections 6-7 and the Actors table). If Code Hygiene has TODOs in security-critical paths (Section 8), drop one tier. Absence of TODOs does NOT raise the tier. The Engine ground truth line below does NOT move the tier — the verdict describes structural posture, not the engine's bug count.]

[IMPORTANT: Test tier is based on test EXISTENCE from Step 1 file scan counts (test_files, test_functions, stateless_fuzz, etc.), NOT on whether tests pass or fail at runtime. If enumeration found 23 unit test functions, the Tests signal is "unit tests exist" regardless of compilation or runtime failures.]

[Tier thresholds:]
[Tests: EXPOSED=0 test functions found, FRAGILE=unit only, ADEQUATE=unit + fuzz OR invariant, HARDENED=unit + fuzz + invariant, FORTIFIED=+ formal verification (Certora/Halmos/HEVM/Move Prover)]
[Docs: EXPOSED=no doc comments + no spec, FRAGILE=sparse doc comments, ADEQUATE=doc comments present, HARDENED=+ spec/whitepaper, FORTIFIED=+ thorough inline comments]
[Access Control: EXPOSED=unclear roles, FRAGILE=roles exist + no timelock, ADEQUATE=roles + boundaries clear, HARDENED=+ timelock or multisig, FORTIFIED=+ emergency pause]

**Engine ground truth:** [N] VERIFIED-PROVEN ([N] fuzz PoCs) · [N] VERIFIED-STATIC ([critical]/[high]/[medium]/[low]) · [N] invariants held under fuzz · [N] engine could not deploy · [N] Solana plans validated (execution deferred) · [N] not engine-checkable · [N] REASONED surfaces in §2 · [N] EXTERNAL results folded in. [If the engine did not run: "engine did not run — every claim in this report is REASONED or (per spec)".]

**Structural facts:**
1. [Verifiable structural fact — e.g., "15K nSLOC across N subsystems", "N upgradeable contracts", "2 developers wrote N% of code", "program upgrade authority: could not determine"]
2. [...]
3. [...]
[3-5 items. ONLY measurable, verifiable facts from Sections 1-8. No security claims, no speculation about what "could" happen, no bug hypotheses, no attack scenarios. The verdict describes the codebase's structural posture (tests, docs, access control, complexity) — NOT its security. The auditor forms their own security conclusions.]
```

# Entry Point Map Template

Write `recon/entry-points.md` using this structure. This file is a purely structural reference — no threat analysis, no invariants, no git history. It answers: "what can be called, by whom, and what does it touch."

```markdown
# Entry Point Map

> [Protocol Name] | [N] entry points | [N] permissionless | [N] role-gated | [N] admin-only | chains: [list]

---

## Protocol Flow Paths

[Order entry points into expected execution flows — the "story" of the protocol from deployment to steady-state operation. Each major user-facing entry point gets a path showing every step that must happen before it becomes callable. This lets auditors immediately see the full prerequisite chain for any function.]

[Group flows by actor. For each flow, trace backwards from the destination function to deployment, listing every function call that must have succeeded first. Use simple arrow chains — no boxes, no diagrams. Annotate non-obvious preconditions with `◄──` comments.]

[Example format:]

### Setup (Owner)

`initReserve()` → `setLeverager()` → `initVault()` → `setLeverageParams()`

### User Flow

`[owner setup above]` → `Lender.deposit()` → `openPosition()`  ◄── liquidity must exist
                                                    ├─→ `withdraw()`
                                                    └─→ `liquidatePosition()`  ◄── position unhealthy

### Maintenance (Keeper)

`[deposit above]` → [rebalanceInterval passes] → [price in range] → `rebalance()`

[Rules for flow paths:]
[- One chain per major destination function. Branch with `├─→` and `└─→` when a function has multiple exit paths.]
[- Reference earlier flows with `[owner setup above]` or `[deposit above]` instead of repeating the chain.]
[- Add `◄──` annotations for preconditions that are NOT function calls (time passage, market conditions, position health, sufficient liquidity, an account/PDA having been created, a TTL still being live).]
[- Keep it factual — trace from require/assert/require_auth statements and state checks back to the functions that write those variables.]
[- This section should be 15-30 lines. It is an index into the detailed sections below, not a replacement.]

---

## Permissionless

[Entry points callable by any address with no effective access restriction. Sorted by value flow: tokens-in first, tokens-out second, no-token-movement last.]

### `Contract.functionName()`

| Aspect | Detail |
|--------|--------|
| Visibility | [external/public], [nonReentrant if present] — see chain notes |
| Caller | [Who actually calls this — User, Anyone, etc.] |
| Parameters | [paramName (user-controlled), paramName (protocol-derived)] |
| Accounts / objects | [Solana: each account in the `Accounts` struct with its type + constraints; Sui: each `&`/`&mut` object param and whether it is shared/owned; Soroban: each `Address` param and whether `require_auth` is called on it; EVM/Aptos: omit row] |
| Call chain | `→ Contract.fn() → Contract.fn() → ...` |
| State modified | [storage vars/mappings that change — Solana: which accounts' data/lamports; Move: which resources/objects; Soroban: which `DataKey`s and which storage tier] |
| Value flow | [Tokens: sender → Vault / Vault → recipient / None] |
| Reentrancy guard | [yes / no / n.a. (runtime-blocked on this chain)] |

[Repeat for each permissionless entry point]

---

## Role-Gated

[Entry points restricted by a role modifier. Group by role. Within each role, sort by value flow.]

### `OCT_KEEPER`

#### `Contract.functionName()`

| Aspect | Detail |
|--------|--------|
| Visibility | [external], [modifier name / `Signer` field / capability param / `require_auth` target] |
| Caller | [Keeper bot / Relayer / etc.] |
| Parameters | [paramName (user-signed), paramName (keeper-provided), paramName (protocol-derived)] |
| Accounts / objects | [as above, non-EVM only] |
| Call chain | `→ Contract.fn() → Contract.fn() → ...` |
| State modified | [storage vars/mappings that change] |
| Value flow | [direction] |
| Reentrancy guard | [yes / no / n.a.] |

[Repeat for each role and function]

---

## Admin-Only

[Entry points restricted to DEFAULT_ADMIN_ROLE or owner (EVM), the stored admin / upgrade authority (Solana, Soroban), the `@module_addr` admin (Aptos), or an `AdminCap` holder (Sui). These configure the protocol rather than operate it.]

[For admin functions, use a compact table instead of per-function detail blocks — auditors need to see the full admin surface at a glance:]

| Contract | Function | Gate | Parameters | State Modified | Delay |
|----------|----------|------|------------|----------------|-------|
| [Contract] | `functionName()` | [`onlyOwner` / `has_one = admin` + `Signer` / `&AdminCap` / `admin.require_auth()`] | [params] | [what changes] | [instant / timelocked N] |

[Repeat for each admin function]

---

## Initialization

[Include if the protocol has one-time setup entry points: EVM `initialize()` behind a proxy; Solana `#[account(init)]` instructions; Aptos `init_module` (private — list only if a public initialiser also exists); Sui `fun init` (private — list only if a public initialiser also exists); Soroban `initialize`. State the re-entry guard for each (`initializer` modifier / `init` vs `init_if_needed` / `instance().has(&Admin)` check / none).]
```

## Rules

- **No overlap with recon.md**: Do not include threat analysis, adversary model, invariants, attack surfaces, git history, test analysis, or documentation quality. Those belong in the readiness report.
- **Factual only**: Extract facts from code. Do not speculate about risks or suggest mitigations.
- **Call chains**: Trace the full downstream path from entry point to leaf (token transfer, storage write, CPI, or external call). Use `→` notation. Stop at the first external protocol call or token transfer. Use concrete contract/program/module names, NOT interface or trait names.
- **Parameter trust**: Mark each parameter as `(user-controlled)`, `(user-signed)`, `(keeper-provided)`, or `(protocol-derived)`. User-controlled = the caller chooses the value freely. User-signed = value comes from a user's off-chain signature (or, on Solana, a `Signer` account the user must co-sign). Keeper-provided = the keeper selects the value (e.g., indexPrice from price feed). Protocol-derived = read from on-chain state.
- **Chain-aware visibility (what counts as an entry point):**
  - EVM: `external` / `public` non-view non-pure functions.
  - Solana/Anchor: every `pub fn` inside the `#[program]` module (each is an instruction). Native: every branch of the instruction dispatch in `process_instruction`.
  - Move: `public entry fun` and `entry fun` (transaction entry points) **and** `public fun` (callable from other modules / PTBs — these are entry points for composability even though not transaction-level). Private `fun` and `public(friend)`/`public(package)` are downstream.
  - Soroban: every `pub fn` in a `#[contractimpl]` block.
- **Chain-aware access classification:**
  - EVM: modifiers and `msg.sender` checks.
  - Anchor: a function is role-gated when the `Accounts` struct binds the privileged account as `Signer<'info>` **and** ties it to state via `has_one = …` / `constraint = …` / `seeds` including its key. A `Signer` alone with no binding is "any signer" — treat as permissionless with a signature requirement, and say so.
  - Aptos: role-gated when the body compares `signer::address_of(account)` to stored state, or when a capability/`friend` restricts the caller. A `&signer` parameter alone is not a gate.
  - Sui: role-gated when a capability object (`&AdminCap`) is a parameter, or `ctx.sender()` is compared to stored state. A `public fun` taking `&mut SharedObject` with neither is permissionless.
  - Soroban: role-gated when the function calls `require_auth()` on an `Address` that is read from storage (admin) or on the `Address` whose funds move (owner-gated). A `pub fn` with no `require_auth` is permissionless.
- **Exclude**: view/pure functions (`#[view]` in Move, `&Env`-only readers in Soroban, Anchor instructions that only read), interface/trait-only declarations, library internal functions, test-only (`#[cfg(test)]`, `#[test_only]`) code, mock contracts.
- **Include initializers separately**: see the Initialization section above.

# Invariant Map Template

Write `recon/invariants.md` using this structure. This file is a deep structural reference for invariants only — no threat analysis, no git history, no test analysis. It answers: "what must always be true, what enforces it, what breaks if it doesn't hold — and what the engine already said about it."

```markdown
# Invariant Map

> [Protocol Name] | [N] guards | [N] inferred | [N] not enforced on-chain | engine: [N] held · [N] BROKEN · [N] not checkable · [N] EXTERNAL

---

## 1. Enforced Guards (Reference)

Per-call preconditions. Heading IDs below (`G-N`) are anchor targets from recon.md attack surfaces.

[NatSpec/doc-comment-stated global invariants do NOT belong here — they route directly to §2/§3/§4 by shape.]

#### G-1
`require(...)` · `Contract.sol:LN` · [one-line purpose — *why* this guard exists / which invariant or trust boundary it enforces, not what it checks]

[Repeat `#### G-N` for every guard. Two lines per guard: (1) H4 heading with ID only — preserves the `#g-1` anchor used by cross-file links from recon.md — and (2) a single body line with three ` · `-separated fields: verbatim predicate in backticks, file:line in backticks, purpose prose. Separate guards with a blank line only — no `---` rules.]

[Chain note — what counts as a guard: EVM `require`/`assert`/`if … revert`; Anchor `require!`/`require_eq!`/`require_keys_eq!`, `#[account(constraint = …)]`, `has_one`, `Signer<'info>` (record as `Signer: authority` · `struct Withdraw` · purpose); Move `assert!(…, E_CODE)` and `abort`; Soroban `require_auth()`, `panic!`/`panic_with_error!` under an `if`, `.expect(…)` on a checked op. Quote the predicate verbatim in the source language.]

---

## 2. Inferred Invariants (Single-Contract)

Inferred invariants are derived from structural analysis of the source code. Each block below cites one of five extraction methods in its `Derivation` field:

- **Δ-pair (delta-pair) analysis** — two or more storage variables in the same function body that change by equal-and-opposite amounts (e.g. `totalSupply += x` paired with `balances[to] += x`), implying a conservation law like `A == Σ B[key]` or `A + B = const`. Chain equivalents: Anchor `vault.balance += x` with `**vault.lamports -= x`; Move `pool.reserve_x.join(...)` with `coin::take(&mut pool.reserve_y, ...)`; Soroban `set(&from, from_bal - amount)` with `set(&to, to_bal + amount)`.

- **Guard lift** — a `require` / `if-revert` / `assert!` / `require_auth` on a storage variable, promoted from a per-call precondition to a global property by checking that *every* other write site of that variable enforces an equivalent guard. If any write site lacks it, the lifted invariant is On-chain=**No** (and a candidate bug).

- **State-machine edge** — a storage variable that transitions through discrete values via patterns like `require(state == A); state = B`, with no reverse path. Captures one-shot latches (`setStrategy`) and lifecycle machines (`Pending → Claimable → Claimed`). Chain equivalents: Anchor `init` (account exists → cannot re-init), Soroban `instance().has(&Admin)` latch, Aptos `pending_admin` → `admin` two-step.

- **Temporal predicate** — a check tied to `block.timestamp`, `block.number`, `Clock`, `timestamp::now_seconds()`, `env.ledger().timestamp()/sequence()`, a stored duration/deadline, or a storage TTL.

- **Doc-comment-stated global property** — a developer-asserted invariant in a NatSpec `@invariant` tag, a `///` doc comment, or an inline comment (e.g. *"totalSupply always equals Σ balances"*). Routed directly to this section and then confirmed or contradicted by the structural scan.

Each block is classified into one of five **categories** by shape: `Conservation` · `Bound` · `Ratio` · `StateMachine` · `Temporal`. Category definitions at the end of §2.

---

#### I-1

`Category` · On-chain: **Yes/No** · Engine: **[held (engine, seed S, N iters) | BROKEN — VERIFIED-PROVEN | engine could not deploy: <reason> | validated plan (execution deferred) | not checkable by engine | EXTERNAL: <tool> <result> | not run]**

> [the global property claim — prose or code — in a blockquote for visual emphasis]

**Derivation** — [Δ-pair / guard-lift + write-sites / edge / temporal / doc-comment citation]

**If violated** — [consequence]

**Engine check** — [the exact command run, or why none applies: "shape not auto-detected (needs `.invar`: `sum(balances) == total`)" / "Move — `--dynamic` unsupported, route to Move Prover" / "constructor takes arguments — engine could not deploy" / "relative imports — engine could not deploy" / "Solana — plan validated, execution deferred in this release". For BROKEN: "PoC in recon.md §4".]

---

[Repeat `#### I-N` block for every inferred invariant. Fields separated by blank lines. The small category/on-chain/engine meta line sits between the heading and the claim so readers can scan status at a glance.]

**Categories:**
- **Conservation**: Two or more storage variables change by equal-and-opposite amounts in the same function body. Pattern: `Δ(A) = +x, Δ(B) = -x` → `A + B = const`. **This is the shape the EVM fuzzer auto-detects when the contract exposes ERC20-shaped `totalSupply()`/`balanceOf()`; it is also the Solana plan `token_conservation` shape.**
- **Bound**: A guard on a storage variable, *lifted to a global property* and enforced across every write site of that variable. Pattern: `require(x <= MAX)` enforced at every writer of `x` → `x ∈ [0, MAX]` globally. On-chain=**No** if any write site lacks the equivalent guard — that unguarded path is a potential bug. Per-call guards with no global implication stay in §1 and are NOT promoted here.
- **Ratio**: A storage variable is defined as a formula of other storage variables. Pattern: `withdrawAmount = totalBalance * shares / totalSupply`.
- **StateMachine**: A storage variable transitions through discrete values with guards preventing reversal. Pattern: `require(state == A); state = B`. **The EVM fuzzer's access-control check covers the special case "only the owner can change the owner"; the Solana plan `account_owner` shape covers "an account's owner never changes".**
- **Temporal**: A condition depends on `block.timestamp`, `block.number`, a chain clock, a duration/deadline variable, or a storage TTL.

**Doc-comment-routed blocks**: If an `I-N` block is derived from a doc-comment claim rather than structural scan, cite it as `NatSpec: Contract.sol:LN — "<verbatim comment>"` (or `doc: program.rs:LN — "…"`) in Derivation. Still run the structural scans afterward — they determine the On-chain=Yes/No verdict.

---

## 3. Inferred Invariants (Cross-Contract)

Trust assumptions that span contract/program/module boundaries. Each block cites both caller-side and callee-side code. Chain note: on Solana the boundary is a CPI or a shared account written by two instructions; on Move a cross-module call or a shared object mutated by two modules; on Soroban an `invoke_contract`/`Client` call.

---

#### X-1

On-chain: **Yes/No** · Engine: **[held | BROKEN — VERIFIED-PROVEN | not checkable by engine | EXTERNAL | not run]**

> [what the caller assumes about the callee's return value or state]

**Caller side** — `Caller.sol:LN` — [how the value is used]

**Callee side** — `Callee.sol:LN` — [write sites that could break the assumption]

**If violated** — [consequence]

**Engine check** — [command or reason; a cross-contract property is engine-checkable only when both sides compile into one deployable unit the fuzzer can drive, or an `.invar` file binds both sides' views]

---

## 4. Economic Invariants

Higher-order properties derived from combinations of §2 and §3 invariants. Every block traces back to concrete invariant IDs.

---

#### E-1

On-chain: **Yes/No** · Engine: **[held | BROKEN — VERIFIED-PROVEN | not checkable by engine | EXTERNAL | not run]**

> [economic property]

**Follows from** — `I-N` + `I-M` [+ `X-N`]

**If violated** — [consequence]

**Engine check** — [command or reason; if every source I-N/X-N was `held`, say "components held; composite not executed" — a held component is not a held composite]

```

## Rules for `invariants.md`

- **Heading-block format, NOT tables**: Each guard/invariant is a `#### G-N` / `#### I-N` / `#### X-N` / `#### E-N` heading. For §2/§3/§4 the heading is followed by bolded field labels separated by blank lines. For §1 the heading is followed by a single compact ` · `-separated body line (predicate · location · purpose). H4 headings produce slug anchors (`#g-1`, `#i-17`, …) that cross-file markdown links in recon.md resolve reliably in VS Code, GitHub, and every renderer. Inline `<a id>` anchors inside table cells do NOT work cross-file in VS Code — never use tables for referenced IDs.
- **No overlap with recon.md**: recon.md §3 is a pointer with counts; recon.md §4 holds the fuzz PoCs. This file has the full set and the per-invariant engine verdict.
- **§1 (Enforced Guards) is reference-only** for falsifiability. Each `G-N` entry is exactly two lines. The purpose field MUST explain *why* the guard exists / which invariant or trust boundary it enforces — not a restatement of what the predicate checks. A body line without a purpose field is insufficient.
- **If a guard implies a global property**, that global property goes to §2 as a separate `I-N` Bound block via the guard-lift methodology (see SKILL.md Step 2g, step 2 "Guard extraction and lift").
- **Doc-comment routing**: Developer-stated global invariants route DIRECTLY to §2, §3, or §4 by shape — never to §1.
- **Derivation discipline**: every inferred block MUST cite exactly one of:
  - `Δ-pair: Contract.sol:Lx ↔ Contract.sol:Ly` (conservation)
  - `guard-lift: <verbatim require/if/assert> + <write-site enumeration>` (bound / ratio — the lift citation MUST include all write sites of the constrained variable; a single-callsite guard is not a valid lift)
  - `edge: State@Lx → State@Ly` (state machine)
  - `temporal: <verbatim timestamp / deadline / TTL check>` (temporal)
  - `NatSpec: Contract.sol:LN — "<verbatim comment>"` / `doc: file:LN — "…"` (developer-stated global)
  Blocks that cannot cite one of these are dropped. No "implied by semantics."
- **On-chain field**: Yes or No only. If partially enforced, split into two blocks — one for what IS enforced (Yes), one for the gap (No). Guard-lift blocks with any unguarded write site are On-chain=No.
- **Engine field**: exactly one of `held (engine, seed S, N iters)`, `BROKEN — VERIFIED-PROVEN`, `engine could not deploy: <reason>`, `validated plan (execution deferred)`, `not checkable by engine`, `EXTERNAL: <tool> <result>`, `not run`. `held` is only valid when the fuzzer printed `✓ no violation found in N runs` for a contract whose auto-detected invariant *is this property* (ERC20 conservation, monotonic accumulator, owner-only-changes-owner, reentrancy) or an `.invar` file stated it. A `✓` for a *different* auto-detected invariant does not make this one `held`. `BROKEN` requires the `✗ [PROVEN]` output in recon.md §4. A `⚠ not analysed` or any `Error:` line is `not checkable by engine` with the reason quoted; a constructor-revert panic or an unresolved-import solc error is `engine could not deploy: <reason>`. **Only EVM blocks can be `held` or `BROKEN` in truent 0.6.0**: the Solana path validates the IDL + plan and then prints `IDL and plan are valid (N fuzzable instruction(s)), but this release cannot execute them` — that is `validated plan (execution deferred)`, and Move/Soroban `--dynamic` errors outright.
- **No fabrication**: if an invariant cannot be traced to concrete code (or a doc-comment quote), omit it. If an engine result cannot be pasted verbatim, it did not happen.
- **Cross-contract blocks (§3)**: must cite both sides — the caller-side usage AND the callee-side write sites. Only include blocks where both sides are inside the scope files (do not speculate about out-of-scope contracts).
- **Economic blocks (§4)**: must derive from one or more §2/§3 blocks. The `Follows from` field must reference specific I-N / X-N IDs. Economic invariants that cannot be traced to concrete single-contract invariants are dropped.
- **Anchor slug normalization**: When recon.md attack surfaces link to `invariants.md#x-4`, use LOWERCASE because VS Code and GitHub normalize heading IDs to lowercase. The heading itself can be uppercase (`#### X-4`) — only the link fragment needs lowercasing.

# Architecture Diagram Guide

## architecture.json Format

```json
{
  "title": "[Protocol] Architecture",
  "nodes": [
    {"id": "unique_id", "label": "DisplayName", "subtitle": "One-word role", "type": "actor|protocol|external", "row": 0}
  ],
  "edges": [
    {"from": "source_id", "to": "target_id", "label": "action description"}
  ],
  "groups": [
    {"label": "Group Name", "nodes": ["id1", "id2"]}
  ]
}
```

### Node types
- `actor`: users/roles — pill shape. Include the chain-level admin (upgrade authority / `UpgradeCap` holder / Soroban admin) as an actor when it exists.
- `protocol`: in-scope contracts / programs / modules — blue accent stripe
- `external`: out-of-scope (oracles, token programs, framework modules, other protocols) — amber accent stripe. On Solana, `spl_token` / `system_program` are external nodes only when a CPI to them is a primary flow; on Move, framework modules (`coin`, `balance`) are omitted unless they hold the value.

### subtitle
Optional short role description as second line (e.g. "Coordinator", "Price Feed"). For composite nodes, list individual contracts (e.g. "Aave / Ethena / Lido / Lista"). For mixed-chain repos, put the chain in the subtitle of each protocol node ("Vault · solana").

### row
Assign rows to **minimize edge distance**, not by node type. Place each node on the row adjacent to its primary caller. Actors typically land at the top, leaf dependencies at the bottom, but an external node called only from row 1 belongs on row 2 — NOT on a distant "externals" row.

### groups
Optional. Groups related nodes under a labeled enclosure (e.g. "Vault Layer").

**Group containment rule (CRITICAL):** Every node must be either (a) inside exactly one group, or (b) on a row that has NO group box. The SVG generator draws group boxes around all rows that contain grouped nodes. If an ungrouped node sits on the same row as a group, it will visually escape or overlap the group boundary. To fix: either add the node to the appropriate group, or move it to a different row. When deciding which group a node belongs to, classify by **primary caller** — e.g., an ACL contract called by the coordinator belongs in the coordinator's group, not in a downstream infrastructure group.

---

## Budgets & Layout Rules

### Node & edge budgets

Scale budget based on in-scope contract count (excluding interfaces):

| In-scope contracts | Max nodes | Max edges | Max per row |
|--------------------:|----------:|----------:|------------:|
| ≤10                | 12        | 14        | 4           |
| 11–20              | 16        | 18        | 4           |
| 21–35              | 20        | 22        | 5           |
| 36+                | 24        | 26        | 5           |

**Prioritize completeness over compression.** Every contract that holds funds, gates access, or sits on a critical call path should be visible — either as its own node or clearly named in a composite node's subtitle.

### Compositing rules (when to combine contracts into one node)

Apply in order — use the first tier that fits within the node budget:
- **Tier 1 — Always composite**: Contracts in the same subsystem with identical caller AND callee. Use subsystem name as label, list contracts in subtitle.
- **Tier 2 — When budget requires**: Contracts with same primary caller OR callee. Helper/satellite contracts composite into their parent node.
- **Tier 3 — Last resort**: Same-subsystem contracts with same trust level but different callers/callees.
- **Never composite across trust levels** — combining permissionless and admin-only hides trust boundaries.

### Actor and external node rules

- **Combine actors** only when they share the same trust level AND capabilities. Keep actors separate when trust levels differ.
- **External dependencies** that are sole data sources for critical logic (oracles, price feeds) should be their own node. Others can be composited by type when budget is tight.

### Same-row arc rules
- **≤2 same-row arcs per node**. If 3+ needed, move one target to adjacent row.
- **Balance directions**: 2 same-row arcs from one node → one LEFT, one RIGHT.
- **Automatic below-routing**: The SVG generator detects when a same-row arc would cross intermediate boxes and routes it below the row instead of above. Multiple below-arcs are staggered at different depths to avoid overlapping.

### Hub node layout
When a node has 3+ same-row connections (a "hub"), position it **centrally** among its same-row targets in the JSON `nodes` ordering. This minimizes arc distances and lets the generator route short connections above and long ones below.

### Edge rules
- **Every edge label must be unique**. Never repeat the same label on multiple edges.
- **Labels: 2-3 words max**.
- **No row-skipping edges**. Every edge connects adjacent rows or same row. If an edge would span 2+ rows, move the target to an adjacent row.
- Show primary interaction flows only — not every internal call.

---

## SVG Generation & Validation

### Generate
```bash
python3 $SKILL_DIR/scripts/generate_svg.py recon/architecture.json recon/architecture.svg
```

### Render to PNG for inspection
Try in order (use first that works):
```bash
convert -density 300 recon/architecture.svg /tmp/architecture-preview.png
rsvg-convert recon/architecture.svg -o /tmp/architecture-preview.png
python3 -c "import cairosvg; cairosvg.svg2png(url='recon/architecture.svg', write_to='/tmp/architecture-preview.png', scale=3)"
```
Then `Read` the PNG. If no renderer is available, skip the validation loop.

### Audit checklist (max 3 iterations)

1. **Structure**: Top-to-bottom flow? Actors top, externals bottom, core middle?
2. **Edge labels**: Readable font (≥4.5), dark fill (#1E293B), sitting on their arrows (not pushed away).
3. **Edge routing**: No row-skipping edges, no arrows through boxes. Same-row arcs balanced (one LEFT, one RIGHT). Long same-row arcs that would cross intermediate boxes should route below (the generator does this automatically — verify visually).
4. **No overlapping labels**: Stagger y by ≥8 units if bounding boxes overlap.
5. **Groups**: All group rects aligned (same x-edge/width). No ungrouped node on a row that has a group box.
6. **Centering**: Nodes roughly centered on canvas, balanced across rows.

### Fix types
- **JSON-level** (regenerate): row assignments, node ordering, edges, groups → edit JSON, re-run `generate_svg.py`, re-render.
- **SVG-level** (post-process): label font/color/position → edit SVG directly, re-render.

### Cleanup
```bash
rm -f recon/architecture.json recon/git-security.json recon/engine-threat-model.json recon/engine-exposure.json recon/engine-deps.json /tmp/architecture-preview.png
```
Keep `recon/engine-findings.json` — it is the machine-readable twin of recon.md §4 and the input the `truent-audit` skill expects. Keep `recon/plan.json` only if the engine validated it (Solana); otherwise remove it too.
