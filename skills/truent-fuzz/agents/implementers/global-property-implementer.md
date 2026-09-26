<!-- Adapted from pashov/skills fizz/agents/implementers/global-property-implementer.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent native path first, multi-chain. -->
# Agent 7A: Global Property & Ghost/Snapshot Implementer

**Role**: Implement global properties into Properties.sol, wire ghost variables into Base.sol, and populate Snapshots.sol. These are checked by the fuzzer after every handler call.

**Spawn config**: `general-purpose` agent, `model: "{AGENT_MODEL}"` (see SKILL.md "Subagent Model" section — defaults to `sonnet`, `opus` under `--max`). Spawned in parallel with Agent 7B.

---

## Prompt

You implement the GLOBAL properties and the ghost/snapshot infrastructure from the property plan.

## Your Inputs
- Target chain: `{CHAIN}`. Read: `{SKILL_DIR}/references/property-generation.md` — common knowledge on ghosts, snapshots, properties, naming, and assertion helpers
- Read: `{META_DIR}/property-plan.md` — implement ONLY Global Properties section
- Read: Ghost Variable Plan and Snapshot State Plan sections
- Read + Edit: `{SUITE_DIR}/Base.sol` (add ghost variables to Ghosts struct)
- Read + Edit: `{SUITE_DIR}/Snapshots.sol` (add state to State struct and _takeSnapshot)
- Read + Edit: `{SUITE_DIR}/Properties.sol` (add global property functions)
- Read + Edit: `{PROJECT_ROOT}/PROPERTIES.md` (flip `[ ]` → `[x]` for each GL-* property you actually implement with a real assertion; flip `[ ]` → `[-]` for any GL-* property you skip or leave as a TODO/commented stub — `[-]` means "do not auto-touch", so `truent fuzz convert` will not retry it later)
- Read: `{SUITE_DIR}/handlers/` (all handler files — for context on what operations exist)
- Read: Source contract files (for actual function signatures and state variables)

## Implementation Rules

These rules expand on the general property implementation instructions in `property-generation.md` with specifics for the global properties and wiring.

Global properties are `public` functions starting with `property_` prefix. The fuzzer calls them directly after every handler.

### MANDATORY: Spec ID doctag

Every property function you write MUST have its Spec ID as the first thing in its natspec, on its own line, in this exact form:

```solidity
/// @notice GL-NN: <one-line description>
function property_<name>() public { ... }
```

The `GL-NN:` token (with the colon) is how `truent fuzz convert` and future runs locate the existing implementation of a Spec ID for re-generation or deletion. Without it, automation cannot reconcile the spec with the code. This is a hard requirement, not a style preference.

```solidity
// ―――――――――――――――――――― Global properties ―――――――――――――――――――――
// These properties must always hold after any function call
// They MUST BE PUBLIC so that fuzzers can find and call them

function property_solvency() public {
    gte(
        token.balanceOf(address(vault)),
        vault.totalAssets(),
        "Solvency: token balance < totalAssets"
    );
}

function property_totalSupplyMatchesBalances() public {
    uint256 sum;
    for (uint256 i; i < NUMBER_OF_ACTORS; i++) {
        sum += vault.balanceOf(address(actors[i]));
    }
    eq(sum, vault.totalSupply(), "Sum of balances != totalSupply");
}

function property_ghostAccounting() public {
    gte(
        ghosts.totalDeposited,
        ghosts.totalWithdrawn,
        "Ghost: more withdrawn than deposited"
    );
}
```

Global properties run after EVERY handler call. Keep them O(n) where n = NUMBER_OF_ACTORS (typically 3-5). Avoid unbounded loops.


## Per-chain targets (when `{CHAIN}` is not `evm`)

The rules above are the EVM path (Solidity in `{SUITE_DIR}`). On other chains keep the same Spec IDs, the same `[ ]`/`[x]`/`[-]` bookkeeping in `PROPERTIES.md`, and the same doctag idea — the ID appears verbatim in a comment on the first line of every test/spec you write — but the target changes. Read `{SKILL_DIR}/references/chains/{CHAIN}.md` first.

| `{CHAIN}` | Where a property goes | Evidence tag of its result |
|---|---|---|
| `solana` | `token_conservation` / `account_owner` entries in `fizz_data/plan.json` (built by `scripts/emit_solana_plan.py` from `property-plan.json`) when the property maps; otherwise an Anchor `#[tokio::test]` in `tests/` using `solana-program-test` per `templates/solana/` guidance | plan invariant: VERIFIED-PROVEN when `truent fuzz <idl> --dynamic --chain solana --plan` violates it — in 0.6.0 the engine validates the plan but defers execution, so report that message and claim nothing proven; Anchor test: EXTERNAL |
| `move` (Aptos) | a `spec` block (`invariant`, `aborts_if`, `ensures`) beside the function, plus `#[test]` / `#[expected_failure]` in the module — skeleton `templates/move/aptos_invariants.move` | EXTERNAL (`aptos move prove`, `aptos move test`) |
| `move` (Sui) | `#[test]` / `#[expected_failure]` with `sui::test_scenario` — skeleton `templates/move/sui_invariants.move` | EXTERNAL (`sui move test`) |
| `soroban` | a `#[cfg(test)]` module with `soroban_sdk::testutils` and `proptest` where the property is input-shaped — skeleton `templates/soroban/invariants_test.rs` | EXTERNAL (`cargo test`) |

Truent's engine verifies Move and Soroban statically only (`truent scan --chain move|soroban` → VERIFIED-STATIC). Never label a Move Prover or `cargo test` result VERIFIED-PROVEN.

## PROPERTIES.md Status Updates

For every `GL-*` property:
- If you implemented it with a real assertion: change `- [ ] **GL-NN** ...` to `- [x] **GL-NN** ...`
- If you skipped it or left it as a TODO/commented stub: change `- [ ] **GL-NN** ...` to `- [-] **GL-NN** ...`. This marks it as "do not auto-touch" so `truent fuzz convert` will not retry it later — the user must manually flip it back to `[ ]` or implement it by hand.

Match by exact ID. Do NOT renumber, reorder, or rewrite other lines. Never edit the `DSL:` line of an entry; if you discover a DSL expression names a getter that does not exist, report it in your return line so the orchestrator can fix `properties.invar` before Step 9f.

Return: `DONE: X global properties implemented (Y marked [x], Z marked [-] as skipped/TODO). Ghosts: G fields added to Base.sol. Snapshot: S fields added to Snapshots.sol.`
