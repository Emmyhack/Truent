<!-- Adapted from pashov/skills fizz/agents/implementers/specific-property-implementer.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent native path first, multi-chain. -->
# Agent 7B: Specific Property & Handler Wiring Implementer

**Role**: Implement specific (per-handler) properties into Properties.sol and wire ghost updates + snapshot calls + property assertions into handler files.

**Spawn config**: `general-purpose` agent, `model: "{AGENT_MODEL}"` (see SKILL.md "Subagent Model" section — defaults to `sonnet`, `opus` under `--max`). Spawned in parallel with Agent 7A.

---

## Prompt

You implement SPECIFIC properties and wire all ghost/snapshot/property calls into the handler files.

## Your Inputs
- Target chain: `{CHAIN}`. Read: `{SKILL_DIR}/references/property-generation.md` — common knowledge on ghosts, snapshots, properties, naming, and assertion helpers
- Read: `{META_DIR}/property-plan.md` — implement Specific Properties + Handler Wiring Plan
- Read + Edit: `{SUITE_DIR}/Properties.sol` (add specific property functions as internal)
- Read + Edit: `{PROJECT_ROOT}/PROPERTIES.md` (flip `[ ]` → `[x]` for each SP-* property you actually implement AND wire into a handler; flip `[ ]` → `[-]` for any SP-* property you skip or leave as a TODO/commented stub — `[-]` means "do not auto-touch", so `truent fuzz convert` will not retry it later)
- Read + Edit: `{SUITE_DIR}/handlers/<Contract>Handler.sol` (wire ghost updates, snapshot calls, property calls)
- Read: `{SUITE_DIR}/Base.sol` (for ghosts struct and actor array)
- Read: `{SUITE_DIR}/Snapshots.sol` (for snapshot state and before/after access)
- Read: Source contract files (for actual function signatures)

## Implementation Rules

These rules expand on the general property implementation instructions in `property-generation.md` with specifics for the per-handler properties and wiring.

Specific properties are `internal` functions called at the end of relevant handlers. They check postconditions for specific operations.

### MANDATORY: Spec ID doctag

Every property function you write MUST have its Spec ID as the first thing in its natspec, on its own line, in this exact form:

```solidity
/// @notice SP-NN: <one-line description>
function property_<name>() internal { ... }
```

The `SP-NN:` token (with the colon) is how `truent fuzz convert` and future runs locate the existing implementation of a Spec ID for re-generation or deletion. Without it, automation cannot reconcile the spec with the code. This is a hard requirement, not a style preference.

```solidity
// ――――――――――――――――――― Specific properties ――――――――――――――――――――
// These properties must hold after specific function calls
// They MUST BE INTERNAL and called at the end of the relevant handlers

function property_depositIncreasesShares() internal {
    gt(
        stateAfter.vaultTotalSupply,
        stateBefore.vaultTotalSupply,
        "Deposit did not increase total supply"
    );
}

function property_withdrawDecreasesAssets() internal {
    lt(
        stateAfter.vaultTotalAssets,
        stateBefore.vaultTotalAssets,
        "Withdraw did not decrease total assets"
    );
}

function property_roundTripNoFreeValue(uint256 balanceBefore, uint256 balanceAfter) internal {
    lte(
        balanceAfter,
        balanceBefore,
        "Round-trip created free value"
    );
}
```

## Wiring Specific Property Calls into Handlers

Call specific properties at the END of the handler, AFTER ghost updates and snapshotAfter():

```solidity
function vault_withdraw_clamped(uint256 assets) public {
    // ... clamping logic ...
    vault_withdraw(assets);
}

function vault_withdraw(uint256 assets) public asActor {
    snapshotBefore();

    vm.prank(address(actor));
    vault.withdraw(assets);

    snapshotAfter();
    ghosts.totalWithdrawn += assets;

    property_withdrawDecreasesAssets();
}
```

## Round-Trip / Liveness Properties

For round-trip and liveness checks that need to execute a multi-step sequence and then revert (no state pollution), implement them as handler-level functions that test the sequence inline:

```solidity
/// @notice Liveness: every actor with balance > 0 can withdraw
function property_allCanWithdraw() public {
    for (uint256 i; i < NUMBER_OF_ACTORS; i++) {
        uint256 bal = vault.balanceOf(address(actors[i]));
        if (bal > 0) {
            vm.prank(address(actors[i]));
            try vault.redeem(bal, address(actors[i]), address(actors[i])) {}
            catch { t(false, "Liveness: user cannot withdraw"); }
        }
    }
}
```

Note: Stateless properties are properties that must not pollute state, as they are extreme cases that will make subsequent calls revert. For stateless properties, use `try/catch` patterns or implement them as view-approximations where possible. For true round-trip tests, consider using `FoundryTester.sol` for Foundry-based scenario tests.


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

For every `SP-*` property:
- If you implemented it with a real assertion AND wired it into the relevant handler: change `- [ ] **SP-NN** ...` to `- [x] **SP-NN** ...`
- If you skipped it or left it as a TODO/commented stub: change `- [ ] **SP-NN** ...` to `- [-] **SP-NN** ...`. This marks it as "do not auto-touch" so `truent fuzz convert` will not retry it later.

Match by exact ID. Do NOT renumber, reorder, or rewrite other lines. Never edit the `DSL:` line of an entry; if you discover a DSL expression names a getter that does not exist, report it in your return line so the orchestrator can fix `properties.invar` before Step 9f.

Return: `DONE: X specific properties implemented (Y marked [x], Z marked [-] as skipped/TODO). Handler wiring: A handlers updated with ghost updates, B with snapshot calls, C with property assertions.`
