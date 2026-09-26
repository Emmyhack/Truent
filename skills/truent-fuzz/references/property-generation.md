<!-- Adapted from pashov/skills fizz/references/property-generation.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent native path first, multi-chain. -->
# Property Generation

Common instructions for generating properties, ghost variables, snapshot state, and harness contracts after handlers are in place. These rules apply to both global properties and specific properties.

This phase runs after handler generation. The agent reads the target contract source files and the generated handlers to produce:

**Ghost variables** in `Base.sol` — track cumulative state not directly readable from the contract.
**Ghost updates** wired into per-contract handler files (`handlers/<Contract>Handler.sol`).
**Snapshot state** in `Snapshots.sol` — before/after state for delta-based properties.
**Harness contracts** in `{SUITE_DIR}/harness/` — for accessing private/internal state when necessary.
**Properties** in `Properties.sol` — global and function-specific invariant checks, called explicitly from handlers or shared helper functions.

## 1. Naming convention

All property functions must start with `property_` prefix.

## 2. Ghost Variables

### What they are

Ghost variables track state that the contract doesn't expose directly but that is needed to write meaningful invariants. Common examples:

- `ghosts.totalDeposited` — sum of all deposits across all actors
- `ghosts.totalWithdrawn` — sum of all withdrawals
- `ghosts.totalMinted` — cumulative minted amount
- `ghosts.lastTimestamp` — timestamp of last state-changing call

### Where they go

In `Base.sol`, inside the `Ghosts` struct:

```solidity
struct Ghosts {
    uint256 totalDeposited;
    uint256 totalWithdrawn;
    uint256 totalMinted;
}
```

Replace the placeholder `uint256 _placeholder;` with real ghost variables.

### How to choose ghosts

Read the source contracts and identify:
- **Accumulative operations**: deposits, withdrawals, mints, burns, transfers — track running totals.
- **Counter operations**: number of users, number of positions — track counts.
- **Extreme values**: max/min seen amounts — track with `max()`/`min()` in handlers.

Only add ghosts that are needed by at least one property. Don't add speculative ghosts.

### Wiring ghost updates into handlers

Add ghost updates AFTER the external call in each handler (so they only execute on success).

For clamped handlers that forward to unclamped: put ghost updates in the UNCLAMPED handler (since both clamped and direct fuzzer calls go through it).

Ghost updates go in the per-contract handler files (`handlers/<Contract>Handler.sol`). Example:

```solidity
function vault_deposit(uint256 assets) public asActor {
    assets = clampBetween(assets, 1, token.balanceOf(address(actor)));

    vm.prank(address(actor));
    vault.deposit(assets);

    ghosts.totalDeposited += assets;
}
```

## 3. Snapshot State

### Purpose

`Snapshots.sol` captures state before and after a handler call, enabling delta-based properties like "user balance decreased by exactly the deposit amount."

### What to track

Read the target contracts and populate the `State` struct with:
- Key balances: `token.balanceOf(address)`, `contract.balanceOf(address)`
- Protocol state: `totalSupply`, `totalAssets`, `totalShares`
- Actor state: balances of the current actor

Example:

```solidity
struct State {
    uint256 actorTokenBalance;
    uint256 vaultTotalAssets;
    uint256 vaultTotalSupply;
}

function _takeSnapshot(State storage state) private {
    state.actorTokenBalance = token.balanceOf(actor);
    state.vaultTotalAssets = vault.totalAssets();
    state.vaultTotalSupply = vault.totalSupply();
}
```

Snapshot reads must NOT revert. Use try/catch for any call that could fail.

### Wiring snapshots into handlers

For handlers that need before/after comparison, call `snapshotBefore()` before the external call and `snapshotAfter()` after it. The full wiring sequence in an unclamped handler is:

1. `snapshotBefore()` — capture state before the call
2. External call — the actual protocol interaction
3. `snapshotAfter()` — capture state after the call
4. Ghost updates — track derived state (only executes on success)
5. Property assertions — call specific properties that check deltas

```solidity
function vault_deposit(uint256 assets) public asActor {
    snapshotBefore();

    vm.prank(address(actor));
    vault.deposit(assets);

    snapshotAfter();
    ghosts.totalDeposited += assets;
    property_depositIncreasesShares(assets);
}
```

Do NOT add snapshot calls to every handler — only where delta-based properties exist. They cost gas and slow fuzzing.

## 4. Harness Contracts

If a property requires access to `private` or `internal` state that is not reachable via the public interface, create a harness contract:

- Place it at `{SUITE_DIR}/harness/{TargetContract}Harness.sol`
- The harness inherits from the target contract and adds only the minimal getter(s) needed
- Update `Base.sol` to declare and instantiate `{TargetContract}Harness` instead of `{TargetContract}` — the harness is ABI-compatible so handlers and properties continue to work unchanged
- Only create a harness when strictly necessary — prefer public interface access

## 5. Assertion helpers

These are the assertion helpers from `utils/PropertiesAsserts.sol`:

| Function | Check |
|---|---|
| `t(bool, string)` | assert true |
| `eq(a, b, reason)` | `a == b` |
| `neq(a, b, reason)` | `a != b` |
| `gt(a, b, reason)` | `a > b` |
| `gte(a, b, reason)` | `a >= b` |
| `lt(a, b, reason)` | `a < b` |
| `lte(a, b, reason)` | `a <= b` |

All have both `uint256` and `int256` overloads. All emit descriptive failure events before `assert(false)`.

## 6. Truent DSL mapping rules (native cross-check)

Every property in `property-plan.md` / `PROPERTIES.md` carries a `DSL` field. When it is non-null, the same property is also checked by Truent's native fuzzer with no harness:

```bash
truent fuzz <Contract.sol> --dynamic --chain evm --iterations 1000 --seed 1 --invariants fizz_data/properties.invar
```

Rules for deciding `DSL` (full grammar and binding rules in `references/dsl.md`):

| Property shape | `DSL` | Reason |
|---|---|---|
| State predicate over zero-argument public views of one contract (`totalAssets() <= cap()`) | `total_assets <= cap` | binds directly |
| Mapping read with a literal key (`balanceOf(address(0)) == 0`) | `balanceOf(0) == 0` | literal-argument calls bind to a getter of that arity |
| ERC20 conservation, monotonic accumulator, owner stability | `null` | auto-detected by the engine without a file; still implement in Solidity |
| Sum over the actor set, `forAll`, `exists` | `null` | **`sum()` / `forAll()` do not exist at runtime** — the grammar has no quantifiers. Expose an aggregate getter on a harness contract if you need the native check |
| Before/after delta, round-trip, liveness ("must not revert"), multi-step scenario | `null` | the DSL has no `old()`/snapshots; these stay in `Snapshots.sol` + handlers |
| Uses `%`, strings, addresses, `msg.sender` | `null` | not in the grammar |
| Any non-EVM chain | `null` | the DSL binds EVM getters only |

Identifiers are matched to getters ignoring case and underscores (`total_supply` ⇒ `totalSupply()`). An identifier that does not bind is a hard error for the whole file, so a wrong `DSL` is worse than `null`. Values are compared as unsigned 128-bit integers; keep products below 2^128 or the check is undecidable for that state.

`.invar` file conventions: one block per property, named `GL_NN_<camelName>` / `SP_NN_<camelName>` (identifiers cannot contain `-`), preceded by a `// GL-NN <GUARANTEE> — <english>` comment; one file per contract (`properties.invar` for the primary target, `properties.<Contract>.invar` for others).
