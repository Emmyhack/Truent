# truent-fuzz templates

Skeletons the skill copies or points at. Nothing here is engine output; each
file is a starting point that the steps in `SKILL.md` refine.

## `evm/` — the Echidna/Medusa suite scaffold (Section B)

Copied verbatim into `{SUITE_DIR}` (default `test/fizz/`) by
`scripts/generate_suite.js`; `echidna.yaml` and `medusa.json` go to the
project root. Adapted from pashov/skills `fizz/templates/…` (MIT, Copyright
(c) 2024 AI Skills Contributors); every file carries its own attribution
comment except `medusa.json`, which JSON cannot carry — **this paragraph is
the attribution for `evm/medusa.json`** (adapted from
`fizz/templates/medusa.json`; unchanged apart from location).

| File | Role |
|---|---|
| `Actor.sol` | Actor contract (ETH holder, `forceSendETH`, ERC-721/1155 receivers, flash-loan callback). |
| `Base.sol` | Constants, `Ghosts` struct, actors, `asActor`/`asAdmin`, `setup()` FIXMEs, helpers. |
| `Snapshots.sol` | `State` struct + `snapshotBefore()` / `snapshotAfter()`. |
| `Properties.sol` | Global (`public property_*`) and specific (`internal property_*`) invariants. |
| `handlers/Handlers.sol` | Aggregator inheriting every `<Contract>Handler`; actor switching. |
| `FuzzTester.sol` | Echidna/Medusa entry point (never edited). |
| `FoundryTester.sol` | Foundry debug harness; Step 11 appends `test_repro_*`. |
| `README.md` | Copied into the generated suite as its runbook. |
| `utils/*.sol` | `Clamp`, `PropertiesAsserts`, `Hevm`, `Logger`, `Math`, `StringUtils`, `Deployer`, `DecimalPrinter`, `EnumerableSet`, `MockERC20`. |
| `echidna.yaml`, `medusa.json` | Runner configs targeting `FuzzTester`, corpora under `fizz_data/`. |

Inheritance chain and per-step roles: `references/template-map.md`.

## `solana/plan.example.json` — a complete fuzz plan (Section D)

The shape `truent fuzz <idl> --dynamic --chain solana --plan` consumes
(schema: `crates/dynamic/solana/src/config.rs`): genesis accounts,
signer/writable/readonly pools, pins, and the two invariant types
(`token_conservation`, `account_owner`). Pubkeys in the example are real
well-known program/mint addresses used only as syntactically valid base58;
replace every one. `scripts/emit_solana_plan.py` writes this file from an IDL
plus `property-plan.json`. In truent 0.6.0 the engine validates such a plan
(`IDL and plan are valid (N fuzzable instruction(s))`) but defers execution to a
later release; see `references/chains/solana.md`.

## `move/aptos_invariants.move`, `move/sui_invariants.move` (Section D)

Aptos: a module skeleton with `spec` blocks (`invariant`, `aborts_if`,
`ensures`) for `aptos move prove` and `#[test]` / `#[expected_failure]`
functions for `aptos move test`. Sui: a `#[test_only]` module using
`sui::test_scenario` for `sui move test`. Results are `EXTERNAL`; Truent
verifies Move statically only.

## `soroban/invariants_test.rs` (Section D)

A `#[cfg(test)]` module built on `soroban_sdk::testutils` with a global
invariant helper, a scoped-auth access-control test and a `proptest`
round-trip property, for `cargo test`. `EXTERNAL`; Truent verifies Soroban
statically only.

## What is deliberately absent

No template pretends to be a Move or Soroban *fuzzer* driven by Truent: the
engine has no execution backend for those chains (`--dynamic --chain
move|soroban` is an error). Solana has no DSL template because the plan
accepts exactly two invariant types.
