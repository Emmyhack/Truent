# truent-fuzz

Stateful invariant fuzzing for smart contracts, engine-first.

| Path | What you get | Evidence |
|---|---|---|
| **Section A — native (default)** | `truent fuzz <file.sol> --dynamic --chain evm [--invariants props.invar]`: auto-detected conservation / monotonicity / access-control / reentrancy invariants plus your own `.invar` properties, adversarial sequences, minimal-PoC shrinking. One binary, no harness. | `VERIFIED-PROVEN` |
| **Section B — suite generation** | A fizz-grade Echidna/Medusa suite under `test/fizz/` + `fizz_data/`: scaffold, setup wiring, handlers, Medusa coverage loop, five invariant-discovery agents, synthesizer, implementers, campaigns, Foundry repros, report, drift snapshot. The synthesizer also emits `fizz_data/properties.invar` so the native fuzzer checks the same properties. | `EXTERNAL` (upgraded to `VERIFIED-PROVEN` by the native cross-check) |
| **Section C — sub-commands** | `truent fuzz convert` (English → Solidity properties), `truent fuzz sync` (drift reconciliation). | — |
| **Section D — other chains** | Solana: IDL + `plan.json` native fuzzing (`token_conservation`, `account_owner`) and Anchor test harnesses; Move: Prover `spec` blocks + `aptos`/`sui move test`; Soroban: `soroban_sdk::testutils` + `proptest` harness. Move and Soroban are verified statically only by Truent. | Solana plan: `VERIFIED-PROVEN` once the deferred backend ships (0.6.0 validates the plan but does not execute it); the rest: `EXTERNAL` |

Start with `SKILL.md`. References: `references/dsl.md` (what the engine's
`.invar` grammar really accepts), `references/chains/*.md`, and the fizz-derived
handler/property/setup guides.

## Attribution

Section B, the agents, the EVM templates and the JS/shell scripts are adapted
from the `fizz` skill in [pashov/skills](https://github.com/pashov/skills)
(MIT, Copyright (c) 2024 AI Skills Contributors). Each adapted file carries an
attribution line; `templates/README.md` carries the one for `medusa.json`.
Full notice: `skills/THIRD_PARTY_NOTICES.md`. Changes: Truent's native fuzzer
is the default path, evidence tiers, the `.invar` cross-check, and the
Solana/Move/Soroban extensions.
