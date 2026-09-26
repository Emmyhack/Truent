# Soroban harness guide

**Truent verifies Soroban statically only.** `truent fuzz --dynamic --chain
soroban` is an engine error (`--dynamic fuzzing currently only supports
--chain evm (Move/Soroban need their own execution backends, not yet
built)`). The engine gives you `truent scan <crate> --chain soroban --output
json` → `VERIFIED-STATIC` (real bug shapes in
`crates/analyzer/soroban/tests/corpus/bad/`, e.g. `missing_require_auth`).

Every dynamic result here is `EXTERNAL`: a Rust `#[cfg(test)]` module run by
`cargo test`.

## Harness shape

Skeleton: `$SKILL_DIR/templates/soroban/invariants_test.rs`. Put it in the
contract crate as `src/fizz_properties.rs` behind `#[cfg(test)] mod
fizz_properties;`, or as `tests/fizz_properties.rs`.

Building blocks from `soroban_sdk::testutils`:

- `Env::default()` — an in-memory host; `env.mock_all_auths()` to satisfy
  `require_auth` for every address, or `env.mock_auths(&[MockAuth{…}])` to
  authorise exactly one call (use this to prove access-control properties:
  the un-mocked caller must panic).
- `Address::generate(&env)` — actors.
- `env.register(Contract, ())` / `ContractClient::new(&env, &id)` —
  deployment and typed client.
- `env.ledger().with_mut(|l| { l.timestamp += 3600; l.sequence_number += 10; })`
  — time travel (`use soroban_sdk::testutils::Ledger`).
- `client.try_<fn>(…)` — returns `Result` instead of panicking; use it for
  liveness ("must succeed") and expected-failure properties.
- `env.budget().reset_default()` when a property drives long sequences.

| fizz category | Soroban target |
|---|---|
| HIGH_LEVEL state predicate (conservation, solvency) | a helper `fn check_invariants(&client, &actors)` called after every step of a scripted sequence |
| STATE_TRANSITION / VARIABLE_TRANSITION | `let before = client.total(); … ; assert!(client.total() == before + amount)` |
| Access control | `#[should_panic]` or `assert!(client.try_set_fee(&non_admin, &1).is_err())` with `mock_auths` scoped to the admin only |
| Input-shaped properties (round-trip, rounding, bounds) | `proptest!` strategies over `i128` amounts, with the invariant helper as the oracle |
| Liveness | `assert!(client.try_withdraw(&user, &bal).is_ok())` for every actor with balance |

FORMAT skeleton:

```rust
// GL-01 SHOULD-HOLD — sum of balances == total supply after any sequence
#![cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, Env};
use crate::{Token, TokenClient};

fn setup() -> (Env, TokenClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(Token, ());
    let client = TokenClient::new(&env, &id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin, user)
}

fn gl_01_holds(client: &TokenClient, actors: &[Address]) -> bool {
    let sum: i128 = actors.iter().map(|a| client.balance(a)).sum();
    sum == client.total_supply()
}

#[test]
fn gl_01_conservation_over_sequence() {
    let (_env, client, admin, user) = setup();
    let actors = [admin.clone(), user.clone()];
    client.mint(&user, &1_000);
    assert!(gl_01_holds(&client, &actors), "GL-01 violated after mint");
    client.transfer(&user, &admin, &400);
    assert!(gl_01_holds(&client, &actors), "GL-01 violated after transfer");
}

// ADV-02 SHOULD-HOLD — non-admin cannot mint
#[test]
fn adv_02_non_admin_cannot_mint() {
    let env = Env::default();            // no mock_all_auths here
    let id = env.register(Token, ());
    let client = TokenClient::new(&env, &id);
    let admin = Address::generate(&env);
    let mallory = Address::generate(&env);
    env.mock_all_auths();
    client.initialize(&admin);
    env.set_auths(&[]);                  // drop blanket auth, keep the call unauthorised
    assert!(client.try_mint(&mallory, &1).is_err(), "ADV-02 violated");
}
```

`proptest` (add `proptest = "1"` under `[dev-dependencies]`) for input-shaped
properties:

```rust
proptest::proptest! {
    // RT-01 EXPLORATORY — deposit then withdraw never leaves the user richer
    #[test]
    fn rt_01_roundtrip_no_profit(amount in 1i128..1_000_000_000) {
        let (_env, client, _admin, user) = setup();
        client.mint(&user, &amount);
        let before = client.balance(&user);
        client.deposit(&user, &amount);
        client.withdraw(&user, &amount);
        proptest::prop_assert!(client.balance(&user) <= before);
    }
}
```

Run `cargo test` (add `-- --nocapture` to see assertion messages). Report as
`EXTERNAL`.

## What has no Soroban analogue

- No Truent dynamic verification — no PoC shrinking (proptest shrinks its own
  inputs, but that is `EXTERNAL`), no auto-detected invariants, no `.invar`
  binding. Say so in the report.
- No Medusa/Echidna coverage loop, no `FoundryTester` repro, no
  `fizz_sync.js` drift detection, no bytecode-only fuzzing.
- Ghosts become test-local counters; snapshots become `let before = …`.
