# Move (Aptos, Sui) harness guide

**Truent verifies Move statically only.** `truent fuzz --dynamic --chain move`
is an engine error (`--dynamic fuzzing currently only supports --chain evm
(Move/Soroban need their own execution backends, not yet built)`). What the
engine gives you:

- `truent scan <package> --chain move --output json` → `VERIFIED-STATIC`
  detector hits. Real bug shapes it knows are in
  `crates/analyzer/move/tests/corpus/bad/` — e.g. `aptos_unguarded_withdraw`,
  `aptos_cap_move_to_caller`, `aptos_admin_no_timelock`, `aptos_stale_pyth`,
  `sui_swap_no_invariant`, `sui_divide_before_multiply`, `sui_hot_potato_drop`,
  `sui_unguarded_shared_setter`.

Everything dynamic is `EXTERNAL`: the Move Prover (a proof, but not Truent's
engine) and the unit-test runners.

## Aptos — Move Prover `spec` blocks + unit tests

Skeleton: `$SKILL_DIR/templates/move/aptos_invariants.move`.

Where each property category lands:

| fizz category | Aptos target | Command |
|---|---|---|
| HIGH_LEVEL / VALID_STATE state predicate over module state | `spec module { invariant … }` or `spec fun … { ensures … }` | `aptos move prove` |
| STATE_TRANSITION postcondition | `spec entry_fn { ensures global<T>(addr).x == old(global<T>(addr).x) + amount; }` | `aptos move prove` |
| Access control ("only admin") | `spec entry_fn { aborts_if signer::address_of(caller) != @admin; }` plus a `#[test] #[expected_failure(abort_code = …)]` | `aptos move prove`, `aptos move test` |
| Round-trip / rounding / liveness | `#[test]` functions that execute the sequence and `assert!` | `aptos move test` |
| Monotonic accumulator | `spec fn { ensures global<T>(addr).acc >= old(global<T>(addr).acc); }` | `aptos move prove` |

FORMAT skeleton for a spec block (adapt the resource and function names):

```move
spec my_module {
    // GL-01 SHOULD-HOLD — pool never accounts more than it holds
    spec module {
        invariant forall addr: address where exists<Pool>(addr):
            global<Pool>(addr).total_shares <= global<Pool>(addr).total_assets;
    }
    // SP-01 SHOULD-HOLD — deposit increases total_assets by exactly `amount`
    spec deposit(user: &signer, amount: u64) {
        let addr = @pool_addr;
        ensures global<Pool>(addr).total_assets == old(global<Pool>(addr).total_assets) + amount;
        aborts_if amount == 0;
    }
}
```

Prover caveats to state in the report: `aborts_if` must be complete or use
`pragma aborts_if_is_partial = true`; loops need `invariant` annotations or
`pragma unroll`; a proof time-out is "not proven", not "holds".

## Sui — `test_scenario` unit tests

Sui has no Move Prover in the standard toolchain today; properties become
`#[test]` / `#[expected_failure]` functions using `sui::test_scenario`.
Skeleton: `$SKILL_DIR/templates/move/sui_invariants.move`. Run `sui move test`.

| fizz category | Sui target |
|---|---|
| State predicates | a `#[test]` that drives a sequence through `test_scenario::next_tx` and asserts the predicate after every step |
| Access control | `#[test] #[expected_failure(abort_code = my_module::ENotAdmin)]` with the wrong sender |
| Conservation on `Coin<T>` / `Balance<T>` | assert `balance::value(&pool.reserve) == sum of user coin values` after each tx |
| Object ownership stability | assert `object::owner`-style checks via `test_scenario::has_most_recent_for_address` |

FORMAT skeleton:

```move
#[test_only]
module my_pkg::fizz_properties {
    use sui::test_scenario as ts;
    use my_pkg::pool::{Self, Pool};

    const ADMIN: address = @0xA;
    const USER: address = @0xB;

    // SP-01 SHOULD-HOLD — deposit credits exactly `amount`
    #[test]
    fun sp_01_deposit_credits_amount() {
        let mut s = ts::begin(ADMIN);
        pool::init_for_testing(ts::ctx(&mut s));
        ts::next_tx(&mut s, USER);
        {
            let mut p = ts::take_shared<Pool>(&s);
            let before = pool::total_assets(&p);
            pool::deposit(&mut p, /* coin of 100 */, ts::ctx(&mut s));
            assert!(pool::total_assets(&p) == before + 100, 0);
            ts::return_shared(p);
        };
        ts::end(s);
    }

    // ADV-03 SHOULD-HOLD — non-admin cannot set fee
    #[test]
    #[expected_failure(abort_code = pool::ENotAdmin)]
    fun adv_03_non_admin_cannot_set_fee() { /* … */ }
}
```

## What has no Move analogue

- No Truent dynamic verification at all — no PoC shrinking, no auto-detected
  invariants, no `.invar` binding. State this plainly in the report.
- No Medusa/Echidna coverage loop, no `FoundryTester` repro, no `fizz_sync.js`
  drift detection, no bytecode-only fuzzing.
- Ghost variables become test-local counters; snapshots become `old()` in
  specs or `let before = …` in tests.
