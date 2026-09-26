# Chain primer — Move (Aptos and Sui)

Appended to every agent bundle when `.move` files are in scope. Aptos Move and Sui Move share
the language and differ in the storage model; both are covered, and each section says which
one it means.

## Execution model

Move is a resource language. A `struct` has **abilities** that the compiler enforces:
`copy` (can be duplicated), `drop` (can be discarded), `store` (can live inside another
struct or in storage), `key` (can be a top-level resource / object). A value with no `drop`
**cannot be thrown away** — the function that receives it must store it, return it, or
destructure it through the declaring module. That is the *hot potato* pattern and it is the
strongest guarantee any chain offers for "you must repay this". A value with `store` can leave
its module through generic transfer functions; a capability with `store` is a capability
anyone can pass around.

Arithmetic **aborts on overflow and on division by zero**. There is no silent wrap and no
`unchecked` — so "integer overflow" is not a finding; a hand-rolled overflow mask is (it is
either dead code or a sign the author expected wrap semantics). Division truncates, so
`a / b * c` loses precision that `a * c / b` keeps.

There is **no dynamic dispatch** and no re-entrancy: a module can only call modules it
imports at compile time, and a callee cannot call back into a caller mid-function. The
execution-trace lens has no reentrancy work here.

**Aptos:** global storage keyed by address. `move_to(&signer, resource)` publishes a resource
under the signer's address; `borrow_global[_mut]<T>(addr)` reads it; a function that touches
global storage declares `acquires T`. Authority is a `&signer` — proof that the transaction
was signed by that address — and a `SignerCapability` is that proof stored in a resource so a
*resource account* can sign later. `entry fun` is callable from a transaction; `public fun`
from other modules; `public(friend)` from listed friends only. `#[randomness]` marks an entry
function that consumes on-chain randomness, and the framework refuses to run it from a public
function (so a caller cannot abort-and-retry on a bad roll).

**Sui:** everything is an **object** with a `UID`. Objects are *owned* (only the owner's
transaction can pass them), *shared* (anyone can pass them, mutably, so the function is the
only guard), or *immutable*. A **capability** is an owned object whose possession is the
authorization: `&AdminCap` as a parameter means "the caller owns an AdminCap". Transactions
are **PTBs** (programmable transaction blocks): a caller chains many calls in one transaction,
passing outputs to inputs — so any sequence of public functions is one atomic transaction,
and a "you must call B after A" convention is only enforced when A returns a hot potato B
consumes. `TxContext::sender` is the caller; `init` runs once at publish; `public(package)`
limits visibility to the package. Sui's `random` module exists and, like Aptos, must not be
consumed from a public function.

## Trust boundaries

- **Callers:** anyone, with any signer / any objects they own / any shared object.
- **Type arguments:** a generic `T` is attacker-chosen unless the function constrains it
  (`Coin<T>` with `T` unconstrained accepts any coin type the caller minted).
- **Shared objects (Sui):** every mutable reference to a shared object is available to every
  caller; the function body is the whole access control.
- **Capabilities:** who created them, in `init` only, or from a public function; do they have
  `store`; did any function `transfer` one to `ctx.sender()`.
- **Framework:** `aptos_framework::coin` / `fungible_asset`, `sui::coin` / `balance`,
  `sui::transfer::public_transfer` (works on any `store` object), oracle modules (Pyth:
  `get_price_no_older_than` vs `get_price_unsafe`).
- **Upgrades:** Aptos packages have an upgrade policy; Sui packages upgrade through an
  `UpgradeCap` — a single key holding it is the admin-key problem.

## Where each specialty hunts here

| Specialty | On Move |
|---|---|
| math-precision | divide-before-multiply (`sui_divide_before_multiply`); `(x as u64)` down-casts that abort at runtime (a DoS, not a wrap); hand-rolled overflow masks; fee bps with no upper bound |
| access-control | Sui: a `public fun` taking `&mut SharedObject` and no capability; a capability struct with `store`; a capability transferred to `ctx.sender()` outside `init`. Aptos: `public fun` returning a `signer` from a `SignerCapability`; a setter with no `signer::address_of(s) == admin` check; single-step admin transfer; no timelock |
| economic-security | unconstrained generic `T` credited at face value (fake token deposit); pool pricing from its own reserves; stale Pyth price (`get_price_unsafe`) |
| execution-trace | PTB composition: which public functions, chained in one PTB, reach a state the author assumed two transactions apart; `acquires` on a resource the function mutates and another function reads mid-way |
| invariant | `x * y >= k` after every swap (`move_liquidity_conservation`); `total_supply == sum(balances)` for a custom ledger; a hot potato whose `amount` field is not compared on repay |
| periphery | wrapper modules around framework coin functions; `public(package)` that should be private; a helper that returns `&mut` into a resource |
| first-principles | "only the admin can…" — through what? a `&signer` compared to a constant, an `AdminCap` parameter, or nothing; "this receipt must be returned" — does it have `drop`? |
| asymmetry | `deposit<T>` keyed by type vs `withdraw<T>` not keyed; user `swap` asserts the invariant, admin `rebalance` does not |
| boundary | zero-amount coin; `vector` with 0 or 10 000 entries (unbounded growth, gas abort); `@0x0` as an address parameter; `Option::none` unwrapped |
| numerical-gap | share price from `total / supply` with `u64` truncation at small supply; a fee floor of 0 that makes small trades free |
| trust-gap | admin `set_fee` unbounded + fee applied at settlement; `UpgradeCap` / upgrade policy held by the treasury key; randomness consumed from a public function so a caller can retry (`move_randomness_public_function`) |
| flow-gap | flash loan returning a receipt with `drop` (`sui_hot_potato_drop`); a `public_transfer` of an object the module meant to keep; a PTB that calls `borrow` then never `repay` because nothing forces it |

## What the engine already covers (do not re-derive)

`move_access_control` · `move_access_control_missing` · `move_signer_requirement` ·
`move_privileged_handle_exposed` · `move_capability_transferred_to_caller` ·
`move_capability_with_store` · `move_admin_no_timelock` · `move_admin_transfer_single_step` ·
`move_unbounded_parameter` · `move_hot_potato_has_abilities` · `move_type_safety` ·
`move_unconstrained_type_argument` · `move_resource_leaks` · `move_integer_overflow` ·
`move_manual_overflow_check` · `move_divide_before_multiply` · `move_liquidity_conservation` ·
`move_oracle_spot_price` · `move_oracle_stale_price` · `move_randomness_public_function` ·
`move_weak_randomness` · `move_unbounded_vector_growth` — plus the chain-neutral
`unauthorized_privileged_mutation`.

**Dynamic:** none. `truent fuzz --dynamic --chain move` is an error in the engine. A
`property:` you state on Move is verified, if at all, by the Move Prover or a `move test` the
orchestrator runs on a copy outside the repository, and labelled EXTERNAL. Your finding stays
`REASONED`. State the property anyway: a `spec` block is written from it.

## Concrete bug shapes (the engine's own corpus)

`crates/analyzer/move/tests/corpus/bad/`:

Aptos — `aptos_unguarded_withdraw.move` (privileged mutation, no signer check),
`aptos_unguarded_set_fee.move` (no guard + no bound), `aptos_signer_leak.move` (a
`public fun` returns the resource account's `signer` from a stored `SignerCapability`),
`aptos_cap_move_to_caller.move`, `aptos_single_step_admin.move`, `aptos_admin_no_timelock.move`,
`aptos_spot_price.move`, `aptos_stale_pyth.move`, `aptos_randomness_public.move`,
`aptos_weak_randomness.move`.

Sui — `sui_unguarded_withdraw.move`, `sui_unguarded_shared_setter.move` (a `public fun` on a
shared object with no capability), `sui_cap_to_caller.move` (capability transferred to
`ctx.sender()` from a public function), `sui_cap_with_store.move`, `sui_hot_potato_drop.move`
(a flash-loan receipt declared `has drop`, so the borrower never repays),
`sui_fake_token_deposit.move` (`deposit<T>` credits any `Coin<T>` to one ledger),
`sui_divide_before_multiply.move`, `sui_manual_overflow_mask.move`, `sui_swap_no_invariant.move`,
`sui_unbounded_fee.move`, `sui_unbounded_vector.move`, `sui_randomness_public.move`.

`good/aptos_vault.move` and `good/sui_vault.move` are the safe shapes.

## No analogue here — be honest

- **Reentrancy:** none. No dynamic dispatch, no callbacks. The nearest thing is PTB
  composition on Sui — many calls in one atomic transaction — which is about ordering, not
  re-entry.
- **Integer overflow / underflow as silent wrap:** none; arithmetic aborts. The finding is a
  *DoS by abort* (an attacker makes a legitimate call abort) or a manual mask that hides the
  abort the author wanted.
- **`msg.sender` / `tx.origin`:** replaced by `&signer` (Aptos) and `ctx.sender()` (Sui);
  there is no origin/sender split.
- **Fee-on-transfer / rebasing tokens:** none in the framework coin types. The analogue is an
  *unconstrained type argument* — the caller supplies a coin type the code did not expect.
- **Delegatecall / storage collision:** none. Upgrades replace code under a policy; storage
  layout is typed.
- **Sentinel addresses:** `@0x0` exists but nothing special-cases it at the language level.
- **Unchecked external-call return values:** none; a callee aborts the whole transaction.
