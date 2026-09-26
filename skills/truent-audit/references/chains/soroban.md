# Chain primer — Soroban (Stellar)

Appended to every agent bundle when Soroban `.rs` files (`soroban_sdk`) are in scope.

## Execution model

A Soroban contract is Rust compiled to Wasm and run by the Stellar host. The contract gets an
`Env`; everything — storage, auth, cross-contract calls, ledger info — goes through it. There
is **no `msg.sender`**. Authorization is explicit: `address.require_auth()` asks the host to
prove that `address` authorised *this* invocation (with these arguments, in this call tree),
and it panics if not. `require_auth_for_args` narrows the authorised arguments. A function that
moves value on behalf of `from` and never calls `from.require_auth()` lets anyone move
`from`'s value.

**Storage has three tiers**, and the tier is a security property:

- `instance()` — small, lives and dies with the contract instance; its TTL is the contract's.
- `persistent()` — durable, but it has a **TTL**: when nobody extends it (`extend_ttl`), the
  entry is *archived* — reads fail — and must be restored before use. Balances and admin
  addresses belong here, with `extend_ttl` on access.
- `temporary()` — cheap and **guaranteed to disappear** when its TTL lapses. Correct for
  nonces and short-lived allowances, wrong for anything that must survive: a balance in
  temporary storage is a balance that evaporates.

**Reentrancy is forbidden by the host** by default: a contract cannot be re-entered while a
call from it is in flight. The cross-contract-call risk is not reentrancy but *state read
after a call whose result the callee controlled*, and a contract that opts into reentrancy.
**Arithmetic** is Rust: `i128` overflows panic only when the profile sets `overflow-checks`
(the Soroban templates do); `checked_*` is explicit. A **panic** aborts the invocation — which
is fine for auth failures and wrong for user-input paths that should return a typed error.
**Initialization:** contracts had no constructor before protocol 22; an `initialize` function
with no instance-storage guard can be called again by whoever arrives second. **Upgrade:**
`env.deployer().update_current_contract_wasm(hash)` replaces the code; it must sit behind
`admin.require_auth()`.

Tokens: the **Stellar Asset Contract** (SAC) wraps classic assets behind the standard token
interface (`transfer`, `approve` with an expiration ledger, `burn`, `mint` by the admin).
Custom tokens implement the same interface and can do anything.

## Trust boundaries

- **Callers:** any account or contract invokes any public function; the `require_auth` calls
  inside are the access control.
- **Storage TTL:** the ledger itself is a boundary — an entry nobody extended is not there.
- **Cross-contract calls:** `env.invoke_contract` / generated clients; the callee's return
  value is a claim; the callee may panic and abort the caller.
- **Admin:** an `Address` in instance storage; who can change it; is the change two-step.
- **Upgrade:** the Wasm hash; who can call `upgrade`.
- **Oracle / price:** a pool's own reserves (`sor_thin_liquidity_oracle_price`) vs an oracle
  contract with staleness thresholds.

## Where each specialty hunts here

| Specialty | On Soroban |
|---|---|
| math-precision | `i128` `+`/`-`/`*` without `checked_*` (and check the release profile for `overflow-checks`); fee bps math that truncates; `u32` ledger arithmetic on TTLs |
| access-control | every function that takes `from: Address` and changes `from`'s state without `from.require_auth()`; `initialize` with no guard; `upgrade` / `set_admin` with no `admin.require_auth()`; `require_auth` called *after* the state change (the panic still reverts — but a call ordering that reads state between is the smell) |
| economic-security | a custom token whose `transfer` does not move the full amount; an allowance with an expiration ledger nobody checks; prices from a thin pool |
| execution-trace | state read after a cross-contract call that could change it; `env.invoke_contract` with a caller-supplied contract id; a panic on user input that blocks a batch |
| invariant | `sum(balances) == total_supply` kept across tiers; an allowance decremented in temporary storage while the balance sits in persistent |
| periphery | helper modules that wrap storage without `extend_ttl`; a `Client` generated for another contract with assumptions about its return type |
| first-principles | "this is persistent" — is it, and who extends it? "only the admin" — which `Address`, and did it `require_auth`? "initialised once" — by whom, guarded how? |
| asymmetry | `deposit` extends TTL, `withdraw` does not; `mint` requires admin auth, `clawback` does not; `set_admin` one-step vs a two-step elsewhere |
| boundary | zero and negative `i128` amounts (the type is signed!); an `Address` that is a contract vs an account; an archived entry (`get` returns `None`) treated as zero balance |
| numerical-gap | negative amounts passing a `<= balance` check; a fee that rounds to 0 for small transfers |
| trust-gap | admin `set_fee` unbounded + fee at settlement; upgrade authority = one key; `mock_all_auths` in the test suite hiding a missing `require_auth` in production |
| flow-gap | balance read, cross-contract call, balance written from the stale read; TTL lapsed between `approve` and `transfer_from` so the allowance is gone but the caller's accounting says it exists |

## What the engine already covers (do not re-derive)

`sor_missing_require_auth` · `sor_require_auth_checks` · `sor_init_guard` · `sor_reinitialization` ·
`sor_unprotected_upgrade` · `sor_no_unprotected_upgrade` · `sor_checked_arithmetic` ·
`sor_unchecked_arithmetic` · `sor_temporary_storage_critical_state` · `sor_storage_ttl_not_extended` ·
`sor_storage_ttl_extended` · `sor_reentrancy_external_call` · `sor_no_reentrancy` ·
`sor_thin_liquidity_oracle_price` · `sor_unhandled_panic` — plus the chain-neutral
`unauthorized_privileged_mutation`.

**Dynamic:** none. `truent fuzz --dynamic --chain soroban` is an error in the engine. A
`property:` you state is verified, if at all, by a `cargo test` with `soroban-sdk`
`testutils` (and `proptest`) that the orchestrator runs on a copy outside the repository,
labelled EXTERNAL. Your finding stays `REASONED`. State the property anyway; the test is
written from it.

## Concrete bug shapes (the engine's own corpus)

`crates/analyzer/soroban/tests/corpus/bad/missing_require_auth.rs` — a `transfer(env, from,
to, amount)` that reads and writes persistent balances and never calls `from.require_auth()`.
The engine flags four things on that one file: the missing auth (`sor_missing_require_auth`
and `unauthorized_privileged_mutation`), the plain `-`/`+` on `i128`
(`sor_unchecked_arithmetic`), and the persistent read with no `extend_ttl`
(`sor_storage_ttl_not_extended`). `good/guarded_token.rs` is the safe shape.

## No analogue here — be honest

- **Reentrancy:** forbidden by the host by default. Only flag a contract that re-enables it,
  or a stale read across a cross-contract call.
- **`msg.value` / native value in the call:** none. Native XLM moves through the SAC like any
  token.
- **`tx.origin`:** none; `require_auth` authorises a specific address for a specific
  invocation, and there is no originating-signer concept.
- **Delegatecall / storage collision:** none. `update_current_contract_wasm` replaces code in
  place with the same storage.
- **Fee-on-transfer / rebasing:** not in the SAC; only in custom tokens.
- **Sentinel addresses:** none at the language level.
- **Storage that lives forever:** none — this is the reverse case. The EVM specialties never
  ask "is this slot still here?"; on Soroban every persistent read has to.
