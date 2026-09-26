# Chain primer — Solana (Anchor and native programs)

Appended to every agent bundle when Solana `.rs` files are in scope. The specialty files were
written for Solidity; this primer says what each of their lenses means on Solana, and where a
concept has no analogue.

## Execution model

A **program** is stateless code. All state lives in **accounts** — byte arrays with an owner
program, a lamport balance and data. A transaction lists every account an instruction touches,
marks which are signers and which are writable, and the runtime enforces only that: a signer
account really signed, a writable account is writable, and only the owner program may change
an account's data or debit its lamports. **Everything else is the program's job.** The caller
chooses every account; the program must check that each one is what the instruction assumes.

Anchor makes those checks declarative: the `#[derive(Accounts)]` struct *is* the access
control. `Account<'info, T>` deserialises and checks owner + discriminator; `Signer<'info>`
checks the signature; `has_one = authority` checks a stored pubkey equals a passed account;
`seeds = [...], bump` re-derives a PDA; `Program<'info, Token>` checks the program id;
`Sysvar<'info, Rent>` checks the sysvar address. A bare `AccountInfo<'info>` or
`UncheckedAccount<'info>` checks nothing — the `/// CHECK:` comment above it is a promise
the program body has to keep. Native programs (`solana_program::entrypoint`) do all of this
by hand: `is_signer`, `owner ==`, `Pubkey::find_program_address`, and forgetting one is the
classic Solana bug.

**CPI** (cross-program invocation) is how programs compose: `invoke` passes the caller's
signer privileges through; `invoke_signed` lets a PDA sign. CPI depth is limited (4), and a
program cannot be re-entered except by direct self-recursion — EVM-style reentrancy through a
third program does not exist. What does exist is **privilege propagation**: every signer
account in the outer instruction is a signer in the inner one, so a program that CPIs into an
attacker-chosen program hands it the user's signature.

**Rent**: an account must hold enough lamports to be rent-exempt or it is garbage-collected at
the end of the transaction; a program that debits lamports below that minimum destroys the
account. **Arithmetic**: `u64` in Rust wraps in release builds unless `overflow-checks = true`
is set in the profile (Anchor's template sets it; check `Cargo.toml`); `checked_*` is the
explicit form. **Randomness, timestamps**: `Clock` sysvar, slot hashes — validator-influenced.

## Trust boundaries

- **Caller:** anyone submits any transaction with any accounts. The program is the only
  check.
- **Accounts:** every one is attacker-chosen unless a constraint pins it. Type cosplay: an
  account of type A whose bytes parse as type B (same size, no discriminator check).
- **Sysvars:** must be read by address (`Sysvar<'info, T>` / `Clock::get()`), never from an
  account the client passed as "the clock".
- **Token program:** SPL Token and Token-2022 (extensions: transfer fees, transfer hooks,
  confidential transfers — the Solana analogue of fee-on-transfer).
- **Oracles:** Pyth / Switchboard accounts — check the owner program, the feed id, staleness
  and confidence; never a pool's own reserves.
- **Upgrade authority:** programs are upgradeable by default; a single-key upgrade authority
  can replace all the code.

## Where each specialty hunts here

| Specialty | On Solana |
|---|---|
| math-precision | `u64` arithmetic with no `checked_*` and no `overflow-checks`; `as u64` casts from `u128`; decimals from a `Mint` the client passed; lamport math near the rent minimum |
| access-control | every `AccountInfo` / `UncheckedAccount` authority; `has_one` missing on the governed account; PDA seeds that omit a user-specific component (one PDA for everyone); `init` on an account that can be re-initialised (`init` vs `init_if_needed`); a stored `authority` nobody re-checks after `set_authority` |
| economic-security | Token-2022 transfer fees credited at face value; oracle account owner unchecked; a pool that prices from its own reserves (`sol_oracle_self_trade`); closing an account and reclaiming lamports twice |
| execution-trace | instruction data parsed by hand with trailing bytes ignored; `remaining_accounts` used without checks; CPI into a program id the caller supplied; a PDA bump taken from instruction data instead of `find_program_address` |
| invariant | `sum(token account amounts) == mint supply` — the one a fuzz plan states (validated now, executed when the backend ships); vault `balance` field vs actual lamports; a counter in a PDA that two instructions update with different arithmetic |
| periphery | helper functions that take `&AccountInfo` and trust it; `try_borrow_mut_lamports` in a utility; account-size constants that drift from the struct |
| first-principles | "this account is the vault" — says who? "this is the user's token account" — owner and mint checked? "only the authority can call" — is `authority` a `Signer`? |
| asymmetry | `deposit` constrains the token account's mint, `withdraw` does not; `close` on one path returns rent to the user, the other to the caller |
| boundary | `Option<Pubkey>` defaulting to `Pubkey::default()`; zero-amount transfers; `remaining_accounts` empty; an account with zero data length passed where a struct is expected |
| numerical-gap | share math on `u64` with `u128` intermediates missing; fee that truncates to 0 below a threshold, so small transfers are free |
| trust-gap | a PDA authority whose seeds are guessable; an admin `set_fee` with no bound + a fee applied at settlement; upgrade authority = treasury authority = one key |
| flow-gap | CPI to the token program with the user's signer privilege carried into an attacker program; a "transfer then update balance" that the runtime rolls back only if the whole transaction fails |

## What the engine already covers (do not re-derive)

`sol_missing_signer` · `sol_signer_checks` · `sol_account_validation` · `sol_pda_derivation` ·
`sol_pda_authority_validation` · `sol_unchecked_token_account_type` · `sol_sysvar_account_validation` ·
`sol_fake_sysvar_instruction_account` · `sol_oracle_rate_account` · `sol_oracle_self_trade` ·
`sol_integer_overflow` · `sol_instruction_parsing` · `sol_durable_nonce_validation` ·
`sol_lamport_balance` · `sol_rent_exemption` · `sol_rent_exemption_check` ·
`sol_treasury_single_authority` · `sol_admin_no_timelock` — plus the chain-neutral
`unauthorized_privileged_mutation`.

**Dynamic:** `truent fuzz <anchor-idl.json> --dynamic --chain solana --plan plan.json` exists
and, in truent 0.6.0, **validates the IDL and the plan and then stops** — the execution
backend is deferred to a later release. The plan's two invariant types are
`token_conservation` and `account_owner`; a `property:` in one of those shapes gives the
orchestrator a plan it can validate today and run when the backend ships. Nothing on Solana is
`VERIFIED-PROVEN` in this release: verification beyond the static detectors is EXTERNAL
(Anchor `#[test]`, `solana-program-test`), and your finding stays `REASONED` and says so.

## Concrete bug shapes (the engine's own corpus)

`crates/analyzer/solana/tests/corpus/bad/`:

- `missing_signer.rs` — `withdraw` debits `vault.balance` and credits `authority`, and
  `authority` is `AccountInfo<'info>`, not `Signer<'info>`; anyone drains the vault to any
  account.
- `drain_below_rent.rs` — `has_one = authority` and a `Signer` are present, and the lamport
  debit has no rent-exempt floor; the vault account is destroyed by a large enough `amount`.
- `raw_sysvar.rs` — a sysvar read from a client-passed account instead of by address; the
  client passes a fake clock.
- `single_authority_treasury.rs` — one key holds the treasury; no multisig, no timelock.

`good/anchor_vault.rs` is the safe shape: typed accounts, `Signer`, `has_one`, seeds + bump.

## No analogue here — be honest

- **Reentrancy** as the EVM knows it does not exist: no third program can call back into
  yours mid-instruction. The reentrancy lens becomes *CPI privilege escalation* and *state
  written after a CPI whose target the caller chose*.
- **`msg.value` / payable** does not exist: lamports move by debiting one account and
  crediting another, inside the owner program's rules. The boundary agent's "payable" step
  becomes "lamport transfers near the rent floor".
- **Sentinel-address branches** (`token == ETH_ADDRESS`) have no direct analogue; the
  nearest is `Pubkey::default()` / `Option<Pubkey>` and the native-SOL vs wrapped-SOL
  distinction.
- **Fee-on-transfer / rebasing** tokens: only through Token-2022 extensions (transfer fee,
  transfer hook). Classic SPL Token has none.
- **Delegatecall / proxies**: none. The analogue is the program upgrade authority replacing
  all the code at once.
- **`tx.origin`**: none. There is no originating-signer distinction; every signer is a
  signer.
