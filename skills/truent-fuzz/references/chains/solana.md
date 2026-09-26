# Solana harness guide

Two targets exist for a Solana property, and only one of them is verified by
Truent's engine.

| Target | What it checks | Evidence |
|---|---|---|
| **Fuzz plan** (`plan.json`) run by `truent fuzz <idl> --dynamic --chain solana --plan plan.json` | `token_conservation` and `account_owner` invariants after every generated instruction | `VERIFIED-PROVEN` on violation **once the backend ships** — see release status below |
| **Anchor test harness** (`solana-program-test` / `#[tokio::test]`) | anything else: postconditions, liveness, authority checks, arithmetic bounds | `EXTERNAL` |

`truent scan <program> --chain solana --output json` runs the static
detectors (`VERIFIED-STATIC`); the corpus of real bug shapes it recognises is
under `crates/analyzer/solana/tests/corpus/bad/` (missing signer, raw sysvar,
drain below rent, single-authority treasury …).

## 1. The fuzz plan — what the engine needs that the IDL cannot say

An Anchor IDL (legacy `isMut`/`isSigner` or 0.30+ `writable`/`signer`) gives
the instruction surface, discriminators and argument types. Instructions with
`String`/`Vec`/struct arguments are skipped by the generator and reported.
The plan adds the world (schema: `crates/dynamic/solana/src/config.rs`):

```json
{
  "program_id": "<base58, optional if the IDL carries address/metadata.address>",
  "program_so": "target/deploy/<program>.so",
  "accounts": [
    { "name": "mint",  "pubkey": "<base58>", "lamports": 1000000000, "space": 82 },
    { "name": "alice", "pubkey": "<base58>", "space": 165 },
    { "name": "cfg",   "pubkey": "<base58>", "data_hex": "0x…", "owner": "<program>" }
  ],
  "signers":  ["<authority pubkey>"],
  "writable": ["<mint>", "<alice>"],
  "readonly": [],
  "pin": { "mint": "<mint>" },
  "invariants": [
    { "type": "token_conservation", "name": "GL-01 supply == sum(amounts)",
      "mint": "<mint>", "token_accounts": ["<alice>", "<bob>"],
      "amount_offset": 64, "supply_offset": 36 },
    { "type": "account_owner", "name": "GL-04 config owner never changes", "account": "<cfg>" }
  ],
  "seed": 1, "runs": 500, "depth": 10
}
```

Field notes:

- `accounts[]` are genesis accounts: `space` zero-fills, `data_hex` sets exact
  bytes, `owner` defaults to the program under test, `lamports` defaults to
  1 SOL.
- `signers` / `writable` / `readonly` are the pools the generator draws each
  instruction's accounts from by role (signer wins over writable).
- `pin` forces a named IDL account (e.g. `mint`) to one concrete pubkey.
- `token_conservation`: `sum(u64 at amount_offset of each token account) ==
  u64 at supply_offset of the mint`. SPL Token layout: token-account `amount`
  at byte 64, mint `supply` at byte 36. Other layouts: set the offsets from
  the account struct.
- `account_owner`: the owner program of `account` must never change.
- **A plan with no invariants is rejected by the engine** ("a fuzz run with
  nothing to check proves nothing").

Generate it from the synthesized plan rather than by hand:

```bash
python3 $SKILL_DIR/scripts/emit_solana_plan.py \
  --idl target/idl/<program>.json \
  --properties fizz_data/property-plan.json \
  --accounts fizz_data/solana-accounts.json \
  --out fizz_data/plan.json
```

`solana-accounts.json` is the only hand-written input — the IDL has no
pubkeys. Shape: `{"<idl account name or property contract>": {"pubkey": "...", "space": 165, "role": "mint|token_account|signer|state", "owner": "..."}}`.
The script maps:

| Property (from `property-plan.json`) | Plan entry |
|---|---|
| `category: HIGH_LEVEL` conservation (`sources` contain `CON-`, or english mentions supply/sum/conservation) with a `mint` and ≥1 `token_account` in the accounts map | `token_conservation` |
| authority / owner stability (`sources` contain `ADV-` privilege or `VS-`/`ST-` owner properties, or english mentions owner/authority "never changes") naming a `state`/`signer` account | `account_owner` |
| everything else | listed under `unmapped` in the script output → Anchor test |

Run:

```bash
truent fuzz target/idl/<program>.json --dynamic --chain solana --plan fizz_data/plan.json
```

Without `--plan` the engine errors: `--dynamic --chain solana requires --plan <plan.json>: the genesis accounts and invariants to check. An IDL describes instructions, not what must stay true.`

### Release status (truent 0.6.0, observed)

With a valid IDL and plan the engine currently stops after validation:

```
Error: IDL and plan are valid (2 fuzzable instruction(s)), but this release cannot execute them.

Running real Solana bytecode needs an in-process Solana VM, whose dependencies currently carry unpatched security advisories. Truent will not ship known-vulnerable crypto, so the dynamic Solana backend is deferred to a later version.

Static Solana analysis is fully available:

    truent scan <path> --chain solana
```

Report this verbatim. The plan is still worth producing: validation catches
malformed pubkeys/hex, unknown invariant types and empty invariant lists, and
the file is the exact input the backend will execute. Until then, Solana
evidence is `VERIFIED-STATIC` (scan) and `EXTERNAL` (Anchor tests) only.

## 2. The Anchor test harness (EXTERNAL) — for every unmapped property

Put one `#[tokio::test]` per property in `tests/fizz_properties.rs` (or the
program's `tests/` crate). Keep the Spec ID in a comment on the first line of
each test so `PROPERTIES.md` bookkeeping still works. FORMAT skeleton — adapt
names, do not paste blindly:

```rust
// SP-02 EXPLORATORY — deposit then withdraw of the same amount leaves the user no richer
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{signature::Keypair, signer::Signer, transaction::Transaction};

#[tokio::test]
async fn sp_02_roundtrip_no_profit() {
    let mut pt = ProgramTest::new("my_program", my_program::id(), processor!(my_program::entry));
    let user = Keypair::new();
    // seed accounts here (mint, token accounts, program state)
    let (mut banks, payer, hash) = pt.start().await;

    let before = /* read user token amount */ 0u64;
    let ixs = vec![/* deposit(amount) */, /* withdraw(amount) */];
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &[&payer, &user], hash);
    banks.process_transaction(tx).await.unwrap();
    let after = /* read user token amount */ 0u64;

    assert!(after <= before, "SP-02 violated: {after} > {before}");
}
```

Liveness properties (`must not revert`) assert `process_transaction(..).await.is_ok()`;
access-control properties assert `.is_err()` for the non-authority signer.
Run with `cargo test-sbf` (or `anchor test`). Report the result as `EXTERNAL`.

## 3. What has no Solana analogue

- No Medusa/Echidna, no coverage loop, no `FoundryTester` repro, no
  `fizz_sync.js` drift detection.
- No user DSL: the plan supports exactly two invariant types. A property that
  is neither conservation nor owner-stability cannot be engine-verified today.
- No `--address/--rpc-url` bytecode fuzzing; the plan needs `program_so`
  (or a program the backend can load) and genesis accounts.
