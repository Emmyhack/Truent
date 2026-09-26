# Truent invariant DSL — what `truent fuzz --invariants` actually accepts

Read this before writing or emitting a `.invar` file. The runtime grammar is
the pest grammar in `crates/dsl_parser/src/grammar.rs`; the binding rules are
in `crates/dynamic/evm/src/dsl_invariant.rs`. `docs/DSL_REFERENCE.md`
describes a richer future syntax (`description:`, `severity:`, `sum()`,
`forAll()`, `hasRole()` …). **The fuzzer does not run that syntax.** Only what
is listed here works today (truent 0.6.0).

## File shape

```
// comments are allowed on their own line
invariant Name {
    <expr>
}
invariant AnotherName {
    <expr>
}
```

- One or more `invariant` blocks per file; `Name` is an identifier
  (`[A-Za-z_][A-Za-z0-9_]*`) — `GL_01_solvency` is fine, `GL-01` is not.
- The block body is exactly one boolean expression. No metadata keys inside
  the braces.
- Optional layer scoping `invariant Name(account, paymaster) { … }` and
  `layer::identifier` exist for the account-abstraction analyser; do not use
  them for contract fuzzing.

## Expression grammar (precedence low → high)

| Level | Operators |
|---|---|
| logical or | `\|\|` |
| logical and | `&&` |
| comparison | `== != <= >= < >` |
| sum | `+ -` |
| term | `* /` |
| unary | `!` |
| primary | `( expr )`, integer literal (optionally negative), `true`/`false`, identifier, `identifier(args…)` |

Not in the grammar: `%`, `**`, ternaries, strings, hex/address literals,
`msg.sender`, `storage.x`, `balance.x`, `sum()`, `forAll()`, `exists()`,
`len()`, `hasRole()`, `_before`/`_after` suffixes.

## Binding rules (how identifiers get values)

- A bare identifier binds to a **zero-argument view function** of the same
  name on the contract under fuzz. Matching ignores case and underscores:
  `total_supply`, `totalSupply`, `TotalSupply` all bind `totalSupply()`.
- A call with only **integer or boolean literal** arguments binds to a getter
  with that name and arity: `balanceOf(0)` binds `balanceOf(address)` with
  the zero address; `shareOf(1, 2)` binds a two-argument getter. This is how
  a property reaches into a mapping. A call whose argument is itself an
  expression is not resolved; only the reads inside it are.
- Every identifier/call is read again **after every call** in the fuzzed
  sequence; the expression is then evaluated over the values read.
- **An identifier that cannot be bound is an error and the run is aborted** —
  never a silently skipped property. The error names the identifier and lists
  the available zero-argument getters (real output):
  ```
  invariant 'Unbound' references a variable with no matching zero-argument view on the contract.
    unbound: balance_of
    available getters: decimals, name, owner, symbol, totalSupply
  ```
- Values are unsigned 128-bit. A getter that returns more than 2^128-1, a
  getter that reverts, or an arithmetic overflow / division by zero makes the
  property **undecidable for that state** — not a violation and not a pass.
  Keep intermediate products small (`a * b` on two 1e30 values overflows).

## Five real examples (from `examples/invariants.invar`)

Each one parses today; each binds when the named zero-argument getters exist
on the contract.

```
invariant BalanceNeverNegative {
    balance >= 0
}

invariant TokenConservation {
    (balance_alice + balance_bob + balance_charlie) == total_supply
}

invariant MultipleConditions {
    (total_supply >= 0) && (total_supply <= max_supply)
}

invariant AllowanceConstraint {
    delegated_amount <= total_balance
}

invariant LiquidityPreservation {
    (reserve_a > 0) && (reserve_b > 0) && ((reserve_a * reserve_b) >= constant_product)
}
```

The same file also contains `AuthorityCheck { is_signer(msg_sender) }`,
`FunctionCall { validate_owner(account_owner) }`, `AccessControl { (caller == owner) || (is_admin(caller)) }`
and `StateTransition { valid_state_transition(previous_state, current_state) }`.
They parse, but against an ordinary contract they will not bind (no getter
named `msg_sender`, `caller`, `previous_state`, and calls with non-literal
arguments are not resolved). Treat them as parser demos, not templates.

## A real violation (truent 0.6.0, `--iterations 200 --seed 1`)

Property file:

```
invariant SupplyIsConstant {
    total_supply == 1000000000000000000000
}
```

Engine output for an ERC20 with a public `burn`:

```
✗ [PROVEN] Token1.sol
Invariant violated: SupplyIsConstant
violated with total_supply = 999999999999578235281

Reproduction (1 call):
  1. burn(0000000000000000000000000000000000000000000000000000000019239e6f)  [caller=0x0101010101010101010101010101010101010101]

Failing step: #1 (burn)
```

That block is `VERIFIED-PROVEN` evidence. Paste it verbatim.

## Mapping fizz property categories to the DSL

| Property kind | DSL? | How |
|---|---|---|
| Bound / cap (`totalAssets <= cap`) | yes | `total_assets <= cap` |
| Cross-variable identity (`totalDebt == shares * index`) | yes if all are zero-arg getters | `total_debt == total_borrow_shares * borrow_index` (watch 128-bit overflow) |
| Zero-state coupling (`totalSupply == 0 <=> reserves == 0`) | yes | `(total_supply == 0 && reserve0 == 0) \|\| (total_supply > 0 && reserve0 > 0)` |
| Owner stability | auto-detected (owner()+transferOwnership) | leave `dsl: null`; the engine checks it without a file |
| Sum over actors = total | auto-detected for ERC20 shape; otherwise no (`sum()` absent) | expose an aggregate getter on a thin harness contract, or Solidity suite only |
| Monotonic accumulator | auto-detected for no-arg accumulator getters | `dsl: null` |
| Before/after deltas, round-trips, liveness | no | Solidity suite (`Snapshots.sol`, handler-level properties) |
| Per-actor mapping reads | partial | only with literal keys: `balanceOf(0) == 0` (address zero holds nothing) |
| Anything on Solana / Move / Soroban | no | plan invariants / `spec` / Rust tests — see `references/chains/` |

## Running

```bash
truent fuzz <Contract.sol> --dynamic --chain evm --iterations 1000 --seed 1 \
  --invariants fizz_data/properties.invar
```

Observed limits (0.6.0): the contract must deploy with **no constructor
arguments** (add a no-arg wrapper contract in the same file), and the file
must be **self-contained** (imports are not resolved from the temporary
compile directory — flatten first). One `.invar` file per contract: it may
only name getters that exist on the contract it is run against.
