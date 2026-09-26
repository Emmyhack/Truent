# Engine verification of REASONED findings — Turn 4 step 3b

A prompt-only auditor stops at "I think this is a bug." Truent does not: it tries to **make
the bug fire in a real execution engine** and, if it does, ships the runnable sequence. This
file is how a `REASONED` candidate becomes a `VERIFIED-PROVEN` finding — and how one that
the engine refutes stops being a finding.

It is read by the orchestrator in Turn 4, for every gated FINDING and LEAD whose `property:`
line is not `none`. Agents never run the engine; they state the property, the orchestrator
runs it, on a copy of nothing — the engine reads the repository, it does not write to it.

## The rule, first

**The machine is the arbiter.** A model's confidence never promotes a finding above
`REASONED`; only an engine reproduction does. An engine that cannot break a claimed property
after a real search (several seeds, raised iterations) demotes the claim: the finding becomes
a Lead, or is dropped when the engine showed the guard the model missed. An engine that could
not *run* (no ABI shape, no plan, a compiler failure, no backend for the chain) changes
nothing: the finding stays `REASONED` and its "what remains unverified" clause says why.

Three outcomes and no fourth:

| Engine result | Tier | What the report says |
|---|---|---|
| Reproduced the violation | `VERIFIED-PROVEN`, confidence 100 | the engine's reproduction, pasted verbatim, as **Proof (engine)** |
| Searched and the property held | demote to LEAD, or drop | "the engine held `<property>` across seeds 1–3 at N iterations" |
| Could not run | stays `REASONED` | the exact reason the engine printed |

## What the engine can verify, per chain

| Chain | Path | What it proves |
|---|---|---|
| EVM | `truent fuzz <file.sol> --dynamic --chain evm` | a property violated by a concrete call sequence, executed in revm |
| EVM | `truent symbolic <foundry-project> [--tool halmos\|hevm\|mythril] --format json` | a counterexample input for a `check_*` / `prove_*` test — proven |
| EVM, deployed | `truent fuzz --dynamic --address 0x… --rpc-url URL` | the same, against fetched runtime bytecode (code only, no on-chain storage) |
| Solana | `truent fuzz <anchor-idl.json> --dynamic --chain solana --plan plan.json` | in truent 0.6.0: **validates** the IDL and the plan and stops — execution is deferred to a later release, so nothing is proven |
| Solana | none in Truent — external | Anchor `#[test]` / `solana-program-test` |
| Move | none in Truent — external | Move Prover `spec` blocks, `aptos move test`, `sui move test` |
| Soroban | none in Truent — external | `cargo test` with `soroban-sdk` `testutils` (optionally `proptest`) |

`--dynamic` with `--chain move` or `--chain soroban` is an **error** in the engine, and the
skill says so instead of pretending: the engine prints
`--dynamic fuzzing currently only supports --chain evm (Move/Soroban need their own execution backends, not yet built)`.
`--dynamic --chain solana --plan` goes one step further and then stops: it validates the IDL
and the plan and reports `IDL and plan are valid (N fuzzable instruction(s)), but this release
cannot execute them … dynamic Solana backend is deferred to a later version.` So in this
release **the only `VERIFIED-PROVEN` path is EVM** (revm fuzzing, symbolic counterexamples).
Results from the external tools are labelled **EXTERNAL** in the finding's proof and the
finding stays `REASONED`. Truent did not execute it, so Truent does not call it
`VERIFIED-PROVEN`. A later editor must not relabel an external test result as an engine
result — the Reproduce footer only lists commands the engine runs.

## EVM — the property shapes

`truent fuzz --dynamic` deploys the contract in an in-memory revm, drives adversarial call
sequences, checks the invariants after **every** call, and shrinks any violation to a minimal
reproduction. It recognises these shapes from the ABI without any authoring:

| Property shape | Auto-detected from | What a violation proves |
|---|---|---|
| **Conservation** | `totalSupply()` + `balanceOf(address)` | value credited with no matching supply change |
| **Monotonicity** | a no-argument accumulator getter | a quantity that must never decrease went down |
| **Access control** | `owner()` + `transferOwnership(address)` | ownership changed by a call from a non-owner |
| **Reentrancy** | the execution trace | the contract re-entered itself and wrote state after the external call |

A property that is none of these is written in the Truent DSL and passed with
`--invariants props.invar`. Each free variable binds to a zero-argument view of the same name
on the contract; a variable that cannot be bound is an error, never a silently skipped check.
The syntax, from `examples/invariants.invar` in the Truent repo:

```
invariant TokenConservation {
    (balance_alice + balance_bob + balance_charlie) == total_supply
}

invariant MultipleConditions {
    (total_supply >= 0) && (total_supply <= max_supply)
}
```

Write the `.invar` file in `{bundle_dir}`, never in the audited repository.

### The loop

1. **Match the `property:` line to a shape.** "Airdrop credits balance without updating
   supply" → conservation. "Share price dropped after a sequence" → monotonicity. "Non-owner
   rotated the admin" → access control. "Withdraw re-enters before zeroing balance" →
   reentrancy. Anything else → a DSL invariant over the contract's views, or reduce it toward
   a shape (reframe "vault share math is wrong" as a monotone `sharePrice()`).
2. **Run the fuzzer against the file that exhibits the shape:**
   ```bash
   truent fuzz <file.sol> --dynamic --chain evm --iterations 1000 --seed 1 [--invariants {bundle_dir}/props.invar]
   ```
3. **Read the result.** This is a real run (a scratch ERC20 whose `airdrop` credits a balance
   and never touches supply):
   ```
   ▶ Dynamically fuzzing airdrop.sol (revm, 300 runs, depth 10)...

   ✗ [PROVEN] airdrop.sol
   Invariant violated: ERC20 conservation: sum(balanceOf) == totalSupply()
   ERC20 conservation: sum(balanceOf) == totalSupply(): sum(balanceOf) = 926440076 != totalSupply() = 0

   Reproduction (1 call):
     1. airdrop(00000000000000000000000004040404040404040404040404040404040404040000000000000000000000000000000000000000000000000000000037385a8c)  [caller=0x0101010101010101010101010101010101010101]

   Failing step: #1 (airdrop)
   ```
   That block is the proof. Promote the finding to `VERIFIED-PROVEN`, confidence 100, and
   paste it unchanged under **Proof (engine)** in the run file. Record the exact command as a
   `repro_N` key (SKILL.md Turn 2-engine says how) so the Reproduce footer carries it.
4. **Vary the seed before concluding "not reproducible"** — `--seed 2`, `--seed 3`, and a
   raised `--iterations`. The search is deterministic per seed. If the property holds across
   all of them, the engine is telling you it is not violated the way the model claimed:
   **demote to LEAD** with the clause "the engine held `<property>` across seeds 1–3 at 3000
   iterations", or **drop** when the search also showed the guard the agent missed.
5. **When the engine cannot run, say so and stop.** Also a real run, on a corpus file with no
   ERC20-shaped ABI:
   ```
   ⚠ not analysed: no auto-detectable invariant on this ABI (looked for ERC20-shaped totalSupply/balanceOf, or monotonic accumulator getters) and no --invariants file supplied — nothing to check

   ✗ 1 of 1 contract(s) could not be analysed — this is not a pass:
   ```
   The engine says it in its own words: *this is not a pass*. The finding stays `REASONED`
   and the clause quotes the reason. The same holds for a `solc` failure (the engine prints
   the compiler error and suggests `SOLC_PATH` / `TRUENT_SOLC_VERSION`) and for a constructor
   that reverts on deployment. Never present "could not run" as "no dynamic bugs", and never
   present it as a reproduction.

### Observed engine limits (truent 0.6.0) — document, do not work around

Two limits of `truent fuzz --dynamic --chain evm` were observed on real runs, and the
orchestrator records them as the `skipped` reason rather than editing the contract to get
past them (the READ-ONLY rule):

- **Constructor arguments.** The fuzzer deploys with no constructor arguments. A contract
  whose constructor takes parameters reverts on deployment and the engine stops with
  `could not deploy the contract in the in-memory EVM: constructor reverted … The constructor
  takes N argument(s) and the fuzzer deploys with none.` Observed on `examples/evm_token.sol`
  in the Truent repo itself. Record `dynamic skipped (constructor takes arguments)`.
- **Relative imports.** The fuzzer compiles a temporary copy of the file, so `import
  "./Lib.sol"` and remappings do not resolve; `solc` fails with an undeclared identifier or
  a missing file. Record `dynamic skipped (relative import; the engine compiles a temp copy)`.

A contract with neither — a self-contained file with a no-argument constructor and an
ERC20-shaped or accumulator-shaped ABI — is the target the fuzzer runs on today. State the
limit in the finding's unverified clause; never call the skip a pass and never rewrite the
contract to make it fuzzable.

### Symbolic execution

When the repository is a Foundry project with `check_*` / `prove_*` tests and `halmos`,
`hevm` or `mythril` is installed, `truent symbolic <project> --format json` turns a
counterexample into a proven finding (`evm_symbolic_counterexample`) and an undecided check
into `evm_symbolic_unresolved`. A counterexample is `VERIFIED-PROVEN`. Truent does not write
the tests: it drives the ones the repository already has, so the READ-ONLY rule holds.

### Deployed targets

```bash
truent fuzz --dynamic --address 0x<contract> --rpc-url <endpoint> --iterations 1000 --seed 1
```

Truent fetches the runtime bytecode, probes it against known ERC20/Ownable selectors, and
fuzzes the confirmed surface. It does not fork on-chain storage — it exercises the code's own
accounting from a fresh state. State that scope in the finding.

## Solana — plan generation and validation; execution deferred

An Anchor IDL describes the instruction surface but says nothing about the world the program
runs in: which accounts exist, what is in them, which one is *the* mint, what must stay true.
The plan is that world. The orchestrator writes it in `{bundle_dir}` from the agent's
`property:` line and the account layout it can read in the source, then runs:

```bash
truent fuzz <anchor-idl.json> --dynamic --chain solana --plan {bundle_dir}/plan.json
```

**In truent 0.6.0 this validates and stops.** The engine parses the IDL, parses the plan,
checks every pubkey, every invariant type and every pinned account, reports
`IDL and plan are valid (N fuzzable instruction(s)), but this release cannot execute them`,
and exits. That is still worth doing — it is deterministic, it catches a malformed property
before a human spends time on it, and the plan is ready for the backend when it ships — but
**it proves nothing**. No Solana finding is `VERIFIED-PROVEN` in this release. Verification
beyond the static detectors is **EXTERNAL**: an Anchor `#[test]` or a `solana-program-test`
harness the orchestrator runs on a copy in `{bundle_dir}/ext-solana/`, labelled EXTERNAL in
the proof, tier unchanged. Record `engine_dynamic_solana` as
`n/a (plan validated; execution deferred in truent 0.6.0)` when a plan was validated, and
`n/a (execution deferred in truent 0.6.0)` otherwise.

The IDL comes from the repository's `target/idl/` when it has been built, or from the `idl/`
directory the project commits; the skill does not build the program (that would write into
`target/`).

The plan, field by field (`crates/dynamic/solana/src/config.rs` in the Truent repo is the
schema):

```json
{
  "program_id": "<base58 program id, optional>",
  "program_so": "target/deploy/my_program.so",
  "accounts": [
    { "name": "mint",  "pubkey": "<base58>", "lamports": 1000000000, "space": 82 },
    { "name": "alice", "pubkey": "<base58>", "lamports": 1000000000, "space": 165 },
    { "name": "bob",   "pubkey": "<base58>", "data_hex": "0x00ff…", "owner": "<base58>" }
  ],
  "signers":  ["<authority pubkey>"],
  "writable": ["<mint>", "<alice>", "<bob>"],
  "readonly": [],
  "pin": { "mint": "<mint>" },
  "invariants": [
    { "type": "token_conservation", "name": "supply matches accounts",
      "mint": "<mint>", "token_accounts": ["<alice>", "<bob>"],
      "amount_offset": 64, "supply_offset": 36 },
    { "type": "account_owner", "name": "vault stays program-owned", "account": "<vault>" }
  ],
  "seed": 1, "runs": 500, "depth": 10
}
```

- `accounts[]` — genesis accounts. `space` gives zero-filled data of that length; `data_hex`
  gives exact bytes and overrides `space`; `owner` defaults to the program under test;
  `lamports` defaults to 1 000 000 000.
- `signers[]` / `writable[]` / `readonly[]` — the pool the generator draws instruction accounts
  from. A pubkey in `signers` is treated as having signed; that is how "what if the authority
  did not sign" is exercised — leave it out.
- `pin{}` — an IDL account name pinned to one pubkey, so `mint` is always *the* mint.
- `invariants[]` — exactly two types exist: `token_conservation` (`sum(amount)` over the
  listed token accounts equals the mint's supply; `amount_offset` 64 and `supply_offset` 36
  are the SPL Token layout) and `account_owner` (the account's owner never changes). A plan
  with no invariants is an error: a fuzz run with nothing to check proves nothing.

Match the agent's `property:` to these two shapes. "Anyone can mint to their own account" and
"withdraw moves tokens out of the vault without burning" → `token_conservation`. "The vault
account can be reassigned / closed / re-owned" → `account_owner`. A property that is neither
(a PDA-seed collision, a missing signer on a lamport transfer) is **not** machine-verifiable
by Truent today: the finding stays `REASONED`, and the clause says "no plan invariant type
expresses this". Do not stretch `account_owner` to mean something it does not check.

When the backend ships, a violation will print the broken invariant and a minimal instruction
sequence, like the EVM output above, and that block will be the proof. Until then: a plan the
engine **accepts** leaves the finding `REASONED` with the clause "plan validated by the
engine (N fuzzable instructions); execution deferred in truent 0.6.0; verified externally by
…" or "…; not verified"; a plan the engine **rejects** (bad pubkey, unknown invariant type)
leaves it `REASONED` with the engine's error quoted. A later editor who reads a newer engine's
help and finds the backend present must move Solana into the PROVEN row of the table above
and delete this paragraph — not before.

## Move — external verification only

Truent has no Move execution backend. What exists, outside Truent:

- **Move Prover.** A `spec` block on the function states the property (`aborts_if`,
  `ensures`, a global invariant over a resource) and `aptos move prove` (Aptos) or the Sui
  prover checks it. A failed proof is a counterexample; a passed proof is the strongest
  refutation this chain offers.
- **`aptos move test`** / **`sui move test`.** A `#[test]` function that drives the attack:
  call the unguarded setter from a non-admin signer, pass a coin of the wrong type to the
  generic deposit, drop the receipt without repaying.
- **Type-level facts need no test.** A struct with no `drop` cannot be dropped; the compiler
  proves it. A capability with `store` *can* leave the module; the declaration proves it. When
  the property is an ability, quote the declaration — that is the proof, and it is static.

The READ-ONLY rule stands. To run a test, copy the package to `{bundle_dir}/ext-move/`, add
the test module there, run it there. Label the result **EXTERNAL** in the finding's proof:
`Proof (external, aptos move test): …`. The finding stays `REASONED`. A passed attack test is
strong evidence a human should weigh; it is not something Truent executed, so the tier does
not move and the Reproduce footer does not list it.

## Soroban — external verification only

Truent has no Soroban execution backend either. What exists:

- **`cargo test` with `soroban-sdk` `testutils`.** `Env::default()`, register the contract,
  call the entry point from an `Address` that did not authorise. **Beware `mock_all_auths()`:**
  a test suite that mocks every auth hides a missing `require_auth`. The attack test must use
  `mock_auths` for the addresses that *should* authorise and none for the attacker, or check
  `env.auths()` after the call.
- **`proptest`** for arithmetic and storage-tier properties: any `i128` sequence that
  overflows a plain `+`, any TTL that lapses between two calls (`env.ledger().set_sequence_number`
  moves the ledger forward in tests).
- **Storage tier is static.** `env.storage().temporary()` for a balance is visible in the
  source; quote it. That is the proof, and the engine already has a detector for it
  (`sor_temporary_storage_critical_state`).

Same handling: copy to `{bundle_dir}/ext-soroban/`, run there, label **EXTERNAL**, tier stays
`REASONED`.

## The rule, again

The machine is the arbiter. LLM confidence never promotes a finding to a `VERIFIED` tier; only
an engine reproduction does. An engine that can't break a claimed property, after a real
search, demotes it. An engine that cannot run leaves the tier alone and the report says why.
This is exactly the step a prompt-only tool structurally cannot perform — it has no engine to
appeal to — and it is the step a later editor must not soften into "the orchestrator judged
the fuzzer would probably find it".
