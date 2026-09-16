# truent-analyzer-move

Move language analyzer for the Truent framework: **Aptos** and **Sui**, from
one grammar and one set of detectors.

Performs static analysis on Move module *source* (not compiled bytecode) to
detect security invariant violations. Every finding is a lead traced through
real syntax; nothing here claims proof.

## Usage

```toml
[dependencies]
truent-analyzer-move = "0.6.0"
truent-core = "0.6.0"
truent-ir = "0.6.0"
```

```rust
use truent_analyzer_move::run_all_detectors;

let source = std::fs::read_to_string("vault.move")?;
let findings = run_all_detectors(&source, "vault.move");
```

## How it works

1. **Parse.** The vendored Sui Move tree-sitter grammar, extended locally for
   Aptos syntax (`acquires` and Move 2 access specifiers, `inline`, `for`
   loops, `script { }` blocks, `address 0x1 { }` blocks, arrow-less function
   types), produces a tree. A tree with any error node is rejected outright.
2. **Model.** `ast.rs` turns the tree into modules, structs (abilities,
   fields), functions (visibility, `entry`, attributes, parameters, return
   type, `acquires`) and bodies (calls, method calls, assignments, bindings,
   `assert!`s, binary operators, aborts, loops, returns).
3. **Dialect.** `ast::detect_dialect` fingerprints the framework in use; every
   finding carries `metadata["dialect"] = aptos | sui | move`.
4. **Privilege.** `privilege::analyze` decides, per function, what is shared
   state and what is authorization:
   - *Aptos*: `borrow_global_mut<T>(addr)` at a fixed or caller-supplied
     address is protocol state; at `signer::address_of(account)` it is the
     caller's own resource. Taking a `&signer` is not a check; asserting who it
     is, or using it as the storage key, is.
   - *Sui*: a `&mut T` parameter whose type the module passes to
     `transfer::share_object` is shared state; an owned object can only be
     supplied by its owner, which is the authorization. A capability
     parameter (`&AdminCap`, `&mut TreasuryCap`, a marker object) is a guard.
     A function that returns an ability-less struct (hot potato) is guarded by
     construction.
   - Reachability: `entry` or plain `public`. `public(package)` and
     `public(friend)` are trusted-caller only; test functions never ship.
5. **Detect.** Every detector reads the model, never the text. If a file does
   not parse, only the text-based manual-overflow check and the regex fallback
   for the shared rule run, and those findings are labelled
   `extraction = regex-fallback`.

## Detectors (17 + 1 shared)

| Detector | Class |
|---|---|
| `move_access_control_missing` | Reachable function writes a parameter of shared / global state with no guard |
| `unauthorized_privileged_mutation` (shared IR rule) | Same, for fund movement, authority change, upgrade, resource removal |
| `move_admin_no_timelock` | Admin-gated change takes effect in the same transaction, no delay in the module |
| `move_admin_transfer_single_step` | Admin reassigned in one call; no pending / accept |
| `move_capability_transferred_to_caller` | Unguarded function mints a capability for a caller-chosen address or signer |
| `move_capability_with_store` | Capability declared `key, store` |
| `move_hot_potato_has_abilities` | Borrow / flash-loan receipt can be dropped or stored |
| `move_liquidity_conservation` | Swap moves both sides of a pool and never asserts the invariant |
| `move_oracle_spot_price` | Price derived from live reserves |
| `move_oracle_stale_price` | Feed read (`get_price_unsafe`, ...) with no age check |
| `move_weak_randomness` | Random outcome from timestamp / epoch / block height / object id |
| `move_randomness_public_function` | Randomness API consumed from a `public` function (test-and-abort) |
| `move_privileged_handle_exposed` | Public function returns a `signer`, `SignerCapability`, `TreasuryCap`, ... |
| `move_divide_before_multiply` | Integer division result multiplied |
| `move_unconstrained_type_argument` | Any `Coin<T>` credited to a store not keyed by `T` |
| `move_unbounded_vector_growth` | Anyone can append to a shared vector the module iterates |
| `move_unbounded_parameter` | Fee / rate / threshold written from an argument with no bound |
| `move_manual_overflow_check` | Hand-rolled shift-and-mask overflow check (Cetus, 2025) |

## Corpus

`tests/corpus/good/` holds a complete, correct Aptos protocol and a complete,
correct Sui protocol; both must produce zero findings. `tests/corpus/bad/`
holds one file per detector, per dialect where the pattern differs, each with
an `// EXPECT:` header naming the detector that must fire. The CLI's golden
snapshot pins the exact output of the whole corpus.

## Grammar

See `vendor/tree-sitter-move-sui/PROVENANCE.md` for the upstream commit and
the local modifications. Regenerate with:

```sh
cd vendor/tree-sitter-move-sui
npx -y tree-sitter-cli@0.25.3 generate --abi 14
```

## License

MIT
