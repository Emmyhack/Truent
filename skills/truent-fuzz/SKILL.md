---
name: truent-fuzz
description: "Stateful invariant fuzzing for smart contracts. Default path runs Truent's native revm-backed fuzzer — auto-detected invariants, adversarial call sequences, and minimal-PoC shrinking in one binary, no external toolchain. Optionally emits an equivalent Echidna/Medusa harness for teams standardized on those runners (strict superset, not lock-in). Triggers on 'truent fuzz', 'fuzz this', 'invariant fuzzing', 'stateful fuzzing', 'build a fuzz harness', 'property testing', 'generate fuzz suite'."
license: MIT
metadata:
  version: "0.1.0"
  author: Emmyhack
  homepage: https://github.com/Emmyhack/Truent
  domain: smart-contract-security
  subdomain: fuzzing
  chains:
    - evm
    - solana
    - move
    - soroban
  requires:
    - "truent >= 0.6.0"
  taxonomy:
    - CWE
    - SWC
    - OWASP-SC-Top-10-2025
    - DASP
  tags:
    - smart-contract
    - fuzzing
    - invariant-testing
    - property-testing
    - echidna
    - medusa
    - revm
    - evm
    - proof-of-concept
---

# Truent Fuzz

Fuzz a contract for broken invariants. The **default** path needs no Echidna,
no Medusa, no Foundry setup, and no hand-written handlers: Truent's native
fuzzer deploys the contract in an in-memory EVM, drives adversarial call
sequences, checks auto-detected invariants after every call, and shrinks any
violation to a minimal, runnable proof-of-concept. One binary, one command.

For teams standardized on Echidna/Medusa, this skill also **emits an equivalent
harness** for the same invariant shapes — so Truent is a strict superset of a
harness generator, never a lock-in.

`$SKILL_DIR` = the directory containing this SKILL.md.

## Default: native fuzzing (recommended)

1. Preflight: locate the `truent` binary; `truent doctor` if unsure.
2. Run per in-scope EVM contract:
   ```bash
   truent fuzz <contract.sol> --dynamic --chain evm --iterations 1000 --seed 1
   ```
   Truent auto-detects invariant shapes from the ABI — **conservation**
   (`totalSupply`/`balanceOf`), **monotonicity** (accumulator getters),
   **access control** (`owner`/`transferOwnership`), **reentrancy** (execution
   trace) — and needs no property authoring for them.
3. On a violation it prints the broken invariant and a **minimal reproduction**
   (the shortest call sequence that triggers it). That sequence IS the PoC —
   report it verbatim. Vary `--seed` (2, 3) and raise `--iterations` before
   concluding an invariant holds.
4. Deployed / unverified target (no source): fuzz fetched bytecode directly —
   ```bash
   truent fuzz --dynamic --address 0x<contract> --rpc-url <https-endpoint>
   ```

The native fuzzer requires `solc` (Truent auto-downloads it, or set
`SOLC_PATH`). Nothing else.

## Optional: emit an Echidna/Medusa harness (interop)

When the team wants the industry-standard runners, generate a property suite
for the same invariants:

```bash
python3 $SKILL_DIR/scripts/emit_harness.py \
  --contract <ContractName> --path <path/to/Contract.sol> \
  --props conservation,supply-monotonic,owner-stable --actors 3 --out test/fizz
```

This writes `test/fizz/TruentHarness.sol` (Echidna/Medusa `echidna_*` property
functions), `medusa.json`, and `echidna.yaml`. The one thing that always needs
human judgment — how the target is deployed and seeded — is a single marked
`TODO` in the constructor; wire it to the project's real setup. Then:

```bash
medusa fuzz --config test/fizz/medusa.json
echidna test/fizz/TruentHarness.sol --contract TruentHarness --config test/fizz/echidna.yaml
```

## Why native-first beats a harness generator

A harness generator's output is only as correct as the handlers and ghost
accounting an LLM wrote for it, and it still needs Echidna/Medusa/Foundry
installed and configured. Truent's native fuzzer removes all of that from the
default path: the invariants are detected, the sequences are generated, the
counterexample is shrunk — deterministically, in one binary — and you still get
the harness on demand if you want it. Less setup, fewer moving parts, a runnable
PoC either way.
