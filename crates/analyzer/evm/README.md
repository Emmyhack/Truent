# truent-analyzer-evm

EVM (Solidity) analyzer for the Truent framework.

## Usage

```toml
[dependencies]
truent-analyzer-evm = "0.3.0"
truent-core = "0.3.0"
truent-ir = "0.3.0"
```

## Key Components

- `EvmAnalyzer` — implements `ChainAnalyzer` (`analyze(&self, path: &Path) -> Result<ProgramModel>`); parses via `solc`'s JSON AST when `solc` is installed
- `detectors::run_all_detectors(source, file_path)` — the entry point the CLI calls; runs all 77 EVM pattern detectors (regex/source-text based, no `solc` required) plus the shared cross-chain `unauthorized_privileged_mutation` rule (best-effort, needs `solc`)
- `bytecode::BytecodeAnalyzer` — disassembles and inspects compiled bytecode (not currently wired into `run_all_detectors`)
- `cfg::ControlFlowGraph`, `symbolic` — control-flow/symbolic-value scaffolding used internally by `semantic_model`

## Example

```rust
use truent_analyzer_evm::detectors::run_all_detectors;

let source = std::fs::read_to_string("Vault.sol")?;
let findings = run_all_detectors(&source, "Vault.sol");
println!("Found {} findings", findings.len());
```

## Detectors (77)

Eighteen detectors were added after ranking 23,625 public audit-contest
findings by severity-weighted frequency and keeping the classes a static
source scanner can decide (`token_handling.rs`, `eth_and_calls.rs`,
`numeric_and_params.rs`, `protocol_state.rs`, `crypto_and_oracle.rs`): raw
ERC-20 calls on caller-chosen tokens, hard-coded 18-decimal maths, unsafe
approvals, `transferFrom` for NFTs, 2300-gas Ether sends, `msg.value` reused
in loops, `tx.origin` authorisation, front-runnable `permit`, unsafe
downcasts, unbounded fee setters, zero-address setters, interest not accrued,
missing reward checkpoints, flash-loanable vote weight, swaps whose deadline
is the current block, unvalidated `ecrecover`, `abi.encodePacked` collisions
and unvalidated oracle answers. The slippage detector was rewritten at the
same time: a caller-supplied minimum is protection, a minimum derived from
the pool's own quote is not.

Named historical-exploit patterns (health check, merkle root, DVN single
point of failure, unbacked synthetic mint, LST depeg, oracle self-trade,
ERC4626 inflation, arbitrary call `msg.value`, reentrancy via whitelisted
contracts, proxy storage collision, bridge address verification, read-only
reentrancy, insufficient multisig threshold, arbitrary function-selector
dispatch, stale oracle price, fee-on-transfer/rebasing incompatibility,
cross-chain signature replay, unbounded pricing input, ERC-4337 validation
side effects, and more) plus one proactive detector for an emerging
(not-yet-publicly-exploited) risk — EIP-7702 breaking `tx.origin` EOA
assumptions — plus a base set of classic patterns (reentrancy, missing
signer/access checks, unchecked math, missing conservation checks). See
`src/detectors/mod.rs` for the full list.

## Supported Chains

Any EVM-compatible chain (Ethereum, Arbitrum, Optimism, Polygon, ...) —
detection is source/AST based, not chain-ID specific.

## License

MIT
