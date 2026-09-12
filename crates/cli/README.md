# truent

Multi-chain smart contract invariant checker for EVM, Solana, Move, and Soroban.

[![Crates.io](https://img.shields.io/crates/v/truent-cli)](https://crates.io/crates/truent-cli)
[![Downloads](https://img.shields.io/crates/d/truent-cli)](https://crates.io/crates/truent-cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/Emmyhack/Truent/blob/main/LICENSE)

## What is Truent?

Truent is a unified invariant checking framework for smart contracts. Define security properties once in Truent's DSL and verify them across EVM, Solana, Move, and Soroban contracts automatically.

## Quick Start

### Install

```bash
cargo install truent-cli
```

Verify installation:
```bash
truent doctor
```

### Usage

Initialize project:
```bash
truent init
```

Run checks:
```bash
truent check ./contracts --chain evm
```

Generate report:
```bash
truent check ./contracts --format json --output report.json
```

## Supported Chains

| Chain | Language | Checks | Status |
|-------|----------|--------|--------|
| **EVM** | Solidity, Vyper | 44 built-in detectors | ✅ Stable |
| **Solana** | Rust (Anchor, native) | 11 built-in detectors | ✅ Stable |
| **Move** | Move (Aptos, Sui) | 7 built-in detectors, real AST via a vendored Sui tree-sitter grammar | ✅ Stable |
| **Soroban** | Rust (Stellar) | 9 built-in detectors | ✅ Stable |

## Features

- 71 smart contract vulnerability detectors, plus a chain-agnostic rule (`unauthorized_privileged_mutation`) shared across all four
- Custom invariant DSL
- JSON/HTML/text reports
- CI/CD integration
- Violation suppression
- Cross-platform binaries
- Production-ready security analysis

## Documentation

Full documentation: [github.com/Emmyhack/Truent](https://github.com/Emmyhack/Truent)

## License

MIT

