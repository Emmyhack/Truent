# Truent Security Gate (GitHub Action)

A **deterministic** smart-contract security gate for CI. It runs Truent's
compiled static engine on every push/PR, **fails the check** when findings at
or above a threshold exist, and uploads **SARIF** so findings appear inline on
the PR diff and in the repository's **Security → Code scanning** tab.

No LLM. No API keys. No per-run cost. The identical result every time — the
same scan a developer can reproduce locally with `truent scan`.

## Usage

```yaml
name: Security
on: [pull_request, push]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  truent-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Build the truent binary (cache it for speed).
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release --bin truent
      - run: echo "$PWD/target/release" >> "$GITHUB_PATH"

      # The gate: fail the PR on critical findings, publish SARIF.
      - uses: Emmyhack/Truent/.github/actions/truent-gate@main
        with:
          path: src            # your contracts
          chain: evm           # evm | solana | move | soroban
          fail-on: critical    # low | medium | high | critical
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | File or directory to scan. |
| `chain` | `evm` | `evm`, `solana`, `move`, or `soroban`. |
| `fail-on` | `critical` | Minimum severity that fails the check. |
| `truent-bin` | `truent` | Path to the (already built) binary. |
| `upload-sarif` | `true` | Upload SARIF to code scanning. |

## Why a gate, not a chat

Prompt-only audit tools are interactive and non-deterministic — they can't be a
silent, reproducible check on every commit. Truent can: it's a compiled engine,
so the gate is free, fast, and gives the same verdict to every developer and
every reviewer. Pair it with the [`truent-audit`](../../../skills/truent-audit)
skill for deep on-demand review.
