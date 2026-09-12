# Truent Installation Guide

Truent is a production-grade, audit-ready multi-chain smart contract invariant enforcement tool.

## System Requirements

- Minimum 2GB RAM
- 500MB disk space
- Supported platforms: Linux, macOS, Windows

## Installation Methods

### 1. Pre-compiled Binaries (Recommended)

Download the latest release from [GitHub Releases](https://github.com/Emmyhack/Truent/releases).

#### Linux / macOS

```bash
# Download and verify
curl -L -O https://github.com/Emmyhack/Truent/releases/download/v0.3.0/truent-linux-x86_64-0.3.0
curl -L -O https://github.com/Emmyhack/Truent/releases/download/v0.3.0/truent-linux-x86_64-0.3.0.sha256

# Verify checksum (critical for security)
sha256sum -c truent-linux-x86_64-0.3.0.sha256

# Install
chmod +x truent-linux-x86_64-0.3.0
sudo mv truent-linux-x86_64-0.3.0 /usr/local/bin/truent

# Verify installation
truent --version
```

#### macOS (ARM64 / Apple Silicon)

```bash
curl -L -O https://github.com/Emmyhack/Truent/releases/download/v0.3.0/truent-darwin-aarch64-0.3.0
sha256sum -c truent-darwin-aarch64-0.3.0.sha256
chmod +x truent-darwin-aarch64-0.3.0
sudo mv truent-darwin-aarch64-0.3.0 /usr/local/bin/truent
truent --version
```

#### Windows

Download `truent-windows-x86_64-0.3.0.exe` from the releases page and add it to your PATH.

### 2. Install from Source

Requires Rust 1.70.0+. Install from [https://rustup.rs/](https://rustup.rs/).

```bash
git clone https://github.com/Emmyhack/Truent.git
cd Truent
cargo install --path crates/cli
```

### 3. Cargo Install

```bash
# Install latest version
cargo install truent-cli

# Install specific version
cargo install truent-cli --version 0.4.0
```

#### Optional: dynamic Solana fuzzing

Running Solana programs under a real VM (`truent fuzz <idl.json> --dynamic
--chain solana --plan <plan.json>`) links `litesvm`, which more than doubles
the build — 449 crates against 221 — so it is opt-in:

```bash
cargo install truent-cli --features solana-dynamic
```

Nothing else changes: **static** Solana analysis (`truent scan --chain solana`)
is always available, and so is dynamic EVM fuzzing. The prebuilt binaries
(GitHub releases and the npm package) already include the Solana backend, since
those are downloaded rather than compiled.

## Verification

### Check Installation

```bash
truent --version
truent --help
```

### Verify Binary Integrity

Always verify checksums for downloaded binaries:

```bash
# Get the SHA256 sum of your binary
sha256sum /usr/local/bin/truent

# Compare with the published checksum from releases page
# If they match, your binary is verified
```

## Configuration

Truent supports configuration via:

1. **Command-line arguments** (highest priority)

   ```bash
   truent --config path/to/config.toml
   ```

2. **Environment variables**

   ```bash
   export TRUENT_STRICT_MODE=true
   export TRUENT_CHAIN=solana
   ```

3. **Configuration file** (`~/.truent/config.toml`)

   ```toml
   [enforcement]
   strict_mode = true
   re_parse_verification = true
   tamper_detection = true

   [chains]
   enabled = ["solana", "evm", "move"]
   ```

## Uninstallation

```bash
# If installed to /usr/local/bin
sudo rm /usr/local/bin/truent

# If installed via cargo
cargo uninstall truent
```

## Troubleshooting

### Binary not found after installation

Ensure `/usr/local/bin` is in your PATH:

```bash
echo $PATH | grep -q /usr/local/bin || echo "/usr/local/bin not in PATH"
```

### Checksum verification fails

This indicates a corrupted download. Re-download the binary and try again:

```bash
rm truent-*
# Re-download from releases page
```

### Permission denied on Linux/macOS

Make sure the binary is executable:

```bash
chmod +x /usr/local/bin/truent
```

## Security Considerations

1. **Always verify checksums** before running downloaded binaries
2. **Keep Truent updated** to get security patches
3. **Run with least privilege** - don't run as root unless necessary
4. **Enable strict mode** for production deployments:

   ```bash
   truent --strict-mode analyze --file invariants.invar
   ```

## Getting Help

- Report bugs: [https://github.com/Emmyhack/Truent/issues](https://github.com/Emmyhack/Truent/issues)
- Documentation: [https://github.com/Emmyhack/Truent/wiki](https://github.com/Emmyhack/Truent/wiki)
- Community: Discussions at [https://github.com/Emmyhack/Truent/discussions](https://github.com/Emmyhack/Truent/discussions)

## Release Notes

See [RELEASES.md](RELEASES.md) for version history and changelog.

## Building from Source (Advanced)

For reproducible builds from source:

```bash
# Ensure Rust 1.70.0 is installed
rustc --version

# Build in release mode with reproducible settings
cargo build --release -p truent

# Verify the build (if tests are available)
cargo test --release

# Binary will be at target/release/truent
./target/release/truent --version
```

### Reproducibility Verification

All binaries in official releases are built with:

- Rust 1.70.0 (pinned version)
- LTO (Link Time Optimization) enabled
- Optimization level 3
- Cargo.lock committed and locked
- Deterministic build ordering

This ensures that rebuilding the same source code produces bit-for-bit identical binaries.
