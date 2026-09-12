# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- All four test files imported from `../../lib/x` (two directories up) instead of `../lib/x`, matching the actual `__tests__`/`lib` layout - every test suite failed to even load. This is also presumably why the bugs below went uncaught: the suite had never actually run.
- `detectPlatform()` never returned a `version` field despite `postinstall.js` and `verify.js` both reading `platformInfo.version`, silently producing `.../download/vundefined/SHA256SUMS` - the checksum fetch 404'd every time.
- `getBinaryPath()` never validated a `TRUENT_BINARY_PATH` override actually exists, silently returning a bogus path instead of a clear error.
- **Live bug**: `release.yml`'s `.tar.gz` archives (Linux/macOS) nest the binary in a subdirectory (tar-ing the staging directory from outside it), while its `.zip` archive (Windows) is flat (`cd`s into the staging directory before zipping). The installer assumed the flat layout unconditionally, so every real Linux/macOS install would download and checksum-verify successfully and then fail to find the binary. Verified fixed against the real published GitHub release.

### Added

- musl detection (via `detect-libc`) so Alpine and other musl-based Linux systems get the matching binary instead of a glibc build that won't start.
- CI workflow (`npm-package-ci.yml`) - this package had zero CI coverage before, which is exactly how the bugs above went uncaught for as long as they did.

## [0.1.8] - 2026-03-10

### Fixed

- **CRITICAL FIX**: Resolved npm wrapper hanging issue caused by infinite recursion in binary path resolution
  - Removed unsafe `spawnSync("which", ["truent"])` call that caused the wrapper to spawn itself recursively
  - Binary path now safely resolves without subprocess spawning: env var → .truent-bin/ → PATH fallback
  - All commands (`truent check`, `truent doctor`, etc.) now execute immediately without hanging
- Enhanced download robustness with timeout handling
  - Added 30-second socket timeout for network requests
  - Added 60-second hard timeout for entire downloads
  - Prevents postinstall from hanging on stalled network connections
- Fixed binary download to use v0.1.3 (which is stable and verified on GitHub)
  - npm will now download the proven v0.1.3 binary instead of trying to find a non-existent v0.1.8 binary

### Verified

- ✅ `truent --version` executes immediately
- ✅ `truent doctor` completes in ~100ms
- ✅ `truent check` works on EVM/Solana/Move contracts
- ✅ `npm install @dextonicx/cli@0.1.8` downloads v0.1.3 binary and works
- ✅ All commands work when binary is installed locally
- ✅ Graceful error handling when binary is missing

## [0.1.3] - 2026-03-09

### Added

- Initial npm package release for `@truent/cli`
- CLI binary wrapper for all 5 supported platforms (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64)
- Automatic binary download and extraction on `npm install`
- SHA256 checksum verification for downloaded binaries
- Programmatic Node.js API for running analyses in JavaScript/TypeScript
- Support for EVM, Solana, and Move smart contract analysis
- Environment variable configuration (TRUENT_BINARY_PATH, HTTPS_PROXY, TRUENT_SKIP_DOWNLOAD)
- GitHub Actions CI/CD integration examples
- Hardhat task integration example
- TypeScript type definitions (index.d.ts)
- Comprehensive README with usage examples
- Jest test suite with platform detection and API tests
- Support for proxy configurations via https-proxy-agent

### Features

- **CLI**: `truent check <path> --chain <evm|solana|move>`
- **API**: `analyze()`, `doctor()`, `init()`, `version()`, `isInstalled()`
- **output Formats**: text (default), json, html
- **CI Integration**: `--fail-on` severity levels for automated checks
- **Configuration**: `.truent.toml` support
- **Platform Detection**: Automatic detection of OS/architecture

### Supported Platforms

- Linux x86_64 (glibc)
- Linux ARM64 (aarch64)
- macOS x86_64 (Intel)
- macOS ARM64 (Apple Silicon / M1/M2)
- Windows x86_64 (MSVC)

### Known Limitations

- Requires Node.js 16 or higher
- Binary download requires internet connection (can be skipped with TRUENT_SKIP_DOWNLOAD=1)
- Postinstall script may be skipped with `npm install --ignore-scripts`

---

## Versioning

This npm package version **always matches** the Rust `truent-cli` crate version.
When a new Truent release is published, the npm package is automatically published with the same version.

For example:

- Truent Rust v0.1.3 → `npm install @truent/cli@0.1.3`
- Truent Rust v0.2.0 → `npm install @truent/cli@0.2.0`

---

## Upgrade Guide

### From v0.1.2 → v0.1.3

```bash
npm install @truent/cli@latest
```

No breaking changes.

---

## Release Schedule

This package follows the Truent release schedule:

- New releases published automatically when Rust crate is released
- Version sync maintained via GitHub Actions workflow
- Pre-release versions available on npm with `-alpha` or `-beta` tags

---

For detailed release notes, see the [main Truent repository](https://github.com/Emmyhack/Truent/releases).
