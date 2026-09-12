# Contributing to @truent/cli

Thank you for interested in contributing! This document provides guidelines for contributing to the npm package wrapper.

## What is @truent/cli?

This npm package is a **thin wrapper** around the Rust `truent-cli` binary. It:
- Downloads platform-specific binaries from GitHub releases
- Provides a Node.js programmatic API
- Enables integration with JavaScript/TypeScript projects

## Where to Contribute

### Issues & Features for the npm package

- **Binary download issues**: Report at https://github.com/Emmyhack/Truent/issues
- **Node.js API suggestions**: Post on https://github.com/Emmyhack/Truent/discussions
- **Installation problems**: Github Issues with error message and `npm --version`, `node --version`

### Rust/Invariant Analysis Features

**The actual Truent analysis engine is written in Rust.** Contributions to:
- Invariant detection
- New blockchain support
- Analysis algorithms
- Core invariants

Should be made to the main Truent repository at https://github.com/Emmyhack/Truent

## Development Setup

### Prerequisites
```bash
Node.js >= 16
npm >= 8
```

### Local Development

```bash
git clone https://github.com/Emmyhack/Truent.git
cd Truent/truent-npm

# Install dependencies
npm install

# Run tests
npm test

# Test the package locally
npm link
truent --version

# Unlink when done
npm unlink @truent/cli
```

## Making Changes

### Code Style
- Use 2-space indentation
- Use camelCase for variables/functions
- Add JSDoc comments for all exported functions
- No semicolons (but use them if you prefer — we don't enforce)

### Examples
```javascript
/**
 * Analyze the given path.
 * 
 * @param {object} options Analysis options
 * @param {string} options.path Path to analyze
 * @param {string} options.chain blockchain (evm, solana, move)
 * @returns {Promise<Report>} Analysis report
 */
async function analyze(options) {
  // implementation
}
```

### Testing
Add tests for any new functionality:

```bash
# Run all tests
npm test

# Run specific test file
npm test detect-platform.test.js

# Watch mode
npm test -- --watch
```

### Error Messages
Follow this pattern for user-facing errors:
1. **What went wrong** (be specific)
2. **Why it happened** (context)
3. **How to fix it** (actionable)

Example:
```javascript
throw new Error(
  `Failed to download Truent binary\n` +
  `URL: https://github.com/Emmyhack/Truent/releases/download/...\n` +
  `HTTP 404: Release not found\n\n` +
  `Solutions:\n` +
  `1. Check if the version exists: https://github.com/Emmyhack/Truent/releases\n` +
  `2. Install via Rust: cargo install truent-cli\n` +
  `3. See: https://github.com/Emmyhack/Truent/issues`
);
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following the code style above
4. **Add tests** for new functionality
5. **Run tests locally**:
   ```bash
   npm test
   ```
6. **Commit with clear message**:
   ```bash
   git commit -m "feat: Add feature description"
   ```
   Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`

7. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
8. **Open a Pull Request** on GitHub
   - Link any related issues: `Closes #123`
   - Describe what your PR does
   - Mention any breaking changes

## Commit Message Guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat: Add new feature`
- `fix: Fix a bug`
- `docs: Update documentation`
- `test: Add or update tests`
- `chore: Update dependencies or config`
- `refactor: Code restructuring without behavior change`

## Platform Support

The npm package supports:
- ✅ Linux x86_64 (glibc and musl)
- ✅ Linux ARM64
- ✅ macOS x86_64
- ✅ macOS ARM64 (Apple Silicon)
- ✅ Windows x86_64

When adding features, ensure they work on all platforms. Remember:
- `process.platform`: "linux" | "darwin" | "win32"
- `process.arch`: "x64" | "arm64"
- Use `path.join()` for cross-platform paths
- Use `.bat` files on Windows, `.sh` on Unix

## Release Process

**Note**: This package version is synchronized with Truent releases.

Releases are automated via GitHub Actions:
1. Create a git tag in the Rust repo: `git tag v0.1.4`
2. Push the tag: `git push origin v0.1.4`
3. GitHub Actions:
   - Builds Rust binaries for all platforms
   - Updates npm package version
   - Publishes to npmjs.com

The npm package version **always equals** the Rust version.

## Reporting Bugs

Found a bug? Open an issue with:
1. **Title**: Clear one-liner (e.g., "Binary download fails behind corporate proxy")
2. **Environment**:
   ```
   - OS: macOS 12.0
   - Node.js: 18.0.0
   - npm: 9.0.0
   - @dextonicx/cli: Latest
   ```
3. **Steps to reproduce**: Exact commands to trigger the bug
4. **Expected vs actual behavior**
5. **Full error message** (paste the complete output)
6. **Screenshots** if applicable

## Questions?

- **Discussions**: https://github.com/Emmyhack/Truent/discussions
- **Issues**: https://github.com/Emmyhack/Truent/issues
- **Email**: Open an issue and mention if you need direct contact

---

Thank you for contributing! 🚀
