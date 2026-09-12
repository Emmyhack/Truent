# Contributing to Truent

Thank you for your interest in contributing to Truent! This document provides guidelines for contributing to the project.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please be respectful and professional in all interactions.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork: `git clone https://github.com/your-username/Truent.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Commit with clear messages
6. Push to your fork: `git push origin feature/your-feature`
7. Open a Pull Request

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Emmyhack/Truent.git
cd Truent

# Install dependencies
cargo build

# Run tests
cargo test

# Format code
cargo fmt

# Check with clippy
cargo clippy
```

## Code Quality Standards

Truent maintains high code quality standards:

- **No unsafe code** in production paths (enforced via compiler)
- **No compiler warnings**: Compiled with `-D warnings`
- **No unwrap() in production**: Use explicit error handling
- **100% deterministic**: Same input produces same output
- **Comprehensive tests**: Unit, property, CLI, integration, security

## Code Standards

### Rust Code

All code must meet these standards before being merged:

#### 1. **Compilation**
```bash
cargo build --all
```
Must compile without errors on Rust stable (1.93+).

#### 2. **Clippy Linting**
```bash
cargo clippy --all --all-targets -- -D warnings
```
All clippy warnings must be resolved. No exceptions.

#### 3. **Formatting**
```bash
cargo fmt --all -- --check
```
Code must be formatted with `rustfmt`. Run `cargo fmt --all` to auto-format.

#### 4. **Tests**
```bash
cargo test --all
```
All tests must pass. New features must include tests with >90% coverage.

#### 5. **Documentation**
```bash
cargo doc --all --no-deps
```
All public items must have documentation comments.
```rust
/// Analyzes a smart contract program.
///
/// # Arguments
///
/// * `path` - Path to the program source file
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn analyze(&self, path: &Path) -> Result<ProgramModel>
```

#### 6. **No Panics in CLI**
- Library code may use `unwrap()` only in unreachable branches with explicit comments
- CLI code must never panic - use `Result` types instead
- All user-facing operations must return `Result<T, InvarError>` (or `TruentError` once refactored)

#### 7. **No Unsafe Code**
- All unsafe code must be explicitly justified with a comment
- Unsafe blocks must be minimized and isolated
- Document the safety invariant being upheld

#### 8. **Determinism**
- No global mutable state
- Use seeded RNGs where randomness is needed
- Use sorted collections (BTreeMap, BTreeSet) instead of unordered ones
- Tests must be deterministic and reproducible

## Coding Standards

### Naming

- Functions: `snake_case`
- Types/Structs: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Modules: `snake_case`
- Private items: prefix with `_` if intentionally unused

### Comments

```rust
/// Public API documentation comment
/// 
/// # Examples
/// ```
/// let result = my_function();
/// ```
pub fn my_function() {
    // Implementation comment for clarity
    let x = do_something();
    
    // Explain *why*, not *what*
    // We use binary search here because the list is sorted
    binary_search(&x)
}
```

### Error Handling

```rust
// Bad - Don't use unwrap
let value = parse(input).unwrap();

// Good - Use explicit error handling
let value = parse(input)
    .map_err(|e| MyError::ParseFailed(e))?;

// Good - Or provide context
let value = parse(input)
    .context("Failed to parse input")?;
```

### Formatting & Linting

Use `cargo fmt`:
```bash
cargo fmt              # Auto-format code
cargo fmt -- --check  # Check formatting
```

Address all clippy warnings:
```bash
cargo clippy                      # Check all warnings
cargo clippy -- -D clippy::all    # Check specific rules
```

## Commit Message Guidelines

Follow conventional commits with clear, descriptive messages:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

**Examples**:
```
feat(parser): Add support for optional type annotations

Previously, type annotations were always required. This change
makes them optional, inferring types when not specified.

Fixes #42
```

Good:
- "Fix invariant parser handling of logical operators"
- "Add cross-chain invariant validation"
- "docs: Update getting started guide"

Bad:
- "fix stuff"
- "update"
- "wip"

## Testing Requirements

All changes must include tests. Run tests with:

```bash
# Run all tests
cargo test

# Run specific test category
cargo test --test unit
cargo test --test property
cargo test --test cli
cargo test --test integration
cargo test --test security

# Check test coverage
cargo tarpaulin --out Html

# Run benchmarks
cargo bench
```

**Coverage Goals**:
- Core module: 90%+
- Overall: 80%+

### Unit Tests

Test individual functions:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_expression() {
        let input = "balance >= 0";
        let result = parse_expr(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "balance");
    }

    #[test]
    fn test_invalid_syntax_fails() {
        let input = "balance >= ";
        let result = parse_expr(input);
        assert!(result.is_err());
    }
}
```

### Integration Tests

Place in `tests/` directory:
```rust
// tests/integration_test.rs
#[test]
fn test_end_to_end_analysis() {
    let analyzer = SolanaAnalyzer::new();
    let result = analyzer.analyze("examples/solana_token_transfer.rs");
    assert!(result.is_ok());
    let program = result.unwrap();
    assert_eq!(program.functions.len(), 2);
}
```

### Performance Tests

For performance-critical code:
```rust
#[bench]
fn bench_parse_large_expression(b: &mut Bencher) {
    let expr = /* large expression */;
    b.iter(|| parse_expr(&expr));
}
```

## Documentation Guidelines

Documentation must be updated with code changes:

```bash
# Check documentation builds
cargo doc --no-deps --open
```

Include:
- Doc comments on public APIs
- Example usage for new features
- Update README if scope changes
- Update guides in `/docs/` if needed

### Module-Level Documentation

```rust
//! Module description.
//!
//! This module handles X and is responsible for Y.
//!
//! # Examples
//!
//! ```
//! let item = ModuleName::new();
//! item.do_something()?;
//! ```
```

### Function Documentation

```rust
/// Short description (one sentence).
///
/// Longer description explaining behavior, constraints, etc.
///
/// # Arguments
///
/// * `param1` - Description of param1
/// * `param2` - Description of param2
///
/// # Returns
///
/// Returns X when successful.
///
/// # Errors
///
/// Returns `InvarError::InvalidInput` if param validation fails.
///
/// # Examples
///
/// ```
/// let result = function(arg1, arg2)?;
/// assert_eq!(result.value, expected);
/// ```
pub fn function(param1: Type1, param2: Type2) -> Result<ReturnType>
```

## Pull Request Process

1. **Create descriptive PR title**: "Add feature X" or "Fix issue #123"
2. **Provide context**: Explain what, why, and how
3. **Link issues**: "Closes #42" or "Fixes #123"
4. **Ensure tests pass**: All CI checks must pass
5. **Request review**: At least one maintainer must approve
6. **Maintainer merges**: After approval, maintainer will merge

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No compiler warnings
- [ ] Code formatted with `cargo fmt`
- [ ] Passes `cargo clippy`
- [ ] Coverage goals met
- [ ] Determinism verified
- [ ] Commits have clear, descriptive messages

## Issue Reporting

### Feature Requests

Before implementing a new feature:

1. Open a GitHub issue with the label `enhancement`
2. Describe the use case and expected behavior
3. Discuss with maintainers
4. Get consensus before starting implementation

**Include**:
- Motivation for the feature
- Proposed API (if code changes)
- Example usage
- Any known concerns or edge cases

### Bug Reports

When reporting bugs, include:

1. Your Rust version (`rustc --version`)
2. A minimal reproduction example
3. Expected vs actual behavior
4. Relevant logs (enable with `RUST_LOG=debug`)

**Example**:
```
**Describe the bug**
Parser fails on valid logical operator syntax.

**To Reproduce**
```
invariant Test {
    (a || b) && c
}
```

**Expected behavior**
Should parse successfully.

**Actual behavior**
Error: expected unary at ...

**Environment**
- Rust version: 1.93.0
- Truent version: 0.1.0
- OS: Linux
```

## Code Review

All contributions go through code review:

- **Maintainers** review for correctness and quality
- **Security focus** on sensitive code
- **Architecture review** for larger changes
- **Documentation review** for clarity

**Review feedback** should be constructive and helpful.

## Release Process

Maintainers handle releases. The process is:

1. Update version in `Cargo.toml` (semantic versioning)
2. Update `CHANGELOG.md`
3. Run full test suite
4. Create GitHub release
5. Publish to crates.io

**When the release is ready**:
- Create a git tag: `git tag v0.2.0`
- Push tag: `git push origin v0.2.0`
- GitHub Actions builds and uploads release artifacts

Contributors should not publish releases.

## Adding Dependencies

Dependencies should be:
- **Necessary**: Only add if truly needed
- **Maintained**: Actively maintained projects
- **Audited**: No known security vulnerabilities

When adding a dependency, explain in your PR:
- Why the dependency is needed
- Version pinning rationale
- Security considerations

Run audit to check for vulnerabilities:
```bash
cargo audit
```

## Performance Considerations

When contributing performance-sensitive code:

- Profile before optimizing
- Benchmark improvements with `cargo bench`
- Consider memory allocation patterns
- Use iterators instead of collecting vectors when possible
- Avoid cloning where feasible

## Architecture Decisions

For significant changes, open an issue for discussion:

1. **Problem Statement**: What are we solving?
2. **Proposed Solution**: How would we solve it?
3. **Alternatives Considered**: Other approaches?
4. **Pros and Cons**: Trade-offs?
5. **Implementation Plan**: How would we build it?

Major architectural changes should:
- Be discussed in a GitHub discussion first
- Include design rationale
- Consider backward compatibility
- Include migration guide if breaking

## Community

- **GitHub Discussions**: Questions and ideas
- **GitHub Issues**: Bugs and feature requests
- **Discord**: Real-time chat
- **Email**: security@truent.dev (security issues only)

## License

Contributions are licensed under the same license as the project (check LICENSE file).

## Questions?

Have questions?
- Check [Getting Started](docs/getting-started.md)
- Read [Architecture Overview](docs/architecture-overview.md)
- Open a GitHub discussion
- Check existing issues
- Ask in pull request comments
- Email maintainers

Thank you for contributing to Truent!
