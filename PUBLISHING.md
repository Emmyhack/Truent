# Automated Publishing Guide

This guide explains how to publish Truent to **crates.io** (Rust packages) and **npm** (Node.js wrapper) using GitHub Actions.

## Quick Start

### 1. Create a Git Tag and Push

```bash
# Update the workspace version, internal dependency pins, and package.json
./scripts/update_version.sh 0.6.1

# Create annotated tag
git tag -a v0.6.1 -m "Release v0.6.1: Bug fixes and improvements"

# Push tag to trigger CI/CD
git push origin main v0.6.1
```

That's it! GitHub Actions will automatically:

- Run comprehensive tests
- Build multi-platform binaries
- Publish to **crates.io**
- Publish to **npm**
- Create a GitHub release with all binaries

## Prerequisites

### Secrets Configuration

You need to configure two GitHub secrets in your repository:

#### 1. **CRATES_IO_TOKEN** (for Rust publishing) ✅ CONFIGURED

```bash
# Generate at https://crates.io/me
# Click "API Tokens" → "New Token"
# Scopes: select "Only allow API calls scoped to crates.io"
# Confirm the token is active before starting a release.
```

Navigate to:

1. GitHub repo → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `CRATES_IO_TOKEN`
4. Value: (paste your crates.io API token)
5. Click "Add secret"

#### 2. **NPM_TOKEN** (for npm publishing)

```bash
# Generate at https://www.npmjs.com/settings/YOUR_USERNAME/tokens
# Token type: "Automation"
```

Navigate to:

1. GitHub repo → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `NPM_TOKEN`
4. Value: (paste your npm automation token)
5. Click "Add secret"

## Publishing Workflows

### Workflow 1: Automatic Release (Recommended)

**Trigger**: Git tag on main branch matches `v[0-9]+.[0-9]+.[0-9]+`

```bash
# 1. Update version in all files
./scripts/update_version.sh 0.6.1

# 2. Commit version bump
git add .
git commit -m "chore: bump version to 0.6.1"

# 3. Create and push tag
git tag -a v0.6.1 -m "Release v0.6.1"
git push origin main v0.6.1
```

This triggers:

1. **release.yml** → Publishes to crates.io + creates GitHub release
2. **publish-npm.yml** → Publishes to npm registry

### Workflow 2: Manual npm Publication

If crates.io published but npm wasn't triggered:

```bash
# Via GitHub UI:
# 1. Go to Actions → Publish to npm
# 2. Click "Run workflow"
# 3. Enter version (e.g., "0.6.1")
# 4. Click "Run workflow"
```

Or via CLI:

```bash
gh workflow run publish-npm.yml \
  -f version="0.6.1"
```

## Version Control Process

### Step 1: Update the Workspace and npm Versions

All Rust crates inherit the workspace version. Update it once in the root
`Cargo.toml`; do not edit individual crate manifests:

```toml
[workspace.package]
version = "0.6.1"
```

Run `./scripts/update_version.sh 0.6.1` so the workspace version, lockfile,
and npm wrapper stay synchronized.

**truent-npm/package.json**:

```json
{
  "name": "@dextonicx/cli",
  "version": "0.6.1",  // ← Update this
  "description": "..."
}
```

### Step 2: Update CHANGELOG

**CHANGELOG.md** − Add section at top:

```markdown
## [0.6.1] - YYYY-MM-DD

### Added
- Enhanced Solana vulnerability detection with Anchor program support
- 8 additional EVM vulnerability patterns
- 7 Move-specific vulnerability patterns
- Detailed violation messages with code examples

### Fixed
- Improved confidence scoring for all chains
- Better false positive reduction

### Security
- All binaries are deterministically built and reproducible

[0.6.1]: https://github.com/Emmyhack/Truent/releases/tag/v0.6.1
```

### Step 3: Commit and Tag

```bash
git add -A
git commit -m "chore: prepare v0.6.1 release

- Update the workspace and npm package versions
- Update npm package version
- Update CHANGELOG with new features"

git tag -a v0.6.1 -m "Release v0.6.1: Enhanced vulnerability detection"
git push origin main
git push origin v0.6.1
```

## Release Pipeline Stages

The **release.yml** workflow runs these stages in order:

| Stage | Job | Purpose |
| --- | --- | --- |
| 1 | validate-version | Verify semantic version format |
| 2 | ci-verification | Run all tests, formatting, linting |
| 3 | security-audit | Cargo audit, unsafe code review |
| 4 | build-* (6 jobs) | Build for 6 platforms in parallel |
| 5 | verify-reproducibility | Ensure deterministic builds |
| 6 | package-artifacts | Create tar.gz and zip distributions |
| 7 | generate-checksums | Generate SHA256SUMS file |
| **8** | **publish-crates** | **Publish all crates to crates.io** |
| 9 | github-release | Create release with binaries |

The **publish-npm.yml** workflow:

| Stage | Job | Purpose |
| --- | --- | --- |
| 1 | extract-version | Parse version from release tag |
| 2 | wait-crates-io | Verify crates.io has truent-cli |
| 3 | build-npm (6 jobs) | Build binaries for npm package |
| 4 | package-npm | Create npm tarball with binaries |
| 5 | test-npm (6 jobs) | Test on Linux/macOS/Windows |
| **6** | **publish-npm** | **Publish to npm registry** |
| 7 | update-release | Add npm link to GitHub release |

## Monitoring Progress

### GitHub Actions UI

1. Go to: **Actions** tab in your GitHub repo
2. Select workflow: **Release Pipeline** or **Publish to npm**
3. Click the running workflow
4. View real-time logs for each stage

### Key Checkpoints

```
✓ validate-version    → Version format OK
✓ ci-verification     → All tests pass
✓ security-audit      → No critical vulnerabilities
✓ build-* (6 jobs)    → All 6 platforms built
✓ verify-reproducibility → Builds are deterministic
✓ publish-crates      → All crates on crates.io
✓ github-release      → Release created with binaries
✓ publish-npm         → Package on npm registry
```

## Verification After Publishing

### Verify crates.io

```bash
# Check Rust package
cargo search truent-cli

# Install from crates.io
cargo install truent-cli@0.6.1
```

### Verify npm

```bash
# Check npm package
npm view @dextonicx/cli@0.6.1

# Install from npm
npm install -g @dextonicx/cli@0.6.1

# Test it works
truent --version
truent doctor
```

### Verify GitHub Release

1. Go to: **Releases** in your GitHub repo
2. Click the new release tag (v0.6.1)
3. Check:
   - ✓ Release notes with installation instructions
   - ✓ Multi-platform binaries (6 files)
   - ✓ SHA256SUMS file
   - ✓ npm link in description

## Troubleshooting

### Issue: Publishing fails with "already uploaded" error

**Cause**: Package already exists on crates.io/npm

**Fix**:
- Increment version in Cargo.toml and package.json
- Create new tag and push again

### Issue: "CRATES_IO_TOKEN" not found

**Fix**:
1. Settings → Secrets and variables → Actions
2. New secret: `CRATES_IO_TOKEN`
3. Value: (paste token from crates.io)

### Issue: "NPM_TOKEN" not found

**Fix**:
1. Settings → Secrets and variables → Actions
2. New secret: `NPM_TOKEN`
3. Value: (paste token from npm)

### Issue: Some platforms fail to build

**Solution**:
- Click "Re-run failed jobs" in GitHub Actions
- If persistent, check if cross-compilation dependencies installed

### Issue: npm publish hangs

**Solution**:
- Check NPM_TOKEN is an "Automation" token (not "Classic")
- Verify npm account is not locked
- Try manual publish from CLI:
  ```bash
  cd truent-npm
  npm version 0.6.1 --no-git-tag-version
  npm publish --access public
  ```

## Manual Publishing (if needed)

### Publish to crates.io manually

```bash
# Generate token at https://crates.io/me
cargo login YOUR_TOKEN

# Publish in dependency order
cargo publish -p truent-core
cargo publish -p truent-utils
(... other crates in order ...)
cargo publish -p truent-cli

# Verify
cargo search truent-cli
```

### Publish npm manually

```bash
# Generate token at https://www.npmjs.com/settings/YOUR_USERNAME/tokens
npm adduser  # or npm login

cd truent-npm

# Update version
npm version 0.6.1 --no-git-tag-version

# Build Rust binaries (if needed)
./build-binaries.sh

# Publish
npm publish --access public

# Verify
npm view @dextonicx/cli@0.6.1
```

## Version Numbering

Use [Semantic Versioning](https://semver.org/):

- **Major.Minor.Patch** (e.g., `0.6.1`)
- Major: Breaking changes
- Minor: New features (backward compatible)
- Patch: Bug fixes

Examples:
- `0.6.1` → patch release
- `0.2.0` → minor release with new features
- `1.0.0` → major release / stable

## Additional Resources

- [crates.io Publishing Guide](https://doc.rust-lang.org/cargo/publishing/index.html)
- [npm Publishing Guide](https://docs.npmjs.com/getting-started/publishing-npm-packages)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Keep a Changelog](https://keepachangelog.com/)
- [Semantic Versioning](https://semver.org/)
