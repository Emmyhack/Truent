# Truent CI/CD Integration Guide

Integrate Truent into your continuous integration pipeline to catch invariant violations before they reach production.

## Quick Start

### GitHub Actions

Add this workflow to `.github/workflows/truent.yml`:

```yaml
name: Truent Invariant Check

on:
  push:
    branches: [main, develop]
    paths:
      - 'contracts/**'
      - 'programs/**'
  pull_request:
    branches: [main, develop]
    paths:
      - 'contracts/**'
      - 'programs/**'

jobs:
  truent-check:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      
      - name: Install Truent
        run: cargo install --git https://github.com/Emmyhack/Truent --bin truent
      
      - name: Run Truent Checks
        run: truent check ./contracts --chain evm --fail-on high --format json --output truent-report.json
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: truent-report
          path: truent-report.json
      
      - name: Comment PR
        if: failure() && github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '❌ Truent invariant checks failed. See workflow run for details.'
            })
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
truent:
  image: rust:latest
  stage: test
  script:
    - cargo install --git https://github.com/Emmyhack/Truent --bin truent
    - truent check ./contracts --chain evm --fail-on high --quiet
  artifacts:
    reports:
      junit: truent-report.xml
    paths:
      - truent-report.json
    expire_in: 30 days
  on:
    - main
    - develop
    - merge_requests
```

### CircleCI

Add to `.circleci/config.yml`:

```yaml
jobs:
  truent-check:
    docker:
      - image: rust:latest
    steps:
      - checkout
      - run:
          name: Install Truent
          command: cargo install --git https://github.com/Emmyhack/Truent --bin truent
      - run:
          name: Run Truent Checks
          command: truent check ./contracts --chain evm --fail-on high
      - store_artifacts:
          path: truent-report.json

workflows:
  version: 2
  test:
    jobs:
      - truent-check:
          filters:
            branches:
              only:
                - main
                - develop
```

## Configuration

### Basic Configuration (`.truent.toml`)

```toml
[project]
name = "my-contracts"
version = "1.0.0"

[chains]
enabled = ["evm"]

[invariants]
# Categories: balance_arithmetic, access_control, state_consistency, etc.
categories = ["balance_arithmetic", "access_control"]

# Or explicitly list:
enabled = [
    "balance_conservation",
    "no_reentrancy",
    "owner_only_function"
]

fail_on = "high"  # Fail on CRITICAL/HIGH
```

### Chain-Specific Configuration

```toml
[chains.evm]
enabled = true
invariants = [
    "balance_conservation",
    "no_reentrancy",
    "safe_delegatecall",
    "safe_selfdestruct"
]
target_directory = "contracts/"

[chains.solana]
enabled = false  # Not using Solana

[chains.move]
enabled = false  # Not using Move
```

## CLI Options for CI

### Output Formats

**Text (default)** - Colored output for humans:
```bash
truent check ./contracts --format text
```

**JSON** - Machine-readable format:
```bash
truent check ./contracts --format json --output results.json
```

**HTML** - Styled report for web viewing:
```bash
truent check ./contracts --format html --output report.html
```

### Retry Behavior

**Fail on any violation:**
```bash
truent check ./contracts --fail-on low
```

**Fail only on critical/high:**
```bash
truent check ./contracts --fail-on high
```

**Never fail (just report):**
```bash
truent check ./contracts --fail-on none
```

### Quiet Mode

Suppress all output except errors:
```bash
truent check ./contracts --quiet
```

Useful for CI to reduce log spam.

### Verbose Mode

Show all checks including passed ones:
```bash
truent check ./contracts --verbose
```

## Pre-commit Hook

Ensure developers run checks locally before committing.

Install `.git/hooks/pre-commit`:

```bash
#!/bin/bash

set -e

# Check if truent is installed
if ! command -v truent &> /dev/null; then
    echo "truent not found. Install with: cargo install --bin truent"
    exit 1
fi

# Run truent on staged contracts
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(sol|rs)$' || true)

if [ -n "$STAGED_FILES" ]; then
    echo "Running Truent checks on staged files..."
    
    for file in $STAGED_FILES; do
        if [ -f "$file" ]; then
            truent check "$file" --quiet
            if [ $? -ne 0 ]; then
                echo "❌ Truent check failed for $file"
                echo "Fix violations and try again."
                exit 1
            fi
        fi
    done
    
    echo "✓ All Truent checks passed"
fi
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

## Suppression Patterns

### Inline Suppression

Suppress a specific check for a function:

```solidity
// @truent-suppress: no_reentrancy
function withdraw() public {
    // ... implementation ...
}
```

Suppress multiple checks:

```solidity
// @truent-suppress: no_reentrancy, safe_delegatecall
function complexOperation() public {
    // ...
}
```

### Config-level Suppression

In `.truent.toml`:

```toml
[[suppression]]
file = "contracts/Legacy.sol"
invariant = "no_reentrancy"
reason = "Legacy code - reentrancy not applicable"
until = "2024-12-31"  # Optional expiration

[[suppression]]
file = "contracts/Risky.sol"
invariants = ["no_reentrancy", "safe_delegatecall"]
reason = "Intentional design pattern"
approved_by = "security-team"
```

## GitHub Actions Examples

### Matrix Testing Multiple Chains

```yaml
strategy:
  matrix:
    chain: [evm, solana, move]

steps:
  - run: truent check ./contracts --chain ${{ matrix.chain }}
```

### Report Posting

```yaml
- name: Run Truent
  id: truent
  run: truent check ./contracts --format json --output report.json
  continue-on-error: true

- name: Post Report Comment
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v6
  with:
    script: |
      const fs = require('fs');
      const report = JSON.parse(fs.readFileSync('report.json', 'utf8'));
      
      const summary = `
      ## Truent Analysis
      - **Total violations:** ${report.summary.violations}
      - **Critical:** ${report.summary.critical}
      - **High:** ${report.summary.high}
      - **Status:** ${report.summary.violations === 0 ? '✅ PASS' : '❌ FAIL'}
      `;
      
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: summary
      });
```

### Comparison with Main Branch

```yaml
- name: Checkout main
  run: git fetch origin main:main

- name: Check current branch
  run: truent check ./contracts --format json --output current.json

- name: Check main branch
  run: |
    git stash
    git checkout main
    truent check ./contracts --format json --output main.json
    git checkout -

- name: Compare results
  run: python3 scripts/compare-reports.py main.json current.json
```

## Docker Integration

### Dockerfile

```dockerfile
FROM rust:latest

RUN cargo install --git https://github.com/Emmyhack/Truent --bin truent

WORKDIR /workspace

ENTRYPOINT ["truent"]
CMD ["doctor"]
```

Usage:

```bash
docker build -t truent-check .

docker run -v $(pwd):/workspace truent-check check ./contracts
```

### Docker Compose

```yaml
version: '3'
services:
  truent:
    image: truent-check:latest
    volumes:
      - ./contracts:/workspace/contracts
      - ./truent.toml:/workspace/.truent.toml
    command: check ./contracts --format html --output report.html
```

## Performance Optimization

### Caching

GitHub Actions caching:

```yaml
- name: Cache cargo registry
  uses: actions/cache@v3
  with:
    path: ~/.cargo/registry
    key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}

- name: Cache Truent installation
  uses: actions/cache@v3
  with:
    path: ~/.cargo/bin/truent
    key: ${{ runner.os }}-truent-bin
```

### Limiting Scope

Only check changed files:

```bash
# Get changed files from main
git diff --name-only main...HEAD -- '*.sol' | xargs truent check
```

### Parallel Checks

Check multiple chains in parallel (GitHub Actions):

```yaml
jobs:
  truent:
    strategy:
      matrix:
        chain: [evm, solana]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo install --bin truent
      - run: truent check ./contracts --chain ${{ matrix.chain }}
```

## Monitoring & Analytics

### Report Storage

Store reports over time:

```bash
# On successful run
mkdir -p reports/$(date +%Y-%m-%d)
truent check ./contracts --format json --output reports/$(date +%Y-%m-%d)/report.json
```

### Trend Analysis

```python
import json
import glob

reports = sorted(glob.glob('reports/*/report.json'))

for report_file in reports:
    with open(report_file) as f:
        data = json.load(f)
        print(f"{report_file}: {data['summary']['violations']} violations")
```

### Grafana Integration

Export metrics for Grafana:

```bash
truent check ./contracts --format json | jq '
.summary |
"truent_violations " + (.violations | tostring) + "\n" +
"truent_critical " + (.critical | tostring) + "\n" +
"truent_high " + (.high | tostring)'
```

## Troubleshooting

### "truent: command not found"

Ensure installation in CI environment:

```bash
# Check if installed
which truent

# Install if missing
cargo install --git https://github.com/Emmyhack/Truent --bin truent

# Verify
truent --version
```

### Timeout Issues

Increase timeouts for large contracts:

```yaml
timeout-minutes: 30  # GitHub Actions
```

### Memory Issues

Set memory limits:

```bash
# Limit to 2GB
truent check ./contracts --max-memory 2GB
```

### Configuration Not Found

Ensure `.truent.toml` is in working directory:

```bash
ls -la .truent.toml
truent init .  # Create if missing
```

## Best Practices

1. **Fail Fast** - Use `--fail-on high` to catch critical issues immediately
2. **Review Reports** - Always review the full HTML report
3. **Suppressions** - Document why checks are suppressed with `approved_by`
4. **Regular Updates** - Update Truent regularly for new invariants
5. **Monitoring** - Track violations over time to detect trends
6. **Local Testing** - Run `truent check` locally before pushing
7. **Pre-commit Hooks** - Prevent commits with violations
8. **Documentation** - Link to Truent docs when violations are found

## Example Workflow

Complete GitHub Actions workflow:

```yaml
name: Smart Contract Analysis

on: [push, pull_request]

jobs:
  truent:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      
      - name: Cache Rust
        uses: Swatinem/rust-cache@v2
      
      - name: Install Truent
        run: cargo install --git https://github.com/Emmyhack/Truent --bin truent
      
      - name: Run Truent
        id: truent
        run: |
          truent check ./contracts \
            --chain evm \
            --fail-on high \
            --format json \
            --output truent-report.json
        continue-on-error: true
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: truent-report
          path: truent-report.json
      
      - name: Check Results
        if: steps.truent.outcome == 'failure'
        run: |
          echo "❌ Truent checks failed"
          cat truent-report.json | jq .
          exit 1
  
  test:
    runs-on: ubuntu-latest
    needs: truent
    steps:
      - uses: actions/checkout@v3
      - run: cargo test --lib
```

## Support

For issues with CI integration:
- Check `.truent.toml` syntax: `truent doctor`
- View full output: Remove `--quiet` flag
- See debug info: Add `--verbose`
- Check logs in CI dashboard for error details
