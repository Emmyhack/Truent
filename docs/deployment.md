# Deployment and Operations Guide

## Overview

This guide covers deploying, configuring, and operating Truent in production environments.

**Quick Start:**

```bash
# Install latest release
curl -fsSL https://install.truent.dev | bash

# Initialize project
truent init --project my-project

# Run analysis
truent analyze --config my-project/truent.toml

# Monitor in CI/CD
truent check --strict --output json
```

## Installation

### Pre-Built Binaries

**Latest Release:**
```bash
# Linux
curl -fsSL https://releases.github.com/Emmyhack/truent/latest/linux-x86_64.tar.gz | tar xz
sudo mv truent /usr/local/bin/

# macOS
curl -fsSL https://releases.github.com/Emmyhack/truent/latest/macos-x86_64.tar.gz | tar xz
sudo mv truent /usr/local/bin/

# Windows
curl -fsSL https://releases.github.com/Emmyhack/truent/latest/windows-x86_64.zip -o truent.zip
unzip truent.zip
# Add to PATH
```

**Verify Installation:**
```bash
truent --version
truent --help
```

### Homebrew (macOS/Linux)

```bash
brew tap Emmyhack/truent
brew install truent
```

Update:
```bash
brew upgrade truent
```

### Build from Source

```bash
git clone https://github.com/Emmyhack/Truent.git
cd Truent

# Build release binary
cargo build --release

# Binary at target/release/truent
```

### Docker

```bash
# Pull image
docker pull geekstrancend/truent:latest

# Run analysis
docker run -v /path/to/project:/project geekstrancend/truent:latest \
  analyze --config /project/truent.toml

# Tag and push to registry
docker tag geekstrancend/truent:latest myregistry/truent:v0.1.0
docker push myregistry/truent:v0.1.0
```

Dockerfile:
```dockerfile
FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/truent /usr/local/bin/
ENTRYPOINT ["truent"]
```

## Configuration

### Project initialization

```bash
truent init --project myproject

# Creates:
# myproject/truent.toml
# myproject/invariants.invar
# myproject/.invarignore
```

### Configuration File (truent.toml)

```toml
[project]
name = "my-dapp"
version = "0.1.0"

[chains]
enabled = ["solana", "evm", "move"]

[solana]
programs = ["src/bin/**/*.rs"]

[evm]
contracts = ["contracts/**/*.sol"]

[move]
packages = ["packages/*/Move.toml"]

[reporting]
format = "json"
output = "reports/"
include_warnings = true

[security]
# Fail on violations
strict = false
# Fail on warnings
fail_on_warnings = false
```

### Environment Variables

```bash
# Logging level
export RUST_LOG=debug

# Color output
export RUST_LOG_STYLE=always

# Temporary directory
export TMPDIR=/tmp/truent

# Security: Disable risky features (none available)
export TRUENT_STRICT=1
```

### Ignoring Files

`.invarignore`:
```
# Skip test files
**/test/**
**/tests/**

# Skip examples
examples/

# Platform-specific
*.tmp
*.bak
```

Pattern syntax (gitignore-compatible):
- `*` - Match anything in current directory
- `**` - Match anything, recursively
- `!` - Negation (un-ignore)

## Running Analysis

### Basic Analysis

```bash
# Use config file
truent analyze --config truent.toml

# Specify directory
truent analyze --path /path/to/project

# Multiple paths
truent analyze --path ./src --path ./contracts
```

### Output Formats

```bash
# JSON (for parsing)
truent analyze --output json > report.json

# Markdown (for reading)
truent analyze --output markdown > report.md

# Text (for console)
truent analyze --output text

# Pretty color output
truent analyze --pretty
```

### Filtering

```bash
# Analyze specific chain
truent analyze --chain solana

# Analyze specific invariants
truent analyze --include vault_conservation
truent analyze --exclude experimental_*

# Severity threshold
truent analyze --min-severity warning
```

### Exit Codes

Truent uses exit codes for CI/CD integration:

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success | Continue |
| 1 | Violation found | Fail build |
| 2 | Config error | Fix config, retry |
| 3 | Internal error | File bug report |

**CI/CD Pattern:**
```bash
truent analyze --config truent.toml
case $? in
  0) echo "All invariants satisfied" ;;
  1) echo "Violation detected - halting deploy" && exit 1 ;;
  2) echo "Configuration error" && exit 1 ;;
  3) echo "Internal error - escalate" && exit 1 ;;
esac
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Invariant Check
on: [push, pull_request]

jobs:
  truent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Truent
        run: |
          curl -fsSL https://install.truent.dev | bash
          echo "$HOME/.truent/bin" >> $GITHUB_PATH
      
      - name: Run Analysis
        run: truent analyze --config truent.toml --output json
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: truent-report
          path: truent-report.json
```

### GitLab CI

```yaml
check_invariants:
  image: geekstrancend/truent:latest
  script:
    - truent analyze --config truent.toml --output json --output-file report.json
  artifacts:
    reports:
      dotenv: report.json
  coverage: '/Coverage: (\d+\.\d+)%/'
```

### Jenkins

```groovy
stage('Check Invariants') {
    steps {
        sh '''
            curl -fsSL https://install.truent.dev | bash
            ~/.truent/bin/truent analyze --config truent.toml
        '''
    }
    post {
        always {
            archiveArtifacts artifacts: 'truent-report.*'
        }
        failure {
            currentBuild.result = 'FAILURE'
        }
    }
}
```

### Pre-Commit Hook

`.git/hooks/pre-commit`:
```bash
#!/bin/bash
set -e

echo "Checking invariants..."

if ! truent analyze --config truent.toml --strict; then
    echo "Invariant violations detected"
    exit 1
fi

echo "Invariants satisfied"
```

Install:
```bash
chmod +x .git/hooks/pre-commit
```

## Monitoring & Observability

### Logging

```bash
# Debug level logging
RUST_LOG=debug truent analyze --config truent.toml

# Specific module
RUST_LOG=truent_core=debug truent analyze

# Tracing with spans
RUST_LOG=truent=trace truent analyze
```

### Metrics

Truent produces JSON output for monitoring:

```json
{
  "status": "success",
  "summary": {
    "total_invariants": 42,
    "passed": 40,
    "failed": 2,
    "skipped": 0
  },
  "violations": [
    {
      "invariant": "vault_conservation",
      "severity": "critical",
      "chain": "solana"
    }
  ]
}
```

Parse for monitoring:
```bash
# Extract pass rate
truent analyze --output json | jq '.summary | (.passed / .total_invariants) * 100'

# Alert on violations
if truent analyze --output json | jq '.summary.failed > 0'; then
  send_alert "Invariant violations detected"
fi
```

### Health Checks

```bash
#!/bin/bash
# health_check.sh

# Check installation
truent --version || exit 1

# Check config
truent analyze --config truent.toml --dry-run || exit 1

# Quick smoke test
truent analyze --chain solana --timeout 30s || exit 1

echo "Truent is healthy"
```

Run periodically:
```bash
# In cron
*/5 * * * * /path/to/health_check.sh
```

## Troubleshooting

### Configuration Errors

```bash
# Validate config
truent validate-config --config truent.toml

# Common issues:
# - Missing [project] section
# - Invalid chain name
# - Missing program/contract paths
```

### Performance Issues

```bash
# Profile analysis
time truent analyze --config truent.toml

# Baseline metrics
truent analyze --config truent.toml --benchmark
```

**Optimization:**
- Skip non-critical invariants: `--exclude experimental_*`
- Use specific chains: `--chain solana` (not all)
- Cache results: `--cache /tmp/truent`

### Memory Usage

```bash
# Monitor memory
/usr/bin/time -v truent analyze --config truent.toml

# Reduce memory for large projects
truent analyze --streaming --max-buffer 256M
```

### Debugging

```bash
# Verbose output
truent analyze --config truent.toml -vv

# Generate debug info
truent analyze --config truent.toml --debug-output debug.log

# Backtrace on error
RUST_BACKTRACE=1 truent analyze --config truent.toml
```

## Upgrading

### Check Current Version

```bash
truent --version
# truent 0.1.0
```

### Update Process

```bash
# Check for updates
truent update check

# Install update
truent update --yes

# Verify
truent --version
```

### Breaking Changes

Truent follows [semantic versioning](./versioning.md).

**Migration Guide:**
```bash
# v0.1.0 → v0.2.0
# Review MIGRATION.md before upgrading

# Backup current config
cp truent.toml truent.toml.v0.1.0

# Upgrade
cargo install truent@0.2.0

# Test with dry-run
truent analyze --config truent.toml --dry-run
```

## Security Best Practices

### Access Control

```bash
# Restrict binary permissions
chmod 755 /usr/local/bin/truent

# Only allow specific users
chmod 700 /path/to/truent.toml
chown analyzer:analyzer /path/to/truent.toml
```

### Secret Management

Never commit secrets to config:

```toml
# Bad
[solana]
rpc_url = "http://localhost:8899"
keypair = "secret_key.json"  # Never commit!

# Good
[solana]
rpc_url = "${SOLANA_RPC_URL}"  # From environment
keypair = "${SOLANA_KEYPAIR}"  # From environment
```

Set in CI/CD:
```bash
export SOLANA_RPC_URL="http://localhost:8899"
export SOLANA_KEYPAIR="/secure/path/to/keypair.json"
truent analyze --config truent.toml
```

### Audit Trail

```bash
# Log all runs
truent analyze --config truent.toml --audit-log /var/log/truent.log

# Parse logs
grep "violation" /var/log/truent.log | jq
```

## Production Checklist

Before deploying to production:

- [ ] Test locally with production config
- [ ] Run through CI/CD pipeline
- [ ] Review all invariants are correct
- [ ] Verify reporting/alerts work
- [ ] Check performance on production data
- [ ] Have rollback plan if needed
- [ ] Document any custom configurations
- [ ] Set up monitoring and alerting
- [ ] Train team on tool usage
- [ ] Create runbook for common issues

## Support

- **Issues**: GitHub Issues with `[deployment]` tag
- **Questions**: GitHub Discussions
- **Security**: security@truent.dev
- **Community**: Discord (link in README)

## Summary

**Deployment is straightforward:**
1. Install binary
2. Initialize project config
3. Integrate with CI/CD
4. Monitor results
5. Update regularly

**Success requires:**
- Clear configuration
- Integration with existing CI/CD
- Monitoring for violations
- Regular updates
