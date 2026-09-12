# Installation Guide for @dextonicx/cli

Complete guide to installing and configuring the Truent npm package.

## Table of Contents

1. [Quick Install](#quick-install)
2. [Global Install](#global-install)
3. [Project Install](#project-install)
4. [Using npx](#using-npx)
5. [Cargo Alternative](#cargo-alternative)
6. [CI/CD Integration](#cicd-integration)
7. [Troubleshooting](#troubleshooting)
8. [Uninstall](#uninstall)

---

## Quick Install

```bash
npm install -g @dextonicx/cli
truent --version
```

---

## Global Install

Install globally to use `truent` command anywhere:

```bash
npm install --global @dextonicx/cli
```

Verify:
```bash
truent --version
truent check --help
```

Uninstall:
```bash
npm uninstall --global @dextonicx/cli
```

---

## Project Install

Install as a dev dependency in your project:

```bash
cd my-smart-contracts-project
npm install --save-dev @dextonicx/cli
```

Use in package.json scripts:
```json
{
  "scripts": {
    "audit": "truent check ./contracts --chain evm",
    "audit:json": "truent check ./contracts --chain evm --format json",
    "audit:fail-high": "truent check ./contracts --chain evm --fail-on high"
  }
}
```

Run with npm:
```bash
npm run audit
npm run audit:json
npm run audit:fail-high
```

Or with npx:
```bash
npx truent check ./contracts --chain evm
```

---

## Using npx

No installation needed — download and run in one command:

```bash
npx @dextonicx/cli check ./contracts --chain evm
```

First run downloads the binary, subsequent runs use the cached version in your npm cache.

---

## Cargo Alternative

If you have Rust installed, use Cargo:

```bash
cargo install truent-cli
truent --version
```

Then use npm's API pointing to the Cargo binary:
```bash
export TRUENT_BINARY_PATH=$(which truent)
npm install @dextonicx/cli
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Smart Contract Audit

on: [push, pull_request]

jobs:
  truent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      
      - name: Install Truent
        run: npm install -g @dextonicx/cli
      
      - name: Run Truent checks
        run: truent check ./contracts --chain evm --fail-on high
```

### Behind Corporate Proxy

If npm must go through an HTTP proxy:

```bash
npm config set https-proxy [protocol://]login:password@[host]:[port]
npm config set proxy [protocol://]login:password@[host]:[port]

npm install -g @dextonicx/cli
```

Or set environment variables:
```bash
export HTTPS_PROXY=http://proxy.company.com:8080
npm install -g @dextonicx/cli
```

### CI Environment with Pre-downloaded Binary

Skip automatic download in CI:

```bash
# In your CI config
export TRUENT_SKIP_DOWNLOAD=1
npm install @dextonicx/cli

# Provide your own binary
export TRUENT_BINARY_PATH=/opt/truent/bin/truent
truent check ./contracts --chain evm
```

### Docker

```dockerfile
FROM node:20-slim

# Install Truent npm package
RUN npm install -g @dextonicx/cli

# Copy your contracts
COPY ./contracts /app/contracts
WORKDIR /app

# Run analysis
RUN truent check ./contracts --chain evm --fail-on high
```

Then:
```bash
docker build -t my-contract-auditor .
docker run my-contract-auditor
```

### GitLab CI

```yaml
audit:
  image: node:20
  before_script:
    - npm install -g @dextonicx/cli
  script:
    - truent check ./contracts --chain evm --fail-on high
  artifacts:
    reports:
      codequality: truent-report.json
```

### Jenkins

```groovy
pipeline {
  agent any
  
  stages {
    stage('Install Truent') {
      steps {
        sh 'npm install -g @dextonicx/cli'
      }
    }
    
    stage('Audit Contracts') {
      steps {
        sh 'truent check ./contracts --chain evm --fail-on high'
      }
    }
  }
  
  post {
    always {
      sh 'truent check ./contracts --chain evm --format json --output truent-report.json || true'
      publishHTML([
        reportDir: '.',
        reportFiles: 'truent-report.json',
        reportName: 'Truent Report'
      ])
    }
  }
}
```

---

## Troubleshooting

### Issue: "Command truent not found"

**Solution 1**: Install globally

```bash
npm install -g @dextonicx/cli
```

**Solution 2**: Use npx

```bash
npx @dextonicx/cli check ./contracts --chain evm
```

**Solution 3**: Use npm script in package.json

```json
{
  "scripts": {
    "audit": "truent check ./contracts --chain evm"
  }
}
```

Then run:
```bash
npm run audit
```

---

### Issue: "Truent binary is not installed"

The postinstall script may have been skipped or failed.

```bash
# Reinstall completely
npm uninstall @dextonicx/cli
npm install @dextonicx/cli
```

Or provide your own binary:
```bash
# Install via Cargo
cargo install truent-cli
export TRUENT_BINARY_PATH=$(which truent)
npm install @dextonicx/cli
```

---

### Issue: "Binary file not executable" or "cannot execute binary file"

The binary may have lost execute permission or was compiled for wrong architecture.

**Solution**: Reinstall

```bash
npm uninstall --force @dextonicx/cli
npm install @dextonicx/cli
```

Check your platform is supported:
```bash
node -e "console.log(process.platform, process.arch)"
```

Supported: `linux x64`, `linux arm64`, `darwin x64`, `darwin arm64`, `win32 x64`

---

### Issue: Download fails behind proxy

Set proxy environment variables:

```bash
export HTTPS_PROXY=http://proxy:8080
export HTTP_PROXY=http://proxy:8080
npm install @dextonicx/cli
```

Or configure npm permanently:
```bash
npm config set https-proxy http://proxy:8080
npm config set proxy http://proxy:8080
npm install @dextonicx/cli
```

---

### Issue: "ENOSPC: no space left on device"

Your disk is full. Free up space:

```bash
# Clear npm cache
npm cache clean --force

# Try again
npm install @dextonicx/cli
```

---

### Issue: "HTTP 404" during download

The release may not exist for your version. Check:

```bash
https://github.com/Emmyhack/Truent/releases
```

Install a different version:
```bash
npm install @dextonicx/cli@latest
```

Or install via Cargo:
```bash
cargo install truent-cli
```

---

### Issue: Permission denied on macOS/Linux

macOS prevents execution of unsigned binaries. Allow it:

```bash
# Allow the binary to run
sudo spctl --add /path/to/.truent-bin/truent
```

Or reinstall:
```bash
npm uninstall @dextonicx/cli
npm install @dextonicx/cli
```

---

## Uninstall

```bash
# Global
npm uninstall --global @dextonicx/cli

# Local project
npm uninstall @dextonicx/cli

# Force remove (if stuck)
npm uninstall --force @dextonicx/cli
npm cache clean --force
```

---

## Next Steps

After installation:

1. **Verify setup**:
   ```bash
   truent --version
   ```

2. **Initialize config**:
   ```bash
   truent init ./
   ```

3. **Run your first check**:
   ```bash
   truent check ./contracts --chain evm
   ```

4. **Read full docs**:
   - README.md: Usage and examples
   - GitHub: https://github.com/Emmyhack/Truent

---

**Still having issues?** Open an issue: https://github.com/Emmyhack/Truent/issues
