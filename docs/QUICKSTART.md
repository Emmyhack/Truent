# Truent CLI - Quick Start Guide

Truent is a production-grade multi-chain smart contract invariant checker with a beautiful, intuitive CLI.

## Installation

Install from source:

```bash
cargo install --path . --bin truent
```

## Core Commands

### Check Invariants

Analyze a contract or directory for violations:

```bash
truent check ./contracts --chain evm
truent check ./program.rs --chain solana
```

**Options:**
- `--chain {evm,solana,move}` - Target blockchain (default: `evm`)
- `--fail-on {critical,high,medium,low}` - Exit with status 1 if violations found at this level (default: `low`)
- `--format {text,json,html}` - Output format (default: `text`)
- `--output <path>` - Write output to file (for JSON/HTML)
- `--config <path>` - Use custom configuration file
- `--verbose` - Show all passed checks
- `--quiet` - Suppress all output except errors

### Initialize Project

Create a `.truent.toml` configuration file:

```bash
truent init ./contracts
```

This creates a minimal configuration ready for customization.

### Run Doctor

Check that all Truent components are working:

```bash
truent doctor
```

Output shows health status of:
- truent-core
- EVM, Solana, Move analyzers
- DSL parser
- Invariant library
- Report generator

### Generate Report

Create a report from previous analysis:

```bash
truent report --input results.json --format html --output report.html
```

## Understanding Output

### Banner

On first run, you'll see the Truent ASCII art logo and version. This only shows on interactive terminals.

### Violations

Each violation is displayed in a bordered panel showing:

```
╭─ 1 of 3 ── CRITICAL ──────────────────────────╮
│                                                 │
│ ✗ Reentrancy Vulnerability     no_reentrancy  │
│                                                 │
│ Location  Token.sol:142                        │
│ CWE       CWE-841 · Improper Enforcement      │
│                                                 │
│ [Detailed description of the issue]            │
│                                                 │
│ → [Recommendation for fixing]                  │
│                                                 │
│ Reference  https://docs.truent.dev/...         │
╰─────────────────────────────────────────────────╯
```

**Color Coding:**
- 🔴 **CRITICAL** - Must fix immediately (bright red)
- 🟥 **HIGH** - Should fix soon (red)
- 🟨 **MEDIUM** - Review before deployment (yellow)
- 🔵 **LOW** - Minor improvements (cyan)

### Summary Dashboard

At the end of analysis, you'll see an Analysis Summary with:

- **Target:** The file/directory analyzed
- **Chain:** The blockchain being checked
- **Checks:** Total checks run, violations found, passed, suppressed
- **Duration:** Time taken for analysis
- **Severity Breakdown:** Bar chart of violations by severity
- **Status:** Overall pass/fail verdict

### Passed Checks (verbose mode)

With `--verbose`, shows all checks that passed in a compact 3-column format:

```
Passed Checks (44)

✓ balance_conservation    ✓ no_integer_overflow  ✓ owner_only_withdraw
✓ access_control_present ✓ arithmetic_overflow  ✓ missing_signer_check
```

## Output Formats

### Text (default)

Human-readable with colors and formatting. Best for terminal viewing.

### JSON

For integration with other tools:

```json
{
  "violations": [
    {
      "severity": "critical",
      "title": "Reentrancy Vulnerability",
      "location": "Token.sol:142",
      "cwe": "CWE-841"
    }
  ],
  "summary": {
    "total_checks": 47,
    "violations": 1,
    "passed": 44
  }
}
```

### HTML

Generates a styled report file perfect for sharing with teams.

## Configuration

Create a `.truent.toml` in your project:

```toml
[project]
name = "my_contracts"
version = "0.1.0"

[chains]
enabled = ["evm"]

[invariants]
# Specify which invariant checks to run
```

## Exit Codes

- `0` - Success, no violations found
- `1` - Analysis completed, violations found above threshold
- `2` - Error (file not found, parse error, etc.)

## Tips

1. **CI Integration:** Use `truent check ./contracts --fail-on high --quiet` in CI pipelines
2. **Pre-commit hooks:** Run `truent check` on staged contracts before commit
3. **Verbose debugging:** Add `--verbose` to see all checks including ones that passed
4. **Quiet mode:** Use `--quiet` to suppress output in automated systems
5. **Exit codes:** Check exit codes in scripts to decide next actions

## Examples

### Check EVM contract
```bash
truent check ./contracts/Token.sol --chain evm
```

### Check Solana program with custom config
```bash
truent check ./programs --chain solana --config ./truent.toml
```

### Generate HTML report
```bash
truent check ./contracts && \
truent report --input results.json --format html --output report.html
```

### CI/CD integration
```bash
truent check ./contracts --chain evm --format json --output results.json
if [ $? -eq 1 ]; then
  echo "Contract violations found!"
  exit 1
fi
```

## Getting Help

```bash
truent --help              # Show all commands
truent check --help        # Show check command options
truent doctor              # Check component health
```

## Performance

- Small contracts (< 1KB): ~100ms
- Medium contracts (1-10KB): ~200-500ms
- Large contracts (> 100KB): ~1-2s

Performance varies based on:
- Contract complexity
- Number of invariants checked
- Target chain

## Support

For issues, questions, or feature requests, visit:
- GitHub: https://github.com/Emmyhack/Truent
- Docs: https://docs.truent.dev
- Issues: https://github.com/Emmyhack/Truent/issues
