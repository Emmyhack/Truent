# Truent

[![crates.io](https://img.shields.io/crates/v/truent-cli.svg)](https://crates.io/crates/truent-cli)
[![npm](https://img.shields.io/npm/v/@dextonicx/cli.svg)](https://www.npmjs.com/package/@dextonicx/cli)
[![Downloads](https://img.shields.io/crates/d/truent-cli.svg)](https://crates.io/crates/truent-cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/geekstrancend/Truent/actions/workflows/ci.yml/badge.svg)](https://github.com/geekstrancend/Truent/actions)

**Multi-chain smart contract security analyzer for EVM, Solana, Move, and Soroban.**

Truent checks your smart contracts and programs for vulnerabilities before
deployment. Define what should always be true — invariants — and Truent
verifies your code cannot violate them.

One tool. Four chains. One DSL.

---

## Self-check

`truent doctor` exercises every subsystem rather than reporting that it loaded:
each analyzer runs a known-vulnerable snippet through the real detector
pipeline and asserts it finds the bug, the DSL parser parses an invariant, and
the report generator renders a report and confirms the taxonomy survived. It
exits non-zero if any component is unhealthy, so it works as a CI install gate.

```
✓  truent-core        9 compiled invariants, taxonomy lookup OK
✓  EVM analyzer       1 finding(s) on the built-in self-test
✓  Solana analyzer    2 finding(s) on the built-in self-test
✓  Move analyzer      2 finding(s) on the built-in self-test
✓  Soroban analyzer   6 finding(s) on the built-in self-test
✓  DSL parser         parsed and named a test invariant
✓  Invariant library  28 built-in invariants loaded
✓  Detector taxonomy  134 detectors mapped to CWE/SWC/OWASP/DASP/ATT&CK/NIST
✓  Report generator   rendered a report with taxonomy attached
✓  Skill runtime      ready — no sources registered
```

---

## The go-to for every security pathway

Software, web, system-design and cloud security is not one discipline but a
couple of dozen, spread across design, build, deploy, runtime, response and
recovery. Truent is the entry point for all of them by being explicit about
*how* each is covered — and a test fails the build if that map ever claims
something it cannot back:

| | |
|---|---|
| **Native** | an engine-verified detector runs over the repository — 174 of them across 5 analyzers, the supply-chain engine, the runtime probe and the symbolic-execution driver, mapped to CWE, SWC, OWASP, DASP, **MITRE ATT&CK** and **NIST CSF 2.0** |
| **Proven** | the runtime probe's findings record what a live target actually returned — the only findings Truent marks as demonstrated rather than inferred |
| **Hosted** | a skill subdomain drives the real tool a static engine cannot replace (`aws`, `kubectl`, a SIEM, Volatility) — 46 subdomains via `truent skills` |
| **Assess** | a control only a person with access to the live system can verify — listed, never silently skipped |

```bash
truent assess .                    # every native engine + dependency analysis,
                                   # routed into a per-pathway report with the
                                   # hosted skills and manual controls for each
truent pathways                    # the whole map;  truent pathways api-security
truent threat-model .              # STRIDE from discovered routes, stores,
                                   # outbound calls, secrets and auth markers
truent deps . --advisory-db DB     # vulnerable / unpinned / unlocked dependencies
truent deps . --sbom sbom.cdx.json # CycloneDX 1.5
truent probe https://host --authorized  # live: TLS, security headers, cookies,
                                   # exposed /.env & /.git, open ports — proven
truent exposure . --probe-report probe.json  # how possible each finding is,
                                   # which ones compose into attack chains,
                                   # and the fix + verify step for each
truent harden . --write            # preventive controls + test harnesses
truent symbolic examples/foundry   # halmos/hevm/Mythril: counterexamples → proven
truent release-check . --probe-report probe.json --symbolic-report symbolic.json --strict
                                   # the 33-section safety checklist, item by
                                   # item: PASS / FAIL / PARTIAL / MISSING /
                                   # NEEDS-PROBE / ASSESS — READY or not
```

What each stage gets natively:

- **Design** — `threat-model` (entry points, trust boundaries, STRIDE), IAM and
  architecture findings (single-key admin, wildcard IAM, privileged containers).
- **Build** — SAST for contracts and for Python/JS/TS/Go/shell; secrets; SCA
  (Cargo, npm, pip, Poetry, Pipenv, Go, Yarn against OSV/RustSec); web and API
  configuration (CORS, cookies, CSRF, JWT verification, SSRF, path traversal,
  debug mode); CI workflow attacks.
- **Deploy** — Dockerfile, Kubernetes/compose, Terraform and CloudFormation
  misconfiguration; base-image and action pinning; SBOM.
- **Runtime** — `probe`: a non-exploitative live check of a target you are
  authorized to test. TLS (expiry, untrusted/self-signed/wrong-name
  certificate, no modern protocol), HTTP (HSTS, CSP, frame and content-type
  options, cookie flags, banners, HTTP→HTTPS redirect), files that must never
  be served (confirmed by content signature, never by a `200` alone), and a
  TCP sweep of 20 common ports. Sends only `GET`s and connects; refuses to
  run without `--authorized`; never records cookie values or file bodies.
- **Exploitability without exploitation** — `exposure` rates every finding
  LIKELY / POSSIBLE / UNLIKELY / THEORETICAL from its attack profile (vector,
  prerequisites, victim interaction, impact) and its evidence, names the
  attack chains the findings complete and where to break each, and gives the
  fix and the verify step for all 146 detectors. Truent never fires an
  exploit; this is the honest answer to "could this actually be used?".
- **Release readiness** — `release-check` walks the full codebase safety &
  security test model (functional, regression, SAST, DAST, supply chain,
  fuzz, property, business logic, state, authz, authn, concurrency, data
  integrity, financial, contracts, API, browser, load, chaos, migration,
  performance, differential, mutation, secrets, logging, files, DoS, build,
  boundaries, recovery, code quality, critical path, final validation). What
  an engine can decide is decided; what only your own system can run (load,
  chaos, mutation, DR) is checked for existence *and* CI wiring; what only a
  person can verify is listed for sign-off — never silently passed.
- **Symbolic execution** — `symbolic` drives halmos, hevm or Mythril on a
  Foundry project; a solver counterexample is a **proven** finding with the
  concrete input, an undecided check is a lead, and a missing executor is an
  error — never a pass. Truent does not pretend to be an SMT solver.
- **Risk acceptance** — `[[accept]]` entries in `.truent.toml` with a reason,
  owner and expiry; accepted findings are listed in every report and expire.
  Truent itself is READY by its own `release-check --strict` in CI.
- **Prevention** — `harden` generates the controls that stop whole classes
  of findings from being introduced: secrets `.gitignore`, Dependabot,
  pre-commit scanning, a CI gate, framework security headers, a hardened
  Dockerfile shape, contract invariants, SECURITY.md — each naming the
  detectors it prevents, never overwriting what exists.
- **Response / recovery** — hosted skills (SIEM, EDR, forensics, IR,
  ransomware defence) plus the assessment checklist. No static engine can
  honestly claim these, and Truent does not.

---

## Beyond contracts: any repository

Truent's chain analyzers read contract source. The **general analyzer** reads
everything else in a repository, under the same rules — a detector needs a
dynamic, attacker-influenced input to fire, correct code must produce zero
findings, and every finding carries CWE, **MITRE ATT&CK** and **NIST CSF 2.0**
identifiers:

| Area | What it catches |
|---|---|
| Secrets | Committed AWS/GitHub/Slack/Stripe/Google/npm/GitLab tokens, JWTs, PEM private keys, and real-looking credential assignments — never placeholders, examples, or environment references |
| GitHub Actions | `pull_request_target` + PR-head checkout (pwn request), event data interpolated into `run:` (script injection), secrets echoed to logs, unpinned third-party actions |
| Containers | Root images, unpinned bases, `curl \| sh`, privileged pods, host namespaces, Docker-socket mounts |
| Python · JS/TS · Go · shell | Command, code and SQL injection, XSS sinks, unsafe deserialization, disabled TLS verification, weak password hashing, insecure randomness for tokens |

```bash
truent scan . --chain general     # the repository analyzer alone
truent scan . --chain auto        # every engine, routed per file: .sol → EVM,
                                  # Anchor → Solana, soroban_sdk → Soroban,
                                  # .move → Move, and the general analyzer over all
```

A synthetic key in a test fixture is indistinguishable from a real one by
inspection, so the author says so where it lives — `truent:allow` on the line
or the line above suppresses every finding there, `truent:allow gen_xss_sink`
suppresses one detector. Unpinned third-party actions are reported once per
action per workflow, since pinning is one decision, not one per use.

What this is not: a SIEM, an EDR, a network scanner or a forensics suite.
Those need live systems and their own tooling, and Truent reaches them by
**hosting** the skills that drive `aws`, `tshark`, Volatility and the rest
(`truent skills`) rather than pretending a static engine can replace them.

---

## Detection quality: zero findings on correct code

A scanner that reports eleven criticals on a plain ERC-20 teaches its users to
ignore it. Truent's detectors are held to a regression corpus in every
analyzer crate (`crates/analyzer/*/tests/corpus/`):

- `good/` — contracts and programs correct by construction: OpenZeppelin-style
  ERC-20/721, role-based access control, two-step ownership, ERC-4626 with
  virtual shares, UUPS with `_authorizeUpgrade`, a timelocked multisig,
  EIP-712 permit, a Merkle airdrop, a Chainlink-priced staking pool, a guarded
  Anchor vault, a signer-asserted Move treasury, a `require_auth` Soroban
  token. Each **must produce zero findings.**
- `bad/` — real bugs, each with a `// EXPECT: <detector>` header that must
  still fire, so a detector can never be "fixed" by switching it off.
- Every finding must point at a real source line whose text it reports.

Adding a case is dropping a file in. The same discipline runs at the entry
point: source is normalised once — comments and string contents stripped —
before any detector sees it, so a revert string reading `"ERC20: transfer …"`
can never register as a transfer, and detectors read brace-delimited function
bodies rather than fixed line windows that bleed into neighbouring code.

For injection in Python, JavaScript/TypeScript and Go, the question is no
longer "is this argument a variable?" but "does a value from untrusted input
reach this sink?": an intraprocedural taint pass follows assignments from a
source (request data, argv, stdin, a network read) to a sink (SQL, shell,
`eval`, DOM HTML) unless a sanitizer intervenes. `q = request.args["id"]`
three lines above `cur.execute(sql)` is caught; `q = "constant"` is not
flagged; the parameterized form `execute(sql, (uid,))` is clean because only
the query argument is inspected; and an argument array handed to `spawn`
without a shell is a CLI wrapper, not an injection.

---

## Beyond smart contracts: the skill runtime

Truent's engine answers questions about contract source and bytecode. Most
security work needs different tools entirely — `aws`, `kubectl`, `tshark`, a
SIEM — so Truent **hosts** libraries that already encode that expertise instead
of pretending to reimplement it.

```bash
truent skills source suggest
truent skills source add mukul975/Anthropic-Cybersecurity-Skills   # 818 skills, 46 subdomains

truent skills search T1048.003        # by MITRE ATT&CK technique
truent skills search dns exfiltration # by keyword (AND)
truent skills list --summary          # coverage by subdomain
truent skills doctor                  # what is runnable on this machine
truent skills show <name>             # instructions, metadata, framework IDs
truent skills run <name> --yes        # execute its script
```

Two properties are deliberate:

- **Sources are cloned, never vendored.** The library stays in its own repo
  under its own licence and updates with `truent skills source update`. Truent
  does not fork or relicense someone else's catalogue.
- **Third-party output is `ADVISORY`, never engine-backed.** Truent's claim is
  that it never presents as verified anything it did not verify — so its own
  skills are labelled `ENGINE-BACKED` and everything else `ADVISORY`, on every
  line that mentions them.

`skills run` executes third-party code. It prompts first, and refuses outright
when stdin is not a terminal unless `--yes` is given, so a CI invocation can
never silently run it. Many of these libraries contain offensive and dual-use
techniques — only use them against systems you are authorised to test.

---

## What's new — detector taxonomy & agent skills

**Every finding now carries industry identifiers.** Truent's 134 detectors map
to **CWE**, the **SWC Registry**, the **OWASP Smart Contract Top 10 (2025)**,
**DASP Top 10**, and — for repository findings — **MITRE ATT&CK** and
**NIST CSF 2.0** — so a finding lands in your existing triage process
instead of needing a translation step.

```bash
truent taxonomy                    # full coverage matrix
truent taxonomy --chain soroban    # one chain
truent taxonomy --id SWC-107       # every detector for a weakness class
```

The mapping lives in one table in `truent-core`, and a test fails the build if
a detector ships without a row — or if a row outlives its detector. The
published matrix, [`docs/COVERAGE.md`](docs/COVERAGE.md), is generated from
that table and checked in CI, so it cannot drift from what actually ships.

Surfaced everywhere findings are:

- **Terminal** — CWE/SWC/OWASP/DASP lines under each violation.
- **SARIF** — a real `taxonomies[]` CWE component with per-rule
  `relationships[]`, plus `security-severity`, so GitHub code scanning groups
  and ranks Truent findings by weakness class. (Rules are now deduplicated and
  correctly indexed; previously every result pointed at `ruleIndex: 0`.)
- **JSON / CSV / Markdown** — structured taxonomy per finding, and
  `CWE`/`SWC`/`OWASP_SC` columns in CSV for spreadsheet triage.
- **HTML** — a `Classification` column of badges, each carrying the full
  weakness name in its tooltip.

`truent scan --sarif report.sarif` writes the SARIF artifact alongside the
normal output, and the `truent-gate` action now uses it directly instead of
post-converting the JSON.

An unmapped invariant — a user-authored `.sinv` rule — renders **no** taxonomy
rather than a guess. The previous mapper substring-matched the rule name and
fell back to `CWE-676` for everything it did not recognise, which was most
detectors.

**Six agent skills, installable as a plugin.** `truent-audit`, `truent-recon`
and `truent-fuzz` are joined by `truent-deps` (dependency supply-chain review
that audits the drifted library code every "exclude `lib/`" scanner skips),
`truent-keys` (key custody paired with the engine's on-chain authority
findings), and `truent-ir` (incident response that reproduces the exploit
against deployed bytecode before anyone writes the post-mortem).

```
/plugin marketplace add geekstrancend/Truent
/plugin install truent
```

See [`skills/README.md`](skills/README.md).

---

## What's new in v0.3.0

v0.3.0 reconnects the full detection pipeline into the CLI and adds a
chain-agnostic detection layer on top of it.

**Key improvements:**

- ✅ **71 Smart Contract Vulnerability Detectors** — Comprehensive coverage of critical and high-priority exploits, wired end-to-end into `truent check`/`truent scan`
- ✅ **Chain-agnostic shared rule** — `unauthorized_privileged_mutation` runs against a common semantic model built by each chain's own analyzer, so one rule (missing an authorization check on a privileged mutation) is written once and applies to all four chains
- ✅ **Real Move parsing** — a vendored Sui Move tree-sitter grammar backs Move's semantic extraction, with the original regex heuristic kept as an automatic fallback if a file fails to parse
- ✅ **Soroban (Stellar) support** — a fourth full chain analyzer covering `require_auth` gaps, unprotected contract upgrades, re-initialization, unchecked arithmetic, storage TTL/expiry, and reentrancy-shaped checks-effects-interactions violations
- ✅ **Real fuzzing** — `truent fuzz` mutates real source files and runs them through the live detectors looking for crashes, instead of a no-op stub
- ✅ **Production Ready** — All tests passing, security audit complete, reproducible builds

**Detector Coverage:**
- **EVM**: 44 detectors (reentrancy incl. read-only reentrancy, missing checks, oracle manipulation incl. stale-price feeds, proxy issues, insufficient multisig threshold, arbitrary function-selector dispatch, fee-on-transfer/rebasing incompatibility, cross-chain signature replay, unbounded pricing input, ERC-4337 validation side effects, EIP-7702 EOA assumptions, and 20+ named historical-exploit patterns)
- **Solana**: 11 detectors (PDA validation, authority checks, replay attacks, durable nonce, rent exemption, unchecked token/mint account substitution, fake sysvar instructions account)
- **Move**: 7 detectors (resource destruction, type safety, access control, hand-rolled overflow checks)
- **Soroban**: 9 detectors (missing require_auth, unprotected upgrade, re-initialization, unchecked arithmetic, storage TTL/expiry, reentrancy, thin-liquidity oracle price)

Truent also ships a web dashboard (`web/`) — sign-up, scan submission, and
report viewing on top of the same CLI engine — alongside the `truent` CLI
and its npm wrapper (`@dextonicx/cli`).

---

## What's new in v0.2.2

v0.2.2 adds reproducibility and flexible output options for better CI integration and reporting.

**Key improvements:**

- ✅ **Reproducible analysis** — `--seed` flag for deterministic results across runs
- ✅ **File output** — `--output` flag to write reports to disk (text, JSON, HTML)
- ✅ **HTML reports** — Beautiful formatted security reports with styled tables and summaries
- ✅ **Solana SDK 1.x** — Updated to latest stable Solana SDK

---

## What's new in v0.2.1

v0.2.1 fixes violation location reporting — all violations now show their actual source line numbers instead of defaulting to line 1. This dramatically improves debugging workflow.

**Key improvements:**

- ✅ **Accurate violation locations** — Real line numbers from the vulnerable code
- ✅ **Code context** — Shows 2 lines before/after violation for quick reference
- ✅ **Embedded line tracking** — Line numbers calculated during AST analysis, not post-processing

---

## What's new in v0.2.0

v0.2 replaces pattern matching with real Rust AST parsing via the `syn`
crate. Truent now understands Anchor's type system and eliminates false
positives on idiomatic Anchor programs.

| Pattern | v0.1 | v0.2 |
| --- | --- | --- |
| `Signer<'info>` | ❌ False positive | ✅ Correctly silent |
| `Account<'info, T>` | ❌ Over-flagged | ✅ Recognized as safe |
| `AccountInfo` with `seeds = [...]` | ❌ False positive | ✅ Correctly silent |
| `AccountInfo` with `/// CHECK:` | ❌ False positive | ✅ Downgraded to INFO |
| `AccountInfo` with no constraint | ✅ CRITICAL | ✅ Still CRITICAL |

> **Upgrading from v0.1/v0.2.0?** Run `cargo install truent-cli --force`

---

## Install

```bash
# Rust developers
cargo install truent-cli

# JavaScript / TypeScript developers
npm install -g @dextonicx/cli

# Verify installation
truent --version   # truent 0.4.1
truent doctor
```

Or download a pre-built binary directly from
[GitHub Releases](https://github.com/geekstrancend/Truent/releases).

**Supported platforms:**

- Linux x86_64, aarch64, musl
- macOS x86_64, aarch64 (Apple Silicon)
- Windows x86_64

---

## Use it on your codebase

Three steps: install, point Truent at your repo, gate your CI.

**1. Install** (see above) — `cargo install truent-cli` or `npm install -g @dextonicx/cli`.

**2. Scan your code.** Run from your project root and point Truent at the files
you want checked. `--chain` defaults to `evm`; set it for other ecosystems:

```bash
truent scan .                          # Solidity / EVM (the default)
truent scan ./programs  --chain solana
truent scan ./sources   --chain move
truent scan ./contracts --chain soroban
```

Each finding is printed with its severity, file and line, and the real-world
exploit pattern it maps to. Want a report to share or feed into other tools?

```bash
truent scan . --format html --output truent-report.html   # styled, shareable
truent scan . --format json --output truent-report.json   # machine-readable
```

**3. Gate your CI.** Make a risky change fail the build:

```bash
truent scan . --chain evm --fail-on high   # exit non-zero on High/Critical
```

Drop that into GitHub Actions and you're done:

```yaml
- name: Truent security scan
  run: |
    cargo install truent-cli
    truent scan . --chain evm --fail-on high
```

`truent scan --help` lists every option; `truent doctor` verifies your install.

---

## Quick start

```bash
# Check a Solana program
truent scan ./programs --chain solana

# Check Solidity contracts
truent scan ./contracts --chain evm

# Check Move modules
truent scan ./sources --chain move

# Check Soroban contracts
truent scan ./contracts --chain soroban

# Output as JSON
truent scan ./programs --chain solana --format json

# Output as HTML
truent scan ./programs --chain solana --format html --output ./report.html

# Reproducible analysis with fixed seed
truent scan ./programs --chain solana --seed 42

# Fail CI if high or critical violations found
truent scan ./programs --chain solana --fail-on high

# Run health check
truent doctor

# Initialize config
truent init
```

---

## Output options

### Report formats

```bash
# Text report (default, human-readable)
truent scan ./programs --chain solana --format text

# JSON report (machine-readable, for parsing/CI)
truent scan ./programs --chain solana --format json

# HTML report (styled, shareable with team)
truent scan ./programs --chain solana --format html
```

### Saving reports to disk

```bash
# Save any format to file
truent scan ./programs --chain solana --format json --output ./report.json
truent scan ./programs --chain solana --format html --output ./report.html
truent scan ./programs --chain solana --format text --output ./report.txt
```

### Reproducible analysis

For deterministic results (useful in CI or security audits), use `--seed`:

```bash
# Always uses seed 42 by default
truent scan ./programs --chain solana

# Use a custom seed
truent scan ./programs --chain solana --seed 12345

# Results will be identical on the same code with the same seed
```

---

## GitHub Actions

Add one step to your workflow:

```yaml
- name: Truent security check
  run: |
    cargo install truent-cli
    truent scan ./programs --chain solana --fail-on high
```

CI fails automatically on high or critical violations. Zero additional
configuration required.

---

## Built-in invariants

Truent ships with 28 built-in security checks across all four chains.

### EVM (10 invariants)

| ID | Name | Severity |
| --- | --- | --- |
| `evm_reentrancy_protection` | Reentrancy Protection | Critical |
| `evm_integer_overflow` | Integer Overflow | High |
| `evm_integer_underflow` | Integer Underflow | High |
| `evm_unchecked_returns` | Unchecked Return Values | Medium |
| `evm_delegatecall_injection` | Delegatecall Injection | Critical |
| `evm_access_control` | Access Control | High |
| `evm_timestamp_dependence` | Timestamp Dependence | Medium |
| `evm_frontrunning` | Front-running | Medium |
| `evm_uninitialized_pointers` | Uninitialized Pointers | High |
| `evm_division_by_zero` | Division by Zero | Medium |

### Solana (7 invariants)

| ID | Name | Severity |
| --- | --- | --- |
| `sol_signer_checks` | Signer Checks | Critical |
| `sol_account_validation` | Account Validation | Critical |
| `sol_integer_overflow` | Integer Overflow | High |
| `sol_rent_exemption` | Rent Exemption | Medium |
| `sol_pda_derivation` | PDA Derivation | High |
| `sol_lamport_balance` | Lamport Balance | Critical |
| `sol_instruction_parsing` | Instruction Parsing | Medium |

### Move (5 invariants)

| ID | Name | Severity |
| --- | --- | --- |
| `move_access_control` | Access Control | Critical |
| `move_integer_overflow` | Integer Overflow | High |
| `move_resource_leaks` | Resource Leaks | High |
| `move_type_safety` | Type Safety | High |
| `move_signer_requirement` | Signer Requirement | Critical |

### Soroban (6 invariants)

| ID | Name | Severity |
| --- | --- | --- |
| `sor_require_auth_checks` | Require-Auth Checks | High |
| `sor_no_unprotected_upgrade` | Protected Upgrade | High |
| `sor_init_guard` | Initializer Guard | High |
| `sor_checked_arithmetic` | Checked Arithmetic | High |
| `sor_storage_ttl_extended` | Storage TTL Extended | High |
| `sor_no_reentrancy` | No Reentrancy | High |

---

## Configuration

Create `.truent.toml` in your project root:

```toml
[project]
name = "my-project"
chain = "solana"

[analysis]
severity_threshold = "low"
# suppress = ["sol_rent_exemption"]

[output]
format = "text"   # text | json | html
```

Or run `truent init` to generate a config automatically.

### Inline suppression

```rust
// truent: ignore sol_account_validation — external VRF oracle account
pub oracle_queue: AccountInfo<'info>,
```

---

## Anchor false positive guide (v0.2+)

Truent v0.2 understands Anchor's type system. These patterns are
correctly handled:

```rust
// SAFE — Anchor enforces signer automatically
pub authority: Signer<'info>,

// SAFE — Anchor validates ownership and discriminator
pub arena: Account<'info, Arena>,

// SAFE — seeds constraint validates PDA derivation
#[account(seeds = [b"vault", user.key().as_ref()], bump)]
pub vault: AccountInfo<'info>,

// SAFE — developer has verified this external account
/// CHECK: This is the Switchboard VRF oracle. Address validated off-chain.
pub oracle_queue: AccountInfo<'info>,

// CRITICAL — genuinely unchecked, Truent correctly fires
pub mystery: AccountInfo<'info>,
```

---

## Roadmap

| Version | Focus | Status |
| --- | --- | --- |
| v0.1 | Pattern-based analysis, 22 invariants, full CLI | ✅ Shipped |
| v0.2 | Real AST parsing, Anchor-aware analysis | ✅ Shipped |
| v0.3 | Runtime fuzzing — revm + solana-program-test | 🔨 Next |
| v0.4 | Bounded model checking | 📋 Planned |
| v0.5 | Symbolic execution via Z3 | 📋 Planned |
| v1.0 | Slither + Echidna + Mythril for every chain | 🎯 Goal |

---

## Links

- **GitHub**: [geekstrancend/Truent](https://github.com/geekstrancend/Truent)
- **crates.io**: [truent-cli](https://crates.io/crates/truent-cli)
- **npm**: [@dextonicx/cli](https://www.npmjs.com/package/@dextonicx/cli)
- **Docs**: [docs.rs/truent-cli](https://docs.rs/truent-cli)

---

## Contributing

Issues, PRs, and feedback are welcome.

If you are a Rust engineer familiar with `syn` or Anchor internals,
the v0.3 fuzzing work is the highest-impact contribution area right now.

If you are a smart contract auditor, help expand the invariant library
with real attack patterns you have encountered.

---

## License

MIT — see [LICENSE](LICENSE)
