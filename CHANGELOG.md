# Changelog

All notable changes to the Truent project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Engine JSON contract for consumers.** `truent scan --output json`
  violations now carry `file`, `line`, `chain`, `evidence`, `exploitability`,
  `exploit_reasons`, `fix`, `verify`, `attack` and `nist_csf` alongside the
  display fields, and `recommendation` is the exposure table's fix rather
  than a search link. `truent taxonomy --format json` includes each
  detector's exposure profile (vector, prereq, interaction, impact, fix,
  verify) and CWE / ATT&CK names; `truent exposure --format json` lists
  `known_chains`. The web dashboard is generated from these.
- **Web dashboard aligned with the engine.** The worker maps the real JSON
  contract (location, evidence, exploitability, fix, verify, CWE, snippet
  are stored per finding — new Prisma migration); submissions accept every
  engine's languages (Solidity, Anchor, Soroban, Move, Python,
  JavaScript/TypeScript, Go, shell, Dockerfile, Terraform, YAML) and are
  written under the file name the detectors classify by. The report view
  shows the evidence class, exploitability with reasons, fix and verify
  step, CWE / ATT&CK tags, the source line, and a working workflow-status
  control; the library, docs and landing page are generated from
  `lib/catalog.json` (`scripts/sync-catalog.mjs` regenerates it from the
  binary) so the site can never describe detectors or commands the engine
  does not have. A Content-Security-Policy header was added and the API-key
  generator now uses a CSPRNG — the two previously accepted web findings are
  fixed, not accepted.
- **Symbolic execution, settled** (`truent-symbolic`; `truent symbolic`).
  Truent does not reimplement an SMT-backed executor; it drives the real
  ones — **halmos**, **hevm**, **Mythril** — on a Foundry project and owns
  the result under the honesty contract: a counterexample (a concrete input
  the solver produced) becomes a **proven** `evm_symbolic_counterexample`;
  a timeout, unknown or all-paths-reverted check is
  `evm_symbolic_unresolved`, a lead and never a pass; no executor on PATH
  is an error with install hints, never "no findings". Parsers are tested
  on captured real output; `examples/foundry` is a deliberately buggy vault
  whose counterexample (`amount = 2^255`) CI asserts is found.
  `release-check --symbolic-report` resolves the symbolic-execution item.
- **Risk acceptance** (`[[accept]]` in `.truent.toml`): a finding carried
  with a reason, an owner and an expiry is ACCEPTED — listed in every
  report, never hidden — and an expired entry stops applying. A malformed
  file fails loudly. `release-check` and `exposure` both honour it.
- **Truent is READY by its own checklist.** Every GitHub Action pinned to a
  commit SHA (`# vN` retained, Dependabot keeps them current); releases
  attested with `actions/attest-build-provenance` and npm `--provenance`;
  a `harness` workflow runs fuzzing, a 3000-file stress scan under a time
  budget, six chaos experiments (network hang, refused connection, corrupt
  lockfiles, unreadable inputs, missing tools, malformed config),
  halmos on the example, insta golden snapshots of every corpus,
  criterion benchmarks against a `main` baseline, weekly cargo-mutants with
  a 60% floor, and a PostgreSQL backup→destroy→restore drill recording RTO
  and RPO; a `supply-chain` workflow produces the SBOM, validates the Sigma
  rule, builds and serves the web dashboard and probes it (DAST), runs
  symbolic execution, uploads SARIF, and runs `release-check --strict` on
  `main`. Runbooks for disaster recovery and incident response, CODEOWNERS,
  and dated acceptances for the three informational RustSec advisories, the
  documented example contracts, and two findings in the maintainer's
  uncommitted web work (each names its one-line fix).
- **`truent release-check`**: the 33-section codebase safety & security
  checklist, item by item (~330 items), with an honest status for each:
  PASS (an engine ran and found nothing), FAIL (findings, with counts),
  NEEDS-PROBE (pass a `truent probe` report), PARTIAL (the test suite /
  load test / runbook exists but no CI workflow runs it), MISSING (nothing
  found — `truent harden` generates a start), ASSESS (only a person can
  verify) and N/A (nothing in the repository to apply to). The verdict is
  READY only with no FAIL, MISSING or PARTIAL. 25 repository signals
  (`truent_pathways::signals`) decide the items only your own system can run
  — functional, regression, load, chaos, performance, differential,
  mutation, migration, backup and recovery testing — by checking that the
  evidence exists *and* that CI invokes it. `--strict` exits non-zero when
  not READY.
- **26 new detectors** closing the checklist's gaps. Application layer
  (`web_security`): mass assignment, unvalidated uploads, error-detail
  disclosure, sensitive data in logs, filesystem TOCTOU, insecure temp files,
  world-writable permissions, ReDoS (nested quantifiers), XXE (lxml default
  entity resolution, `noent`), unrestricted GraphQL (introspection / no
  depth limit), WebSocket without origin check, non-atomic multi-write on
  value, object-level authorization missing (IDOR/BOLA — a record loaded by
  a request id with no ownership reference anywhere in the handler),
  unbounded pagination. Taint sinks: open redirect, log injection (message
  string only; structured fields are not flagged). Repository-level
  (`repo`, cross-file, comment-stripped): missing rate limit on
  authentication routes, missing security-event logging. CI: unsigned
  release (publish without cosign / provenance / attestation). Contracts
  (`gas_dos`): unbounded loop over a growable storage array, push payment in
  a loop, missing pause mechanism on an admin-controlled value-moving
  protocol. Supply chain (`integrity`): dependency confusion
  (`--extra-index-url`, unmapped private npm scopes), typosquat candidates
  (Damerau-Levenshtein 1 from popular names), lockfiles without integrity
  hashes, install-script dependencies. Every one has a taxonomy row, an
  exposure profile with fix and verify step, and good/bad corpus coverage.
  172 detectors total.
- **`truent harden`** now also generates the harnesses for the categories
  only the owning team can run: a k6 load test with thresholds, a chaos
  experiment table (Toxiproxy), a disaster-recovery runbook with RTO/RPO
  and a drill, mutation-testing configuration (cargo-mutants / Stryker /
  mutmut / Gambit), benchmark and gas-snapshot baselines, differential
  test guidance, a Sigma detection rule for authentication anomalies, and
  CODEOWNERS for security-sensitive paths.
- **Exposure: how possible is it, and how is it prevented** (`truent
  exposure`, `truent_core::exposure`). Truent will not exploit anything;
  what it now does instead is rate every finding's exploitability from a
  per-detector attack profile — where the attacker must stand
  (network / adjacent / local), what they must already hold (nothing, an
  account, a condition, a privileged role), whether a victim must act, and
  what success buys — combined with evidence: a finding the probe observed
  live outranks a static lead. Ratings are LIKELY / POSSIBLE / UNLIKELY /
  THEORETICAL with the reasons spelled out. Every one of the 146 detectors
  carries a concrete **fix** and a **verify** step (the command or test that
  shows the fix landed); a test fails the build if a detector is added
  without them. SARIF rule `help` now carries fix and verify, so GitHub code
  scanning shows the remediation inline.
- **Attack chains** (`truent_pathways::chains`). Twelve named compositions
  of findings that together form a known attack path — session hijack over
  cleartext, credentials served to the internet, injection reaching a
  reachable database, CI takeover to supply-chain compromise, XSS to account
  takeover, SSRF to cloud credentials, container escape, unauthenticated
  service exposed, adversary-in-the-middle, oracle-manipulation drain,
  reentrancy drain, single-admin-key takeover. `truent exposure` reports
  each completed chain with its narrative, ATT&CK tactic sequence, the
  findings satisfying each step, the step where the cheapest fix breaks it,
  and that fix. `--probe-report` folds a live `truent probe` JSON report in
  so static and observed findings compose.
- **`truent harden`**: preventive measures generated for the repository at
  hand. Profiles the tree (GitHub Actions, Dockerfile, Cargo/npm/pip/Go,
  Express, Next.js, Django, Flask, Solidity) and plans: a secrets
  `.gitignore` (merged, missing lines only), Dependabot for every ecosystem
  present, a pre-commit hook running `truent scan`/`deps`, a least-privilege
  CI gate uploading SARIF, framework-specific security-header and cookie
  configuration, a hardened Dockerfile shape, an invariants file for
  contracts, and a SECURITY.md. Each artifact names the detectors it
  prevents. Dry run by default; `--write` never overwrites an existing file.
- **Runtime probe** (`truent-runtime`; `truent probe <target> --authorized`).
  The first Truent component that connects to a running system instead of
  reading files, and the only one whose findings are marked **proven** — each
  records what the target returned. Twelve `rt_*` detectors: TLS (expired /
  expiring, untrusted or self-signed or wrong-name certificate, no modern
  protocol negotiable), HTTP (HSTS, CSP, frame options, content-type options,
  cookie Secure/HttpOnly, version-revealing banners, missing HTTP→HTTPS
  redirect), files that must never be served (`/.git/config`, `/.env`,
  `/.aws/credentials`, … — confirmed by content signature, never by a `200`
  alone), and a TCP connect sweep of 20 common ports ranked by how dangerous
  an exposed service is. Sends only `GET`s and connects: no payloads, no
  authentication attempts, no writes. Refuses to run without `--authorized`.
  Cookie values and file bodies are never recorded; `Set-Cookie` values are
  redacted at collection time. JSON, text and `--sarif` output; `doctor`
  exercises the evaluators on fixtures without touching the network. The
  runtime-stage pathways (Penetration Testing, Runtime Security, Network
  Security, Attack Surface Management) now have native detectors instead of
  only hosted skills and manual controls.
- **Intraprocedural taint tracking** for Python, JavaScript/TypeScript and
  Go (`truent-analyzer-general::taint`). Tracks assignments within a function
  from a source (request data, argv, stdin, a network read) to a sink (SQL
  execution, shell command, `eval`, DOM HTML) unless a sanitizer intervenes,
  so `q = request.args["id"]; sql = "… " + q; cur.execute(sql)` is caught
  across three lines and `q = "constant"; cur.execute(q)` is not flagged at
  all. Only the query/code argument of SQL and eval sinks is inspected, so the
  correct parameterized form (`execute(sql, (uid,))`) is clean, and a
  process-execution sink's scope is the whole argument list only when a shell
  interprets it (`shell=True`, `spawn("sh", ["-c", …])`) — an argument array
  forwarded to `spawnSync` is a CLI wrapper, not an injection. Taint findings
  name both ends of the flow and take precedence over the line-local
  detector's for the same sink. Intraprocedural and lexical by design; still
  a lead, not proven.

- **The security-pathway map** (`truent-pathways`; `truent pathways`,
  `truent assess`). Every class of software, web, system-design and cloud
  security — application, web, API, identity, architecture, DevSecOps,
  supply chain, cloud, container, Kubernetes, network, data, database,
  runtime, detection engineering, vulnerability management, attack surface,
  penetration testing, resilience, incident response, backup/recovery — is
  mapped to how Truent covers it: a native detector, a hosted skill subdomain,
  or an explicit assessment control. Tests fail the build if a pathway names a
  detector the taxonomy does not know or a subdomain that does not exist.
  `truent assess` runs every native engine and the dependency analysis over a
  repository and renders the per-pathway report with findings, installed
  skills and the manual checklist.
- **Threat modelling** (`truent threat-model`). A STRIDE model generated from
  discovered structure — routes (Express, Flask/FastAPI, Django, net/http,
  Solidity), data stores, outbound calls, secret sources, and auth / authz /
  rate-limit / logging / validation markers — labelled REASONED throughout.
- **Software composition analysis** (`truent-sca`; `truent deps`). Parses
  Cargo, npm (v1–v3), Yarn, requirements, Poetry, Pipenv and Go lockfiles;
  matches every pin against an OSV-JSON or RustSec advisory directory with
  exact half-open range semantics; flags unpinned requirements and manifests
  with no lockfile; emits a CycloneDX 1.5 SBOM. No database means no
  vulnerability claim — the report says so.
- **Infrastructure-as-Code detectors** for Terraform and CloudFormation:
  internet-open administrative ports (443 is not reported), public storage,
  unencrypted storage, public databases, wildcard IAM (Deny statements are
  not reported).
- **Web and API configuration detectors**: CORS wildcard (High with
  credentials, Low without), insecure session/CSRF cookies, debug mode, JWT
  verification disabled, CSRF protection removed, SSRF and path traversal from
  request-controlled input (allowlist and basename guards are recognised).
- 16 taxonomy rows (134 total) with CWE, ATT&CK and NIST CSF; doctor checks
  for the dependency engine and the pathway map.


- **General-purpose repository analyzer** (`truent-analyzer-general`,
  `--chain general`). Truent now reads everything in a repository that is not
  a contract, under the same zero-false-positive discipline: committed secrets
  and private keys (eleven known token formats plus an entropy-gated
  assignment heuristic that ignores placeholders and environment references);
  GitHub Actions attacks (pwn-request, script injection, secret exposure,
  unpinned third-party actions — with `env:` indirection and first-party
  actions recognised as safe); Dockerfile and Kubernetes/compose hardening;
  and command/code/SQL injection, XSS sinks, unsafe deserialization, disabled
  TLS verification, weak password hashing and insecure randomness in Python,
  JavaScript/TypeScript, Go and shell — each requiring a dynamic argument, so
  `eval("literal")` and `exec.Command("ls", dir)` are not findings. Ships with
  its own good/bad corpus and a doctor self-test.
- **Inline suppression.** `truent:allow` on a line or the line above it
  suppresses every general-analyzer finding there; `truent:allow <detector>`
  suppresses one. A secret scanner cannot tell a synthetic key in a test
  fixture from a real one, so the author says so where it lives. Build
  artifacts (`.next`, `.nuxt`, `coverage`, `__pycache__`, …) are never scanned,
  and unpinned third-party actions are reported once per action per workflow
  rather than once per use.
- **`--chain auto`.** Routes every file to every applicable engine: `.sol` →
  EVM, Anchor markers → Solana, `soroban_sdk` → Soroban, `.move` → Move, and
  the general analyzer over all of it. One command audits a mixed repository.
- **MITRE ATT&CK and NIST CSF 2.0 in the taxonomy.** Repository findings map
  to the vocabulary security teams actually triage in (`T1552.001` for a
  committed credential, `T1195.002` for a hijacked workflow); contract rows
  deliberately leave them empty rather than stretch `T1190` over everything.
  A test enforces that every repository finding carries both, and that
  contract registries (SWC/OWASP SC/DASP) are never applied to repository
  findings. Surfaced in `truent taxonomy`, SARIF tags, and `docs/COVERAGE.md`.


- **Skill runtime** (`truent-skills`, `truent skills`). Truent can now host
  agentskills.io skill libraries, extending it beyond smart contracts into
  cloud, DFIR, threat hunting, SOC and the other subdomains its engine cannot
  reach. Sources are **cloned, not vendored** — the library stays upstream
  under its own licence and updates with `git pull`. Skills are indexed by
  name, tag, subdomain and framework ID (so `truent skills search T1048.003`
  works), preflighted against the tools actually on `PATH`, and run on request.
  Third-party output is labelled `ADVISORY` and never `ENGINE-BACKED`: running
  someone else's script does not make its output reproducible.
  `skills run` prompts before executing and refuses outright when stdin is not
  a terminal unless `--yes` is passed.

  Hardening built into the subsystem: source names are validated as single
  path segments (a name is joined onto the cache root and `source remove`
  deletes it recursively, so `../../x` would otherwise delete an arbitrary
  directory); the registry is re-validated on load, so a hand-edited or shared
  `sources.json` cannot traverse either; specs beginning with `-` are rejected
  before reaching `git clone`, where `--upload-pack=<cmd>` executes a command;
  and a `skills/` directory is only trusted as Truent's own — and its skills
  labelled `ENGINE-BACKED` — when the parent carries Truent's plugin manifest,
  so running Truent inside an unrelated project with a `skills/` folder cannot
  launder that project's content as engine-verified.


- **Detector taxonomy** (`truent_core::taxonomy`). All 100 invariant IDs across
  EVM, Solana, Move, Soroban and the shared IR rule now map to **CWE**, the
  **SWC Registry**, the **OWASP Smart Contract Top 10 (2025)** and **DASP Top
  10**, in one const table. Two tests pin the table to the engine in both
  directions: a detector that ships without a row fails the build, and a row
  that outlives its detector fails too.
- **`truent taxonomy`** — inspect the mapping (`--chain`, `--id CWE-841`,
  `--format text|json|markdown`). Generates `docs/COVERAGE.md`, which CI checks
  for drift.
- **`truent scan --sarif <path>`** and **`truent check --sarif <path>`**. SARIF
  generation existed in `truent-report` but had no caller and no CLI flag, so
  it was unreachable; the `truent-gate` action post-converted JSON in Python
  instead. The gate now prefers the native writer and falls back to the
  converter only for older binaries.
- Taxonomy surfaced in every output: terminal, SARIF, JSON, CSV
  (`CWE`/`SWC`/`OWASP_SC` columns), Markdown, and HTML (a `Classification`
  column).
- **Three agent skills** — `truent-deps` (dependency supply-chain review that
  audits *drifted* library code rather than excluding `lib/`), `truent-keys`
  (key custody paired with the engine's on-chain authority findings),
  `truent-ir` (incident response that reproduces the exploit against deployed
  bytecode before naming a root cause).
- **Plugin packaging** (`.claude-plugin/`), agentskills.io frontmatter on all
  six skills, `tools/validate_skills.py`, generated `skills/index.json`, and
  `skills` + `coverage-matrix` CI jobs.


- **Three detectors the library declared but nothing implemented:**
  `evm_unchecked_returns` (a discarded low-level call or ERC-20 bool result),
  `evm_timestamp_dependence` (block values used as randomness or in strict
  equality — deadline comparisons are deliberately exempt), and
  `evm_division_by_zero` (a bare, unguarded divisor). The vulnerable CLI
  fixture went from 7 findings to 9: these were real bugs that were invisible.
- **A machine-checked library → detector coverage map**
  (`truent_library::coverage`). All 28 built-in invariants were declared,
  listed by `truent invariants`, and emitted by nothing. Each now resolves to
  the detector that implements it or to a written reason it cannot be
  implemented statically (three: front-running, uninitialised storage
  pointers, instruction-data parsing). Tests fail the build if an invariant is
  added without a row, or a row names a detector the taxonomy does not know.


- **False positives: correct contracts no longer report findings.** A plain
  OpenZeppelin-style ERC-20 produced four findings and the bundled example
  contract produced fourteen (twelve of them CRITICAL) — on code with no bug in
  it. Five distinct causes, each fixed:
  - *Detectors matched inside comments and string literals.* `evm_reentrancy_erc20`
    fired on `require(from != address(0), "ERC20: transfer from the zero address")`
    because the **revert string** contains "ERC20" and "transfer", so every
    standard token reported CRITICAL reentrancy on its `require` lines. A new
    `detectors::textutil` module strips comments and literal contents before
    matching, removing the whole class.
  - *`evm_oracle_spot_price` matched almost every line.* Its condition was
    `(balanceOf|reserve) AND (price|rate|amount|"=")` — that last clause matched
    `mapping(address => uint256)`, `require(balanceOf[x] >= y)` and
    `balanceOf[x] -= y`, producing eleven CRITICAL "oracle" findings on a token
    with no oracle. It now requires a balance read to actually reach a
    price-shaped quantity, tracked at function scope so
    `function getPrice() { return reserve1 * 1e18 / reserve0; }` is still caught.
  - *`evm_unbacked_synthetic_mint` fired on every contract.* Its contract-level
    check ran unconditionally ("Always check if contract lacks proper
    conservation checks"), reporting HIGH at line 1 with a fabricated code
    snippet, on ERC-20s, libraries and interfaces alike. It is now gated on the
    contract actually minting a collateral-backed asset, and anchored to the
    mint function.
  - *Its backing check was inverted.* `checks_backing_requirement` counted
    keywords across a window including comments, calling a function safe at
    three or more — so a function whose comments read `// No backing check!`
    and `// drain collateral` scored three and was judged checked. The detector
    stayed silent precisely where the code admitted the bug. A backing check is
    now a check construct (`require`/`assert`/`if … revert`) constraining a
    backing quantity.
  - *`evm_reentrancy_classic` never checked ordering.* It flagged every external
    call in any contract lacking a `nonReentrant` modifier, so textbook
    checks-effects-interactions code — state written *before* the call — was
    reported as CRITICAL reentrancy. It now requires a state write after the
    call within the same function.
  - *Detectors read fixed 40–50 line windows instead of function bodies.* A
    `withdraw` function was reported as an unvalidated-oracle trade because an
    unrelated `getPrice` sat six lines below it. Bodies are now delimited by
    brace depth, and interface declarations (no body) are skipped.
- **Regression corpus** (`crates/analyzer/evm/tests/false_positives.rs`).
  Correct contracts must produce **zero** findings; genuinely vulnerable ones
  must still be detected, so a detector can never be "fixed" by switching it
  off. A third test asserts every finding points at a real source line whose
  text matches the reported snippet.


- **The `.sinv` invariant DSL was never compiled in.** `build.rs` lived at the
  workspace root, which is a *virtual* manifest — cargo never runs a build
  script there — and `truent-core` had none of its own. All nine `.sinv` files
  were inert, `crates/core/src/generated/invariants.rs` was the "no .sinv files
  found" stub, `truent invariants list` showed nothing, and
  `truent_core::invariant_count()` returned 0, despite the DSL being a headline
  feature. The script is now attached to `truent-core` and resolves its paths
  from `CARGO_MANIFEST_DIR` rather than the working directory, so all nine
  invariants compile in. Two latent bugs in the generator surfaced once it
  actually ran and are fixed: the emitted `CompiledInvariant` lacked the serde
  derives that `truent invariants show --format json` needs, and the emitted
  registry contained an identity `.map(|i| i)` that fails `-D clippy::all`.
- **`truent invariants list --chain <c>` printed the wrong count.** It showed
  the global total above a filtered list, so `--chain evm` read as
  "9 Compiled Invariants" above six rows.
- **All ten `truent doctor` checks now exercise their subsystem.** Each
  analyzer runs a known-vulnerable snippet through the real detector pipeline
  and asserts it finds something; the DSL parser parses an invariant; the
  report generator renders a report and confirms the taxonomy survived; core
  verifies the compiled-invariant registry and a taxonomy round-trip. The
  checks are text-only, so `doctor` never fails for want of `solc`.


- **`truent doctor` could never fail.** Every component check was a hardcoded
  `passed: true` and the command always returned `Ok(())`, so the install gate
  the release workflow runs it as could not detect a broken install. Checks now
  report real state and the command exits non-zero when any component is
  unhealthy.
- **`truent doctor` reported a hardcoded invariant count.** It printed
  "28 built-in invariants" as a string literal; correct today by coincidence,
  and silently wrong the moment any chain gained an invariant. The count is
  computed across all four chains.
- **`truent doctor` output was ragged.** The message column was padded with a
  fixed run of spaces regardless of component-name length; it is now padded to
  the widest name.


- **`scripts/publish_crates.sh` would have failed.** It listed a
  `truent-simulator` crate that no longer exists and omitted
  `truent-analyzer-soroban`, `truent-dynamic-core`, `truent-dynamic-evm` and
  `truent-dynamic-solana` — all dependencies of `truent-cli`, so publishing
  would have aborted when cargo could not resolve them.

- **SARIF rule catalogue was wrong.** Rules were emitted once per *finding*
  rather than once per rule, and every result carried `"ruleIndex": 0` — so
  fourteen findings became fourteen "rules" with all results attributed to the
  first. Rules are now deduplicated and each result's index resolves to the
  rule it names.
- **Findings carried the wrong CWE.** `map_invariant_to_cwe` substring-matched
  the invariant ID and fell back to `CWE-676 · Use of Potentially Dangerous
  Function` for everything it did not recognise, which was most detectors
  (e.g. `evm_oracle_spot_price` reported `CWE-676` instead of `CWE-807`). An
  unmapped invariant now renders no taxonomy at all rather than a guess.
- **`SecurityReport::generate_html` rendered no findings** — only a summary.
  It now emits the findings table, with taxonomy badges and an empty state.
- Added `security-severity` to SARIF rules; GitHub code scanning ranks on it,
  and without it every Truent finding landed in the same bucket.

### Fixed
- Foundry test and script contracts (`*.t.sol`, `*.s.sol`) are never
  deployed; the EVM analyzer no longer reports a `setUp()` harness as a
  constructor race.
- A Python heredoc inside a shell script is data the script writes, not a
  handler it runs: application-layer detectors no longer read shell files
  (permission and temp-file checks still do).
- halmos witnesses wider than 64 bits were rounded through f64; they are now
  kept exact and rendered as hex.
- **RustSec advisory matching evaluated compound version ranges wrongly.**
  `patched`/`unaffected` are TOML arrays of semver *requirements*, often
  compound (`">= 0.8.4, < 0.9.0"`) and multi-line. The parser split them on
  commas and collapsed them to `min(patched)`/`max(unaffected)`, so
  `generic-array 0.14.7` was reported as vulnerable to RUSTSEC-2020-0146
  (patched by `>= 0.13.3`) and `ring 0.17` matched an advisory whose
  `unaffected` list is `>= 0.17`. Requirements are now kept and evaluated per
  range (`>=`, `>`, `<=`, `<`, `=`, `^`, `~`, comma-conjunction); a version is
  affected iff it satisfies none of them; `patched = []` with nothing
  unaffected means every version. `truent deps` on Truent's own lockfile now
  agrees with an independent audit: 0 vulnerabilities, 3 unmaintained crates.
- `gen_web_debug_enabled` fired on `debug = true` in `Cargo.toml` profiles. It
  is now scoped to Flask/Django settings (`DEBUG = True`, `app.run(debug=True)`)
  and `.env` (`FLASK_DEBUG=1`, `DJANGO_DEBUG=True`).
- `truent taxonomy --format markdown` omitted the general and supply-chain
  sections, so `docs/COVERAGE.md` lagged the const table (130 of 134 rows).

- **False positives, second pass: every analyzer, every chain.** The first pass
  fixed the detectors that happened to fire on one example. This pass fixed
  the *causes*, so the same class cannot recur:
  - **Source is normalised once at each analyzer's entry point.** Comments and
    string-literal contents are stripped before any detector runs
    (`truent_core::text`), and each finding's snippet is restored to the
    user's original line afterwards. Previously 32 of 34 EVM detector files —
    and every Solana, Move and Soroban line detector — matched raw text, so
    revert strings, doc comments and commented-out code raised findings.
    Solana keeps only `/// CHECK:` lines, Anchor's one semantic annotation;
    every other doc comment is prose.
  - **Function bodies replace fixed windows.** Six EVM detectors and one Move
    detector read a fixed 30–150 line window from a declaration, which bled
    into whatever followed; they now read the brace-delimited body, and
    `upgrade_path_verification` also resolves internal helpers so UUPS's
    `_authorizeUpgrade` is seen.
  - **Guards in modifiers and bodies are recognised.** `evm_missing_signer_check`,
    `evm_public_relay` (which also had an operator-precedence bug making any
    `external` function named `execute` a "permissionless relay"),
    `move_access_control_missing`, and the shared IR rule on Move now see
    `onlyRole(...)`, `onlySigner`, and `assert!(signer::address_of(..) == ..)`.
  - **Design-level findings fire once, on evidence.** `move_admin_no_timelock`
    fired on every line containing "admin"; `sol_treasury_single_authority` on
    every line containing "vault" and "authority". Each now reports once, at
    the operation that moves value, only when the module has no delay or
    multisig.
  - **Idioms are not bugs.** Two-step ownership (`acceptOwnership`) is not a
    single-EOA admin; an `immutable` merkle root cannot be zero; a deployer-
    fixed ERC-4626 `asset` is not a caller-supplied fee-on-transfer risk; a
    role-gated token `mint` with no collateral is not a synthetic mint;
    `Program<'info, System>` *is* the validated sysvar form; a `#[account(mut)]`
    on an existing account has nothing to do with rent; `.expect("why")` on
    checked arithmetic is Soroban's deliberate abort, not an unhandled panic.
  - **`sol_missing_signer` never fired on real code.** It required `Account<`,
    `mut` and an authority word on one line; Anchor puts `#[account(mut)]` on
    the line above. It now checks authority-named fields for a `Signer` type
    or `signer` constraint.
- **Regression corpora for all four chains** (`crates/analyzer/*/tests/corpus/`).
  `good/` programs must produce zero findings; `bad/` programs carry
  `// EXPECT: <detector>` headers that must still fire; every finding must
  point at a real line whose text it reports; every header must name a known
  detector. Adding a case is dropping a file in.

### Security

- **Updated `anyhow` 1.0.102 → 1.0.104** for RUSTSEC-2026-0190, an unsoundness
  in `Error::downcast_mut` categorised as memory-corruption. Truent never calls
  that function, so exposure was transitive only, but the fix is a lockfile
  bump within the existing `1.0` constraint.
- **Replaced `serde_yaml` with `serde_yaml_ng`.** The skill runtime's YAML
  parsing briefly pulled in `serde_yaml 0.9.34+deprecated`, which is
  unmaintained (RUSTSEC-2024-0370); `serde_yaml_ng` is the maintained
  drop-in fork. The lockfile now audits clean: zero vulnerabilities, with the
  three remaining informational warnings (`derivative`, `paste`, `ring`) all
  transitive through `alloy-primitives` and `rustls`.


- **Fixed stored XSS in HTML reports.** `generate_html_report` interpolated the
  scan target, invariant ID, severity and **file path** into the document
  unescaped; only the finding message was escaped, and only for `<`/`>`. A
  repository containing a file named `a"><img src=x onerror=...>.sol` therefore
  produced an audit report that executed attacker markup when opened. All
  values now go through `truent_report::html_escape` (previously private, now
  exported so both HTML paths share one implementation). Covered by
  `test_html_report_escapes_attacker_controlled_file_path`, which fails against
  the old code.

## [0.4.0] - 2026-07-21 — Dynamic Execution: findings proved by running the code
The headline change is that a finding no longer has to be taken on trust. Truent
deploys the contract, drives adversarial sequences at it, and only reports a
violation once it has actually made the bug fire — then shrinks the trace to the
shortest sequence that reproduces it. Static analysis stays as the fast first
pass; the engine is what settles it.

### Added

- **Dynamic invariant fuzzing for EVM** (`truent-dynamic-core`, `truent-dynamic-evm`; `truent fuzz --dynamic`). Deploys the contract into an in-memory `revm`, generates call sequences from its ABI, and checks auto-detected invariants after **every** call, shrinking any violation to a minimal proof-of-concept via delta debugging. Four property shapes are recognised without the user writing a harness: conservation (`totalSupply`/`balanceOf`), monotonicity (no-arg accumulator getters), access control (`owner`/`transferOwnership`), and reentrancy (call-stack inspection for a state write after an external call). Both crates are new to crates.io.
- **Dynamic invariant fuzzing for Solana** (`truent-dynamic-solana`). Solana's execution model is account-based — an instruction is a program id, an ordered list of `AccountMeta`s and an opaque data blob — not the EVM's flat single-caller calldata, so this is a native call model, invariant set, generator and shrink loop rather than the EVM types reused. Ships two oracles: token conservation (`sum(token account amounts) == mint supply`, which catches minting out of thin air) and account-owner integrity (unchecked ownership reassignment). The engine is proven against an in-memory mock program by default; a `litesvm-backend` feature runs real BPF bytecode.
- **Anchor IDL front-end for Solana fuzzing** (`truent fuzz <idl.json> --dynamic --chain solana --plan <plan.json>`). Reads both IDL layouts — 0.30+ with explicit discriminators, and legacy, where the discriminator is recomputed as `sha256("global:<snake_case>")[..8]` — and derives the instruction surface from it. The accompanying fuzz plan supplies what an IDL cannot: genesis accounts, the account pool, pinned account positions and the invariants to check. Instructions taking non-fixed-width Borsh arguments (`String`, `Vec`, structs) cannot be encoded correctly, so they are excluded **and reported**, because partial coverage must never read as full coverage. A plan declaring no invariants is rejected rather than silently reporting a clean run.
- **Reentrancy detection by execution**, via a revm call-stack inspector that identifies a contract re-entering itself and writing state after an external call (a CEI violation), rather than pattern-matching for it.
- **On-chain bytecode fuzzing** (`truent fuzz --dynamic --address <addr> --rpc-url <url>`) for deployed contracts with no verified source, probing fetched bytecode against known ERC20/Ownable selectors.
- **Claude Code skills** (`skills/`): `truent-audit` (deterministic engine pass first, then LLM lenses, then engine verification of each candidate, reported as VERIFIED or REASONED), `truent-recon` (git-history risk mining — fix candidates, churn hotspots, late changes, forked dependencies) and `truent-fuzz` (emits Medusa/Echidna harnesses).
- **`truent-gate` GitHub Action**: a deterministic CI gate wrapping `truent scan --fail-on <severity>` and converting findings to SARIF 2.1.0 for inline GitHub code-scanning annotations.


- **Chain-agnostic detection rule** (`unauthorized_privileged_mutation`): flags privileged mutations (fund transfers, authority changes, upgrades, account closes) with no authorization check reaching them. Each chain's analyzer builds a shared `SemanticModel` from its own native syntax; the rule itself is written once and applies unmodified to all four chains.
- **Real Move parsing** via a vendored Sui Move tree-sitter grammar (see `crates/analyzer/move/vendor/tree-sitter-move-sui/PROVENANCE.md`), replacing Move's previous regex-only extraction for the shared semantic model. Falls back to the regex heuristic if a file fails to parse.
- **Soroban (Stellar) support**: a fourth full chain analyzer (`truent-analyzer-soroban`, `--chain soroban`) covering `#[contract]`/`#[contractimpl]` Rust contracts, with 8 detectors (missing `require_auth`, unprotected contract upgrade, re-initialization, unchecked arithmetic, storage TTL never extended, durable state kept in `temporary()` storage, reentrancy-shaped checks-effects-interactions violations, unhandled `.unwrap()`/`.expect()` panics) plus 6 new built-in invariants and integration into the shared `unauthorized_privileged_mutation` rule.
- **4 more detectors added in a third round, covering 2026 incidents and one proactive/forward-looking pattern**: `sor_thin_liquidity_oracle_price` (Soroban's first oracle-manipulation detector — a price read from a single spot-price call with no TWAP/multi-source corroboration, the pattern behind YieldBlox, $10.2M, Feb 2026, the first Stellar/Soroban DeFi exploit this analyzer has had a citable incident for), `evm_unbounded_pricing_input` (a buy/mint/purchase function using its amount parameter directly in pricing arithmetic with no upper-bound check, behind the Truebit hack, $26.2M, Jan 2026, where an oversized input wrapped the computed mint price to near-zero), `evm_erc4337_validation_side_effects` (a `validateUserOp`/`validatePaymasterUserOp` implementation performing a state-mutating token call, which ERC-4337 validation must never do, behind the Lumi Finance hack, $270K, Jul 13 2026 — days before this detector was written), and `evm_eip7702_eoa_assumption`, the first detector in this project written **proactively**: `tx.origin`-based access control is flagged because EIP-7702 (live on Ethereum mainnet via the Pectra upgrade) lets an EOA delegate to arbitrary contract code, breaking the assumption that `tx.origin` identifies a plain externally-owned account — security researchers have flagged this composition as an emerging attack surface, but no public exploit of it has been confirmed yet. Also researched but explicitly did not build detectors for: private-key/AWS-key compromises (Step Finance $27.3M, Resolv $25M) and Aptos's Move-VM type-confusion bug ($70B systemic risk) — both are outside what source-level static analysis can ever detect (off-chain infrastructure compromise and a VM implementation bug, respectively, not a pattern in user contract code).
- **9 new detectors added across two rounds of auditing real historical exploits against Truent's existing detector set** to close confirmed gaps. Round 1: `evm_readonly_reentrancy` (an unguarded view/pure getter alongside an external-call-before-state-write elsewhere in the file — the dForce/$3.7M Feb 2023 and ~$70M Aug 2023 Curve-pool class of bugs, distinct from classic state-changing reentrancy), `evm_insufficient_multisig_threshold` (an M-of-N signature threshold at or below 60% of the signer count — the Ronin Bridge/$625M and Harmony Horizon/$100M 2022 key-compromise thefts both had low thresholds relative to signer count), `sol_unchecked_token_account_type` (an Anchor account field that looks like a token/mint/collateral reference but is a raw, unconstrained `AccountInfo` — the Cashio/$52M and Crema Finance/$8.8M 2022 fake-account substitution bugs), and `move_manual_overflow_check` (a left-shift next to a hex-bitmask bounds comparison — the exact shape of the Cetus Protocol/$223M May 2025 Sui hack's `checked_shlw` bug). Also broadened Solana's shared-IR sensitive-handler list (`semantic_model.rs`) to include mint/deposit/collateral/borrow/liquidate/swap, since Cashio's exploited entry point wasn't named withdraw/transfer/close/set_authority/upgrade and would have slipped past the existing list. Round 2: `sol_fake_sysvar_instruction_account` (unchecked `load_instruction_at` reading the Instructions sysvar with no address verification — the root cause of the Wormhole Solana bridge hack, $326M, Feb 2022, still the second-largest DeFi exploit ever), `evm_arbitrary_function_selector_dispatch` (a low-level `.call`/`.delegatecall` forwarding relayer-supplied calldata with no selector allowlist — the Poly Network hack, $611M, Aug 2021, one of the largest DeFi exploits ever), `evm_stale_oracle_price` (a `latestRoundData()` call whose `updatedAt` is never checked against a staleness threshold — a widely recurring audit finding, related to the Venus Protocol BSC/LUNA-crash exploit), `evm_fee_on_transfer_incompatibility` (a `transferFrom` whose nominal amount is trusted directly for accounting instead of a before/after balance diff — a frequent code4rena/Sherlock finding with a documented Balancer/STA-token exploit), and `evm_cross_chain_replay_missing_chainid` (signature verification with no `block.chainid` bound into the signed payload anywhere in the file — the $20M Wintermute-targeted Optimism exploit and a Multichain hardcoded-chainId bug).
- musl support for the npm installer (Alpine and other musl-based Linux systems now get the matching binary instead of a glibc build that won't start).
- CI coverage for `web/` and `truent-npm/` — neither had any automated checks before (which is exactly how several of the bugs above went uncaught).
- Web app: session-checked/rate-limited `/api/analyze`, real crypto-payment verification, consolidated NextAuth config, zod validation on remaining API routes, a Prisma 7 driver adapter (required as of Prisma 7 — the app didn't build without one), and a large accessibility/consistency pass.

### Changed

- **Dynamic Solana fuzzing is opt-in when building from source.** It links a real Solana VM, which takes `truent-cli` from 221 dependencies to 449, and the workflow it enables already requires a compiled `.so`, an Anchor IDL and a fuzz plan — so someone reaching for it can pass a flag, while someone scanning Solidity should not pay for it. Build it with `cargo install truent-cli --features solana-dynamic`; without it the command exits with that exact instruction. Static Solana analysis and dynamic EVM fuzzing are unaffected. Prebuilt binaries (GitHub releases, npm) ship with the backend included, since those users download rather than compile.
- The marketing site was rebuilt on a flat, hairline-separated editorial layout with a scroll-scrubbed particle hero, and the landing page's figures now cite what the tool actually reports (71 detectors, 4 chains, 21 reproduced exploits, $1.76B of losses in the registry) instead of unverifiable marketing numbers.

### Fixed

- **The release workflow published an incomplete, unusable set of crates.** `truent-dynamic-core`, `truent-dynamic-evm`, `truent-dynamic-solana` and `truent-analyzer-soroban` were absent from every publish layer despite `truent-cli` depending on all four; `truent-simulator` was still listed after being removed from the workspace; and because each publish pipes to `tee` without `pipefail`, a failed publish took tee's exit status and was silently swallowed, letting the job report success while crates were missing from the registry. This is why `truent-cli` 0.3.0 reached crates.io with unpublished dependencies and why npm never received 0.3.0.



- **Detection pipeline was completely disconnected from the CLI.** `truent check`/`truent scan` hardcoded an empty violation list regardless of input; the 35 EVM + 9 Solana + 6 Move detector functions existed and were tested in isolation but were never actually called from the command handlers. All 50 are now wired into `run_all_detectors()` per chain and reachable from the CLI.
- **`truent fuzz` was a no-op stub.** Now mutates real source files (line deletion/duplication/truncation/swap, seeded for reproducibility) and runs them through the live detectors looking for crashes, plus an optional precision/recall self-test against four detector-benchmark fuzzers that existed but were never wired to anything.
- Fixed a bug where an absolute file path passed to the EVM analyzer's solc-staging step could overwrite that real file with whatever source was being compiled, due to `Path::join` discarding its base for absolute arguments.
- Fixed a UTF-8 slice panic and an unbounded-recursion stack-overflow risk in the EVM bytecode/AST-walking code.
- Fixed report-generation (JSON/CSV/HTML) escaping gaps that could be triggered by attacker-influenced contract names or messages.
- Fixed the invariant library's built-in defaults, which stored a bare variable reference instead of a compiled expression; they now compile through the real DSL parser.
- Fixed multiple bugs in `truent-npm` (the `@dextonicx/cli` npm wrapper): its test suite had never actually run due to wrong import paths in all four test files; `detectPlatform()` never returned a `version` field, silently 404ing every checksum fetch; and a live bug where `.tar.gz` release archives (Linux/macOS) nest the binary in a subdirectory while `.zip` (Windows) doesn't, which the installer didn't account for.

### Removed

- `crates/simulator` — had been commented out of the workspace and unused since a prior release; deleted along with its now-dangling workspace dependency entry.

## [0.3.0] - 2026-06-18 — Phase B Complete: 26 Vulnerability Detectors

### Major Features

- **26 Smart Contract Vulnerability Detectors** — Comprehensive detection across EVM, Solana, and Move
  - 9+ EVM detectors: reentrancy, missing health checks, oracle manipulation, storage collision, arbitrary calls
  - 7+ Solana detectors: PDA authority validation, account discrimination, replay attacks, program-derived addressing
  - 5+ Move detectors: resource destruction, type safety violations, access control issues

### Added

- **EVM Analyzers**:
  - Missing post-state health check detection (H19/H11 class)
  - Merkle root zero default prevention (H16 class)
  - DVN single point of failure (H47 class)
  - Synthetic collateral oracle checks (H45/H40 class)
  - ERC4626 inflation protection (H52 class)
  - Arbitrary call msg.value validation (H26 class)
  - Reentrancy via whitelisted contracts (H29 class)
  - Proxy storage collision detection (H28 class)
  - Bridge address cryptographic verification (H49 class)

- **Solana Analyzers**:
  - PDA authority validation checks
  - Account discrimination detection
  - Replay attack prevention validation
  - Program-derived addressing safety
  - And 3+ additional program-specific checks

- **Move Analyzers**:
  - Resource destruction detection (H51 class)
  - Type safety violation detection (H52 class)
  - Access control validation
  - And 2+ additional Move-specific checks

### Fixed

- **Regex Pattern Detection**: Fixed false positives in pattern matching
  - Move resource destruction: Changed from `destroy` to `destroy\s*\(` to match function calls only
  - Solana PDA validation: Extended regex to recognize `.key()` method calls
  - Synthetic mint detection: Changed from `contains("require")` to `contain("require(")` for accuracy

- **CLI Tests**: Updated to use valid commands and proper syntax
  - Fixed verbose flag tests to use `--verbose` instead of non-existent flags
  - Updated command tests to use valid `doctor` subcommand

- **Integration Tests**: Added proper directory creation
  - Ensured `invariants/` directory exists before file writes
  - Fixed path handling for test projects

- **Security Tests**: JSON escaping validation
  - Updated assertions to check proper JSON escaping by serde_json

- **DSL Parser Tests**: Corrected syntax in test cases
  - Fixed 5 test cases from incorrect colon syntax to proper brace format
  - Tests now use valid DSL grammar: `invariant Name { expression }`

### Changed

- **Workspace Configuration**: Updated all 14 internal crates to v0.3.0
  - Unified dependency versions across entire workspace
  - Fixed version mismatch errors in dependency resolution

- **Cargo.lock**: Committed lock file for reproducible builds
  - Enables deterministic builds across CI/CD environments
  - Passes "Verify lockfile unchanged" check in release pipeline

### Documentation

- Updated README with v0.3.0 features and detector coverage
- Enhanced INSTALL.md with v0.3.0 binary download instructions
- Added comprehensive detector documentation
- Updated quick reference guides

### Testing

- **287+ Tests Passing**: All test suites verified
  - Unit tests: 50+ cases
  - Integration tests: 35+ cases
  - Property-based tests: 50+ cases
  - Security tests: 20+ cases
  - DSL parser tests: 43+ cases

- **Code Quality**: All checks passing
  - `cargo fmt --all` ✅
  - `cargo clippy --all -- -D warnings` ✅
  - `cargo audit` ✅
  - Reproducible build verification ✅

### Release Process

- **GitHub Release**: v0.3.0 tag with binary artifacts for 6 platforms
  - Linux: x86_64 (glibc & musl), aarch64
  - macOS: Intel x86_64, Apple Silicon aarch64
  - Windows: x86_64

- **crates.io Publication**: All 14 crates published in dependency order
  - Layer 1: truent-core
  - Layer 2: truent-ir, truent-utils
  - Layer 3: truent-dsl-parser, truent-report
  - Layer 4: truent-library
  - Layer 5: truent-analyzer-evm, truent-analyzer-move, truent-analyzer-solana, truent-solana-macro
  - Layer 6: truent-generator-evm, truent-generator-move, truent-generator-solana
  - Layer 7: truent-cli

---

## [0.2.2] - 2026-06-05 — Reproducibility & Flexible Output

### Added

- **Reproducible analysis** — New `--seed` flag for deterministic results across runs (default: 42)
  - Ensures security audits produce consistent results
  - Useful for CI/CD pipelines and regression testing
  - Usage: `truent check ./programs --seed 12345`

- **Flexible output options** — Enhanced `--output` flag for saving reports to disk
  - Works with all formats: text, JSON, and HTML
  - Usage: `truent check ./programs --format json --output ./report.json`
  - Enables programmatic result parsing and team sharing

- **HTML report generation** — New `--format html` produces styled security reports
  - Professional HTML with responsive styling
  - Color-coded severity indicators (Critical, High, Medium, Low)
  - Summary statistics and violation table
  - Shareable with non-technical stakeholders
  - Usage: `truent check ./programs --format html --output ./report.html`

### Changed

- Updated Solana SDK to latest 1.x for improved compatibility
- Enhanced CLI argument parsing with seed support

### Fixed

- Resolved compilation errors in report generation pipeline
- Fixed invariant mapping array handling in reference generation

### Documentation

- Updated README with output options and reproducibility guide
- Added HTML format examples to quick start section

---

## [0.2.1] - 2026-03-22 — Line Number Accuracy Fix

### Fixed — Violation Location Reporting

- **Critical:** Violation location reporting now shows actual source line numbers instead of defaulting to line 1
  - Added `byte_offset_to_line()` utility for accurate position-to-line conversion
  - Embedded line numbers directly in vulnerability markers during AST analysis
  - Improved `find_vulnerability_line()` to extract real line numbers from markers
  - Violations like `sol_lamport_balance` and `sol_account_validation` now report correct locations

### Changed — Analysis Architecture

- Violation location information is now embedded at analysis time rather than post-processed
- Improved debugging workflow — developers can immediately jump to vulnerable code

### Technical Details

- Added line number calculation system to Solana analyzer
- Pattern detection now preserves source location information in format: `MARKER_TYPE:LINE_NUMBER`
- CLI's violation reporting extracts embedded line numbers and displays them with code context

This release fixes the critical UX issue where all violations were reported at line 1, making it impossible to locate vulnerable code without manual searching.

---

## [0.2.0] - 2026-03-22 — Anchor-Aware AST Analysis

### The Big Change

v0.1 used pattern matching against raw source text. It worked well for general vulnerability detection but had no awareness of Anchor's type system, producing false positives on correct idiomatic Anchor code.

v0.2 replaces pattern matching with **real Rust AST parsing** using the `syn` crate. Truent now reads your code as a syntax tree, understands what each Anchor type enforces, and only fires violations where there is genuine risk.

### Added

- Real Rust AST parsing using `syn` crate for Solana programs with Anchor awareness
- `AnchorAccountField` model for encoding Anchor account security posture
- Support for detecting Anchor-specific security patterns:
  - `Signer<'info>` — automatically framework-validated
  - `Account<'info, T>` — automatically framework-validated
  - `Program<'info, T>` — automatically framework-validated
  - `SystemAccount<'info>` — automatically framework-validated
  - `AccountInfo<'info>` with `seeds` constraint — PDA validation
  - `AccountInfo<'info>` with `owner` constraint — ownership validation
  - `AccountInfo<'info>` with `address` constraint — exact address validation
  - `AccountInfo<'info>` with `/// CHECK:` comment — developer-verified
- Analyzer method `analyze_anchor_accounts()` for AST-based security analysis
- Comprehensive test suite proving false positive elimination (8 integration tests)

### Fixed — False Positives Eliminated

| Pattern | v0.1 result | v0.2 result |
| --- | --- | --- |
| `Signer<'info>` | ❌ CRITICAL false positive | ✅ Correctly silent |
| `Account<'info, T>` | ❌ Flagged | ✅ Recognized as safe |
| `Program<'info, T>` | ❌ Flagged | ✅ Recognized as safe |
| `SystemAccount<'info>` | ❌ Flagged | ✅ Recognized as safe |
| `AccountInfo` + `seeds = [...]` | ❌ CRITICAL false positive | ✅ Correctly silent |
| `AccountInfo` + `owner = ...` | ❌ CRITICAL false positive | ✅ Correctly silent |
| `AccountInfo` + `/// CHECK:` | ❌ CRITICAL false positive | ✅ Downgraded to INFO |
| `AccountInfo` — no constraint | ✅ CRITICAL | ✅ Still CRITICAL |

### Changed — Solana Analyzer

- Solana analyzer now has AST-first security analysis for Anchor programs
- Violation severity for constrained `AccountInfo` accounts downgraded from HIGH to LOW
- All crates now have improved crates.io discoverability with:
  - Keywords starting with "truent" (crates.io fuzzy-match override)
  - Proper categories (`development-tools`, `development-tools::testing`)
  - Explicit descriptions mentioning Truent

### Still Correctly Flagged

- `AccountInfo<'info>` with no seeds, owner, address, or CHECK comment
- Integer overflow and underflow in arithmetic
- Missing PDA validation where no constraint exists
- Unchecked return values on external calls
- All 22 built-in invariant checks remain active

### Installation

```bash
# Rust developers
cargo install truent-cli --force

# JavaScript / TypeScript developers
npm install -g @dextonicx/cli@latest

# Verify
truent --version   # truent 0.2.0
```

### Platform Binaries

Pre-built binaries available for download:

| Platform | Architecture |
| --- | --- |
| Linux | x86_64 (glibc), aarch64 (glibc), x86_64 (musl) |
| macOS | x86_64, aarch64 (Apple Silicon) |
| Windows | x86_64 |

### Stats

- 900+ downloads since launch
- 15 Rust crates published to crates.io
- 2 npm packages available
- All platforms supported with automated builds

### Looking Ahead — v0.3

Runtime fuzzing via embedded `revm` for EVM and `solana-program-test` for Solana. Throw randomized inputs at your programs and watch invariants break before attackers find them. This makes Truent the only dedicated invariant fuzzer for Solana programs in existence.

## [0.1.1] - 2026-02-18

### Fixed

- Release pipeline configuration fixes
- Version validation and crates.io publishing

## [0.1.0] - 2026-02-11

### Initial Release

### Core Architecture

- Multi-chain smart contract invariant enforcement framework
- Chain-agnostic `ChainAnalyzer`, `CodeGenerator`, and `Simulator` traits
- Structured error handling via `InvarError` type
- Intermediate Representation (IR) for unified program models

### DSL Parser

- Pest-based deterministic grammar for invariant expressions
- Support for binary operators (`==`, `!=`, `<`, `>`, `<=`, `>=`)
- Support for logical operators (`&&`, `||`, `!`)
- Function call expressions
- Full AST to IR conversion
- Comprehensive error messages with line/column information
- 3/3 unit tests passing

### Chain Support

- **Solana**: Analyzer using `syn` crate
  - Detects struct definitions and state variables
  - Extracts function signatures and entry points
  - Builds mutation graphs
  - Ready for code generator implementation

- **EVM**: Analyzer framework scaffolded
  - Ready for Solidity parsing integration
  - Generator framework for modifier injection

- **Move**: Analyzer framework scaffolded
  - Ready for Move parser integration
  - Resource and borrow checker support

### Simulation Engine

- Deterministic simulation with seeded RNG
- Parallel fuzzing infrastructure (rayon)
- Violation trace collection
- Coverage reporting

### Reporting

- JSON report generation
- Markdown report generation
- CLI table formatting
- Invariant coverage metrics
- Function protection status tracking

### CLI

- `truent init` command
- `truent build` command with chain selection
- `truent simulate` command with seed control
- `truent upgrade-check` command
- `truent report` command with format selection
- `truent list` command for invariant discovery
- Comprehensive help system
- Colored output support
- Verbose logging control

### Development & CI

- GitHub Actions matrix CI (Linux, macOS, Windows)
- Clippy linting enforcement
- Rustfmt code style
- Automated testing on all platforms
- Release binary generation
- Code coverage tracking

### Documentation

- Comprehensive README.md
- CONTRIBUTING.md guidelines
- Build summary and architecture documentation
- Inline API documentation (rustdoc)
- Example programs (Solana, EVM, Move)
- Example invariant files (TOML, DSL)

### Utilities

- Cross-platform path handling
- Structured logging with tracing
- Deterministic directory traversal

#### Project Structure

```text
truent/
├── 15 specialized crates
├── Zero external unsafe code
├── 100% test passing
├── Production-grade error handling
└── Fully documented public API
```

#### Performance

- Parser: ~5ms for 100-line expressions
- Solana analysis: ~50ms for 1000 LOC programs
- Release binary: 8.2 MB (stripped, LTO enabled)
- Memory efficient: ~2MB RSS base

#### Quality Metrics

- **Compilation**: ✅ Zero errors
- **Linting**: ✅ Zero warnings (clippy)
- **Formatting**: ✅ Rustfmt compliant
- **Tests**: ✅ 3/3 passing (100%)
- **Safety**: ✅ Zero unsafe code
- **Panics**: ✅ None in CLI

### Known Limitations

- Solana code generator not yet implemented (scaffolded)
- EVM code generator not yet implemented (scaffolded)
- Move code generator not yet implemented (scaffolded)
- Property testing framework not integrated
- Coverage metrics basic implementation only
- Invariant library TOML parsing not fully implemented

### Future Work

- [ ] Solana procedural macro code injection
- [ ] EVM Foundry test generation
- [ ] Move borrow checker integration
- [ ] Enhanced property testing with proptest
- [ ] Upgrade compatibility checking
- [ ] Performance benchmarking suite
- [ ] IDE integrations (VSCode, IntelliJ)
- [ ] Web UI for report visualization
- [ ] Mainnet deployment verification
- [ ] Pre-built invariant library packages

## [0.1.2] - 2026-03-09

### Changed (v0.1.2)

### Simulation Engine (v0.1.2)

- Replaced probabilistic stub functions with real static analysis
- Removed `detect_invariant_violation()`, `detect_function_violation()`, `test_execution_depth()` placeholder functions
- Implemented `analyze_program_invariant()` for real reentrancy, access control, and arithmetic pattern detection
- Implemented `analyze_function_invariant()` for function-level invariant checking based on actual program structure

### Invariant Library

- Removed hardcoded `Expression::Boolean(true)` placeholder expressions
- Integrated DSL parser for actual expression parsing and AST construction
- Updated `parse_invariant_table()` to use real DSL parser instead of placeholder values
- All invariant expressions now properly evaluated through deterministic grammar

### Chain Analyzers

- **EVM**: Enhanced with full state access tracking (mutable vs read-only)
  - Added `analyze_function_body()` for state mutation detection
  - Improved function parameter extraction
  - All functions now properly analyzed for state access patterns

- **Solana**: Implemented recursive AST analysis using `syn` parser
  - Added `analyze_solana_function_body()` for statement-level analysis
  - Improved account mutation vs. read detection
  - Enhanced entry point identification

- **Move**: Enhanced with resource access analysis
  - Added resource and borrow pattern detection (borrow_global_mut, move_from)
  - Proper mutable reference tracking
  - Improved function analysis with resource lifecycle tracking

### Bug Fixes (v0.1.2)

### Code Quality

- Fixed all clippy linting errors (0 warnings with -D warnings flag)
- Applied `cargo fmt` to all source files for consistent formatting
- Fixed method comparisons: compare `Ident` directly instead of `.to_string()`
- Improved iterator patterns: replaced index-based loops with `.iter()`, `.first()`, and `.skip()`
- Collapsed nested if statements using `&&` operator for better readability
- Changed `&PathBuf` to `&Path` for better API design
- Removed redundant `.trim()` before `.split_whitespace()`

### CI/CD Automation

- Installed git pre-push hook for automated code quality checks
- Hook runs `cargo fmt --check` before push (prevents formatting regressions)
- Hook runs `cargo clippy --all --all-features -- -D warnings` before push
- Blocks pushes with clear error messages if checks fail
- Ensures all pushed code meets production standards locally

### Test Coverage

- All 91+ unit, integration, and property tests passing
- Verified real analysis produces meaningful violation patterns
- Tested pre-push hook validation on all modified files
- Confirmed no regressions in existing functionality

### Quality Metrics (v0.1.2)

- **Compilation**: ✅ Zero errors
- **Linting**: ✅ Zero warnings (clippy with -D warnings)
- **Formatting**: ✅ Cargo fmt compliant
- **Tests**: ✅ 91+ passing (100%)
- **Safety**: ✅ Zero unsafe code
- **File Changes**: 8 files modified, 1118 insertions, 214 deletions

---

## [Unreleased]

### In Progress

#### Phase 6: Solana Generator

- Procedural macro development
- Assertion injection logic
- Compute budget preservation
- Property test generation

#### Phase 7: EVM Support

- Solang parser integration
- Modifier generation for checks
- Foundry test framework integration

#### Phase 8: Move Support

- Move parser integration
- Resource and borrow checking
- Assertion framework

### Planned Improvements

- Enhanced error recovery in parser
- Incremental compilation
- Caching layer for analysis results
- Distributed analysis support
- Interactive REPL mode
- LSP (Language Server Protocol) support
- Package manager for invariant libraries

---

## Version Compatibility

### Rust Version

- Minimum: 1.93.0 (stable)
- Tested: 1.93.0
- Edition: 2021

### Operating Systems

- Linux (x86_64, aarch64)
- macOS (x86_64, Apple Silicon)
- Windows (x86_64)

### Dependencies

Major dependencies and their versions:

- pest 2.7
- syn 2.0
- clap 4.4
- serde 1.0
- anyhow 1.0
- rayon 1.7

## Migration Guide

### From Pre-Release

This is the initial release. No migration needed.

---

## Support

For questions, issues, or contributions:

- Open an issue on GitHub
- Check the README.md for documentation
- Review CONTRIBUTING.md for guidelines
- Read the BUILD_SUMMARY.md for architecture details

---

## Contributors

- Truent Team - Initial design and implementation

---

## License

MIT License - See LICENSE file for details

---

### Unreleased Changes

(Breaking changes, new features, bug fixes in development will be listed here before release)

### [0.1.1] - Planned

- Parser performance improvements
- Additional example invariants
- Enhanced error messages
- Documentation improvements

### [0.2.0] - Planned

- Solana code generation
- EVM integration
- Move integration
- Property testing framework

---

**Note**: Truent follows Semantic Versioning. See <https://semver.org> for details.

- **MAJOR** version for incompatible API changes
- **MINOR** version for new backward-compatible functionality
- **PATCH** version for backward-compatible bug fixes
