# Release check — .

**Verdict: READY** — ACCEPTED 4 · ASSESS 32 · PASS 371

PASS = an engine ran and found nothing · ACCEPTED = findings carried under a dated, owned risk acceptance · FAIL = findings · PARTIAL = the test exists but CI never runs it (or a check is undecided) · MISSING = nothing found (`truent harden` generates a start) · NEEDS-TOOL = pass a `truent probe` / `truent symbolic` report · ASSESS = a person must verify · N/A = nothing to apply to

## Risk acceptances

- **evm_single_eoa_admin** ./examples/evm_token.sol:27 — accepted until 2027-12-31 by @Emmyhack: intentionally minimal example contract used by the documentation to show what a scan reports; not deployed anywhere.
- **sca_unmaintained_dependency** Cargo.lock:1 — accepted until 2027-03-31 by @Emmyhack: transitive, not in the normal build graph (dev/build only); no exposure in the shipped binary.
- **sca_unmaintained_dependency** Cargo.lock:1 — accepted until 2027-03-31 by @Emmyhack: transitive via alloy-primitives → revm; the maintained fork is not yet resolvable from revm 14. Re-evaluate at the next revm upgrade.
- **sca_unmaintained_dependency** Cargo.lock:1 — accepted until 2027-03-31 by @Emmyhack: ring is the rustls crypto provider used by truent-runtime and ureq; the aws-lc-rs provider adds a C/cmake build across six release targets. Informational advisory, no vulnerability. Re-evaluate when rustls' aws-lc-rs provider ships prebuilt for musl and Windows.
- **rt_no_https_redirect** http://127.0.0.1:3111:1 — accepted until 2027-03-31 by @Emmyhack: The CI DAST target is `next start` on localhost, which serves plain HTTP by design; TLS termination and the HTTP→HTTPS redirect are the production edge's job. Verified separately by `truent probe https://<production-host>` before each release.
- **evm_symbolic_counterexample** examples/foundry/test/Vault.t.sol:1 — accepted until 2027-12-31 by @Emmyhack: examples/foundry is the documented symbolic-execution demo: a deliberately buggy vault whose counterexample CI asserts is found. Not deployed.

| # | Section | Worst | Pass | Fail | Partial | Missing | Assess |
|---|---|---|---|---|---|---|---|
| 1 | Functional Testing | PASS | 7 | 0 | 0 | 0 | 0 |
| 2 | Regression Testing | ASSESS | 8 | 0 | 0 | 0 | 2 |
| 3 | Static Application Security Testing (SAST) | PASS | 13 | 0 | 0 | 0 | 0 |
| 4 | Dynamic Application Security Testing (DAST) | ASSESS | 12 | 0 | 0 | 0 | 1 |
| 5 | Dependency & Supply-Chain Security Testing | ACCEPTED | 10 | 0 | 0 | 0 | 0 |
| 6 | Fuzz Testing | PASS | 14 | 0 | 0 | 0 | 0 |
| 7 | Property-Based Testing | PASS | 8 | 0 | 0 | 0 | 0 |
| 8 | Business-Logic Testing | ASSESS | 11 | 0 | 0 | 0 | 3 |
| 9 | State-Transition Testing | ASSESS | 10 | 0 | 0 | 0 | 1 |
| 10 | Authorization & Access-Control Testing | ACCEPTED | 13 | 0 | 0 | 0 | 0 |
| 11 | Authentication & Session Security Testing | ASSESS | 11 | 0 | 0 | 0 | 2 |
| 12 | Race-Condition & Concurrency Testing | ASSESS | 10 | 0 | 0 | 0 | 1 |
| 13 | Data-Integrity Testing | ASSESS | 9 | 0 | 0 | 0 | 4 |
| 14 | Financial / Value-Movement Testing | ASSESS | 16 | 0 | 0 | 0 | 1 |
| 15 | Smart-Contract Security Testing | PASS | 24 | 0 | 0 | 0 | 0 |
| 16 | API Security Testing | ASSESS | 12 | 0 | 0 | 0 | 3 |
| 17 | CORS & Browser Security Testing | PASS | 11 | 0 | 0 | 0 | 0 |
| 18 | Load & Stress Testing | PASS | 13 | 0 | 0 | 0 | 0 |
| 19 | Chaos & Failure Testing | PASS | 14 | 0 | 0 | 0 | 0 |
| 20 | Migration & Upgrade Testing | ASSESS | 9 | 0 | 0 | 0 | 2 |
| 21 | Performance Testing | ASSESS | 10 | 0 | 0 | 0 | 1 |
| 22 | Differential Testing | ASSESS | 6 | 0 | 0 | 0 | 1 |
| 23 | Mutation Testing | PASS | 8 | 0 | 0 | 0 | 0 |
| 24 | Secrets & Configuration Testing | ASSESS | 9 | 0 | 0 | 0 | 1 |
| 25 | Logging & Monitoring Security Testing | ASSESS | 8 | 0 | 0 | 0 | 2 |
| 26 | File & Resource Security Testing | PASS | 8 | 0 | 0 | 0 | 0 |
| 27 | Availability & Denial-of-Service Testing | PASS | 10 | 0 | 0 | 0 | 0 |
| 28 | Supply-Chain & Build Security | PASS | 10 | 0 | 0 | 0 | 0 |
| 29 | Security Boundary Testing | ASSESS | 7 | 0 | 0 | 0 | 2 |
| 30 | Recovery & Disaster Testing | ASSESS | 10 | 0 | 0 | 0 | 1 |
| 31 | Code Quality & Safety Testing | ASSESS | 8 | 0 | 0 | 0 | 3 |
| 32 | Critical-Path Security Testing | ACCEPTED | 21 | 0 | 0 | 0 | 0 |
| 33 | Final Security Validation | ASSESS | 25 | 0 | 0 | 0 | 1 |

## 1. Functional Testing — PASS

- [x] **Unit testing** — PASS: unit tests present and run in CI (truent-npm/__tests__/detect-platform.test.js, truent-npm/__tests__/index.test.js, truent-npm/__tests__/download.test.js)
- [x] **Integration testing** — PASS: integration tests present and run in CI (crates/core/src/integration_testing.rs, crates/cli/tests/integration/mod.rs, crates/cli/tests/integration.rs)
- [x] **End-to-end (E2E) testing** — PASS: end-to-end tests present and run in CI (crates/cli/tests/cli/mod.rs, crates/cli/tests/cli.rs, tests/cli.rs)
- [x] **API/endpoint testing** — PASS: API/contract tests present and run in CI (crates/cli/tests/cli/mod.rs, crates/cli/tests/cli.rs, tests/cli.rs)
- [x] **Contract/interface testing** — PASS: API/contract tests present and run in CI (crates/cli/tests/cli/mod.rs, crates/cli/tests/cli.rs, tests/cli.rs)
- [x] **Input validation testing** — PASS: 4 detector(s) ran, no findings
- [x] **Output validation testing** — PASS: 3 detector(s) ran, no findings

## 2. Regression Testing — ASSESS

- [x] **Full regression test suite** — PASS: unit tests present and run in CI (truent-npm/__tests__/detect-platform.test.js, truent-npm/__tests__/index.test.js, truent-npm/__tests__/download.test.js)
- [ ] **Previously fixed vulnerability regression tests** — ASSESS: Every fixed vulnerability has a test that reproduces it; keep them in a `regressions/` corpus the way Truent keeps its own `tests/corpus/bad`
- [ ] **Previously fixed bug regression tests** — ASSESS: Bug fixes land with a failing-then-passing test
- [x] **Critical user-flow regression tests** — PASS: end-to-end tests present and run in CI (crates/cli/tests/cli/mod.rs, crates/cli/tests/cli.rs, tests/cli.rs)
- [x] **Authentication regression tests** — PASS: 3 detector(s) ran, no findings
- [x] **Authorization regression tests** — PASS: 2 detector(s) ran, no findings
- [x] **Payment/withdrawal regression tests** — PASS: 3 detector(s) ran, no findings
- [x] **Database-operation regression tests** — PASS: 2 detector(s) ran, no findings
- [x] **Smart-contract interaction regression tests** — PASS: 7 detector(s) ran, no findings
- [x] **State-transition regression tests** — PASS: 8 detector(s) ran, no findings

## 3. Static Application Security Testing (SAST) — PASS

- [x] **SQL injection detection** — PASS: 1 detector(s) ran, no findings
- [x] **Command injection detection** — PASS: 2 detector(s) ran, no findings
- [x] **Cross-site scripting (XSS) detection** — PASS: 1 detector(s) ran, no findings
- [x] **Server-side request forgery (SSRF) detection** — PASS: 1 detector(s) ran, no findings
- [x] **Path traversal detection** — PASS: 1 detector(s) ran, no findings
- [x] **Insecure deserialization detection** — PASS: 2 detector(s) ran, no findings
- [x] **Hardcoded secrets detection** — PASS: 2 detector(s) ran, no findings
- [x] **Weak/unsafe cryptography detection** — PASS: 3 detector(s) ran, no findings
- [x] **Authentication flaws** — PASS: 5 detector(s) ran, no findings
- [x] **Authorization flaws** — PASS: 14 detector(s) ran, no findings
- [x] **Dangerous function/API usage** — PASS: 4 detector(s) ran, no findings
- [x] **Unsafe configuration detection** — PASS: 6 detector(s) ran, no findings
- [x] **Security-sensitive code pattern analysis** — PASS: 4 detector(s) ran, no findings

## 4. Dynamic Application Security Testing (DAST) — ASSESS

- [ ] **Authentication bypass testing** — ASSESS: Active bypass attempts are exploitation; Truent's exposure rating and the authentication detectors cover the static half — run authorized manual testing for the rest
- [x] **IDOR/BOLA testing** — PASS: 1 detector(s) ran, no findings
- [x] **Privilege-escalation testing** — PASS: 3 detector(s) ran, no findings
- [x] **Session-management testing** — PASS: probe observed no issue
- [x] **CORS testing** — PASS: 1 detector(s) ran, no findings
- [x] **CSRF testing** — PASS: 1 detector(s) ran, no findings
- [x] **Rate-limit testing** — PASS: 1 detector(s) ran, no findings
- [x] **Rate-limit bypass testing** — PASS: 1 detector(s) ran, no findings
- [x] **API abuse testing** — PASS: 5 detector(s) ran, no findings
- [x] **Malformed-request testing** — PASS: 3 detector(s) ran, no findings
- [x] **Injection testing** — PASS: 4 detector(s) ran, no findings
- [x] **Security-header testing** — PASS: probe observed no issue
- [x] **Error-handling and information-disclosure testing** — PASS: probe observed no issue

## 5. Dependency & Supply-Chain Security Testing — ACCEPTED

- [x] **Direct dependency vulnerability scanning** — PASS: 1 detector(s) ran, no findings
- [x] **Transitive dependency vulnerability scanning** — PASS: 1 detector(s) ran, no findings
- [x] **Known CVE detection** — PASS: 1 detector(s) ran, no findings
- [x] **Outdated dependency detection** — ACCEPTED: under risk acceptance: sca_unmaintained_dependency ×3
- [x] **Malicious-package detection** — PASS: 2 detector(s) ran, no findings
- [x] **Dependency-confusion checks** — PASS: 1 detector(s) ran, no findings
- [x] **Lockfile integrity checks** — PASS: 2 detector(s) ran, no findings
- [x] **Dependency provenance verification** — PASS: SBOM generation present and run in CI (crates/sca/src/sbom.rs)
- [x] **Package integrity/signature verification** — PASS: 1 detector(s) ran, no findings
- [x] **Build-pipeline dependency checks** — PASS: 2 detector(s) ran, no findings

## 6. Fuzz Testing — PASS

- [x] **Random-input fuzzing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Malformed-input fuzzing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Boundary-value fuzzing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Type-confusion fuzzing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Null/empty-value fuzzing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Extremely large input testing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Extremely small input testing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Integer boundary testing** — PASS: 8 detector(s) ran, no findings
- [x] **Maximum-value testing** — PASS: 8 detector(s) ran, no findings
- [x] **Negative-value testing** — PASS: 1 detector(s) ran, no findings
- [x] **Unicode/encoding fuzzing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **JSON/XML/parser fuzzing** — PASS: 2 detector(s) ran, no findings
- [x] **API parameter fuzzing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Transaction-input fuzzing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)

## 7. Property-Based Testing — PASS

- [x] **Define security invariants** — PASS: invariant tests present and run in CI (crates/dynamic/core/src/invariant.rs, crates/dynamic/solana/src/invariant.rs, crates/dynamic/evm/src/dsl_invariant.rs)
- [x] **Define financial invariants** — PASS: 6 detector(s) ran, no findings
- [x] **Define data-integrity invariants** — PASS: 2 detector(s) ran, no findings
- [x] **Define authorization invariants** — PASS: 14 detector(s) ran, no findings
- [x] **Generate randomized test cases** — PASS: property-based tests present and run in CI (crates/cli/tests/property/mod.rs, crates/cli/tests/property.rs, tests/property.rs)
- [x] **Verify invariants across thousands of scenarios** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Test edge cases automatically** — PASS: property-based tests present and run in CI (crates/cli/tests/property/mod.rs, crates/cli/tests/property.rs, tests/property.rs)
- [x] **Test state invariants after failures** — PASS: invariant tests present and run in CI (crates/dynamic/core/src/invariant.rs, crates/dynamic/solana/src/invariant.rs, crates/dynamic/evm/src/dsl_invariant.rs)

## 8. Business-Logic Testing — ASSESS

- [ ] **Business-rule validation** — ASSESS: Rules are specific to the product; encode them as invariants (`.sinv`) so `truent scan`/`fuzz` enforce them
- [x] **Unauthorized workflow testing** — PASS: 14 detector(s) ran, no findings
- [x] **Workflow-bypass testing** — PASS: 8 detector(s) ran, no findings
- [x] **Price manipulation testing** — PASS: 11 detector(s) ran, no findings
- [x] **Quantity manipulation testing** — PASS: 2 detector(s) ran, no findings
- [ ] **Discount/coupon abuse testing** — ASSESS: Product-specific; test coupon reuse, stacking and negative totals in the E2E suite
- [x] **Fee manipulation testing** — PASS: 2 detector(s) ran, no findings
- [x] **Balance manipulation testing** — PASS: 3 detector(s) ran, no findings
- [x] **Duplicate-operation testing** — PASS: 2 detector(s) ran, no findings
- [x] **Replay testing** — PASS: 3 detector(s) ran, no findings
- [x] **Double-spending testing** — PASS: 7 detector(s) ran, no findings
- [x] **Transaction-order manipulation testing** — PASS: 3 detector(s) ran, no findings
- [ ] **Trust-boundary testing** — ASSESS: Run `truent threat-model`; every boundary it lists needs a test that crosses it without credentials
- [x] **Privilege-boundary testing** — ACCEPTED: under risk acceptance: evm_single_eoa_admin ×1

## 9. State-Transition Testing — ASSESS

- [ ] **Test every valid state transition** — ASSESS: Enumerate the state machine and cover each edge in the unit suite
- [x] **Test every invalid state transition** — PASS: 3 detector(s) ran, no findings
- [x] **Test unauthorized state transitions** — PASS: 14 detector(s) ran, no findings
- [x] **Test state-transition bypasses** — PASS: 8 detector(s) ran, no findings
- [x] **Test state rollback** — PASS: migration rollback present and run in CI (migration tool with rollback support)
- [x] **Test repeated transitions** — PASS: 3 detector(s) ran, no findings
- [x] **Test skipped states** — PASS: 2 detector(s) ran, no findings
- [x] **Test failed transitions** — PASS: invariant tests present and run in CI (crates/dynamic/core/src/invariant.rs, crates/dynamic/solana/src/invariant.rs, crates/dynamic/evm/src/dsl_invariant.rs)
- [x] **Test partial transitions** — PASS: 2 detector(s) ran, no findings
- [x] **Test concurrent transitions** — PASS: 7 detector(s) ran, no findings
- [x] **Verify terminal states cannot be improperly reversed** — PASS: 3 detector(s) ran, no findings

## 10. Authorization & Access-Control Testing — ACCEPTED

- [x] **Role-based access-control testing** — PASS: 14 detector(s) ran, no findings
- [x] **Permission testing** — PASS: 2 detector(s) ran, no findings
- [x] **Object-level authorization testing** — PASS: 1 detector(s) ran, no findings
- [x] **Function-level authorization testing** — PASS: 14 detector(s) ran, no findings
- [x] **Horizontal privilege-escalation testing** — PASS: 1 detector(s) ran, no findings
- [x] **Vertical privilege-escalation testing** — PASS: 2 detector(s) ran, no findings
- [x] **Admin-access testing** — ACCEPTED: under risk acceptance: evm_single_eoa_admin ×1
- [x] **Owner-access testing** — PASS: 2 detector(s) ran, no findings
- [x] **Guest-access testing** — PASS: 2 detector(s) ran, no findings
- [x] **Cross-user data-access testing** — PASS: 1 detector(s) ran, no findings
- [x] **Tenant-isolation testing** — PASS: 1 detector(s) ran, no findings
- [x] **API authorization matrix testing** — PASS: 3 detector(s) ran, no findings
- [x] **Smart-contract access-control testing** — PASS: 14 detector(s) ran, no findings

## 11. Authentication & Session Security Testing — ASSESS

- [x] **Login testing** — PASS: 2 detector(s) ran, no findings
- [x] **Logout testing** — PASS: 1 detector(s) ran, no findings
- [x] **Password-reset testing** — PASS: 2 detector(s) ran, no findings
- [ ] **MFA testing** — ASSESS: Verify enrolment, recovery codes and step-up on sensitive actions in the E2E suite
- [x] **Session-expiration testing** — PASS: probe observed no issue
- [ ] **Session-revocation testing** — ASSESS: Logout and password change must invalidate every other session; test it
- [x] **Session-fixation testing** — PASS: probe observed no issue
- [x] **Token-reuse testing** — PASS: 2 detector(s) ran, no findings
- [x] **JWT validation testing** — PASS: 1 detector(s) ran, no findings
- [x] **Refresh-token testing** — PASS: 2 detector(s) ran, no findings
- [x] **Credential-stuffing resistance testing** — PASS: 1 detector(s) ran, no findings
- [x] **Brute-force protection testing** — PASS: 1 detector(s) ran, no findings
- [x] **Account-enumeration testing** — PASS: 1 detector(s) ran, no findings

## 12. Race-Condition & Concurrency Testing — ASSESS

- [x] **Concurrent-request testing** — PASS: 1 detector(s) ran, no findings
- [x] **Race-condition testing** — PASS: 2 detector(s) ran, no findings
- [x] **TOCTOU testing** — PASS: 2 detector(s) ran, no findings
- [x] **Double-spend testing** — PASS: 7 detector(s) ran, no findings
- [x] **Duplicate-transaction testing** — PASS: 3 detector(s) ran, no findings
- [x] **Concurrent withdrawal testing** — PASS: 2 detector(s) ran, no findings
- [x] **Concurrent state-update testing** — PASS: 2 detector(s) ran, no findings
- [x] **Database race-condition testing** — PASS: 1 detector(s) ran, no findings
- [ ] **Queue/message race testing** — ASSESS: Idempotency keys on consumers; test redelivery in the integration suite
- [x] **Replay-under-concurrency testing** — PASS: 3 detector(s) ran, no findings
- [x] **Locking/atomicity testing** — PASS: 1 detector(s) ran, no findings

## 13. Data-Integrity Testing — ASSESS

- [x] **Database integrity testing** — PASS: 2 detector(s) ran, no findings
- [x] **Transaction atomicity testing** — PASS: 1 detector(s) ran, no findings
- [x] **Consistency testing** — PASS: 6 detector(s) ran, no findings
- [ ] **Duplicate-record testing** — ASSESS: Unique constraints and idempotent writes, tested
- [ ] **Missing-record testing** — ASSESS: Referential integrity under deletes, tested
- [x] **Corrupted-state testing** — PASS: 2 detector(s) ran, no findings
- [x] **Rollback testing** — PASS: migration rollback present and run in CI (migration tool with rollback support)
- [ ] **Database constraint testing** — ASSESS: Constraints exist for every invariant the application relies on
- [ ] **Referential-integrity testing** — ASSESS: Foreign keys with the intended on-delete behaviour
- [x] **Backup restoration testing** — PASS: disaster-recovery runbook present and run in CI (docs/runbooks/incident-response.md, docs/runbooks/disaster-recovery.md)
- [x] **Disaster-recovery testing** — PASS: disaster-recovery runbook present and run in CI (docs/runbooks/incident-response.md, docs/runbooks/disaster-recovery.md)
- [x] **Data migration integrity testing** — PASS: database migrations present and run in CI (web/prisma/migrations/migration_lock.toml, web/prisma/migrations/20260912160000_engine_fields/migration.sql, web/prisma/migrations/20260621132501_init/migration.sql)
- [x] **Financial-balance reconciliation testing** — PASS: 6 detector(s) ran, no findings

## 14. Financial / Value-Movement Testing — ASSESS

- [x] **Deposit testing** — PASS: 3 detector(s) ran, no findings
- [x] **Withdrawal testing** — PASS: 7 detector(s) ran, no findings
- [x] **Transfer testing** — PASS: 2 detector(s) ran, no findings
- [ ] **Refund testing** — ASSESS: Refunds cannot exceed the original charge or be issued twice; test it
- [x] **Fee calculation testing** — PASS: 3 detector(s) ran, no findings
- [x] **Balance calculation testing** — PASS: 6 detector(s) ran, no findings
- [x] **Rounding/precision testing** — PASS: 3 detector(s) ran, no findings
- [x] **Negative-value testing** — PASS: 1 detector(s) ran, no findings
- [x] **Zero-value testing** — PASS: 2 detector(s) ran, no findings
- [x] **Maximum-value testing** — PASS: 8 detector(s) ran, no findings
- [x] **Double-spending testing** — PASS: 7 detector(s) ran, no findings
- [x] **Replay testing** — PASS: 3 detector(s) ran, no findings
- [x] **Unauthorized transfer testing** — PASS: 14 detector(s) ran, no findings
- [x] **Transaction ordering testing** — PASS: 2 detector(s) ran, no findings
- [x] **Partial-failure testing** — PASS: 2 detector(s) ran, no findings
- [x] **Atomicity testing** — PASS: 1 detector(s) ran, no findings
- [x] **Accounting/reconciliation testing** — PASS: 6 detector(s) ran, no findings

## 15. Smart-Contract Security Testing — PASS

- [x] **Reentrancy testing** — PASS: 7 detector(s) ran, no findings
- [x] **Access-control testing** — PASS: 14 detector(s) ran, no findings
- [x] **Integer overflow/underflow testing** — PASS: 8 detector(s) ran, no findings
- [x] **Precision/rounding testing** — PASS: 3 detector(s) ran, no findings
- [x] **Oracle manipulation testing** — PASS: 11 detector(s) ran, no findings
- [x] **Price manipulation testing** — PASS: 11 detector(s) ran, no findings
- [x] **Flash-loan attack testing** — PASS: 3 detector(s) ran, no findings
- [x] **Front-running testing** — PASS: 2 detector(s) ran, no findings
- [x] **MEV-related attack testing** — PASS: 3 detector(s) ran, no findings
- [x] **Replay-attack testing** — PASS: 3 detector(s) ran, no findings
- [x] **Signature-validation testing** — PASS: 3 detector(s) ran, no findings
- [x] **Initialization testing** — PASS: 3 detector(s) ran, no findings
- [x] **Uninitialized-contract testing** — PASS: 2 detector(s) ran, no findings
- [x] **Upgradeability testing** — PASS: 8 detector(s) ran, no findings
- [x] **Proxy security testing** — PASS: 3 detector(s) ran, no findings
- [x] **Storage-collision testing** — PASS: 1 detector(s) ran, no findings
- [x] **Emergency/pause mechanism testing** — PASS: 1 detector(s) ran, no findings
- [x] **Token-standard compatibility testing** — PASS: 3 detector(s) ran, no findings
- [x] **Denial-of-service/gas-griefing testing** — PASS: 2 detector(s) ran, no findings
- [x] **Gas-consumption testing** — PASS: 2 detector(s) ran, no findings
- [x] **Invariant testing** — PASS: invariant tests present and run in CI (crates/dynamic/core/src/invariant.rs, crates/dynamic/solana/src/invariant.rs, crates/dynamic/evm/src/dsl_invariant.rs)
- [x] **Symbolic-execution testing** — PASS: every symbolic check passed
- [x] **Smart-contract fuzzing** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Static-analysis testing** — PASS: 7 detector(s) ran, no findings

## 16. API Security Testing — ASSESS

- [ ] **Endpoint discovery** — ASSESS: `truent threat-model` lists discovered routes; reconcile against the API inventory
- [x] **Authentication testing** — PASS: 2 detector(s) ran, no findings
- [x] **Authorization testing** — PASS: 1 detector(s) ran, no findings
- [x] **BOLA/IDOR testing** — PASS: 1 detector(s) ran, no findings
- [x] **Parameter tampering** — PASS: 2 detector(s) ran, no findings
- [ ] **HTTP-method manipulation** — ASSESS: Every route rejects methods it does not implement (405); test with the API suite
- [x] **Mass-assignment testing** — PASS: 1 detector(s) ran, no findings
- [x] **Input validation testing** — PASS: 4 detector(s) ran, no findings
- [x] **Output encoding testing** — PASS: 2 detector(s) ran, no findings
- [x] **Rate-limit testing** — PASS: 1 detector(s) ran, no findings
- [x] **Pagination abuse testing** — PASS: 1 detector(s) ran, no findings
- [x] **Resource-exhaustion testing** — PASS: 5 detector(s) ran, no findings
- [ ] **API version compatibility testing** — ASSESS: Contract tests against the previous API version in CI
- [x] **GraphQL security testing (if applicable)** — PASS: 1 detector(s) ran, no findings
- [x] **WebSocket security testing (if applicable)** — PASS: 1 detector(s) ran, no findings

## 17. CORS & Browser Security Testing — PASS

- [x] **CORS policy testing** — PASS: 1 detector(s) ran, no findings
- [x] **Origin-validation testing** — PASS: 2 detector(s) ran, no findings
- [x] **Credentialed-CORS testing** — PASS: 1 detector(s) ran, no findings
- [x] **Wildcard-origin testing** — PASS: 1 detector(s) ran, no findings
- [x] **CSRF testing** — PASS: 1 detector(s) ran, no findings
- [x] **Clickjacking testing** — PASS: probe observed no issue
- [x] **Content-Security-Policy testing** — PASS: probe observed no issue
- [x] **Security-header testing** — PASS: probe observed no issue
- [x] **Cookie security testing** — PASS: probe observed no issue
- [x] **SameSite testing** — PASS: 1 detector(s) ran, no findings
- [x] **Secure/HttpOnly cookie testing** — PASS: probe observed no issue

## 18. Load & Stress Testing — PASS

- [x] **Normal-load testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Peak-load testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **High-concurrency testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Stress testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Spike testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Endurance/soak testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **CPU-exhaustion testing** — PASS: 1 detector(s) ran, no findings
- [x] **Memory-exhaustion testing** — PASS: 2 detector(s) ran, no findings
- [x] **Database-exhaustion testing** — PASS: 1 detector(s) ran, no findings
- [x] **Connection-exhaustion testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Queue-overload testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **API timeout testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Cascading-failure testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)

## 19. Chaos & Failure Testing — PASS

- [x] **Database failure testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Cache failure testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **RPC-node failure testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Network failure testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Network-latency testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Third-party-service failure testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **API timeout testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Message-queue failure testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Transaction-revert testing** — PASS: 3 detector(s) ran, no findings
- [x] **Partial-service failure testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Restart/recovery testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Failover testing** — PASS: disaster-recovery runbook present and run in CI (docs/runbooks/incident-response.md, docs/runbooks/disaster-recovery.md)
- [x] **Graceful-degradation testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Recovery-state integrity testing** — PASS: invariant tests present and run in CI (crates/dynamic/core/src/invariant.rs, crates/dynamic/solana/src/invariant.rs, crates/dynamic/evm/src/dsl_invariant.rs)

## 20. Migration & Upgrade Testing — ASSESS

- [x] **Database migration testing** — PASS: database migrations present and run in CI (web/prisma/migrations/migration_lock.toml, web/prisma/migrations/20260912160000_engine_fields/migration.sql, web/prisma/migrations/20260621132501_init/migration.sql)
- [x] **Schema migration testing** — PASS: database migrations present and run in CI (web/prisma/migrations/migration_lock.toml, web/prisma/migrations/20260912160000_engine_fields/migration.sql, web/prisma/migrations/20260621132501_init/migration.sql)
- [x] **Migration rollback testing** — PASS: migration rollback present and run in CI (migration tool with rollback support)
- [x] **Partial-migration failure testing** — PASS: migration rollback present and run in CI (migration tool with rollback support)
- [x] **Existing-data compatibility testing** — PASS: database migrations present and run in CI (web/prisma/migrations/migration_lock.toml, web/prisma/migrations/20260912160000_engine_fields/migration.sql, web/prisma/migrations/20260621132501_init/migration.sql)
- [x] **Version-upgrade testing** — PASS: end-to-end tests present and run in CI (crates/cli/tests/cli/mod.rs, crates/cli/tests/cli.rs, tests/cli.rs)
- [ ] **API backward-compatibility testing** — ASSESS: Contract tests against the previous client version
- [x] **Smart-contract upgrade testing** — PASS: 8 detector(s) ran, no findings
- [x] **Proxy upgrade testing** — PASS: 2 detector(s) ran, no findings
- [x] **Storage-layout compatibility testing** — PASS: 1 detector(s) ran, no findings
- [ ] **Configuration migration testing** — ASSESS: Config schema is versioned and validated at startup

## 21. Performance Testing — ASSESS

- [x] **Response-time testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Throughput testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **CPU profiling** — PASS: performance benchmarks present and run in CI (crates/cli/benches/scan.rs, benches/benchmarks.rs)
- [x] **Memory profiling** — PASS: performance benchmarks present and run in CI (crates/cli/benches/scan.rs, benches/benchmarks.rs)
- [x] **Database-query performance testing** — PASS: 1 detector(s) ran, no findings
- [ ] **N+1 query detection** — ASSESS: Enable query logging in tests and assert query counts per request
- [x] **RPC-call performance testing** — PASS: performance benchmarks present and run in CI (crates/cli/benches/scan.rs, benches/benchmarks.rs)
- [x] **Network-performance testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Cache-performance testing** — PASS: performance benchmarks present and run in CI (crates/cli/benches/scan.rs, benches/benchmarks.rs)
- [x] **Smart-contract gas-usage testing** — PASS: 2 detector(s) ran, no findings
- [x] **Performance-regression testing** — PASS: performance benchmarks present and run in CI (crates/cli/benches/scan.rs, benches/benchmarks.rs)

## 22. Differential Testing — ASSESS

- [x] **Compare old and new implementations** — PASS: snapshot/differential tests present and run in CI (truent-npm/INSTALL.md, truent-npm/scripts/postinstall.js, truent-npm/scripts/preuninstall.js)
- [x] **Compare outputs for identical inputs** — PASS: snapshot/differential tests present and run in CI (truent-npm/INSTALL.md, truent-npm/scripts/postinstall.js, truent-npm/scripts/preuninstall.js)
- [x] **Compare financial calculations** — PASS: snapshot/differential tests present and run in CI (truent-npm/INSTALL.md, truent-npm/scripts/postinstall.js, truent-npm/scripts/preuninstall.js)
- [x] **Compare state transitions** — PASS: snapshot/differential tests present and run in CI (truent-npm/INSTALL.md, truent-npm/scripts/postinstall.js, truent-npm/scripts/preuninstall.js)
- [x] **Compare API responses** — PASS: snapshot/differential tests present and run in CI (truent-npm/INSTALL.md, truent-npm/scripts/postinstall.js, truent-npm/scripts/preuninstall.js)
- [x] **Compare serialization/deserialization** — PASS: snapshot/differential tests present and run in CI (truent-npm/INSTALL.md, truent-npm/scripts/postinstall.js, truent-npm/scripts/preuninstall.js)
- [ ] **Investigate unexpected behavioral differences** — ASSESS: Every snapshot change is reviewed, never blindly accepted

## 23. Mutation Testing — PASS

- [x] **Mutate comparison operators** — PASS: mutation testing present and run in CI (mutation job in CI)
- [x] **Mutate arithmetic operators** — PASS: mutation testing present and run in CI (mutation job in CI)
- [x] **Mutate boolean conditions** — PASS: mutation testing present and run in CI (mutation job in CI)
- [x] **Remove validation checks** — PASS: mutation testing present and run in CI (mutation job in CI)
- [x] **Remove authorization checks** — PASS: mutation testing present and run in CI (mutation job in CI)
- [x] **Change boundary conditions** — PASS: mutation testing present and run in CI (mutation job in CI)
- [x] **Verify tests detect injected mutations** — PASS: mutation testing present and run in CI (mutation job in CI)
- [x] **Measure test-suite mutation score** — PASS: mutation testing present and run in CI (mutation job in CI)

## 24. Secrets & Configuration Testing — ASSESS

- [x] **Hardcoded-secret scanning** — PASS: 2 detector(s) ran, no findings
- [x] **API-key scanning** — PASS: 1 detector(s) ran, no findings
- [x] **Private-key scanning** — PASS: 1 detector(s) ran, no findings
- [x] **Credential scanning** — PASS: 2 detector(s) ran, no findings
- [x] **Environment-variable security** — PASS: 2 detector(s) ran, no findings
- [x] **Production/debug configuration checks** — PASS: 2 detector(s) ran, no findings
- [x] **Insecure default configuration checks** — PASS: 4 detector(s) ran, no findings
- [x] **Exposed configuration testing** — PASS: probe observed no issue
- [ ] **Secret rotation testing** — ASSESS: Rotation is automated (or at least runbooked) and exercised on a schedule
- [x] **Secret-access authorization testing** — PASS: 2 detector(s) ran, no findings

## 25. Logging & Monitoring Security Testing — ASSESS

- [x] **Sensitive-data logging checks** — PASS: 1 detector(s) ran, no findings
- [x] **Secret/token logging checks** — PASS: 2 detector(s) ran, no findings
- [x] **Security-event logging** — PASS: 1 detector(s) ran, no findings
- [x] **Authentication-event logging** — PASS: 1 detector(s) ran, no findings
- [x] **Authorization-event logging** — PASS: 1 detector(s) ran, no findings
- [ ] **Financial-transaction logging** — ASSESS: Every value movement writes an immutable audit record
- [ ] **Audit-trail integrity** — ASSESS: Logs are append-only and shipped off-host; tampering is detectable
- [x] **Log-injection testing** — PASS: 1 detector(s) ran, no findings
- [x] **Alerting verification** — PASS: alerting/detection rules present and run in CI (security/alerts/auth-anomalies.sigma.yml)
- [x] **Detection-rule testing** — PASS: alerting/detection rules present and run in CI (security/alerts/auth-anomalies.sigma.yml)

## 26. File & Resource Security Testing — PASS

- [x] **File-upload testing** — PASS: 1 detector(s) ran, no findings
- [x] **Malicious-file testing** — PASS: 1 detector(s) ran, no findings
- [x] **File-type validation** — PASS: 1 detector(s) ran, no findings
- [x] **Path-traversal testing** — PASS: 1 detector(s) ran, no findings
- [x] **File-size limit testing** — PASS: 1 detector(s) ran, no findings
- [x] **Resource-exhaustion testing** — PASS: 5 detector(s) ran, no findings
- [x] **Temporary-file security** — PASS: 2 detector(s) ran, no findings
- [x] **File-permission testing** — PASS: 1 detector(s) ran, no findings

## 27. Availability & Denial-of-Service Testing — PASS

- [x] **Application-level DoS testing** — PASS: 5 detector(s) ran, no findings
- [x] **API resource-exhaustion testing** — PASS: 5 detector(s) ran, no findings
- [x] **Database resource-exhaustion testing** — PASS: 1 detector(s) ran, no findings
- [x] **Memory-exhaustion testing** — PASS: 2 detector(s) ran, no findings
- [x] **CPU-exhaustion testing** — PASS: 1 detector(s) ran, no findings
- [x] **Expensive-operation abuse testing** — PASS: 2 detector(s) ran, no findings
- [x] **Gas-griefing testing** — PASS: 2 detector(s) ran, no findings
- [x] **Queue exhaustion testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Connection exhaustion testing** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Rate-limit bypass testing** — PASS: 1 detector(s) ran, no findings

## 28. Supply-Chain & Build Security — PASS

- [x] **CI/CD pipeline security testing** — PASS: 4 detector(s) ran, no findings
- [x] **Build-script review** — PASS: 2 detector(s) ran, no findings
- [x] **Dependency-lock verification** — PASS: 3 detector(s) ran, no findings
- [x] **Artifact-integrity testing** — PASS: 1 detector(s) ran, no findings
- [x] **Container-image scanning** — PASS: 2 detector(s) ran, no findings
- [x] **Base-image vulnerability scanning** — PASS: 1 detector(s) ran, no findings
- [x] **Secret exposure in CI/CD** — PASS: 1 detector(s) ran, no findings
- [x] **Build-environment isolation** — PASS: 1 detector(s) ran, no findings
- [x] **Deployment-permission testing** — PASS: 2 detector(s) ran, no findings
- [x] **Release-integrity verification** — PASS: release signing/provenance present and run in CI (signing / attestation in the release workflow)

## 29. Security Boundary Testing — ASSESS

- [x] **User-to-user isolation** — PASS: 1 detector(s) ran, no findings
- [x] **User-to-admin isolation** — PASS: 2 detector(s) ran, no findings
- [ ] **Service-to-service authorization** — ASSESS: Internal calls carry an identity (mTLS / signed tokens) and are authorized, tested
- [x] **API-to-database boundaries** — PASS: 2 detector(s) ran, no findings
- [x] **Frontend-to-backend trust boundaries** — PASS: 3 detector(s) ran, no findings
- [x] **Backend-to-RPC boundaries** — PASS: 2 detector(s) ran, no findings
- [x] **Smart-contract trust boundaries** — PASS: 4 detector(s) ran, no findings
- [x] **Third-party integration boundaries** — PASS: 3 detector(s) ran, no findings
- [ ] **Internal-service authentication** — ASSESS: No internal service accepts unauthenticated calls from the network; verify with `truent probe --ports`

## 30. Recovery & Disaster Testing — ASSESS

- [x] **Backup creation testing** — PASS: backup configuration present and run in CI (tests/dr/backup-restore-drill.sh)
- [x] **Backup restoration testing** — PASS: disaster-recovery runbook present and run in CI (docs/runbooks/incident-response.md, docs/runbooks/disaster-recovery.md)
- [x] **Database recovery testing** — PASS: disaster-recovery runbook present and run in CI (docs/runbooks/incident-response.md, docs/runbooks/disaster-recovery.md)
- [x] **Service recovery testing** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [ ] **Key recovery procedures** — ASSESS: Signing and encryption keys have a documented, rehearsed recovery path
- [x] **Failed-transaction recovery** — PASS: 2 detector(s) ran, no findings
- [x] **Interrupted-operation recovery** — PASS: 1 detector(s) ran, no findings
- [x] **Disaster-recovery testing** — PASS: disaster-recovery runbook present and run in CI (docs/runbooks/incident-response.md, docs/runbooks/disaster-recovery.md)
- [x] **Business-continuity testing** — PASS: disaster-recovery runbook present and run in CI (docs/runbooks/incident-response.md, docs/runbooks/disaster-recovery.md)
- [x] **Recovery-time objective testing** — PASS: disaster-recovery runbook present and run in CI (docs/runbooks/incident-response.md, docs/runbooks/disaster-recovery.md)
- [x] **Recovery-point objective testing** — PASS: backup configuration present and run in CI (tests/dr/backup-restore-drill.sh)

## 31. Code Quality & Safety Testing — ASSESS

- [x] **Linting** — PASS: linting present and run in CI (web/.next/cache/eslint/.cache_16wwkx5, web/.eslintrc.json)
- [x] **Type checking** — PASS: type checking present and run in CI (crates/dynamic/core/src/sequence.rs, crates/dynamic/core/src/shrink.rs, crates/dynamic/core/src/backend.rs)
- [x] **Compiler/static type checks** — PASS: type checking present and run in CI (crates/dynamic/core/src/sequence.rs, crates/dynamic/core/src/shrink.rs, crates/dynamic/core/src/backend.rs)
- [ ] **Dead-code detection** — ASSESS: Compiler warnings / `knip` / `vulture` run in CI with warnings denied
- [x] **Unsafe-code detection** — PASS: 3 detector(s) ran, no findings
- [x] **Error-handling analysis** — PASS: 3 detector(s) ran, no findings
- [x] **Exception-path testing** — PASS: 2 detector(s) ran, no findings
- [ ] **Null/undefined handling** — ASSESS: Strict null checks / Option types enforced by the type checker
- [x] **Boundary-condition testing** — PASS: 8 detector(s) ran, no findings
- [ ] **Complexity analysis** — ASSESS: Cyclomatic complexity is measured and capped in CI
- [x] **Code-coverage analysis** — PASS: code coverage present and run in CI (truent-npm/jest.config.js, codecov.yml, crates/invariant_library/src/coverage.rs)

## 32. Critical-Path Security Testing — ACCEPTED

- [x] **No completed attack chain** — PASS: no known attack chain is completed by the findings
- [x] **No LIKELY-exploitable finding** — PASS: no finding rated LIKELY
- [x] **Move money or tokens** — PASS: 7 detector(s) ran, no findings
- [x] **Change balances** — PASS: 6 detector(s) ran, no findings
- [x] **Transfer ownership** — ACCEPTED: under risk acceptance: evm_single_eoa_admin ×1
- [x] **Change permissions** — PASS: 3 detector(s) ran, no findings
- [x] **Execute privileged operations** — PASS: 14 detector(s) ran, no findings
- [x] **Modify critical configuration** — PASS: 3 detector(s) ran, no findings
- [x] **Access sensitive user data** — PASS: 3 detector(s) ran, no findings
- [x] **Delete or corrupt data** — PASS: 3 detector(s) ran, no findings
- [x] **Execute smart contracts** — PASS: 3 detector(s) ran, no findings
- [x] **Sign transactions** — PASS: 2 detector(s) ran, no findings
- [x] **Modify prices or exchange rates** — PASS: 11 detector(s) ran, no findings
- [x] **Control oracles** — PASS: 11 detector(s) ran, no findings
- [x] **Upgrade contracts** — PASS: 8 detector(s) ran, no findings
- [x] **Pause/unpause systems** — PASS: 1 detector(s) ran, no findings
- [x] **Shut down or exhaust the application** — PASS: 5 detector(s) ran, no findings
- [x] **Bypass authentication** — PASS: 2 detector(s) ran, no findings
- [x] **Bypass authorization** — PASS: 2 detector(s) ran, no findings
- [x] **Cause permanent loss of funds** — PASS: 3 detector(s) ran, no findings
- [x] **Cause irreversible state changes** — PASS: 3 detector(s) ran, no findings

## 33. Final Security Validation — ASSESS

- [x] **All unit tests pass** — PASS: unit tests present and run in CI (truent-npm/__tests__/detect-platform.test.js, truent-npm/__tests__/index.test.js, truent-npm/__tests__/download.test.js)
- [x] **All integration tests pass** — PASS: integration tests present and run in CI (crates/core/src/integration_testing.rs, crates/cli/tests/integration/mod.rs, crates/cli/tests/integration.rs)
- [x] **All E2E tests pass** — PASS: end-to-end tests present and run in CI (crates/cli/tests/cli/mod.rs, crates/cli/tests/cli.rs, tests/cli.rs)
- [x] **Regression suite passes** — PASS: unit tests present and run in CI (truent-npm/__tests__/detect-platform.test.js, truent-npm/__tests__/index.test.js, truent-npm/__tests__/download.test.js)
- [x] **SAST passes** — PASS: 4 detector(s) ran, no findings
- [x] **DAST passes** — PASS: probe observed no issue
- [x] **Dependency scan passes** — PASS: 1 detector(s) ran, no findings
- [x] **Fuzz tests pass** — PASS: fuzzing present and run in CI (crates/dynamic/solana/src/fuzz.rs, crates/core/src/merkle_root_fuzzer.rs, crates/core/src/fuzzer.rs)
- [x] **Property/invariant tests pass** — PASS: invariant tests present and run in CI (crates/dynamic/core/src/invariant.rs, crates/dynamic/solana/src/invariant.rs, crates/dynamic/evm/src/dsl_invariant.rs)
- [x] **Business-logic tests pass** — PASS: 11 detector(s) ran, no findings
- [x] **Authorization matrix passes** — PASS: 14 detector(s) ran, no findings
- [x] **Race-condition tests pass** — PASS: 1 detector(s) ran, no findings
- [x] **Data-integrity tests pass** — PASS: 6 detector(s) ran, no findings
- [x] **Financial/value-movement tests pass** — PASS: 7 detector(s) ran, no findings
- [x] **Smart-contract security tests pass** — PASS: 14 detector(s) ran, no findings
- [x] **Load/stress tests pass** — PASS: load/stress tests present and run in CI (tests/load/stress-scan.sh)
- [x] **Failure/chaos tests pass** — PASS: chaos/failure experiments present and run in CI (tests/chaos/run.sh)
- [x] **Migration tests pass** — PASS: database migrations present and run in CI (web/prisma/migrations/migration_lock.toml, web/prisma/migrations/20260912160000_engine_fields/migration.sql, web/prisma/migrations/20260621132501_init/migration.sql)
- [x] **Performance regression checks pass** — PASS: performance benchmarks present and run in CI (crates/cli/benches/scan.rs, benches/benchmarks.rs)
- [x] **Mutation tests meet the required threshold** — PASS: mutation testing present and run in CI (mutation job in CI)
- [x] **Secrets/configuration scans pass** — PASS: 2 detector(s) ran, no findings
- [x] **Logging/monitoring checks pass** — PASS: 2 detector(s) ran, no findings
- [x] **Recovery tests pass** — PASS: disaster-recovery runbook present and run in CI (docs/runbooks/incident-response.md, docs/runbooks/disaster-recovery.md)
- [x] **Critical-path security review completed** — PASS: no known attack chain is completed by the findings
- [x] **No unresolved critical vulnerabilities** — PASS: no finding rated LIKELY
- [ ] **No unresolved high-severity vulnerabilities without explicit risk acceptance** — ASSESS: Every remaining HIGH has a written, dated risk acceptance

