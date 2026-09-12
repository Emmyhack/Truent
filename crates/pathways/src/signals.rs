//! Repository signals: does the repository *have* a test suite, a load test,
//! a chaos experiment, a disaster-recovery runbook, a mutation-testing
//! config — and does CI actually run it?
//!
//! Functional, regression, load, chaos, performance, mutation, differential
//! and recovery testing are things a team runs against its own system; no
//! scanner can run them for you. What a scanner *can* do is refuse to let
//! their absence pass silently: each [`Signal`] is evaluated as
//! `present` (the files exist) and `wired` (a CI workflow invokes them), and
//! the release checklist reports both. A signal with `present` but not
//! `wired` is a test suite that decorates the repository without
//! protecting it.

use serde::Serialize;

/// One kind of evidence the repository can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Signal {
    UnitTests,
    IntegrationTests,
    E2eTests,
    ApiTests,
    Coverage,
    Lint,
    TypeCheck,
    Fuzzing,
    PropertyTests,
    Invariants,
    LoadTests,
    ChaosTests,
    Benchmarks,
    SnapshotOrDifferentialTests,
    MutationTesting,
    Migrations,
    MigrationRollback,
    BackupConfig,
    DrRunbook,
    IncidentRunbook,
    AlertingConfig,
    Sbom,
    ReleaseSigning,
    SecurityPolicy,
    Codeowners,
}

impl Signal {
    pub fn label(&self) -> &'static str {
        match self {
            Self::UnitTests => "unit tests",
            Self::IntegrationTests => "integration tests",
            Self::E2eTests => "end-to-end tests",
            Self::ApiTests => "API/contract tests",
            Self::Coverage => "code coverage",
            Self::Lint => "linting",
            Self::TypeCheck => "type checking",
            Self::Fuzzing => "fuzzing",
            Self::PropertyTests => "property-based tests",
            Self::Invariants => "invariant tests",
            Self::LoadTests => "load/stress tests",
            Self::ChaosTests => "chaos/failure experiments",
            Self::Benchmarks => "performance benchmarks",
            Self::SnapshotOrDifferentialTests => "snapshot/differential tests",
            Self::MutationTesting => "mutation testing",
            Self::Migrations => "database migrations",
            Self::MigrationRollback => "migration rollback",
            Self::BackupConfig => "backup configuration",
            Self::DrRunbook => "disaster-recovery runbook",
            Self::IncidentRunbook => "incident-response runbook",
            Self::AlertingConfig => "alerting/detection rules",
            Self::Sbom => "SBOM generation",
            Self::ReleaseSigning => "release signing/provenance",
            Self::SecurityPolicy => "security policy (SECURITY.md)",
            Self::Codeowners => "CODEOWNERS",
        }
    }

    /// Every signal, in display order.
    pub fn all() -> &'static [Signal] {
        &[
            Self::UnitTests,
            Self::IntegrationTests,
            Self::E2eTests,
            Self::ApiTests,
            Self::Coverage,
            Self::Lint,
            Self::TypeCheck,
            Self::Fuzzing,
            Self::PropertyTests,
            Self::Invariants,
            Self::LoadTests,
            Self::ChaosTests,
            Self::Benchmarks,
            Self::SnapshotOrDifferentialTests,
            Self::MutationTesting,
            Self::Migrations,
            Self::MigrationRollback,
            Self::BackupConfig,
            Self::DrRunbook,
            Self::IncidentRunbook,
            Self::AlertingConfig,
            Self::Sbom,
            Self::ReleaseSigning,
            Self::SecurityPolicy,
            Self::Codeowners,
        ]
    }
}

/// What was found for one signal.
#[derive(Debug, Clone, Serialize)]
pub struct SignalResult {
    pub signal: Signal,
    /// Files or config that constitute the evidence.
    pub present: bool,
    /// A CI workflow invokes it.
    pub wired: bool,
    /// The paths / commands that satisfied the check (first few).
    pub evidence: Vec<String>,
}

/// Repository contents the evaluator needs: relative paths, plus the text of
/// CI workflows and manifests (only those are read).
pub struct RepoView<'a> {
    pub files: &'a [String],
    /// `(path, content)` for `.github/workflows/*.yml`, `.gitlab-ci.yml`,
    /// `Jenkinsfile`, `.circleci/config.yml`, `Makefile`, `package.json`,
    /// `Cargo.toml`, `pyproject.toml`, `foundry.toml`, `hardhat.config.*`.
    pub texts: &'a [(String, String)],
}

impl RepoView<'_> {
    fn any_path(&self, pred: impl Fn(&str) -> bool) -> Vec<String> {
        self.files
            .iter()
            .filter(|f| pred(&f.to_ascii_lowercase()))
            .take(3)
            .cloned()
            .collect()
    }
    fn ci_text(&self) -> String {
        self.texts
            .iter()
            .filter(|(p, _)| {
                p.starts_with(".github/workflows/")
                    || p.ends_with(".gitlab-ci.yml")
                    || p.ends_with("Jenkinsfile")
                    || p.ends_with(".circleci/config.yml")
                    || p.ends_with("bitbucket-pipelines.yml")
                    || p.ends_with("azure-pipelines.yml")
            })
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
    fn manifest_text(&self) -> String {
        self.texts
            .iter()
            .filter(|(p, _)| {
                p.ends_with("package.json")
                    || p.ends_with("Cargo.toml")
                    || p.ends_with("pyproject.toml")
                    || p.ends_with("foundry.toml")
                    || p.contains("hardhat.config")
                    || p.ends_with("Makefile")
                    || p.ends_with("go.mod")
            })
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn has(text: &str, needles: &[&str]) -> bool {
    let t = text.to_ascii_lowercase();
    needles.iter().any(|n| t.contains(&n.to_ascii_lowercase()))
}

/// Evaluate every signal.
pub fn evaluate(repo: &RepoView<'_>) -> Vec<SignalResult> {
    let ci = repo.ci_text();
    let manifests = repo.manifest_text();
    let mut out = Vec::new();
    // The unit-test runner (`cargo test`, `pytest`, `npm test`, …) executes
    // every test in the tree: integration, end-to-end, property and snapshot
    // tests that live in the same suite are wired when it is.
    let suite_runner_wired = has(
        &ci,
        &[
            "cargo test",
            "pytest",
            "npm test",
            "npm run test",
            "yarn test",
            "pnpm test",
            "go test",
            "forge test",
            "hardhat test",
            "npx jest",
            "vitest",
            "mocha",
            "unittest",
            "make test",
            "anchor test",
        ],
    );
    // A CLI's contract is its command line: `assert_cmd` / `tests/cli` tests
    // are its end-to-end and interface tests.
    let cli_e2e = has(&manifests, &["assert_cmd", "click.testing", "oclif"])
        || repo
            .files
            .iter()
            .any(|f| f.contains("tests/cli") || f.contains("test/cli"));

    let mut push = |signal: Signal, present: Vec<String>, wired: bool| {
        out.push(SignalResult {
            signal,
            present: !present.is_empty(),
            wired,
            evidence: present,
        });
    };

    // ---- tests ---------------------------------------------------------
    let unit = repo.any_path(|f| {
        (f.contains("/tests/")
            || f.contains("/test/")
            || f.contains("/__tests__/")
            || f.starts_with("tests/")
            || f.starts_with("test/")
            || f.starts_with("spec/"))
            && (f.ends_with(".rs")
                || f.ends_with(".py")
                || f.ends_with(".js")
                || f.ends_with(".ts")
                || f.ends_with(".tsx")
                || f.ends_with(".go")
                || f.ends_with(".sol")
                || f.ends_with(".move"))
            || f.ends_with("_test.go")
            || f.ends_with("_test.py")
            || f.ends_with("test_")
            || f.contains(".test.")
            || f.contains(".spec.")
            || f.ends_with(".t.sol")
    });
    push(
        Signal::UnitTests,
        unit,
        has(
            &ci,
            &[
                "cargo test",
                "pytest",
                "npm test",
                "npm run test",
                "yarn test",
                "pnpm test",
                "go test",
                "forge test",
                "hardhat test",
                "npx jest",
                "vitest",
                "mocha",
                "unittest",
                "make test",
                "anchor test",
                "aptos move test",
                "sui move test",
            ],
        ),
    );

    let integ =
        repo.any_path(|f| f.contains("integration") && (f.contains("test") || f.contains("spec")));
    let integ_wired = has(
        &ci,
        &[
            "integration",
            "testcontainers",
            "docker compose up",
            "docker-compose up",
            "services:",
        ],
    ) || (!integ.is_empty() && suite_runner_wired);
    push(Signal::IntegrationTests, integ, integ_wired);

    let e2e = repo.any_path(|f| {
        f.contains("e2e")
            || f.contains("cypress")
            || f.contains("playwright")
            || f.ends_with(".feature")
            || f.contains("/acceptance/")
    });
    let e2e = if e2e.is_empty() && cli_e2e {
        repo.any_path(|f| f.contains("tests/cli") || f.contains("test/cli"))
    } else {
        e2e
    };
    let e2e_wired = has(
        &ci,
        &[
            "e2e",
            "cypress",
            "playwright",
            "puppeteer",
            "selenium",
            "webdriver",
        ],
    ) || (!e2e.is_empty() && suite_runner_wired);
    push(Signal::E2eTests, e2e, e2e_wired);

    let api = repo.any_path(|f| {
        f.contains("postman")
            || f.contains("openapi")
            || f.contains("swagger")
            || f.contains("pact")
            || f.contains("api-test")
            || f.contains("api_test")
            || f.contains("supertest")
            || f.contains("schemathesis")
    });
    let api = if api.is_empty() && cli_e2e {
        repo.any_path(|f| f.contains("tests/cli") || f.contains("test/cli"))
    } else {
        api
    };
    let api_wired = has(
        &ci,
        &[
            "supertest",
            "schemathesis",
            "dredd",
            "newman",
            "pact",
            "openapi",
            "tavern",
            "hurl",
        ],
    ) || (!api.is_empty() && suite_runner_wired);
    push(Signal::ApiTests, api, api_wired);

    let cov = repo.any_path(|f| {
        f.contains("codecov")
            || f.contains(".coveragerc")
            || f.contains("tarpaulin")
            || f.contains("nyc")
            || f.contains("jest.config")
            || f.contains("coverage")
    });
    push(
        Signal::Coverage,
        cov,
        has(
            &ci,
            &[
                "coverage",
                "codecov",
                "tarpaulin",
                "llvm-cov",
                "nyc",
                "c8",
                "--cov",
                "coveralls",
                "forge coverage",
            ],
        ),
    );

    let lint = repo.any_path(|f| {
        f.contains("eslint")
            || f.contains(".flake8")
            || f.contains("ruff")
            || f.contains("pylintrc")
            || f.contains("golangci")
            || f.contains("clippy")
            || f.contains("rustfmt")
            || f.contains(".solhint")
            || f.contains("slither")
    });
    let lint_wired = has(
        &ci,
        &[
            "clippy",
            "eslint",
            "ruff",
            "flake8",
            "pylint",
            "golangci",
            "solhint",
            "slither",
            "rustfmt",
            "prettier --check",
            "lint",
        ],
    );
    let lint = if lint.is_empty() && lint_wired {
        vec!["linters run in CI".into()]
    } else {
        lint
    };
    push(Signal::Lint, lint, lint_wired);

    let types = repo.any_path(|f| {
        f.ends_with("tsconfig.json")
            || f.contains("mypy.ini")
            || f.contains("pyrightconfig")
            || f.ends_with(".rs")
            || f.ends_with(".go")
    });
    push(
        Signal::TypeCheck,
        types,
        has(
            &ci,
            &[
                "tsc",
                "mypy",
                "pyright",
                "cargo build",
                "cargo check",
                "go build",
                "go vet",
                "type-check",
                "typecheck",
            ],
        ),
    );

    // ---- fuzz / property / invariants ---------------------------------
    let fuzz = repo.any_path(|f| {
        f.contains("fuzz")
            || f.contains("atheris")
            || f.contains("libfuzzer")
            || f.contains("echidna")
            || f.contains("medusa")
    });
    push(
        Signal::Fuzzing,
        fuzz,
        has(
            &ci,
            &[
                "cargo fuzz",
                "cargo-fuzz",
                "go test -fuzz",
                "atheris",
                "echidna",
                "medusa",
                "forge test --fuzz",
                "truent fuzz",
                "jazzer",
                "oss-fuzz",
                "fuzz",
            ],
        ) || has(&manifests, &["fuzz_runs", "[fuzz]"]),
    );

    let prop = repo.any_path(|f| {
        f.contains("proptest")
            || f.contains("hypothesis")
            || f.contains("fast-check")
            || f.contains("quickcheck")
            || f.contains("property")
    });
    let prop = if prop.is_empty()
        && has(
            &manifests,
            &["proptest", "hypothesis", "fast-check", "quickcheck"],
        ) {
        vec!["property-testing library in the manifest".into()]
    } else {
        prop
    };
    push(
        Signal::PropertyTests,
        prop.clone(),
        has(
            &ci,
            &[
                "proptest",
                "hypothesis",
                "fast-check",
                "quickcheck",
                "property",
            ],
        ) || (!prop.is_empty() && suite_runner_wired),
    );

    let inv = repo.any_path(|f| {
        f.ends_with(".sinv") || f.contains("invariant") || f.contains(".truent.toml")
    });
    push(
        Signal::Invariants,
        inv,
        has(
            &ci,
            &[
                "truent scan",
                "truent check",
                "forge test --match-contract invariant",
                "invariant",
                "echidna",
                "medusa",
                "certora",
                "halmos",
            ],
        ) || has(&manifests, &["[invariant]"]),
    );

    // ---- load / chaos / perf / differential / mutation ----------------
    let load = repo.any_path(|f| {
        f.contains("k6")
            || f.contains("locust")
            || f.contains("artillery")
            || f.contains("gatling")
            || f.contains("jmeter")
            || f.contains("vegeta")
            || f.contains("wrk")
            || f.contains("loadtest")
            || f.contains("load-test")
            || f.contains("load_test")
            || f.contains("stress")
    });
    push(
        Signal::LoadTests,
        load,
        has(
            &ci,
            &[
                "k6 run",
                "locust",
                "artillery",
                "gatling",
                "jmeter",
                "vegeta",
                "wrk ",
                "loadtest",
                "load-test",
                "load_test",
                "stress",
            ],
        ),
    );

    let chaos = repo.any_path(|f| {
        f.contains("chaos")
            || f.contains("litmus")
            || f.contains("gremlin")
            || f.contains("toxiproxy")
            || f.contains("fault-inject")
            || f.contains("fault_inject")
            || f.contains("resilience")
    });
    push(
        Signal::ChaosTests,
        chaos,
        has(
            &ci,
            &[
                "chaos",
                "litmus",
                "gremlin",
                "toxiproxy",
                "fault-inject",
                "fault_inject",
                "pumba",
                "chaoskube",
            ],
        ),
    );

    let bench = repo.any_path(|f| {
        f.contains("/benches/")
            || f.starts_with("benches/")
            || f.contains("benchmark")
            || f.contains("bench_")
            || f.contains(".bench.")
            || f.contains("criterion")
            || f.contains("gas-snapshot")
            || f.contains(".gas-snapshot")
    });
    push(
        Signal::Benchmarks,
        bench,
        has(
            &ci,
            &[
                "cargo bench",
                "criterion",
                "benchmark",
                "go test -bench",
                "forge snapshot",
                "gas report",
                "lighthouse",
                "hyperfine",
                "bench",
            ],
        ),
    );

    let snap = repo.any_path(|f| {
        f.contains("__snapshots__")
            || f.contains(".snap")
            || f.contains("golden")
            || f.contains("differential")
            || f.contains("approval")
            || f.contains("fixtures/expected")
            || f.contains("insta")
    });
    push(
        Signal::SnapshotOrDifferentialTests,
        snap.clone(),
        has(&ci, &["snapshot", "differential", "golden", "insta"])
            || (!snap.is_empty() && suite_runner_wired),
    );

    let mutation = repo.any_path(|f| {
        f.contains("stryker")
            || f.contains("mutmut")
            || f.contains("cargo-mutants")
            || f.contains("mutants")
            || f.contains("gambit")
            || f.contains("vertigo")
            || f.contains("pitest")
            || f.contains("cosmic-ray")
            || f.contains(".mutation")
    });
    let mutation_wired = has(
        &ci,
        &[
            "stryker",
            "mutmut",
            "cargo mutants",
            "cargo-mutants",
            "gambit",
            "vertigo",
            "pitest",
            "cosmic-ray",
            "mutation",
        ],
    );
    // The mutation configuration may live entirely in the CI job.
    let mutation = if mutation.is_empty() && mutation_wired {
        vec!["mutation job in CI".into()]
    } else {
        mutation
    };
    push(Signal::MutationTesting, mutation, mutation_wired);

    // ---- migrations / backup / DR / IR / alerting ---------------------
    let migrations = repo.any_path(|f| {
        f.contains("/migrations/")
            || f.starts_with("migrations/")
            || f.contains("/migrate/")
            || f.contains("alembic")
            || f.contains("flyway")
            || f.contains("liquibase")
            || f.contains("prisma/migrations")
            || f.contains("knexfile")
            || f.contains("goose")
            || f.contains("atlas.hcl")
            || f.contains("sqlx/migrations")
            || f.contains("diesel.toml")
    });
    push(
        Signal::Migrations,
        migrations.clone(),
        has(
            &ci,
            &[
                "migrate",
                "alembic",
                "flyway",
                "liquibase",
                "prisma migrate",
                "knex migrate",
                "goose",
                "sqlx migrate",
                "diesel migration",
                "manage.py migrate",
                "atlas migrate",
            ],
        ),
    );

    let rollback = repo.any_path(|f| {
        (f.contains("/migrations/") || f.contains("/migrate/") || f.contains("alembic"))
            && (f.contains("down")
                || f.contains("rollback")
                || f.contains("revert")
                || f.contains("undo"))
    });
    let rollback_text = repo.texts.iter().any(|(p, t)| {
        (p.contains("migrat") || p.contains("alembic"))
            && has(
                t,
                &[
                    "def downgrade",
                    "exports.down",
                    "async function down",
                    "-- +goose Down",
                    "-- migrate:down",
                    "rollback",
                ],
            )
    });
    let rollback_present = if !rollback.is_empty() {
        rollback
    } else if rollback_text {
        vec!["migration files define down/rollback".into()]
    } else if !migrations.is_empty()
        && has(
            &manifests,
            &["alembic", "flyway", "prisma", "diesel", "sqlx"],
        )
    {
        vec!["migration tool with rollback support".into()]
    } else {
        vec![]
    };
    push(
        Signal::MigrationRollback,
        rollback_present,
        has(
            &ci,
            &[
                "migrate:rollback",
                "migrate down",
                "alembic downgrade",
                "rollback",
                "revert",
                "down",
            ],
        ),
    );

    let backup = repo.any_path(|f| {
        f.contains("backup")
            || f.contains("snapshot-policy")
            || f.contains("velero")
            || f.contains("pg_dump")
            || f.contains("restic")
            || f.contains("borg")
            || f.contains("aws_backup")
            || f.contains("backup_plan")
            || f.contains("wal-g")
            || f.contains("pgbackrest")
    });
    let backup_text = repo.texts.iter().any(|(_, t)| {
        has(
            t,
            &[
                "aws_backup_plan",
                "backup_retention_period",
                "google_sql_database_instance",
                "velero",
                "pg_dump",
                "wal-g",
                "pgbackrest",
                "restic",
                "snapshot",
            ],
        )
    });
    push(
        Signal::BackupConfig,
        if !backup.is_empty() {
            backup
        } else if backup_text {
            vec!["backup/snapshot policy in IaC".into()]
        } else {
            vec![]
        },
        has(&ci, &["backup", "pg_dump", "restic", "velero", "restore"]),
    );

    let dr = repo.any_path(|f| {
        f.contains("disaster")
            || f.contains("dr-plan")
            || f.contains("dr_plan")
            || f.contains("recovery")
            || f.contains("runbook")
            || f.contains("rto")
            || f.contains("rpo")
            || f.contains("failover")
            || f.contains("business-continuity")
            || f.contains("bcp")
    });
    push(
        Signal::DrRunbook,
        dr,
        has(
            &ci,
            &[
                "restore",
                "failover",
                "disaster",
                "dr-drill",
                "dr_drill",
                "recovery-test",
                "recovery_test",
            ],
        ),
    );

    let ir = repo.any_path(|f| {
        f.contains("incident")
            || f.contains("playbook")
            || f.contains("runbook")
            || f.contains("on-call")
            || f.contains("oncall")
            || f.contains("postmortem")
            || f.contains("post-mortem")
    });
    push(Signal::IncidentRunbook, ir, false);

    let alerts = repo.any_path(|f| {
        f.contains("alert")
            || f.contains("prometheus")
            || f.contains("grafana")
            || f.contains("datadog")
            || f.contains("sentry")
            || f.contains("sigma")
            || f.contains("detection")
            || f.contains("falco")
            || f.contains("monitors/")
            || f.contains("pagerduty")
            || f.contains("opsgenie")
    });
    push(
        Signal::AlertingConfig,
        alerts,
        has(
            &ci,
            &[
                "alert",
                "prometheus",
                "promtool",
                "sigma",
                "falco",
                "datadog",
                "monitor",
            ],
        ),
    );

    // ---- supply chain / policy ----------------------------------------
    let sbom = repo.any_path(|f| {
        f.contains("sbom")
            || f.ends_with(".cdx.json")
            || f.ends_with(".spdx.json")
            || f.contains("bom.json")
    });
    let sbom_wired = has(
        &ci,
        &[
            "sbom",
            "cyclonedx",
            "syft",
            "spdx",
            "--sbom",
            "cargo sbom",
            "cargo cyclonedx",
        ],
    );
    let sbom = if sbom.is_empty() && sbom_wired {
        vec!["SBOM generated in CI".into()]
    } else {
        sbom
    };
    push(Signal::Sbom, sbom, sbom_wired);

    let signing = repo.any_path(|f| {
        f.contains("cosign")
            || f.contains(".sigstore")
            || f.contains("goreleaser")
            || f.contains("slsa")
            || f.contains("gpg")
    });
    let signing_wired = has(
        &ci,
        &[
            "cosign",
            "sigstore",
            "--provenance",
            "provenance: true",
            "gh attest",
            "attest-build-provenance",
            "slsa-github-generator",
            "gpg --detach-sign",
            "sign:",
        ],
    );
    let signing = if signing.is_empty() && signing_wired {
        vec!["signing / attestation in the release workflow".into()]
    } else {
        signing
    };
    push(Signal::ReleaseSigning, signing, signing_wired);

    let sec = repo.any_path(|f| {
        f == "security.md" || f.ends_with("/security.md") || f == ".github/security.md"
    });
    push(Signal::SecurityPolicy, sec, false);

    let owners = repo.any_path(|f| f == "codeowners" || f.ends_with("/codeowners"));
    push(Signal::Codeowners, owners, false);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn get(res: &[SignalResult], s: Signal) -> &SignalResult {
        res.iter().find(|r| r.signal == s).unwrap()
    }

    #[test]
    fn present_and_wired_are_independent() {
        let fs = files(&[
            "src/lib.rs",
            "tests/api.rs",
            "load/k6.js",
            ".github/workflows/ci.yml",
        ]);
        let texts = vec![(
            ".github/workflows/ci.yml".to_string(),
            "run: cargo test --workspace\n".to_string(),
        )];
        let r = evaluate(&RepoView {
            files: &fs,
            texts: &texts,
        });
        let unit = get(&r, Signal::UnitTests);
        assert!(unit.present && unit.wired);
        let load = get(&r, Signal::LoadTests);
        assert!(
            load.present && !load.wired,
            "k6 script exists but CI never runs it"
        );
        assert!(!get(&r, Signal::ChaosTests).present);
    }

    #[test]
    fn every_signal_is_evaluated_once() {
        let fs = files(&["README.md"]);
        let r = evaluate(&RepoView {
            files: &fs,
            texts: &[],
        });
        assert_eq!(r.len(), Signal::all().len());
        let mut seen = std::collections::BTreeSet::new();
        for x in &r {
            assert!(seen.insert(x.signal), "{:?} evaluated twice", x.signal);
        }
    }

    #[test]
    fn rollback_detected_from_migration_contents() {
        let fs = files(&["migrations/001_init.js"]);
        let texts = vec![(
            "migrations/001_init.js".to_string(),
            "exports.up = …; exports.down = …".to_string(),
        )];
        let r = evaluate(&RepoView {
            files: &fs,
            texts: &texts,
        });
        assert!(get(&r, Signal::Migrations).present);
        assert!(get(&r, Signal::MigrationRollback).present);
    }

    #[test]
    fn signing_and_sbom_from_ci() {
        let fs = files(&[".github/workflows/release.yml"]);
        let texts = vec![(
            ".github/workflows/release.yml".to_string(),
            "run: npm publish --provenance\nrun: truent deps . --sbom sbom.cdx.json\n".to_string(),
        )];
        let r = evaluate(&RepoView {
            files: &fs,
            texts: &texts,
        });
        assert!(get(&r, Signal::ReleaseSigning).wired);
        assert!(get(&r, Signal::Sbom).wired);
    }
}
