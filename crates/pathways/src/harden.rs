//! Preventive measures: the controls that stop whole classes of findings
//! from being introduced, generated for the repository at hand.
//!
//! Detection tells you what is wrong now. Prevention is a small set of files
//! that make the wrong thing hard to commit, hard to build and hard to
//! deploy: a `.gitignore` that keeps secrets out, Dependabot so pinned
//! actions and images stay current, a pre-commit hook that runs the scanner,
//! a CI gate, and the security-header configuration for whichever web
//! framework the repository uses.
//!
//! [`plan`] is pure: it takes the repository's file list (and a few file
//! contents) and returns [`Artifact`]s — path, content, and *why*, with each
//! artifact naming the detectors it prevents. Nothing is written here; the
//! CLI prints or writes, and never overwrites an existing file (`.gitignore`
//! is appended to, missing lines only).

use serde::Serialize;

/// One preventive file.
#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    /// Repository-relative path.
    pub path: String,
    pub content: String,
    /// Why this file, in one sentence.
    pub reason: String,
    /// Detector IDs whose findings this prevents.
    pub prevents: Vec<&'static str>,
    /// `.gitignore` semantics: lines are merged into an existing file.
    pub append: bool,
}

/// What the generator learned about the repository.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Profile {
    pub github_actions: bool,
    pub dockerfile: bool,
    pub cargo: bool,
    pub npm: bool,
    pub pip: bool,
    pub go: bool,
    pub express: bool,
    pub nextjs: bool,
    pub django: bool,
    pub flask: bool,
    pub solidity: bool,
    pub has_gitignore: bool,
    pub has_dependabot: bool,
    pub has_precommit: bool,
    pub has_security_md: bool,
    pub has_load_tests: bool,
    pub has_chaos: bool,
    pub has_dr_runbook: bool,
    pub has_mutation: bool,
    pub has_benchmarks: bool,
    pub has_snapshot_tests: bool,
    pub has_alerting: bool,
    pub has_codeowners: bool,
}

/// Inspect the repository. `files` are repository-relative paths; `read`
/// returns a file's content when the profiler needs to look inside (only
/// `package.json`, `requirements.txt`, `pyproject.toml` are read).
pub fn profile(files: &[String], read: &dyn Fn(&str) -> Option<String>) -> Profile {
    let mut p = Profile::default();
    let has = |name: &str| {
        files
            .iter()
            .any(|f| f == name || f.ends_with(&format!("/{name}")))
    };
    p.github_actions = files.iter().any(|f| f.starts_with(".github/workflows/"));
    p.dockerfile = files.iter().any(|f| {
        let n = f.rsplit('/').next().unwrap_or(f);
        n == "Dockerfile" || n.starts_with("Dockerfile.")
    });
    p.cargo = has("Cargo.toml");
    p.npm = has("package.json");
    p.pip = has("requirements.txt") || has("pyproject.toml") || has("Pipfile");
    p.go = has("go.mod");
    p.solidity = files.iter().any(|f| f.ends_with(".sol"));
    p.has_gitignore = files.iter().any(|f| f == ".gitignore");
    p.has_dependabot = files.iter().any(|f| f == ".github/dependabot.yml");
    p.has_precommit = files.iter().any(|f| f == ".pre-commit-config.yaml");
    p.has_security_md = files.iter().any(|f| f.eq_ignore_ascii_case("SECURITY.md"));
    let lower: Vec<String> = files.iter().map(|f| f.to_ascii_lowercase()).collect();
    let anyc = |needles: &[&str]| lower.iter().any(|f| needles.iter().any(|n| f.contains(n)));
    p.has_load_tests = anyc(&[
        "k6",
        "locust",
        "artillery",
        "gatling",
        "jmeter",
        "vegeta",
        "loadtest",
        "load-test",
        "load_test",
    ]);
    p.has_chaos = anyc(&[
        "chaos",
        "litmus",
        "toxiproxy",
        "fault-inject",
        "fault_inject",
    ]);
    p.has_dr_runbook = anyc(&[
        "disaster", "dr-plan", "dr_plan", "recovery", "runbook", "failover",
    ]);
    p.has_mutation = anyc(&[
        "stryker",
        "mutmut",
        "cargo-mutants",
        "mutants",
        "gambit",
        "vertigo",
        "pitest",
    ]);
    p.has_benchmarks = anyc(&[
        "/benches/",
        "benchmark",
        "criterion",
        ".bench.",
        "gas-snapshot",
    ]) || lower.iter().any(|f| f.starts_with("benches/"));
    p.has_snapshot_tests = anyc(&["__snapshots__", ".snap", "golden", "differential", "insta"]);
    p.has_alerting = anyc(&[
        "alert",
        "prometheus",
        "grafana",
        "sigma",
        "falco",
        "datadog",
        "monitors/",
    ]);
    p.has_codeowners = lower
        .iter()
        .any(|f| f == "codeowners" || f.ends_with("/codeowners"));

    for f in files
        .iter()
        .filter(|f| f.ends_with("package.json") && !f.contains("node_modules"))
    {
        if let Some(c) = read(f) {
            p.express |= c.contains("\"express\"");
            p.nextjs |= c.contains("\"next\"");
        }
    }
    for f in files.iter().filter(|f| {
        f.ends_with("requirements.txt") || f.ends_with("pyproject.toml") || f.ends_with("Pipfile")
    }) {
        if let Some(c) = read(f) {
            let l = c.to_ascii_lowercase();
            p.django |= l.contains("django");
            p.flask |= l.contains("flask");
        }
    }
    p.django |= files.iter().any(|f| f.ends_with("manage.py"));
    p
}

/// The preventive files for a profile.
pub fn plan(p: &Profile) -> Vec<Artifact> {
    let mut out = Vec::new();

    // Secrets never enter the repository.
    out.push(Artifact {
        path: ".gitignore".into(),
        content: GITIGNORE.into(),
        reason: "Keeps credentials, keys and local environment files out of commits".into(),
        prevents: vec!["gen_hardcoded_secret", "gen_private_key_committed"],
        append: true,
    });

    // Pinned things stay current.
    if !p.has_dependabot && (p.github_actions || p.dockerfile || p.cargo || p.npm || p.pip || p.go)
    {
        let mut updates = String::new();
        if p.github_actions {
            updates.push_str(DEPENDABOT_ACTIONS);
        }
        if p.dockerfile {
            updates.push_str(DEPENDABOT_DOCKER);
        }
        if p.cargo {
            updates.push_str(&dependabot_eco("cargo"));
        }
        if p.npm {
            updates.push_str(&dependabot_eco("npm"));
        }
        if p.pip {
            updates.push_str(&dependabot_eco("pip"));
        }
        if p.go {
            updates.push_str(&dependabot_eco("gomod"));
        }
        out.push(Artifact {
            path: ".github/dependabot.yml".into(),
            content: format!("version: 2\nupdates:\n{updates}"),
            reason: "Pinned actions, images and dependencies are updated by PR instead of drifting or being left vulnerable".into(),
            prevents: vec![
                "gen_ci_unpinned_action",
                "gen_docker_unpinned_base",
                "sca_vulnerable_dependency",
                "sca_unmaintained_dependency",
            ],
            append: false,
        });
    }

    // The scanner runs before a commit exists.
    if !p.has_precommit {
        out.push(Artifact {
            path: ".pre-commit-config.yaml".into(),
            content: PRECOMMIT.into(),
            reason: "Secrets, injection sinks and misconfiguration are caught on the developer's machine, before they are pushed".into(),
            prevents: vec![
                "gen_hardcoded_secret",
                "gen_private_key_committed",
                "gen_sql_injection",
                "gen_command_injection",
                "gen_web_debug_enabled",
            ],
            append: false,
        });
    }

    // The scanner gates every PR.
    if p.github_actions {
        out.push(Artifact {
            path: ".github/workflows/truent-gate.yml".into(),
            content: GATE_WORKFLOW.into(),
            reason: "Every pull request is scanned with least-privilege permissions and results land in code scanning".into(),
            prevents: vec![
                "gen_ci_pwn_request",
                "gen_ci_script_injection",
                "gen_ci_secret_exposed",
                "sca_vulnerable_dependency",
            ],
            append: false,
        });
    }

    // Security headers for the framework in use.
    if p.express {
        out.push(Artifact {
            path: "security/headers.express.js".into(),
            content: EXPRESS_HEADERS.into(),
            reason: "helmet-based middleware sets HSTS, CSP, frame, content-type and cookie defaults for Express".into(),
            prevents: vec![
                "rt_missing_hsts",
                "rt_missing_csp",
                "rt_missing_frame_options",
                "rt_missing_content_type_options",
                "rt_insecure_cookie",
                "rt_server_banner",
                "gen_web_cors_wildcard",
            ],
            append: false,
        });
    }
    if p.nextjs {
        out.push(Artifact {
            path: "security/headers.next.js".into(),
            content: NEXT_HEADERS.into(),
            reason: "`headers()` block for next.config.js setting HSTS, CSP, frame and content-type options".into(),
            prevents: vec![
                "rt_missing_hsts",
                "rt_missing_csp",
                "rt_missing_frame_options",
                "rt_missing_content_type_options",
            ],
            append: false,
        });
    }
    if p.django {
        out.push(Artifact {
            path: "security/settings_security.py".into(),
            content: DJANGO_SETTINGS.into(),
            reason: "Production security settings for Django: HTTPS redirect, HSTS, secure cookies, debug off, CSRF on".into(),
            prevents: vec![
                "gen_web_debug_enabled",
                "gen_web_insecure_cookie",
                "gen_web_csrf_disabled",
                "rt_missing_hsts",
                "rt_no_https_redirect",
                "rt_missing_frame_options",
                "rt_missing_content_type_options",
            ],
            append: false,
        });
    }
    if p.flask {
        out.push(Artifact {
            path: "security/flask_security.py".into(),
            content: FLASK_SECURITY.into(),
            reason: "Talisman configuration for Flask: HTTPS, HSTS, CSP, secure session cookies"
                .into(),
            prevents: vec![
                "gen_web_debug_enabled",
                "gen_web_insecure_cookie",
                "rt_missing_hsts",
                "rt_missing_csp",
                "rt_insecure_cookie",
            ],
            append: false,
        });
    }
    if p.dockerfile {
        out.push(Artifact {
            path: "security/Dockerfile.hardened.example".into(),
            content: DOCKERFILE.into(),
            reason: "A digest-pinned, non-root, read-only-friendly Dockerfile shape to copy from"
                .into(),
            prevents: vec!["gen_docker_root_user", "gen_docker_unpinned_base"],
            append: false,
        });
    }
    if p.solidity {
        out.push(Artifact {
            path: "security/invariants.example.sinv".into(),
            content: SINV.into(),
            reason:
                "Protocol invariants enforced by `truent scan` and `truent fuzz` on every change"
                    .into(),
            prevents: vec![
                "evm_conservation_check_absent",
                "evm_missing_post_state_health_check",
                "evm_unbacked_synthetic_mint",
            ],
            append: false,
        });
    }
    // Harnesses for the tests only the owning team can run: generated so
    // "MISSING" in `truent release-check` has a concrete next step.
    if !p.has_load_tests && (p.express || p.nextjs || p.django || p.flask || p.go || p.npm || p.pip)
    {
        out.push(Artifact {
            path: "tests/load/k6-smoke.js".into(),
            content: K6_LOAD.into(),
            reason: "A k6 load test with thresholds (p95 latency, error rate) that fails CI when the service degrades under load".into(),
            prevents: vec!["gen_missing_rate_limit", "gen_unbounded_query_limit"],
            append: false,
        });
    }
    if !p.has_chaos && (p.dockerfile || p.go || p.npm || p.pip) {
        out.push(Artifact {
            path: "tests/chaos/toxiproxy-experiments.md".into(),
            content: CHAOS.into(),
            reason: "Failure experiments (dependency down, latency, partition) with the expected graceful behaviour written down before running them".into(),
            prevents: vec![],
            append: false,
        });
    }
    if !p.has_dr_runbook {
        out.push(Artifact {
            path: "docs/runbooks/disaster-recovery.md".into(),
            content: DR_RUNBOOK.into(),
            reason: "A disaster-recovery runbook with RTO/RPO targets and a restore drill that is exercised on a schedule".into(),
            prevents: vec![],
            append: false,
        });
    }
    if !p.has_mutation && (p.cargo || p.npm || p.pip || p.solidity) {
        let (path, content) = if p.cargo {
            ("security/mutation.md", MUTATION_CARGO)
        } else if p.npm {
            ("stryker.config.json", MUTATION_STRYKER)
        } else if p.pip {
            ("setup.cfg.mutmut", MUTATION_MUTMUT)
        } else {
            ("security/mutation.md", MUTATION_GAMBIT)
        };
        out.push(Artifact {
            path: path.into(),
            content: content.into(),
            reason: "Mutation testing configuration: injects operator/condition/authorization mutations and fails when the test suite does not catch them".into(),
            prevents: vec![],
            append: false,
        });
    }
    if !p.has_benchmarks && (p.cargo || p.go || p.solidity) {
        let (path, content) = if p.cargo {
            ("benches/README.md", BENCH_CARGO)
        } else if p.go {
            ("benchmark_test.go.example", BENCH_GO)
        } else {
            ("security/gas-snapshot.md", BENCH_GAS)
        };
        out.push(Artifact {
            path: path.into(),
            content: content.into(),
            reason: "Performance / gas regression benchmarks compared against a committed baseline in CI".into(),
            prevents: vec!["evm_unbounded_loop"],
            append: false,
        });
    }
    if !p.has_snapshot_tests && (p.npm || p.cargo || p.pip) {
        out.push(Artifact {
            path: "tests/differential/README.md".into(),
            content: DIFFERENTIAL.into(),
            reason: "Snapshot / differential tests: identical inputs through the old and new implementation must produce identical outputs".into(),
            prevents: vec![],
            append: false,
        });
    }
    if !p.has_alerting {
        out.push(Artifact {
            path: "security/alerts/auth-anomalies.sigma.yml".into(),
            content: SIGMA_RULE.into(),
            reason: "A Sigma detection rule for authentication anomalies so security-event logs turn into alerts".into(),
            prevents: vec!["gen_missing_security_logging"],
            append: false,
        });
    }
    if !p.has_codeowners && p.github_actions {
        out.push(Artifact {
            path: ".github/CODEOWNERS".into(),
            content: CODEOWNERS.into(),
            reason: "Security-sensitive paths require review from a named owner before merge"
                .into(),
            prevents: vec!["gen_ci_pwn_request", "gen_ci_script_injection"],
            append: false,
        });
    }
    if !p.has_security_md {
        out.push(Artifact {
            path: "SECURITY.md".into(),
            content: SECURITY_MD.into(),
            reason: "A disclosure channel so a researcher who finds the next issue tells you first"
                .into(),
            prevents: vec![],
            append: false,
        });
    }
    out
}

/// Lines of `wanted` absent from `existing` (a `.gitignore` merge).
pub fn missing_lines(existing: &str, wanted: &str) -> Vec<String> {
    let have: std::collections::BTreeSet<&str> = existing.lines().map(str::trim).collect();
    wanted
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !have.contains(t)
        })
        .map(str::to_string)
        .collect()
}

fn dependabot_eco(eco: &str) -> String {
    format!(
        "  - package-ecosystem: \"{eco}\"\n    directory: \"/\"\n    schedule:\n      interval: \"weekly\"\n    open-pull-requests-limit: 10\n"
    )
}

const GITIGNORE: &str =
    "# --- truent harden: secrets and local environment never enter the repository ---
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
*.jks
id_rsa
id_ed25519
*.keystore
credentials.json
service-account*.json
.aws/
.netrc
*.secret
secrets.yml
secrets.yaml
";

const DEPENDABOT_ACTIONS: &str = "  - package-ecosystem: \"github-actions\"
    directory: \"/\"
    schedule:
      interval: \"weekly\"
";

const DEPENDABOT_DOCKER: &str = "  - package-ecosystem: \"docker\"
    directory: \"/\"
    schedule:
      interval: \"weekly\"
";

const PRECOMMIT: &str = "# truent harden: run the scanner before a commit exists.
repos:
  - repo: local
    hooks:
      - id: truent-scan
        name: truent scan (secrets, injection, misconfiguration)
        entry: truent scan --chain auto --fail-on high
        language: system
        pass_filenames: false
      - id: truent-deps
        name: truent deps (lockfile and pinning)
        entry: truent deps --fail-on high
        language: system
        pass_filenames: false
";

const GATE_WORKFLOW: &str = "# truent harden: scan every pull request with least privilege.
name: truent gate
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      # Pin to a commit SHA; Dependabot keeps it current.
      - uses: actions/checkout@34e114876b0b11c390a56d3ba0d9c9e5b3d6e8f4 # v4
      - name: Install truent
        run: cargo install truent-cli --locked
      - name: Scan
        run: truent scan . --chain auto --sarif truent.sarif --fail-on high
      - name: Dependencies
        run: truent deps . --fail-on high
      - name: Upload to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@f09c1c0a94de965c15400f5634aa42fac8fb8f88 # v3
        with:
          sarif_file: truent.sarif
";

const EXPRESS_HEADERS: &str = "// truent harden: security headers and cookie defaults for Express.
// npm install helmet
const helmet = require('helmet');

module.exports = function secure(app) {
  app.disable('x-powered-by');
  app.use(helmet({
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: [\"'self'\"],
        scriptSrc: [\"'self'\"],
        objectSrc: [\"'none'\"],
        frameAncestors: [\"'none'\"],
        upgradeInsecureRequests: [],
      },
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }));
  // Session cookies: Secure, HttpOnly, SameSite. Apply to express-session:
  //   cookie: { secure: true, httpOnly: true, sameSite: 'lax' }
  // CORS: an explicit allowlist, never '*' with credentials.
  //   app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
};
";

const NEXT_HEADERS: &str = "// truent harden: add to next.config.js
//   const { securityHeaders } = require('./security/headers.next.js');
//   module.exports = { async headers() { return [{ source: '/(.*)', headers: securityHeaders }]; } };
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'Content-Security-Policy', value: \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests\" },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
];
module.exports = { securityHeaders };
";

const DJANGO_SETTINGS: &str = "# truent harden: production security settings for Django.
# from .settings_security import *   (after the base settings)
import os

DEBUG = False
SECRET_KEY = os.environ[\"DJANGO_SECRET_KEY\"]          # never in the repository
ALLOWED_HOSTS = os.environ.get(\"ALLOWED_HOSTS\", \"\").split(\",\")

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 63072000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = \"strict-origin-when-cross-origin\"
X_FRAME_OPTIONS = \"DENY\"

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = \"Lax\"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = \"Lax\"
# Keep django.middleware.csrf.CsrfViewMiddleware in MIDDLEWARE; do not use @csrf_exempt on state-changing views.
";

const FLASK_SECURITY: &str = "# truent harden: Flask security configuration.
# pip install flask-talisman
import os
from flask_talisman import Talisman


def secure(app):
    app.config.update(
        DEBUG=False,
        SECRET_KEY=os.environ[\"FLASK_SECRET_KEY\"],  # never in the repository
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=\"Lax\",
    )
    Talisman(
        app,
        force_https=True,
        strict_transport_security=True,
        strict_transport_security_max_age=63072000,
        content_security_policy={\"default-src\": \"'self'\", \"object-src\": \"'none'\", \"frame-ancestors\": \"'none'\"},
        frame_options=\"DENY\",
    )
";

const DOCKERFILE: &str = "# truent harden: the shape of a hardened image.
# 1. Pin the base by digest (Dependabot updates it).
FROM python:3.12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS base
# 2. Install as root, then drop privileges.
RUN groupadd -r app && useradd -r -g app -d /app -s /usr/sbin/nologin app
WORKDIR /app
COPY --chown=app:app . .
RUN pip install --no-cache-dir -r requirements.txt
# 3. Run as the unprivileged user; keep the root filesystem read-only at runtime:
#    docker run --read-only --tmpfs /tmp --cap-drop ALL image
USER app
EXPOSE 8000
CMD [\"gunicorn\", \"-b\", \"0.0.0.0:8000\", \"app:app\"]
";

const SINV: &str = "// truent harden: protocol invariants checked on every change.
// truent scan --invariants security/invariants.sinv
invariant conservation {
  description: \"Total supply never exceeds backing\"
  totalSupply() <= totalBacking()
}
invariant solvency {
  description: \"Every position stays above its liquidation threshold after any call\"
  forall p in positions: collateralValue(p) >= debtValue(p) * liquidationThreshold
}
";

const K6_LOAD: &str = "// truent harden: k6 load test with thresholds that fail CI.
//   k6 run tests/load/k6-smoke.js  (BASE_URL=https://staging.example.com)
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  scenarios: {
    smoke:  { executor: 'constant-vus', vus: 5, duration: '1m' },
    spike:  { executor: 'ramping-vus', startVUs: 0, stages: [{ duration: '30s', target: 200 }, { duration: '30s', target: 0 }], startTime: '1m' },
    soak:   { executor: 'constant-vus', vus: 20, duration: '10m', startTime: '2m' },
  },
  thresholds: {
    http_req_failed:   ['rate<0.01'],           // <1% errors
    http_req_duration: ['p(95)<500', 'p(99)<1500'],
  },
};

export default function () {
  const base = __ENV.BASE_URL || 'http://localhost:8080';
  const r = http.get(`${base}/health`);
  check(r, { 'status 200': (x) => x.status === 200 });
  // Exercise the login route: a rate limiter should start returning 429.
  const l = http.post(`${base}/login`, JSON.stringify({ user: 'load', password: 'x' }), { headers: { 'Content-Type': 'application/json' } });
  check(l, { 'login is rate limited or rejected': (x) => x.status === 401 || x.status === 429 });
  sleep(1);
}
";

const CHAOS: &str = "# Chaos & failure experiments (truent harden)

Run each experiment against staging with Toxiproxy (or your mesh's fault
injection) and record the observed behaviour next to the expected one. An
experiment without a written expectation is not a test.

| # | Fault | Inject with | Expected behaviour | Observed |
|---|---|---|---|---|
| 1 | Database down | `toxiproxy-cli toggle db` | Requests fail fast with 503; no partial writes; recovers within 30s of restore | |
| 2 | Database +2s latency | `toxiproxy-cli toxic add -t latency -a latency=2000 db` | p99 rises, timeouts fire at the configured budget, circuit breaker opens | |
| 3 | Cache down | `toxiproxy-cli toggle redis` | Service degrades to the database; no errors to users | |
| 4 | Upstream API 500s | mock returns 500 | Retries with backoff, then degrade; no retry storm | |
| 5 | Message queue unreachable | `toxiproxy-cli toggle mq` | Producers buffer or fail closed; consumers resume without duplicate side effects | |
| 6 | RPC node unreachable (chain apps) | block RPC egress | Fallback node used or operations pause; no stale-price decisions | |
| 7 | Process restart under load | `kill -9` during k6 run | In-flight transactions roll back; no double credit | |
| 8 | Network partition between services | iptables DROP | Timeouts, not hangs; health checks reflect reality | |

Automate the ones that pass in CI (`tests/chaos/`), so a regression fails the build.
";

const DR_RUNBOOK: &str = "# Disaster-recovery runbook (truent harden)

**RTO target:** ___ minutes   **RPO target:** ___ minutes   **Last drill:** ____-__-__   **Drill result:** ___

## Backups
- What is backed up (databases, object storage, secrets, keys, IaC state): …
- Schedule and retention: …
- Where (separate account/region, immutable/locked): …
- Encryption and who holds the key: …

## Restore procedure (rehearsed, step by step)
1. Declare the incident; freeze writes.
2. Provision infrastructure from IaC: `…`
3. Restore the latest consistent snapshot: `…`
4. Restore secrets and rotate anything that may have been exposed.
5. Verify integrity: row counts, balance reconciliation, checksum of critical tables.
6. Re-point DNS / traffic; monitor error rate and latency for 30 minutes.

## Drill
Quarterly: restore into an isolated environment from the latest backup and
run the integration suite against it. Record time-to-restore (RTO) and
data-loss window (RPO) here. A backup that has never been restored is not a
backup.

## Key recovery
Signing / encryption keys: where the recovery shares live, who holds them,
and the threshold to reconstruct.
";

const MUTATION_CARGO: &str = "# Mutation testing (truent harden)

    cargo install cargo-mutants
    cargo mutants --in-place -j 4 -- --all-features

Add to CI as a nightly job; fail when the caught rate drops below the
threshold your team sets (start at 60%, raise it). Mutants that survive in
authorization checks, arithmetic and boundary conditions are the ones to
chase first — a surviving `>=`→`>` mutant in a balance check is a bug your
tests would not catch.
";
const MUTATION_STRYKER: &str = "{
  \"$schema\": \"./node_modules/@stryker-mutator/core/schema/stryker-schema.json\",
  \"_comment\": \"truent harden: npx stryker run — fails CI below the break threshold\",
  \"mutate\": [\"src/**/*.{js,ts}\", \"!src/**/*.test.{js,ts}\"],
  \"testRunner\": \"jest\",
  \"reporters\": [\"progress\", \"clear-text\", \"html\"],
  \"thresholds\": { \"high\": 80, \"low\": 60, \"break\": 50 },
  \"coverageAnalysis\": \"perTest\"
}
";
const MUTATION_MUTMUT: &str =
    "# truent harden: append to setup.cfg and run `mutmut run` (nightly in CI)
[mutmut]
paths_to_mutate=src/
tests_dir=tests/
runner=python -m pytest -x -q
";
const MUTATION_GAMBIT: &str = "# Mutation testing for Solidity (truent harden)

    # Gambit (Certora) generates mutants; run your test suite against each.
    gambit mutate --json gambit.conf.json
    for m in gambit_out/mutants/*; do forge test --root $m || echo \"killed\"; done

Track the killed rate; a surviving mutant in an access-control modifier or
an arithmetic bound is a test you are missing.
";
const BENCH_CARGO: &str = "# Benchmarks (truent harden)

    cargo install cargo-criterion
    cargo criterion --message-format=json > target/criterion.json

Commit a baseline (`criterion --save-baseline main`) and compare in CI
(`--baseline main`); fail the job on a >10% regression in the hot paths.
";
const BENCH_GO: &str =
    "// truent harden: go test -bench . -benchmem | tee bench.txt; benchstat base.txt bench.txt
package main

import \"testing\"

func BenchmarkHotPath(b *testing.B) {
\tfor i := 0; i < b.N; i++ {
\t\t_ = hotPath()
\t}
}
";
const BENCH_GAS: &str = "# Gas regression (truent harden)

    forge snapshot                 # writes .gas-snapshot
    forge snapshot --check         # in CI: fails when any test's gas grows

Commit `.gas-snapshot`; a loop over a growing storage array shows up here
long before it exceeds the block gas limit in production.
";
const DIFFERENTIAL: &str = "# Differential / snapshot tests (truent harden)

Feed identical inputs to the previous and the current implementation (or a
reference model) and assert identical outputs — financial calculations,
state transitions, serialization, API responses.

- Rust: `insta` (`cargo insta test`), review every changed snapshot.
- JS/TS: `jest` / `vitest` `toMatchSnapshot()`; never run with `-u` in CI.
- Python: `syrupy` / `snapshottest`.
- Contracts: run the same call sequence against v1 and v2 in a fork test and
  diff balances, events and storage.

A snapshot diff is a behavioural change; it is reviewed like code.
";
const SIGMA_RULE: &str =
    "# truent harden: Sigma rule — authentication anomalies. Convert with sigma-cli
# for your SIEM (Splunk, Elastic, Sentinel, Chronicle).
title: Burst of failed logins for one account or from one source
id: 7f3c2d1e-truent-auth-burst
status: experimental
description: More than 10 failed authentication events in 5 minutes for the same user or source IP.
logsource:
  category: application
  product: webapp
detection:
  selection:
    event: 'auth.failed'
  timeframe: 5m
  condition: selection | count() by user > 10 or selection | count() by src_ip > 10
falsepositives:
  - Load tests (exclude the load-test source range)
level: high
tags:
  - attack.credential_access
  - attack.t1110
";
const CODEOWNERS: &str = "# truent harden: security-sensitive paths need a named reviewer.
# Replace @org/security with your team.
/.github/workflows/      @org/security
/security/               @org/security
/contracts/              @org/security
/src/auth/               @org/security
/**/migrations/          @org/security
/SECURITY.md             @org/security
";

const SECURITY_MD: &str = "# Security policy

## Reporting a vulnerability

Email **security@example.com** (replace with a monitored address) with a
description, affected versions and reproduction steps. You will receive an
acknowledgement within 3 business days and a fix or mitigation plan within 30
days. Please do not open a public issue for an unfixed vulnerability.

## Scope

Everything in this repository and the services built from it.

## Verification

Every change is scanned with `truent scan`, `truent deps` and, for deployed
services, `truent probe` — see `.github/workflows/truent-gate.yml`.
";

#[cfg(test)]
mod tests {
    use super::*;
    use truent_core::taxonomy::taxonomy_for;

    fn files(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    fn no_read(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn every_prevents_names_a_real_detector() {
        let p = Profile {
            github_actions: true,
            dockerfile: true,
            cargo: true,
            npm: true,
            pip: true,
            go: true,
            express: true,
            nextjs: true,
            django: true,
            flask: true,
            solidity: true,
            ..Default::default()
        };
        assert!(plan(&p).iter().any(|a| a.path.starts_with("tests/load/")));
        assert!(plan(&p)
            .iter()
            .any(|a| a.path.contains("disaster-recovery")));
        assert!(plan(&p).iter().any(|a| a.path.contains("sigma")));
        for a in plan(&p) {
            for id in &a.prevents {
                assert!(
                    taxonomy_for(id).is_some(),
                    "{}: unknown detector {id}",
                    a.path
                );
            }
            assert!(!a.content.is_empty() && !a.reason.is_empty(), "{}", a.path);
        }
    }

    #[test]
    fn profile_detects_frameworks_from_manifests() {
        let fs = files(&[
            "package.json",
            "requirements.txt",
            ".github/workflows/ci.yml",
            "Dockerfile",
            "contracts/Vault.sol",
        ]);
        let read = |p: &str| -> Option<String> {
            match p {
                "package.json" => Some(r#"{"dependencies":{"express":"4"}}"#.into()),
                "requirements.txt" => Some("Django==5.0\n".into()),
                _ => None,
            }
        };
        let p = profile(&fs, &read);
        assert!(
            p.express
                && p.django
                && p.github_actions
                && p.dockerfile
                && p.solidity
                && p.npm
                && p.pip
        );
        assert!(!p.nextjs && !p.flask && !p.cargo);
    }

    #[test]
    fn plan_is_specific_to_the_profile() {
        let bare = plan(&profile(&files(&["README.md"]), &no_read));
        let paths: Vec<&str> = bare.iter().map(|a| a.path.as_str()).collect();
        assert!(paths.contains(&".gitignore") && paths.contains(&"SECURITY.md"));
        assert!(
            !paths.iter().any(|p| p.contains("dependabot")),
            "nothing to update"
        );
        assert!(!paths.iter().any(|p| p.contains("express")));

        let web = plan(&Profile {
            express: true,
            npm: true,
            has_security_md: true,
            ..Default::default()
        });
        let paths: Vec<&str> = web.iter().map(|a| a.path.as_str()).collect();
        assert!(paths.contains(&"security/headers.express.js"));
        assert!(paths.contains(&".github/dependabot.yml"));
        assert!(!paths.contains(&"SECURITY.md"), "already present");
    }

    #[test]
    fn existing_files_are_respected() {
        let p = Profile {
            github_actions: true,
            has_dependabot: true,
            has_precommit: true,
            ..Default::default()
        };
        let paths: Vec<String> = plan(&p).into_iter().map(|a| a.path).collect();
        assert!(!paths.iter().any(|p| p.contains("dependabot")));
        assert!(!paths.iter().any(|p| p.contains("pre-commit")));
    }

    #[test]
    fn gitignore_merge_adds_only_missing_lines() {
        let m = missing_lines(".env\n*.pem\n", ".env\n*.pem\n*.key\n# comment\n\n");
        assert_eq!(m, vec!["*.key"]);
        assert!(plan(&Profile::default())[0].append);
    }

    #[test]
    fn dependabot_covers_every_ecosystem_present() {
        let p = Profile {
            github_actions: true,
            dockerfile: true,
            cargo: true,
            npm: true,
            pip: true,
            go: true,
            ..Default::default()
        };
        let d = plan(&p)
            .into_iter()
            .find(|a| a.path == ".github/dependabot.yml")
            .unwrap();
        for eco in ["github-actions", "docker", "cargo", "npm", "pip", "gomod"] {
            assert!(d.content.contains(&format!("\"{eco}\"")), "{eco}");
        }
    }
}
