//! GitHub Actions workflow attacks.
//!
//! - **Pwn request** (CWE-829): `pull_request_target` runs with the base
//!   repository's secrets; checking out the PR head and running its code hands
//!   those secrets to any external contributor.
//! - **Script injection** (CWE-94): `${{ github.event.pull_request.title }}`
//!   interpolated into a `run:` step is shell-expanded verbatim. Passing it
//!   through `env:` first is the documented safe pattern and is not flagged.
//! - **Secret exposure** (CWE-532): a secret echoed into the log.
//! - **Unpinned third-party action** (CWE-829): a mutable tag on an action
//!   outside `actions/` or `github/` lets a compromised upstream run with the
//!   workflow's permissions.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::finding;
use crate::text::strip_hash_comment;

lazy_static! {
    static ref PR_TARGET: Regex = Regex::new(r"(?m)^\s*(-\s*)?pull_request_target\b|pull_request_target\s*:").unwrap();
    static ref CHECKOUT_PR_HEAD: Regex = Regex::new(
        r"ref\s*:\s*\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)\s*\}\}"
    ).unwrap();
    /// Attacker-controlled event fields.
    static ref INJECTABLE: Regex = Regex::new(
        r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|commits?|head_commit|workflow_run)\.[a-z_.]*?(title|body|message|name|label|ref|branch|email|login)|head_ref)\s*\}\}"
    ).unwrap();
    static ref RUN_STEP: Regex = Regex::new(r"^\s*(-\s*)?run\s*:").unwrap();
    static ref ECHO_SECRET: Regex = Regex::new(r"\becho\b[^\n]*\$\{\{\s*secrets\.").unwrap();
    static ref USES: Regex = Regex::new(r"^\s*(-\s*)?uses\s*:\s*([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(/[^@\s]+)?@([^\s#]+)").unwrap();
    static ref SHA: Regex = Regex::new(r"^[0-9a-f]{40}$").unwrap();
    /// A step that publishes an artifact users will install.
    static ref PUBLISH: Regex = Regex::new(
        r"\b(npm publish|pnpm publish|yarn publish|cargo publish|twine upload|poetry publish|docker push|gh release (create|upload)|softprops/action-gh-release|pypa/gh-action-pypi-publish|goreleaser/goreleaser-action|push:\s*true)"
    ).unwrap();
    /// Signing or provenance for the published artifact.
    static ref SIGNED: Regex = Regex::new(
        r"cosign|sigstore|--provenance|provenance:\s*true|gh attest|actions/attest-build-provenance|slsa-framework/slsa-github-generator|gpg --detach-sign|--sign\b|signing_key|SIGNING_KEY|GPG_PRIVATE_KEY|sign:\s*true"
    ).unwrap();
}

pub fn detect(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<String> = source.lines().map(strip_hash_comment).collect();
    let joined = lines.join("\n");

    // ---- pwn request ---------------------------------------------------
    if PR_TARGET.is_match(&joined) {
        for (idx, line) in lines.iter().enumerate() {
            if CHECKOUT_PR_HEAD.is_match(line) {
                findings.push(finding(
                    "gen_ci_pwn_request",
                    Severity::Critical,
                    file_path,
                    idx,
                    "pull_request_target workflow checks out the pull request head: the PR's code runs with this repository's secrets and write token",
                    line,
                ));
            }
        }
    }

    // ---- script injection & secret exposure inside run: blocks --------
    let mut in_run = false;
    let mut run_indent = 0usize;
    for (idx, line) in lines.iter().enumerate() {
        let indent = line.len() - line.trim_start().len();
        if RUN_STEP.is_match(line) {
            in_run = true;
            run_indent = indent;
        } else if in_run && !line.trim().is_empty() && indent <= run_indent {
            in_run = false;
        }
        if !in_run {
            continue;
        }
        if INJECTABLE.is_match(line) {
            findings.push(finding(
                "gen_ci_script_injection",
                Severity::High,
                file_path,
                idx,
                "Attacker-controlled event data is interpolated directly into a run: step and shell-expanded; pass it through env: and quote it instead",
                line,
            ));
        }
        if ECHO_SECRET.is_match(line) {
            findings.push(finding(
                "gen_ci_secret_exposed",
                Severity::High,
                file_path,
                idx,
                "A secret is echoed into the job log",
                line,
            ));
        }
    }

    // ---- unsigned release --------------------------------------------------
    if PUBLISH.is_match(&joined) && !SIGNED.is_match(&joined) {
        if let Some((idx, line)) = lines.iter().enumerate().find(|(_, l)| PUBLISH.is_match(l)) {
            findings.push(finding(
                "gen_ci_unsigned_release",
                Severity::Medium,
                file_path,
                idx,
                "Artifacts are published without a signature or build provenance: a consumer cannot tell a release built by this workflow from one uploaded with a stolen token. Sign with cosign / npm --provenance / gh attest (id-token: write) so releases are verifiable",
                line,
            ));
        }
    }

    // ---- unpinned third-party actions ----------------------------------
    //
    // Pinning is one decision per action, not per use: a workflow that calls
    // `rust-toolchain@stable` in nine jobs has one thing to fix. Reported at
    // the first use, with the count.
    let mut seen: std::collections::BTreeMap<String, (usize, String, String, usize)> =
        Default::default();
    for (idx, line) in lines.iter().enumerate() {
        if let Some(c) = USES.captures(line) {
            let owner = c[2].to_string();
            let repo = c[3].to_string();
            let version = c[5].to_string();
            if matches!(owner.as_str(), "actions" | "github") || SHA.is_match(&version) {
                continue;
            }
            let key = format!("{owner}/{repo}");
            let entry = seen.entry(key).or_insert((idx, version, line.clone(), 0));
            entry.3 += 1;
        }
    }
    for (action, (idx, version, line, uses)) in seen {
        let times = if uses > 1 {
            format!(" ({uses} uses in this workflow)")
        } else {
            String::new()
        };
        findings.push(finding(
            "gen_ci_unpinned_action",
            Severity::Low,
            file_path,
            idx,
            format!("Third-party action `{action}` is pinned to mutable ref `{version}`{times}; pin to a commit SHA so an upstream compromise cannot run here"),
            &line,
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pwn_request_is_flagged() {
        let w = "on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm ci && npm test\n";
        let f = detect(w, ".github/workflows/ci.yml");
        assert!(f.iter().any(|f| f.invariant_id == "gen_ci_pwn_request"));
    }

    #[test]
    fn plain_pull_request_checkout_is_fine() {
        let w = "on: [pull_request]\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
        assert!(detect(w, ".github/workflows/ci.yml").is_empty());
    }

    #[test]
    fn direct_interpolation_is_flagged_but_env_indirection_is_not() {
        let bad = "jobs:\n  b:\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n";
        assert!(detect(bad, ".github/workflows/w.yml")
            .iter()
            .any(|f| f.invariant_id == "gen_ci_script_injection"));
        let good = "jobs:\n  b:\n    steps:\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: echo \"$TITLE\"\n";
        assert!(detect(good, ".github/workflows/w.yml").is_empty());
    }

    #[test]
    fn unpinned_action_is_reported_once_per_workflow() {
        let w = "jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@stable\n  b:\n    steps:\n      - uses: dtolnay/rust-toolchain@stable\n  c:\n    steps:\n      - uses: dtolnay/rust-toolchain@stable\n";
        let f = detect(w, ".github/workflows/w.yml");
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].message.contains("3 uses"));
        assert_eq!(f[0].line, 4, "anchored at the first use");
    }

    #[test]
    fn unpinned_third_party_flagged_first_party_and_sha_not() {
        let w = "steps:\n  - uses: actions/checkout@v4\n  - uses: someone/thing@main\n  - uses: other/act@0123456789abcdef0123456789abcdef01234567\n";
        let f = detect(w, ".github/workflows/w.yml");
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("someone/thing"));
    }
}
