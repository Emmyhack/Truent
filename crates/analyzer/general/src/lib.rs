#![deny(unsafe_code)]

//! General-purpose repository security analyzer.
//!
//! Truent's chain analyzers answer questions about contract source. This crate
//! answers the questions every repository raises regardless of what it builds:
//!
//! - **Secrets** — is a credential or private key committed?
//! - **CI** — can a GitHub Actions workflow be hijacked by a pull request?
//! - **Containers** — does a Dockerfile or manifest hand out root or the host?
//! - **Code** — does Python, JS/TS, Go or shell pass attacker input to a
//!   shell, a database, `eval`, a deserializer, or disable TLS?
//!
//! Each detector requires a *dynamic* input to fire: a literal argument, a
//! placeholder value, an environment-variable reference or a comment is never
//! a finding. `tests/corpus/good` holds correct code that must produce zero
//! findings; `tests/corpus/bad` holds real bugs that must still be caught.

pub mod ci_workflows;
pub mod code_patterns;
pub mod containers;
pub mod iac;
pub mod repo;
pub mod secrets;
pub mod taint;
pub mod text;
pub mod web_security;
pub mod webconfig;

use truent_core::Finding;

/// What kind of file this is, which decides which detectors apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// `.github/workflows/*.yml`
    GithubWorkflow,
    /// `Dockerfile`, `*.dockerfile`, `Containerfile`
    Dockerfile,
    /// Kubernetes manifest, docker-compose file, or CloudFormation template.
    ContainerManifest,
    /// Terraform / HCL.
    Terraform,
    /// Python source.
    Python,
    /// JavaScript / TypeScript source.
    JavaScript,
    /// Go source.
    Go,
    /// Shell script.
    Shell,
    /// Configuration or environment file (`.env`, `.json`, `.toml`, `.ini`, …).
    Config,
    /// Anything else the secrets scanner should still read.
    Other,
    /// Documentation, samples and binaries: never scanned.
    Skip,
}

/// Classify a path.
pub fn classify(path: &str) -> FileKind {
    let lower = path.replace('\\', "/").to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower).to_string();
    let ext = name.rsplit('.').next().unwrap_or("").to_string();

    // Documentation, examples and templates describe secrets; they do not
    // hold them. Binaries and lockfiles are noise.
    if matches!(
        ext.as_str(),
        "md" | "rst"
            | "txt"
            | "pub"
            | "lock"
            | "sum"
            | "svg"
            | "png"
            | "jpg"
            | "gif"
            | "ico"
            | "woff"
            | "woff2"
            | "ttf"
            | "pdf"
            | "min.js"
            | "map"
    ) || name.ends_with(".example")
        || name.ends_with(".sample")
        || name.ends_with(".template")
        || name.ends_with(".dist")
        || name.ends_with(".min.js")
        || lower.contains("/node_modules/")
        || lower.contains("/vendor/")
        || lower.contains("/target/")
        || lower.contains("/dist/")
        || lower.contains("/build/")
        || lower.contains("/.next/")
        || lower.contains("/.nuxt/")
        || lower.contains("/.cache/")
        || lower.contains("/coverage/")
        || lower.contains("/__pycache__/")
        || lower.contains("/.venv/")
        || lower.contains("/.git/")
    {
        return FileKind::Skip;
    }

    if lower.contains(".github/workflows/") && (ext == "yml" || ext == "yaml") {
        return FileKind::GithubWorkflow;
    }
    if name == "dockerfile"
        || name == "containerfile"
        || name.starts_with("dockerfile.")
        || ext == "dockerfile"
    {
        return FileKind::Dockerfile;
    }
    match ext.as_str() {
        "py" | "pyw" => FileKind::Python,
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => FileKind::JavaScript,
        "go" => FileKind::Go,
        "sh" | "bash" | "zsh" => FileKind::Shell,
        "yml" | "yaml" => FileKind::ContainerManifest,
        "tf" | "tfvars" | "hcl" => FileKind::Terraform,
        "env" | "json" | "toml" | "ini" | "cfg" | "conf" | "properties" | "xml" => FileKind::Config,
        _ if name.starts_with(".env") => FileKind::Config,
        _ => FileKind::Other,
    }
}

/// Whether this analyzer has anything to say about `path`.
pub fn applies_to(path: &str) -> bool {
    classify(path) != FileKind::Skip
}

/// Run the repository-level detectors over every `(path, source)` pair.
/// These see across files (a login route in one, a limiter in another).
pub fn run_repo_detectors(files: &[(String, String)]) -> Vec<Finding> {
    let mut findings = repo::detect(files);
    for f in &mut findings {
        f.metadata
            .insert("chain".to_string(), "general".to_string());
    }
    findings
}

/// Run every applicable detector over one file.
pub fn run_all_detectors(source: &str, file_path: &str) -> Vec<Finding> {
    let kind = classify(file_path);
    if kind == FileKind::Skip {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Secrets live inside string literals, so this scanner reads the raw text
    // with only comments removed — a credential in a comment is still a
    // committed credential, but a *description* of one in a comment is not,
    // so comments are kept for known-format keys and dropped for the generic
    // assignment heuristic. See `secrets` for the split.
    findings.extend(secrets::detect(source, file_path, kind));

    match kind {
        FileKind::GithubWorkflow => findings.extend(ci_workflows::detect(source, file_path)),
        FileKind::Dockerfile => findings.extend(containers::detect_dockerfile(source, file_path)),
        FileKind::ContainerManifest => {
            findings.extend(containers::detect_manifest(source, file_path));
            findings.extend(iac::detect_cloudformation(source, file_path));
        }
        FileKind::Terraform => findings.extend(iac::detect_terraform(source, file_path)),
        FileKind::Python | FileKind::JavaScript | FileKind::Go | FileKind::Shell => {
            // Taint first: where both it and the line-local detector report
            // the same sink, the dedup below keeps the first — the one that
            // names the source the value came from.
            findings.extend(taint::detect(source, file_path, kind));
            findings.extend(code_patterns::detect(source, file_path, kind));
            findings.extend(webconfig::detect(source, file_path, kind));
            findings.extend(web_security::detect(source, file_path, kind));
        }
        FileKind::Config => {
            findings.extend(iac::detect_cloudformation(source, file_path));
            findings.extend(webconfig::detect(source, file_path, kind));
        }
        FileKind::Other | FileKind::Skip => {}
    }

    // Inline suppression, the convention every secret scanner needs: a
    // synthetic key in a test fixture is indistinguishable from a real one by
    // inspection, so the author says so where it lives.
    //
    //   `truent:allow`                 — suppress every finding on this line
    //   `truent:allow gen_xss_sink`    — suppress that detector on this line
    //
    // Either form applies to its own line or the line directly below it.
    let lines: Vec<&str> = source.lines().collect();
    findings.retain(|f| !is_allowed(&lines, f.line, &f.invariant_id));

    truent_core::text::restore_snippets(source, &mut findings);
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.dedup_key()));
    findings.sort_by(|a, b| match b.severity.cmp(&a.severity) {
        std::cmp::Ordering::Equal => a.line.cmp(&b.line),
        other => other,
    });
    findings
}

/// Whether a `truent:allow` marker covers finding `id` at 1-based `line`.
pub fn is_allowed(lines: &[&str], line: usize, id: &str) -> bool {
    let check = |l: &str| -> bool {
        let Some(pos) = l.find("truent:allow") else {
            return false;
        };
        let rest = l[pos + "truent:allow".len()..].trim();
        let scoped = rest
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("");
        scoped.is_empty() || scoped == id
    };
    let here = line
        .checked_sub(1)
        .and_then(|i| lines.get(i))
        .map(|l| check(l))
        .unwrap_or(false);
    let above = line
        .checked_sub(2)
        .and_then(|i| lines.get(i))
        .map(|l| check(l))
        .unwrap_or(false);
    here || above
}

/// Build a finding with the metadata every general detector carries.
pub(crate) fn finding(
    id: &str,
    severity: truent_core::Severity,
    file: &str,
    line_idx: usize,
    message: impl Into<String>,
    snippet: &str,
) -> Finding {
    Finding::new(
        id.to_string(),
        severity,
        file.to_string(),
        line_idx + 1,
        0,
        message.into(),
        snippet.trim().to_string(),
    )
    .with_metadata("analyzer".to_string(), "general".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_marker_suppresses_on_its_line_or_the_line_below() {
        let src = "key = 'AKIAJ4X7Z2K9M1P3Q5R7'  # truent:allow\n# truent:allow gen_hardcoded_secret\nkey2 = 'AKIAJ4X7Z2K9M1P3Q5R8'\nkey3 = 'AKIAJ4X7Z2K9M1P3Q5R9'\n";
        let ids: Vec<(usize, String)> = run_all_detectors(src, "conf.py")
            .into_iter()
            .map(|f| (f.line, f.invariant_id))
            .collect();
        assert_eq!(ids, vec![(4, "gen_hardcoded_secret".to_string())]);
    }

    #[test]
    fn scoped_allow_only_suppresses_that_detector() {
        let src = "el.innerHTML = userInput; // truent:allow gen_sql_injection\n";
        assert_eq!(
            run_all_detectors(src, "a.js").len(),
            1,
            "wrong id must not suppress"
        );
    }

    #[test]
    fn build_artifacts_are_never_scanned() {
        // Synthetic key; the marker is what a self-scan honours.
        // truent:allow
        let key = "AKIAJ4X7Z2K9M1P3Q5R7";
        assert!(run_all_detectors(key, "web/.next/server/app/page.js").is_empty());
        assert!(run_all_detectors(key, "site/coverage/lcov.js").is_empty());
    }
}
