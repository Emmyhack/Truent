//! Committed credentials (CWE-798) and private keys (CWE-321).
//!
//! Two tiers. **Known formats** — an AWS access key ID, a GitHub token, a
//! Slack token, a PEM private key — have a structure that cannot occur by
//! accident, so they are reported wherever they appear, comments included,
//! unless the value is a vendor's documented example. **Generic assignments**
//! — `password = "…"`, `api_key: "…"` — are reported only when the value is
//! not a placeholder, not an environment reference, and has the entropy of a
//! real credential rather than a word.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::text::{entropy, is_placeholder, strip_hash_comment, strip_slash_comment};
use crate::{finding, FileKind};

lazy_static! {
    /// Known credential formats: (regex, human name).
    static ref KNOWN: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(), "AWS access key ID"),
        (Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b").unwrap(), "GitHub token"),
        (Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b").unwrap(), "GitHub fine-grained token"),
        (Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b").unwrap(), "Slack token"),
        (Regex::new(r"\bsk_live_[0-9a-zA-Z]{20,}\b").unwrap(), "Stripe live secret key"),
        (Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap(), "Google API key"),
        (Regex::new(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b").unwrap(), "SendGrid API key"),
        (Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap(), "npm token"),
        (Regex::new(r"\bglpat-[A-Za-z0-9_-]{20,}\b").unwrap(), "GitLab personal access token"),
        (Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap(), "JSON Web Token"),
        (Regex::new(r"\bAge-secret-key-1[0-9a-z]{58}\b").unwrap(), "age secret key"),
    ];

    static ref PRIVATE_KEY: Regex =
        Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----").unwrap();

    /// `password = "value"`, `api_key: 'value'`, `SECRET=value` (env style).
    static ref GENERIC_ASSIGNMENT: Regex = Regex::new(
        r#"(?i)\b([a-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|token)[a-z0-9_.-]*)\s*[:=]\s*(?:"([^"]{8,})"|'([^']{8,})'|([A-Za-z0-9+/=_\-]{16,})\s*$)"#
    ).unwrap();
}

pub fn detect(source: &str, file_path: &str, kind: FileKind) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, raw) in source.lines().enumerate() {
        // ---- known formats: structure is the evidence -------------------
        for (re, name) in KNOWN.iter() {
            if let Some(m) = re.find(raw) {
                if is_placeholder(m.as_str()) || raw.to_uppercase().contains("EXAMPLE") {
                    continue;
                }
                findings.push(finding(
                    "gen_hardcoded_secret",
                    Severity::Critical,
                    file_path,
                    idx,
                    format!("{name} committed to source: rotate it now — removal from the file does not revoke it"),
                    raw,
                ));
                break;
            }
        }
        if PRIVATE_KEY.is_match(raw) {
            findings.push(finding(
                "gen_private_key_committed",
                Severity::Critical,
                file_path,
                idx,
                "Private key material committed to source: treat the key as compromised and rotate it",
                raw,
            ));
            continue;
        }

        // ---- generic assignments: comments removed, value must look real --
        let line = match kind {
            FileKind::JavaScript | FileKind::Go => strip_slash_comment(raw),
            _ => strip_hash_comment(raw),
        };
        if let Some(caps) = GENERIC_ASSIGNMENT.captures(&line) {
            let key = caps[1].to_lowercase();
            let value = caps
                .get(2)
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))
                .map(|m| m.as_str())
                .unwrap_or("");
            // A key that names itself as public, an example, or a *field*
            // (`password_field`, `token_type`) is not a credential.
            if key.contains("public")
                || key.contains("example")
                || key.contains("sample")
                || key.contains("test")
                || key.contains("_field")
                || key.contains("_name")
                || key.contains("_type")
                || key.contains("_url")
                || key.contains("_path")
                || key.contains("_file")
                || key.contains("_id")
                || key.contains("_length")
                || key.contains("_min")
                || key.contains("_max")
                || key.ends_with("_env")
            {
                continue;
            }
            if is_placeholder(value) || entropy(value) < 3.0 {
                continue;
            }
            // Words separated by spaces are prose, not a credential.
            if value.contains(' ') && value.split_whitespace().count() > 2 {
                continue;
            }
            findings.push(finding(
                "gen_hardcoded_secret",
                Severity::High,
                file_path,
                idx,
                format!("`{}` is assigned a literal that looks like a real credential; load it from the environment or a secret store", caps[1].trim()),
                raw,
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str, path: &str) -> Vec<Finding> {
        detect(src, path, crate::classify(path))
    }

    #[test]
    fn known_formats_are_flagged_anywhere() {
        assert_eq!(run("key = 'AKIAJ4X7Z2K9M1P3Q5R7'", "a.py").len(), 1); // truent:allow
                                                                          // truent:allow
        assert_eq!(
            run(
                "// token ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD", // truent:allow
                "a.js"
            )
            .len(),
            1
        );
        assert_eq!(run("-----BEGIN RSA PRIVATE KEY-----", "id_rsa").len(), 1); // truent:allow
    }

    #[test]
    fn vendor_examples_and_placeholders_are_not() {
        assert!(run("key = 'AKIAIOSFODNN7EXAMPLE'", "a.py").is_empty());
        assert!(run("password = \"changeme\"", "a.py").is_empty());
        assert!(run("password = os.environ['DB_PASSWORD']", "a.py").is_empty());
        assert!(run("SECRET_KEY = \"${SECRET_KEY}\"", "a.env").is_empty());
        assert!(run("api_key: \"<your-api-key>\"", "c.yml").is_empty());
        assert!(run("password_field = \"password\"", "f.py").is_empty());
        assert!(run("token_type = \"Bearer\"", "f.py").is_empty());
        assert!(run("# password = \"k8Dv2nQp9sLx4Zt7Wm1Ry\"", "f.py").is_empty());
        // truent:allow
    }

    #[test]
    fn a_real_looking_generic_secret_is_flagged() {
        assert_eq!(
            run("DB_PASSWORD = \"k8Dv2nQp9sLx4Zt7Wm1RyBc\"", "settings.py").len(), // truent:allow
            1
        );
        assert_eq!(
            run("const apiKey = 'q9Zt7Wm1RyBc4Lx2nQp8Dv6K';", "app.js").len(), // truent:allow
            1
        );
    }

    #[test]
    fn docs_are_never_scanned() {
        assert!(crate::run_all_detectors("AKIAJ4X7Z2K9M1P3Q5R7", "README.md").is_empty()); // truent:allow
        assert!(
            crate::run_all_detectors("password = \"k8Dv2nQp9sLx4Zt7Wm1Ry\"", ".env.example") // truent:allow
                .is_empty()
        );
    }
}
