//! Repository-level detectors: weaknesses that are only visible across files.
//!
//! A missing rate limit cannot be seen in one file — the login route lives in
//! one place and the limiter middleware, if it exists, in another. These
//! detectors take the whole set of applicable sources and answer questions
//! of the form "the repository has X and nowhere has Y".

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::text::{code_lines_hash, code_lines_slash};
use crate::{classify, finding, FileKind};

lazy_static! {
    /// An authentication or credential route: login, signin, token, reset,
    /// otp, verify. Route strings in any of the frameworks.
    static ref AUTH_ROUTE: Regex = Regex::new(
        r#"(?i)(\.(post|get|put|route|handle|all)\s*\(\s*|@\w*\.?route\s*\(\s*|path\s*\(\s*|url\s*\(\s*|\.HandleFunc\s*\(\s*|\.(POST|GET)\s*\(\s*|r\.Post\s*\(\s*)["'`][^"'`]*(/login|/signin|/sign-in|/auth\b|/authenticate|/token|/oauth|/reset[-_]?password|/forgot|/otp|/verify|/2fa|/mfa|/register|/signup|/sign-up)[^"'`]*["'`]"#
    ).unwrap();
    /// Any rate-limiting or brute-force protection mechanism, library or config.
    static ref RATE_LIMIT: Regex = Regex::new(
        r"(?i)express-rate-limit|rateLimit\(|rate_limit|ratelimit|flask_limiter|\bLimiter\(|django_ratelimit|@ratelimit|throttle|slowapi|tollbooth|x/time/rate|ulule/limiter|@nestjs/throttler|limit_req|RateLimiter|rate-limiter-flexible|bucket4j|login_attempts|max_attempts|lockout|axes|fail2ban|brute|hcaptcha|recaptcha|turnstile"
    ).unwrap();
    /// Security-relevant events that should be logged: a login outcome, an
    /// authorization denial, a privileged change.
    static ref AUTH_EVENT_LOG: Regex = Regex::new(
        r"(?i)(log|logger|logging|audit|winston|pino|zap|slog|console)\.\w*\s*\([^\n]*(login|logged in|sign.?in|auth(entication|orization)? (fail|denied|success)|failed login|invalid (password|credentials)|permission denied|forbidden|unauthorized|password (changed|reset)|role (changed|granted)|privilege|audit)"
    ).unwrap();
    /// Markers that a repository *is* a web service with authentication.
    static ref HAS_AUTH_LOGIC: Regex = Regex::new(
        r"(?i)check_password|verify_password|bcrypt\.(compare|checkpw)|argon2\.(verify|PasswordHasher)|authenticate\(|passport\.|login_user\(|jwt\.(sign|encode)|CompareHashAndPassword"
    ).unwrap();
}

/// Run repository-level detectors over `(path, source)` pairs.
pub fn detect(files: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    // Comments are stripped first: a `# TODO: add rate limiting` must not
    // count as a limiter, and a corpus header naming the detector must not
    // either.
    let sources: Vec<(String, String)> = files
        .iter()
        .filter_map(|(p, src)| {
            let code = match classify(p) {
                FileKind::Python | FileKind::Shell => code_lines_hash(src).join("\n"),
                FileKind::JavaScript | FileKind::Go => code_lines_slash(src).join("\n"),
                FileKind::Config => src.clone(),
                _ => return None,
            };
            Some((p.clone(), code))
        })
        .collect();
    if sources.is_empty() {
        return out;
    }
    let any_rate_limit = sources.iter().any(|(_, s)| RATE_LIMIT.is_match(s));
    let any_auth_event_log = sources.iter().any(|(_, s)| AUTH_EVENT_LOG.is_match(s));
    let any_auth_logic = sources.iter().any(|(_, s)| HAS_AUTH_LOGIC.is_match(s));

    // Missing rate limit: report once, at the first auth route found.
    if !any_rate_limit {
        'outer: for (path, src) in &sources {
            for (idx, line) in src.lines().enumerate() {
                if AUTH_ROUTE.is_match(line) {
                    out.push(finding("gen_missing_rate_limit", Severity::Medium, path, idx,
                        "An authentication route exists and nothing in the repository rate-limits or locks out: credential stuffing and brute force run at line speed. Add a limiter (express-rate-limit, flask-limiter, django-ratelimit, tollbooth) on login, reset and token routes", line));
                    break 'outer;
                }
            }
        }
    }

    // Missing security-event logging: the repository authenticates users but
    // never logs an authentication or authorization outcome.
    if any_auth_logic && !any_auth_event_log {
        'outer2: for (path, src) in &sources {
            for (idx, line) in src.lines().enumerate() {
                if HAS_AUTH_LOGIC.is_match(line) {
                    out.push(finding("gen_missing_security_logging", Severity::Low, path, idx,
                        "Credentials are verified here but no authentication or authorization outcome is logged anywhere in the repository: a brute-force campaign, a takeover or a privilege change leaves no trail to detect or investigate", line));
                    break 'outer2;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(files: &[(&str, &str)]) -> Vec<String> {
        let v: Vec<(String, String)> = files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect();
        detect(&v).into_iter().map(|f| f.invariant_id).collect()
    }

    #[test]
    fn login_route_without_any_limiter() {
        let got = ids(&[("app.js", "app.post('/login', login);\n")]);
        assert!(got.contains(&"gen_missing_rate_limit".into()));
    }

    #[test]
    fn limiter_anywhere_in_the_repo_clears_it() {
        let got = ids(&[
            ("routes/auth.js", "router.post('/login', login);\n"),
            ("app.js", "const rateLimit = require('express-rate-limit');\napp.use('/login', rateLimit({ max: 5 }));\n"),
        ]);
        assert!(!got.contains(&"gen_missing_rate_limit".into()));
    }

    #[test]
    fn no_auth_route_means_no_finding() {
        assert!(ids(&[("app.js", "app.get('/health', ok);\n")]).is_empty());
    }

    #[test]
    fn auth_without_event_logging() {
        let got = ids(&[(
            "auth.py",
            "def login(u, p):\n    if check_password(p, u.hash):\n        return token(u)\n",
        )]);
        assert!(got.contains(&"gen_missing_security_logging".into()));
        let ok = ids(&[("auth.py", "def login(u, p):\n    if not check_password(p, u.hash):\n        logger.warning('failed login for %s', u.id)\n")]);
        assert!(!ok.contains(&"gen_missing_security_logging".into()));
    }
}
