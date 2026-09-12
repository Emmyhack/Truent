//! HTTP observations: security headers, cookies, redirects, banners, and a
//! fixed list of files that must never be served.
//!
//! [`analyze`] and [`analyze_paths`] are pure and tested offline; [`observe`]
//! and [`observe_paths`] do the fetching.

use serde::Serialize;
use std::io::Read;
use std::time::Duration;
use truent_core::{Finding, Severity};

use crate::{finding, Target};

/// One response, headers only. Header names are lower-cased.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HttpObservation {
    pub url: String,
    /// After redirects.
    pub final_url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// For `http://` targets only: the first hop, redirects not followed.
    pub first_hop_status: Option<u16>,
    pub first_hop_location: Option<String>,
}

impl HttpObservation {
    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    fn is_html(&self) -> bool {
        self.get("content-type")
            .map(|c| c.to_ascii_lowercase().contains("text/html"))
            .unwrap_or(false)
    }
}

/// A cookie whose name suggests it carries a session or credential.
fn is_session_cookie(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "session", "sess", "token", "auth", "sid", "jwt", "csrf", "xsrf", "remember", "login",
    ]
    .iter()
    .any(|k| n.contains(k))
}

/// A banner that names a product *version* — `nginx/1.18.0`, `PHP/8.1.2` —
/// rather than just a product.
fn reveals_version(v: &str) -> bool {
    let mut digits_seen = false;
    let mut dot_after_digit = false;
    for c in v.chars() {
        if c.is_ascii_digit() {
            if dot_after_digit {
                return true;
            }
            digits_seen = true;
        } else if c == '.' && digits_seen {
            dot_after_digit = true;
        } else {
            digits_seen = false;
            dot_after_digit = false;
        }
    }
    false
}

/// Evaluate one response.
pub fn analyze(obs: &HttpObservation, location: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let https = obs.final_url.starts_with("https://");
    let html = obs.is_html();

    if https && obs.get("strict-transport-security").is_none() {
        out.push(finding(
            "rt_missing_hsts",
            Severity::Medium,
            location,
            "No Strict-Transport-Security header: a first visit over plain HTTP, or a stripped \
             redirect, lets an on-path attacker keep the session on cleartext"
                .into(),
            format!("HTTP {} with no Strict-Transport-Security", obs.status),
        ));
    }

    if html {
        let csp = obs
            .get("content-security-policy")
            .or_else(|| obs.get("content-security-policy-report-only"));
        if csp.is_none() {
            out.push(finding(
                "rt_missing_csp",
                Severity::Low,
                location,
                "No Content-Security-Policy on an HTML response: an injected script runs \
                 unrestricted, and there is no report channel to learn it happened"
                    .into(),
                format!(
                    "HTTP {} text/html with no Content-Security-Policy",
                    obs.status
                ),
            ));
        }
        let frames_restricted = obs.get("x-frame-options").is_some()
            || csp
                .map(|c| c.to_ascii_lowercase().contains("frame-ancestors"))
                .unwrap_or(false);
        if !frames_restricted {
            out.push(finding(
                "rt_missing_frame_options",
                Severity::Low,
                location,
                "Neither X-Frame-Options nor a CSP frame-ancestors directive: the page can be \
                 framed by any origin, the precondition for clickjacking"
                    .into(),
                "no X-Frame-Options, no frame-ancestors".into(),
            ));
        }
    }

    let nosniff = obs
        .get("x-content-type-options")
        .map(|v| v.trim().eq_ignore_ascii_case("nosniff"))
        .unwrap_or(false);
    if !nosniff {
        out.push(finding(
            "rt_missing_content_type_options",
            Severity::Low,
            location,
            "X-Content-Type-Options is not `nosniff`: browsers may reinterpret a response as a \
             different type, which turns some uploads and JSON endpoints into script"
                .into(),
            obs.get("x-content-type-options")
                .map(|v| format!("X-Content-Type-Options: {v}"))
                .unwrap_or_else(|| "no X-Content-Type-Options".into()),
        ));
    }

    for cookie in obs.all("set-cookie") {
        let name = cookie.split('=').next().unwrap_or("").trim();
        let attrs: Vec<String> = cookie
            .split(';')
            .skip(1)
            .map(|a| a.trim().to_ascii_lowercase())
            .collect();
        let secure = attrs.iter().any(|a| a == "secure");
        let httponly = attrs.iter().any(|a| a == "httponly");
        let session = is_session_cookie(name);
        let mut missing = Vec::new();
        if https && !secure {
            missing.push("Secure");
        }
        if session && !httponly {
            missing.push("HttpOnly");
        }
        if !missing.is_empty() {
            out.push(finding(
                "rt_insecure_cookie",
                if session {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                location,
                format!(
                    "Cookie `{name}` is set without {}: {}",
                    missing.join(" or "),
                    if session {
                        "a session cookie readable by script or sendable over cleartext is the session"
                    } else {
                        "it can be sent over cleartext to a network attacker"
                    }
                ),
                // Name and attributes only — never the value.
                format!("Set-Cookie: {name}=… ; {}", attrs.join("; ")),
            ));
        }
    }

    for h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"] {
        if let Some(v) = obs.get(h) {
            if reveals_version(v) {
                out.push(finding(
                    "rt_server_banner",
                    Severity::Low,
                    location,
                    format!(
                        "`{h}` header reveals an exact software version, which lets an attacker \
                         look up applicable CVEs without probing"
                    ),
                    format!("{h}: {v}"),
                ));
            }
        }
    }

    if obs.url.starts_with("http://") {
        if let Some(status) = obs.first_hop_status {
            let to_https = obs
                .first_hop_location
                .as_deref()
                .map(|l| l.to_ascii_lowercase().starts_with("https://"))
                .unwrap_or(false);
            if !to_https {
                out.push(finding(
                    "rt_no_https_redirect",
                    Severity::Medium,
                    location,
                    "Plain HTTP is served without redirecting to HTTPS: every request over it, \
                     cookies included, is readable and modifiable on the path"
                        .into(),
                    match &obs.first_hop_location {
                        Some(l) => format!("HTTP {status} Location: {l}"),
                        None => format!("HTTP {status} with content, no redirect"),
                    },
                ));
            }
        }
    }

    out
}

// ---------------- exposed paths --------------------------------------------

/// A file that must never be served, confirmed by a content signature so a
/// catch-all `200` page can never produce a finding.
struct Sensitive {
    path: &'static str,
    /// Human name of the signature; the body itself is never recorded.
    what: &'static str,
    /// Credential-bearing: a match is High rather than Medium.
    credentials: bool,
    matches: fn(&[u8]) -> bool,
}

fn starts(b: &[u8], p: &[u8]) -> bool {
    b.starts_with(p)
}
fn contains(b: &[u8], p: &[u8]) -> bool {
    b.windows(p.len()).any(|w| w == p)
}
/// `KEY=value` lines: at least two lines that start with an upper-case
/// identifier followed by `=`.
fn dotenv_like(b: &[u8]) -> bool {
    let text = String::from_utf8_lossy(b);
    text.lines()
        .filter(|l| {
            let l = l.trim();
            let Some((k, _)) = l.split_once('=') else {
                return false;
            };
            !k.is_empty()
                && k.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        })
        .count()
        >= 2
}

const SENSITIVE: &[Sensitive] = &[
    Sensitive {
        path: "/.git/config",
        what: "git config ([core] section)",
        credentials: true,
        matches: |b| contains(b, b"[core]"),
    },
    Sensitive {
        path: "/.env",
        what: "dotenv KEY=value lines",
        credentials: true,
        matches: dotenv_like,
    },
    Sensitive {
        path: "/.aws/credentials",
        what: "AWS credentials profile",
        credentials: true,
        matches: |b| contains(b, b"aws_access_key_id"),
    },
    Sensitive {
        path: "/wp-config.php.bak",
        what: "WordPress config backup",
        credentials: true,
        matches: |b| contains(b, b"DB_PASSWORD"),
    },
    Sensitive {
        path: "/.svn/wc.db",
        what: "Subversion working copy database",
        credentials: false,
        matches: |b| starts(b, b"SQLite format 3"),
    },
    Sensitive {
        path: "/.DS_Store",
        what: "macOS directory listing",
        credentials: false,
        matches: |b| starts(b, b"\0\0\0\x01Bud1"),
    },
    Sensitive {
        path: "/server-status",
        what: "Apache server-status page",
        credentials: false,
        matches: |b| contains(b, b"Apache Server Status"),
    },
    Sensitive {
        path: "/actuator/env",
        what: "Spring Boot environment dump",
        credentials: true,
        matches: |b| contains(b, b"propertySources"),
    },
    Sensitive {
        path: "/phpinfo.php",
        what: "phpinfo() output",
        credentials: false,
        matches: |b| contains(b, b"phpinfo()") || contains(b, b"PHP Version"),
    },
];

/// One probed path.
#[derive(Debug, Clone, Serialize)]
pub struct PathObservation {
    pub path: String,
    pub status: u16,
    /// The body carried the expected signature. A `200` alone is not a match.
    pub matched: bool,
    pub bytes: usize,
}

/// Evaluate the probed paths.
pub fn analyze_paths(paths: &[PathObservation]) -> Vec<Finding> {
    paths
        .iter()
        .filter(|p| p.matched)
        .filter_map(|p| {
            let s = SENSITIVE.iter().find(|s| s.path == p.path)?;
            Some(finding(
                "rt_exposed_sensitive_path",
                if s.credentials {
                    Severity::High
                } else {
                    Severity::Medium
                },
                &p.path,
                format!(
                    "{} is served publicly ({}) — {}",
                    p.path,
                    s.what,
                    if s.credentials {
                        "it carries credentials or repository internals; assume they are compromised and rotate"
                    } else {
                        "it discloses server internals that shortcut reconnaissance"
                    }
                ),
                // Never the body: the path and size are the evidence.
                format!("HTTP {} {} bytes, signature: {}", p.status, p.bytes, s.what),
            ))
        })
        .collect()
}

// ---------------- network ---------------------------------------------------

fn agent(timeout: Duration, redirects: u32, trust_anything: bool) -> ureq::Agent {
    let mut b = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(redirects)
        .user_agent(concat!("truent-probe/", env!("CARGO_PKG_VERSION")));
    if trust_anything {
        b = b.tls_config(crate::tls::permissive_config());
    }
    b.build()
}

/// A `4xx`/`5xx` is still a response worth reading.
fn call(agent: &ureq::Agent, url: &str) -> Result<ureq::Response, String> {
    match agent.get(url).call() {
        Ok(r) => Ok(r),
        Err(ureq::Error::Status(_, r)) => Ok(r),
        Err(ureq::Error::Transport(t)) => Err(t.to_string()),
    }
}

/// Response headers are recorded in the report, so a header whose value is
/// itself a secret is redacted at collection time. `Set-Cookie` keeps its
/// name and attributes — everything the evaluator needs — and never its
/// value.
fn redact(name: &str, value: &str) -> String {
    if name != "set-cookie" {
        return value.to_string();
    }
    let (nv, attrs) = value.split_once(';').unwrap_or((value, ""));
    let cname = nv.split('=').next().unwrap_or("").trim();
    if attrs.is_empty() {
        format!("{cname}=<redacted>")
    } else {
        format!("{cname}=<redacted>;{attrs}")
    }
}

fn headers_of(r: &ureq::Response) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in r.headers_names() {
        let lname = name.to_ascii_lowercase();
        for v in r.all(&name) {
            out.push((lname.clone(), redact(&lname, v)));
        }
    }
    out
}

/// Fetch `/` with redirects; for an `http://` target also record the first
/// hop unfollowed, to see whether it redirects to HTTPS.
pub fn observe(
    target: &Target,
    timeout: Duration,
    trust_anything: bool,
) -> Result<HttpObservation, String> {
    let url = format!("{}/", target.origin());
    let r = call(&agent(timeout, 5, trust_anything), &url)?;
    let mut obs = HttpObservation {
        url: url.clone(),
        final_url: r.get_url().to_string(),
        status: r.status(),
        headers: headers_of(&r),
        first_hop_status: None,
        first_hop_location: None,
    };
    if target.scheme == "http" {
        let first = call(&agent(timeout, 0, trust_anything), &url)?;
        obs.first_hop_status = Some(first.status());
        obs.first_hop_location = first.header("location").map(str::to_string);
    }
    Ok(obs)
}

/// Fetch each sensitive path, redirects not followed, reading at most 64 KiB.
pub fn observe_paths(
    target: &Target,
    timeout: Duration,
    trust_anything: bool,
) -> Result<Vec<PathObservation>, String> {
    let agent = agent(timeout, 0, trust_anything);
    let mut out = Vec::new();
    for s in SENSITIVE {
        let url = format!("{}{}", target.origin(), s.path);
        let r = call(&agent, &url)?;
        let status = r.status();
        let mut body = Vec::new();
        let _ = r.into_reader().take(64 * 1024).read_to_end(&mut body);
        out.push(PathObservation {
            path: s.path.to_string(),
            status,
            matched: status == 200 && (s.matches)(&body),
            bytes: body.len(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(final_url: &str, headers: &[(&str, &str)]) -> HttpObservation {
        HttpObservation {
            url: final_url.to_string(),
            final_url: final_url.to_string(),
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            first_hop_status: None,
            first_hop_location: None,
        }
    }
    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.invariant_id.as_str()).collect()
    }

    #[test]
    fn hardened_response_is_clean() {
        let o = obs(
            "https://x/",
            &[
                ("content-type", "text/html"),
                ("strict-transport-security", "max-age=63072000"),
                (
                    "content-security-policy",
                    "default-src 'self'; frame-ancestors 'none'",
                ),
                ("x-content-type-options", "nosniff"),
                ("server", "nginx"),
                ("set-cookie", "session=abc; Secure; HttpOnly; SameSite=Lax"),
            ],
        );
        assert!(
            analyze(&o, "https://x").is_empty(),
            "{:?}",
            ids(&analyze(&o, "x"))
        );
    }

    #[test]
    fn bare_html_response_reports_each_missing_control() {
        let o = obs(
            "https://x/",
            &[
                ("content-type", "text/html; charset=utf-8"),
                ("server", "Apache/2.4.41 (Ubuntu)"),
                ("set-cookie", "PHPSESSID=deadbeef; path=/"),
            ],
        );
        let f = analyze(&o, "https://x");
        let got = ids(&f);
        for want in [
            "rt_missing_hsts",
            "rt_missing_csp",
            "rt_missing_frame_options",
            "rt_missing_content_type_options",
            "rt_insecure_cookie",
            "rt_server_banner",
        ] {
            assert!(got.contains(&want), "missing {want} in {got:?}");
        }
        assert!(f.iter().all(|f| f.is_proven()));
        // The cookie value must never appear anywhere in the finding.
        let cookie = f
            .iter()
            .find(|f| f.invariant_id == "rt_insecure_cookie")
            .unwrap();
        assert!(!cookie.snippet.contains("deadbeef") && !cookie.message.contains("deadbeef"));
    }

    #[test]
    fn json_api_is_not_asked_for_csp_or_frame_options() {
        let o = obs(
            "https://api/",
            &[
                ("content-type", "application/json"),
                ("strict-transport-security", "max-age=1"),
                ("x-content-type-options", "nosniff"),
            ],
        );
        assert!(analyze(&o, "https://api").is_empty());
    }

    #[test]
    fn frame_ancestors_in_csp_counts_as_frame_protection() {
        let o = obs(
            "https://x/",
            &[
                ("content-type", "text/html"),
                ("strict-transport-security", "max-age=1"),
                ("x-content-type-options", "nosniff"),
                ("content-security-policy", "frame-ancestors 'self'"),
            ],
        );
        assert!(!ids(&analyze(&o, "x")).contains(&"rt_missing_frame_options"));
    }

    #[test]
    fn plain_http_without_https_redirect() {
        let mut o = obs("http://x/", &[("x-content-type-options", "nosniff")]);
        o.first_hop_status = Some(200);
        assert!(ids(&analyze(&o, "http://x")).contains(&"rt_no_https_redirect"));
        o.first_hop_status = Some(301);
        o.first_hop_location = Some("https://x/".into());
        assert!(!ids(&analyze(&o, "http://x")).contains(&"rt_no_https_redirect"));
        // No HSTS is not asked of a plain-HTTP response.
        assert!(!ids(&analyze(&o, "http://x")).contains(&"rt_missing_hsts"));
    }

    #[test]
    fn banner_without_version_is_fine() {
        assert!(!reveals_version("nginx"));
        assert!(!reveals_version("cloudflare"));
        assert!(reveals_version("nginx/1.18.0"));
        assert!(reveals_version("PHP/8.1"));
        assert!(!reveals_version("Apache"));
    }

    #[test]
    fn non_session_cookie_over_https_without_secure_is_low() {
        let o = obs(
            "https://x/",
            &[
                ("strict-transport-security", "max-age=1"),
                ("x-content-type-options", "nosniff"),
                ("set-cookie", "theme=dark; Path=/"),
            ],
        );
        let f = analyze(&o, "x");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn exposed_path_needs_signature_not_just_200() {
        let paths = vec![
            PathObservation {
                path: "/.git/config".into(),
                status: 200,
                matched: false,
                bytes: 5000,
            },
            PathObservation {
                path: "/.env".into(),
                status: 200,
                matched: true,
                bytes: 120,
            },
            PathObservation {
                path: "/phpinfo.php".into(),
                status: 404,
                matched: false,
                bytes: 0,
            },
        ];
        let f = analyze_paths(&paths);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].invariant_id, "rt_exposed_sensitive_path");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].file, "/.env");
    }

    #[test]
    fn cookie_values_are_redacted_at_collection_and_still_evaluated() {
        assert_eq!(
            redact("set-cookie", "sid=abc123; Path=/; HttpOnly"),
            "sid=<redacted>; Path=/; HttpOnly"
        );
        assert_eq!(redact("set-cookie", "sid=abc123"), "sid=<redacted>");
        assert_eq!(redact("server", "nginx/1.2"), "nginx/1.2");
        // The redacted form carries what the evaluator needs.
        let o = obs(
            "https://x/",
            &[
                ("strict-transport-security", "max-age=1"),
                ("x-content-type-options", "nosniff"),
                (
                    "set-cookie",
                    &redact("set-cookie", "sessionid=abc123; Path=/"),
                ),
            ],
        );
        let f = analyze(&o, "x");
        assert_eq!(ids(&f), vec!["rt_insecure_cookie"]);
        let text = format!("{:?}", o) + &f[0].message + &f[0].snippet;
        assert!(
            !text.contains("abc123"),
            "value must not survive collection"
        );
    }

    #[test]
    fn signatures() {
        assert!(dotenv_like(b"DB_HOST=x\nDB_PASS=y\n"));
        assert!(!dotenv_like(b"<html>not found</html>"));
        assert!(!dotenv_like(b"A=1")); // one line: too weak
        assert!((SENSITIVE[0].matches)(
            b"[core]\n\trepositoryformatversion = 0"
        ));
        assert!(!(SENSITIVE[0].matches)(b"<html>"));
    }
}
