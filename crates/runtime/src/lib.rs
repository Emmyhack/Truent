//! Runtime probe: live, non-exploitative checks of a target you are
//! authorized to test.
//!
//! Everything else in Truent reads files. This crate connects to a running
//! system and reports what it *observed* — which is why its findings are the
//! only ones in the workspace marked [`Finding::proven`]: an expired
//! certificate or a missing `Strict-Transport-Security` header is not an
//! inference from source, it is a fact recorded from the wire.
//!
//! # What it does
//!
//! - **TLS** — handshake, certificate chain trust, expiry, self-signature,
//!   and whether the server can speak a modern protocol at all.
//! - **HTTP** — security headers (HSTS, CSP, frame options, content-type
//!   options), cookie flags, HTTP→HTTPS redirect, version-revealing banners.
//! - **Exposed paths** — a short fixed list of files that must never be
//!   served (`/.git/config`, `/.env`, …), confirmed by *content signature*,
//!   never by status code alone.
//! - **Ports** — a TCP connect check of a small default set; exposed
//!   administrative or database services are ranked higher than the web ports
//!   a web target is expected to have.
//!
//! # What it deliberately does not do
//!
//! It sends only `GET` requests and TCP connects — the traffic a browser and
//! `curl -I` produce. It carries no payloads, attempts no authentication, and
//! never writes to the target. It is a probe, not an exploit framework, and
//! it refuses to run without [`ProbeOptions::authorized`].
//!
//! # Structure
//!
//! Every check is split into an *observation* (a plain struct describing what
//! the wire returned) and an *evaluator* (a pure function from observation to
//! findings). The evaluators are tested offline against fixtures; the network
//! layer in each module is a thin fetch that produces the observation.

pub mod http;
pub mod ports;
pub mod tls;

use serde::Serialize;
use std::time::Duration;
use truent_core::{Finding, Severity};

/// Where the probe points.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Target {
    /// `http` or `https`.
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Target {
    /// Parse `example.com`, `example.com:8443`, `https://example.com/path`.
    /// A bare host defaults to HTTPS on 443.
    pub fn parse(s: &str) -> Result<Self, ProbeError> {
        let s = s.trim();
        let (scheme, rest) = match s.split_once("://") {
            Some((sc, r)) => (sc.to_ascii_lowercase(), r),
            None => ("https".to_string(), s),
        };
        if scheme != "http" && scheme != "https" {
            return Err(ProbeError::Target(format!("unsupported scheme `{scheme}`")));
        }
        let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') || h.starts_with('[') => (
                h.trim_matches(['[', ']']).to_string(),
                p.parse::<u16>()
                    .map_err(|_| ProbeError::Target(format!("bad port `{p}`")))?,
            ),
            _ => (
                hostport.trim_matches(['[', ']']).to_string(),
                if scheme == "http" { 80 } else { 443 },
            ),
        };
        if host.is_empty() {
            return Err(ProbeError::Target("empty host".into()));
        }
        Ok(Self { scheme, host, port })
    }

    /// The origin URL, e.g. `https://example.com:8443`.
    pub fn origin(&self) -> String {
        let default = if self.scheme == "http" { 80 } else { 443 };
        if self.port == default {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

/// How the probe runs.
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    /// The operator asserts they are authorized to test this target. The
    /// probe refuses to send anything without it.
    pub authorized: bool,
    pub timeout: Duration,
    /// Empty disables the port check.
    pub ports: Vec<u16>,
    /// Probe the exposed-path list.
    pub check_paths: bool,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            authorized: false,
            timeout: Duration::from_secs(8),
            ports: ports::DEFAULT_PORTS.to_vec(),
            check_paths: true,
        }
    }
}

/// The result of a probe: what was observed, and what it means.
#[derive(Debug, Default, Serialize)]
pub struct ProbeReport {
    pub target: Option<Target>,
    pub tls: Option<tls::TlsObservation>,
    pub http: Option<http::HttpObservation>,
    pub exposed: Vec<http::PathObservation>,
    pub ports: Vec<ports::PortObservation>,
    /// Checks that could not run, with the reason. Never silently skipped.
    pub errors: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("invalid target: {0}")]
    Target(String),
    #[error(
        "refusing to probe {0}: pass --authorized to assert you are permitted to test this target"
    )]
    NotAuthorized(String),
}

/// Construct a runtime finding. `file` carries the URL or `host:port` the
/// observation was made against; there is no source line, so `line` is 1 —
/// SARIF requires a positive line and the location text is the URL.
///
/// Every finding here is [`Finding::proven`]: it records something the probe
/// observed on the wire, not something inferred from text.
pub(crate) fn finding(
    id: &str,
    sev: Severity,
    location: &str,
    message: String,
    evidence: String,
) -> Finding {
    Finding::new(
        id.to_string(),
        sev,
        location.to_string(),
        1,
        0,
        message,
        evidence,
    )
    .with_metadata("chain".to_string(), "runtime".to_string())
    .proven()
}

/// Probe a target. Refuses without `opts.authorized`.
pub fn probe(target: &Target, opts: &ProbeOptions) -> Result<ProbeReport, ProbeError> {
    if !opts.authorized {
        return Err(ProbeError::NotAuthorized(target.origin()));
    }
    let mut report = ProbeReport {
        target: Some(target.clone()),
        ..Default::default()
    };
    let now = unix_now();

    // TLS first: it decides whether HTTPS fetches can proceed and how.
    let mut trust_anything = false;
    if target.scheme == "https" {
        match tls::observe(&target.host, target.port, opts.timeout) {
            Ok(obs) => {
                trust_anything = !obs.chain_verified;
                report.findings.extend(tls::analyze(
                    &obs,
                    &format!("{}:{}", target.host, target.port),
                    now,
                ));
                report.tls = Some(obs);
            }
            Err(failure) => {
                // Incompatible protocol support is a finding; a refused or
                // timed-out connection is only an error.
                report.findings.extend(tls::analyze_failure(
                    &failure,
                    &format!("{}:{}", target.host, target.port),
                ));
                report.errors.push(format!("tls: {failure}"));
            }
        }
    }

    // HTTP headers. When the chain did not verify we still read headers — the
    // untrusted certificate is already a finding — but never over a
    // connection whose certificate we could not at least see.
    match http::observe(target, opts.timeout, trust_anything) {
        Ok(obs) => {
            report
                .findings
                .extend(http::analyze(&obs, &target.origin()));
            report.http = Some(obs);
        }
        Err(e) => report.errors.push(format!("http: {e}")),
    }

    if opts.check_paths {
        match http::observe_paths(target, opts.timeout, trust_anything) {
            Ok(paths) => {
                report.findings.extend(http::analyze_paths(&paths));
                report.exposed = paths;
            }
            Err(e) => report.errors.push(format!("paths: {e}")),
        }
    }

    if !opts.ports.is_empty() {
        let obs = ports::observe(&target.host, &opts.ports, opts.timeout);
        report
            .findings
            .extend(ports::analyze(&obs, &target.host, target.port));
        report.ports = obs;
    }

    report
        .findings
        .sort_by_key(|f| std::cmp::Reverse(f.severity));
    Ok(report)
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_targets() {
        let t = Target::parse("example.com").unwrap();
        assert_eq!(
            (t.scheme.as_str(), t.host.as_str(), t.port),
            ("https", "example.com", 443)
        );
        let t = Target::parse("http://example.com:8080/x?y").unwrap();
        assert_eq!(
            (t.scheme.as_str(), t.host.as_str(), t.port),
            ("http", "example.com", 8080)
        );
        assert_eq!(t.origin(), "http://example.com:8080");
        assert_eq!(
            Target::parse("https://a.b").unwrap().origin(),
            "https://a.b"
        );
        assert!(Target::parse("ftp://x").is_err());
        assert!(Target::parse("").is_err());
    }

    #[test]
    fn refuses_without_authorization() {
        let t = Target::parse("example.com").unwrap();
        let e = probe(&t, &ProbeOptions::default()).unwrap_err();
        assert!(matches!(e, ProbeError::NotAuthorized(_)));
        assert!(e.to_string().contains("--authorized"));
    }

    #[test]
    fn findings_are_proven_and_tagged_runtime() {
        let f = finding(
            "rt_missing_hsts",
            Severity::Low,
            "https://x",
            "m".into(),
            "e".into(),
        );
        assert!(f.is_proven());
        assert_eq!(f.metadata.get("chain").map(String::as_str), Some("runtime"));
        assert_eq!(f.line, 1);
    }
}
