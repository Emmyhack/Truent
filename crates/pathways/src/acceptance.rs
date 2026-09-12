//! Risk acceptance: a finding that is known, understood, and consciously
//! carried — with a reason, an owner and an expiry — is not the same as a
//! finding nobody has looked at.
//!
//! The checklist's last item is "no unresolved high-severity vulnerabilities
//! *without explicit risk acceptance*". This is the explicit part. Entries
//! live in `.truent.toml`:
//!
//! ```toml
//! [[accept]]
//! id     = "sca_unmaintained_dependency"
//! path   = "Cargo.lock"                       # prefix/substring match; omit for any
//! match  = "paste"                            # optional: must appear in the message
//! reason = "transitive via alloy-primitives; no maintained replacement resolvable"
//! owner  = "@geekstrancend"
//! until  = "2027-03-31"                       # ISO date; expired acceptances do not apply
//! ```
//!
//! An acceptance is applied only when every field it specifies matches, and
//! only until its date. Accepted findings are reported as ACCEPTED, never
//! dropped: the release check lists each one with its reason and owner.

use serde::{Deserialize, Serialize};
use std::path::Path;
use truent_core::Finding;

/// One acceptance entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acceptance {
    pub id: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(rename = "match", default)]
    pub matches: Option<String>,
    pub reason: String,
    pub owner: String,
    /// ISO date `YYYY-MM-DD`.
    pub until: String,
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    accept: Vec<Acceptance>,
}

/// Load acceptances from `<root>/.truent.toml`. Missing file → none.
/// A malformed file is an error: a typo must not silently un-accept.
pub fn load(root: &Path) -> Result<Vec<Acceptance>, String> {
    let p = root.join(".truent.toml");
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Ok(Vec::new());
    };
    parse(&text)
}

/// Parse the `[[accept]]` entries out of a `.truent.toml` text.
pub fn parse(text: &str) -> Result<Vec<Acceptance>, String> {
    let f: File = toml::from_str(text).map_err(|e| format!(".truent.toml: {e}"))?;
    for a in &f.accept {
        if a.reason.trim().len() < 15 {
            return Err(format!(
                "acceptance of {}: reason is too short to be a reason",
                a.id
            ));
        }
        if parse_date(&a.until).is_none() {
            return Err(format!(
                "acceptance of {}: `until` must be YYYY-MM-DD, got {}",
                a.id, a.until
            ));
        }
        if a.owner.trim().is_empty() {
            return Err(format!("acceptance of {}: owner is required", a.id));
        }
    }
    Ok(f.accept)
}

fn parse_date(s: &str) -> Option<(i32, u32, u32)> {
    let mut it = s.split('-');
    let y = it.next()?.parse().ok()?;
    let m = it.next()?.parse().ok()?;
    let d = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// Today as `(y, m, d)` from the system clock.
fn today() -> (i32, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    civil_from_days(secs.div_euclid(86_400))
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

impl Acceptance {
    /// Whether this entry is still in force on `now`.
    pub fn in_force_on(&self, now: (i32, u32, u32)) -> bool {
        parse_date(&self.until).map(|u| now <= u).unwrap_or(false)
    }

    /// Whether this entry applies to `f` (ignoring expiry).
    pub fn matches(&self, f: &Finding) -> bool {
        if f.invariant_id != self.id {
            return false;
        }
        if let Some(p) = &self.path {
            let file = f.file.trim_start_matches("./");
            if !(file.starts_with(p.trim_start_matches("./")) || file.contains(p.as_str())) {
                return false;
            }
        }
        if let Some(m) = &self.matches {
            if !f.message.contains(m.as_str()) && !f.snippet.contains(m.as_str()) {
                return false;
            }
        }
        true
    }
}

/// A finding paired with the acceptance that covers it.
#[derive(Debug, Clone, Serialize)]
pub struct Accepted {
    pub finding: Finding,
    pub acceptance: Acceptance,
}

/// Split findings into those still open and those covered by an in-force
/// acceptance. Expired acceptances are returned separately so the report can
/// say so.
pub fn apply(
    findings: Vec<Finding>,
    acceptances: &[Acceptance],
) -> (Vec<Finding>, Vec<Accepted>, Vec<Acceptance>) {
    apply_on(findings, acceptances, today())
}

/// [`apply`] with an explicit date, for tests.
pub fn apply_on(
    findings: Vec<Finding>,
    acceptances: &[Acceptance],
    now: (i32, u32, u32),
) -> (Vec<Finding>, Vec<Accepted>, Vec<Acceptance>) {
    let expired: Vec<Acceptance> = acceptances
        .iter()
        .filter(|a| !a.in_force_on(now))
        .cloned()
        .collect();
    let live: Vec<&Acceptance> = acceptances.iter().filter(|a| a.in_force_on(now)).collect();
    let mut open = Vec::new();
    let mut accepted = Vec::new();
    for f in findings {
        match live.iter().find(|a| a.matches(&f)) {
            Some(a) => accepted.push(Accepted {
                finding: f,
                acceptance: (*a).clone(),
            }),
            None => open.push(f),
        }
    }
    (open, accepted, expired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use truent_core::Severity;

    fn f(id: &str, file: &str, msg: &str) -> Finding {
        Finding::new(
            id.into(),
            Severity::High,
            file.into(),
            1,
            0,
            msg.into(),
            "s".into(),
        )
    }

    const TOML: &str = r#"
[[accept]]
id = "sca_unmaintained_dependency"
path = "Cargo.lock"
match = "paste"
reason = "transitive via alloy-primitives; no maintained replacement resolvable"
owner = "@maintainer"
until = "2027-03-31"

[[accept]]
id = "evm_single_eoa_admin"
path = "examples/evm_token.sol"
reason = "intentionally minimal example contract used in docs"
owner = "@maintainer"
until = "2026-01-01"
"#;

    #[test]
    fn parses_and_validates() {
        let a = parse(TOML).unwrap();
        assert_eq!(a.len(), 2);
        assert!(
            parse("[[accept]]\nid='x'\nreason='short'\nowner='o'\nuntil='2030-01-01'\n").is_err()
        );
        assert!(parse(
            "[[accept]]\nid='x'\nreason='a long enough reason here'\nowner='o'\nuntil='soon'\n"
        )
        .is_err());
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn matching_and_expiry() {
        let a = parse(TOML).unwrap();
        let findings = vec![
            f(
                "sca_unmaintained_dependency",
                "Cargo.lock",
                "crates.io paste 1.0.15: unmaintained",
            ),
            f(
                "sca_unmaintained_dependency",
                "Cargo.lock",
                "crates.io ring 0.17: unmaintained",
            ),
            f(
                "evm_single_eoa_admin",
                "./examples/evm_token.sol",
                "single admin",
            ),
            f("gen_sql_injection", "app.py", "x"),
        ];
        let (open, accepted, expired) = apply_on(findings, &a, (2026, 9, 12));
        assert_eq!(
            accepted.len(),
            1,
            "only the paste entry matches and is in force"
        );
        assert!(accepted[0].finding.message.contains("paste"));
        assert_eq!(
            expired.len(),
            1,
            "the example acceptance expired on 2026-01-01"
        );
        assert_eq!(open.len(), 3);
        // Before expiry, the example is accepted too.
        let (open2, accepted2, _) = apply_on(
            vec![f("evm_single_eoa_admin", "examples/evm_token.sol", "m")],
            &a,
            (2025, 12, 31),
        );
        assert!(open2.is_empty() && accepted2.len() == 1);
    }

    #[test]
    fn dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_708), (2026, 9, 12));
        assert!(parse_date("2026-13-01").is_none());
    }
}
