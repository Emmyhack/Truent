//! Advisory databases and matching.
//!
//! Two on-disk formats are read:
//!
//! - **OSV JSON** (`*.json`, one advisory per file, as published by
//!   osv.dev and the GitHub Advisory Database): `affected[].package`,
//!   `ranges[].events` with `introduced` / `fixed` / `last_affected`, and
//!   explicit `versions[]`.
//! - **RustSec** (`crates/<name>/RUSTSEC-*.md` with a TOML front block):
//!   `[versions] patched = [">= x"]`, `unaffected = ["< y"]`.
//!
//! Matching is exact: a package is affected when its pinned version falls in
//! an affected range and is neither patched nor unaffected.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use truent_core::{Finding, Severity};

use crate::lockfile::{Ecosystem, Package};
use crate::version::Version;
use crate::ScaError;

/// One advisory, normalised.
#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub aliases: Vec<String>,
    /// CVSS-ish score if the source gave one.
    pub score: Option<f32>,
    /// `unmaintained` / `unsound` / `notice` — informational, not a vulnerability.
    pub informational: Option<String>,
    pub affected: Vec<Affected>,
}

/// One affected package spec within an advisory.
#[derive(Debug, Clone)]
pub struct Affected {
    pub ecosystem: Ecosystem,
    pub name: String,
    /// `(introduced, fixed-or-last_affected, inclusive_end)` half-open ranges.
    pub ranges: Vec<(Option<Version>, Option<Version>, bool)>,
    /// Explicitly listed affected versions.
    pub versions: Vec<Version>,
    /// RustSec semantics: semver requirements that are patched…
    pub patched: Vec<String>,
    /// …and that were never affected. When either list is non-empty a version
    /// is affected iff it satisfies none of them.
    pub unaffected: Vec<String>,
}

/// A loaded database.
#[derive(Debug, Default)]
pub struct AdvisoryDb {
    /// Human description of where it came from.
    pub source: String,
    by_package: HashMap<(Ecosystem, String), Vec<Advisory>>,
    count: usize,
}

impl AdvisoryDb {
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Load every advisory under `dir`, in either format.
    pub fn load_dir(dir: &Path) -> Result<Self, ScaError> {
        let mut db = Self {
            source: dir.display().to_string(),
            ..Default::default()
        };
        let mut files = Vec::new();
        collect(dir, &mut files, 0);
        for f in files {
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            let parsed = if f.extension().map(|e| e == "json").unwrap_or(false) {
                parse_osv(&text)
            } else if f.extension().map(|e| e == "md").unwrap_or(false)
                && text.starts_with("```toml")
            {
                parse_rustsec(&text)
            } else {
                None
            };
            if let Some(a) = parsed {
                db.insert(a);
            }
        }
        Ok(db)
    }

    /// Add one advisory.
    pub fn insert(&mut self, a: Advisory) {
        self.count += 1;
        for aff in &a.affected {
            self.by_package
                .entry((aff.ecosystem, aff.name.to_lowercase()))
                .or_default()
                .push(a.clone());
        }
    }

    /// Advisories that name this package at all.
    pub fn for_package(&self, eco: Ecosystem, name: &str) -> &[Advisory] {
        self.by_package
            .get(&(eco, name.to_lowercase()))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 8 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out, depth + 1);
        } else {
            out.push(p);
        }
    }
}

// ---------------- OSV -----------------------------------------------------

#[derive(Deserialize)]
struct OsvDoc {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}
#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}
#[derive(Deserialize)]
struct OsvAffected {
    package: Option<OsvPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}
#[derive(Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}
#[derive(Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<HashMap<String, String>>,
}

/// Parse an OSV document.
pub fn parse_osv(text: &str) -> Option<Advisory> {
    let d: OsvDoc = serde_json::from_str(text).ok()?;
    let mut affected = Vec::new();
    for a in d.affected {
        let Some(p) = a.package else { continue };
        let Some(eco) = Ecosystem::from_osv(&p.ecosystem) else {
            continue;
        };
        let mut ranges = Vec::new();
        for r in a.ranges {
            if r.kind != "SEMVER" && r.kind != "ECOSYSTEM" {
                continue;
            }
            let mut intro: Option<Version> = None;
            let mut open = false;
            for ev in r.events {
                if let Some(i) = ev.get("introduced") {
                    intro = if i == "0" {
                        Some(Version::parse("0").unwrap())
                    } else {
                        Version::parse(i)
                    };
                    open = true;
                } else if let Some(f) = ev.get("fixed") {
                    if open {
                        ranges.push((intro.clone(), Version::parse(f), false));
                        open = false;
                    }
                } else if let Some(l) = ev.get("last_affected") {
                    if open {
                        ranges.push((intro.clone(), Version::parse(l), true));
                        open = false;
                    }
                }
            }
            if open {
                ranges.push((intro, None, false));
            }
        }
        let versions = a
            .versions
            .iter()
            .filter_map(|v| Version::parse(v))
            .collect();
        affected.push(Affected {
            ecosystem: eco,
            name: p.name,
            ranges,
            versions,
            patched: vec![],
            unaffected: vec![],
        });
    }
    let score = d
        .severity
        .iter()
        .find(|s| s.kind.starts_with("CVSS"))
        .and_then(|s| cvss_base_score(&s.score));
    let informational = d
        .database_specific
        .as_ref()
        .and_then(|v| v.get("informational"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Some(Advisory {
        id: d.id,
        summary: d
            .summary
            .or(d.details)
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or("")
            .to_string(),
        aliases: d.aliases,
        score,
        informational,
        affected,
    })
}

/// Rough base score from a CVSS vector: uses the numeric score if the string
/// is one, else estimates from the impact metrics.
fn cvss_base_score(s: &str) -> Option<f32> {
    if let Ok(n) = s.parse::<f32>() {
        return Some(n);
    }
    let high = |k: &str| s.contains(&format!("/{k}:H"));
    let n = [high("C"), high("I"), high("A")]
        .iter()
        .filter(|b| **b)
        .count();
    let net = s.contains("AV:N");
    Some(match (n, net) {
        (3, true) => 9.8,
        (3, false) => 7.8,
        (2, true) => 8.1,
        (1, true) => 7.5,
        (0, _) => 5.3,
        _ => 6.5,
    })
}

// ---------------- RustSec -------------------------------------------------

/// Parse a RustSec advisory markdown file.
///
/// `patched` / `unaffected` are TOML arrays of semver *requirements*, often
/// compound (`">= 0.8.4, < 0.9.0"`) and often spanning several lines. They
/// are kept as requirements and evaluated by [`req_matches`]: a version is
/// affected iff it satisfies none of them. An earlier version reduced them to
/// a single bound and reported `generic-array 0.14.7` as vulnerable to an
/// advisory whose patched list ends in `">= 0.13.3"`.
pub fn parse_rustsec(text: &str) -> Option<Advisory> {
    let start = text.find("```toml")? + 7;
    let end = text[start..].find("```")? + start;
    let toml = &text[start..end];
    let field = |k: &str| -> Option<String> {
        toml.lines().find_map(|l| {
            l.trim()
                .strip_prefix(&format!("{k} = "))
                .map(|v| v.trim().trim_matches('"').to_string())
        })
    };
    // Every quoted string between `k = [` and the matching `]`, across lines.
    let array = |k: &str| -> Vec<String> {
        let Some(i) = toml.find(&format!("{k} = [")) else {
            return vec![];
        };
        let rest = &toml[i..];
        let Some(j) = rest.find(']') else {
            return vec![];
        };
        rest[..j]
            .split('"')
            .skip(1)
            .step_by(2)
            .map(|q| q.trim().to_string())
            .filter(|q| !q.is_empty())
            .collect()
    };
    let id = field("id")?;
    let name = field("package")?;
    let patched = array("patched");
    let unaffected = array("unaffected");
    // `patched = []` with nothing unaffected (the shape of every
    // unmaintained-crate advisory) means every version is affected.
    let ranges = if patched.is_empty() && unaffected.is_empty() {
        vec![(Version::parse("0"), None, false)]
    } else {
        vec![]
    };
    let title = text
        .lines()
        .find(|l| l.starts_with("# "))
        .map(|l| l[2..].to_string())
        .unwrap_or_default();
    Some(Advisory {
        id,
        summary: title,
        aliases: array("aliases"),
        score: field("cvss").and_then(|v| cvss_base_score(&v)),
        informational: field("informational"),
        affected: vec![Affected {
            ecosystem: Ecosystem::CratesIo,
            name,
            ranges,
            versions: vec![],
            patched,
            unaffected,
        }],
    })
}

/// Whether `v` satisfies one comma-separated semver requirement such as
/// `">= 0.8.4, < 0.9.0"`, `"^1.2"`, `"~0.3.1"` or `"= 1.0.0"`.
pub fn req_matches(v: &Version, req: &str) -> bool {
    for part in req.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (op, target) = ["<=", ">=", "<", ">", "=", "^", "~"]
            .iter()
            .find(|o| part.starts_with(*o))
            .map(|o| (*o, part[o.len()..].trim()))
            .unwrap_or(("^", part));
        let Some(t) = Version::parse(target) else {
            return false;
        };
        let (vc, tc) = (v.core(), t.core());
        let at = |c: &[u64], i: usize| c.get(i).copied().unwrap_or(0);
        let ok = match op {
            ">=" => *v >= t,
            ">" => *v > t,
            "<=" => *v <= t,
            "<" => *v < t,
            "=" => *v == t,
            // Caret: same leftmost non-zero component.
            "^" => {
                *v >= t
                    && if at(tc, 0) != 0 {
                        at(vc, 0) == at(tc, 0)
                    } else if at(tc, 1) != 0 {
                        at(vc, 0) == 0 && at(vc, 1) == at(tc, 1)
                    } else {
                        at(vc, 0) == 0 && at(vc, 1) == 0 && at(vc, 2) == at(tc, 2)
                    }
            }
            // Tilde: same major.minor when a minor is given.
            "~" => *v >= t && at(vc, 0) == at(tc, 0) && (tc.len() < 2 || at(vc, 1) == at(tc, 1)),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

// ---------------- matching -----------------------------------------------

fn is_affected(aff: &Affected, v: &Version) -> bool {
    if !aff.patched.is_empty() || !aff.unaffected.is_empty() {
        return !aff.patched.iter().any(|r| req_matches(v, r))
            && !aff.unaffected.iter().any(|r| req_matches(v, r));
    }
    if aff.versions.iter().any(|x| x == v) {
        return true;
    }
    aff.ranges.iter().any(|(intro, end, inclusive)| {
        let after_intro = intro.as_ref().map(|i| v >= i).unwrap_or(true);
        let before_end = match end {
            None => true,
            Some(e) => {
                if *inclusive {
                    v <= e
                } else {
                    v < e
                }
            }
        };
        after_intro && before_end
    })
}

/// Match packages against the database; one finding per (package, advisory).
pub fn match_packages(db: &AdvisoryDb, packages: &[Package], lockfile: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in packages {
        let Some(v) = Version::parse(&p.version) else {
            continue;
        };
        for adv in db.for_package(p.ecosystem, &p.name) {
            let hit = adv.affected.iter().any(|a| {
                a.ecosystem == p.ecosystem
                    && a.name.eq_ignore_ascii_case(&p.name)
                    && is_affected(a, &v)
            });
            if !hit {
                continue;
            }
            let sev = if adv.informational.is_some() {
                Severity::Low
            } else {
                match adv.score {
                    Some(s) if s >= 9.0 => Severity::Critical,
                    Some(s) if s >= 7.0 => Severity::High,
                    Some(s) if s >= 4.0 => Severity::Medium,
                    Some(_) => Severity::Low,
                    None => Severity::High,
                }
            };
            let aliases = if adv.aliases.is_empty() {
                String::new()
            } else {
                format!(" ({})", adv.aliases.join(", "))
            };
            let has_fix = adv.affected.iter().any(|a| {
                !a.patched.is_empty() || a.ranges.iter().any(|(_, e, inc)| !*inc && e.is_some())
            });
            let fix = if has_fix {
                " — a fixed version exists".to_string()
            } else {
                String::new()
            };
            let message = format!(
                "{} {} {}: {}{}{}",
                p.ecosystem.as_str(),
                p.name,
                p.version,
                adv.id,
                aliases,
                if adv.summary.is_empty() {
                    fix
                } else {
                    format!(" — {}{}", adv.summary, fix)
                }
            );
            let snippet = format!("{} {}", p.name, p.version);
            // Literal IDs, so the taxonomy's emitted-ID scraper sees them.
            let f = if adv.informational.is_some() {
                Finding::new(
                    "sca_unmaintained_dependency".to_string(),
                    sev,
                    lockfile.to_string(),
                    1,
                    0,
                    message,
                    snippet,
                )
            } else {
                Finding::new(
                    "sca_vulnerable_dependency".to_string(),
                    sev,
                    lockfile.to_string(),
                    1,
                    0,
                    message,
                    snippet,
                )
            };
            out.push(
                f.with_metadata("advisory".to_string(), adv.id.clone())
                    .with_metadata("package".to_string(), p.purl())
                    .with_metadata("analyzer".to_string(), "sca".to_string()),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn osv(id: &str, eco: &str, name: &str, intro: &str, fixed: Option<&str>) -> Advisory {
        let fixed_ev = fixed
            .map(|f| format!(r#",{{"fixed":"{f}"}}"#))
            .unwrap_or_default();
        parse_osv(&format!(r#"{{"id":"{id}","summary":"bad","aliases":["CVE-1"],"affected":[{{"package":{{"ecosystem":"{eco}","name":"{name}"}},"ranges":[{{"type":"SEMVER","events":[{{"introduced":"{intro}"}}{fixed_ev}]}}]}}],"severity":[{{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}"#)).unwrap()
    }
    fn pkg(eco: Ecosystem, n: &str, v: &str) -> Package {
        Package {
            ecosystem: eco,
            name: n.into(),
            version: v.into(),
            source_file: "lock".into(),
        }
    }

    #[test]
    fn half_open_ranges_and_fixed_boundary() {
        let mut db = AdvisoryDb::default();
        db.insert(osv("GHSA-1", "npm", "lodash", "0", Some("4.17.21")));
        assert_eq!(
            match_packages(&db, &[pkg(Ecosystem::Npm, "lodash", "4.17.20")], "l").len(),
            1
        );
        assert!(
            match_packages(&db, &[pkg(Ecosystem::Npm, "lodash", "4.17.21")], "l").is_empty(),
            "fixed version is not affected"
        );
        assert!(
            match_packages(&db, &[pkg(Ecosystem::PyPI, "lodash", "4.17.20")], "l").is_empty(),
            "ecosystem must match"
        );
        let f = &match_packages(&db, &[pkg(Ecosystem::Npm, "lodash", "1.0.0")], "l")[0];
        assert_eq!(f.severity, Severity::Critical, "CVSS 9.8 → critical");
        assert!(f.message.contains("CVE-1"));
    }

    #[test]
    fn open_ended_and_informational() {
        let mut db = AdvisoryDb::default();
        db.insert(osv("GHSA-2", "PyPI", "leftpad", "1.0.0", None));
        assert!(match_packages(&db, &[pkg(Ecosystem::PyPI, "leftpad", "0.9.0")], "l").is_empty());
        assert_eq!(
            match_packages(&db, &[pkg(Ecosystem::PyPI, "leftpad", "9.0.0")], "l").len(),
            1
        );

        let rs = "```toml\n[advisory]\nid = \"RUSTSEC-2024-0370\"\npackage = \"serde_yaml\"\ninformational = \"unmaintained\"\n\n[versions]\npatched = []\n```\n\n# serde_yaml is unmaintained\n";
        let a = parse_rustsec(rs).unwrap();
        assert_eq!(a.informational.as_deref(), Some("unmaintained"));
        let mut db = AdvisoryDb::default();
        db.insert(a);
        let f = match_packages(
            &db,
            &[pkg(Ecosystem::CratesIo, "serde_yaml", "0.9.34")],
            "Cargo.lock",
        );
        assert_eq!(f[0].invariant_id, "sca_unmaintained_dependency");
    }

    #[test]
    fn rustsec_compound_multiline_patched_ranges() {
        // RUSTSEC-2020-0146 as published: six compound patched ranges across
        // lines. 0.14.7 satisfies ">= 0.13.3" and is not affected; 0.12.3
        // falls in the gap between ">= 0.11.2, < 0.12.0" and ">= 0.12.4" and is.
        let rs = "```toml\n[advisory]\nid = \"RUSTSEC-2020-0146\"\npackage = \"generic-array\"\naliases = [\"CVE-2020-36465\"]\n\n[versions]\npatched = [\n    \">= 0.8.4, < 0.9.0\",\n    \">= 0.9.1, < 0.10.0\",\n    \">= 0.10.1, < 0.11.0\",\n    \">= 0.11.2, < 0.12.0\",\n    \">= 0.12.4, < 0.13.0\",\n    \">= 0.13.3\",\n]\nunaffected = [\"< 0.8.0\"]\n```\n\n# arr! macro erases lifetimes\n";
        let a = parse_rustsec(rs).unwrap();
        assert_eq!(a.affected[0].patched.len(), 6);
        assert_eq!(a.aliases, vec!["CVE-2020-36465"]);
        let mut db = AdvisoryDb::default();
        db.insert(a);
        let hit = |v: &str| {
            !match_packages(&db, &[pkg(Ecosystem::CratesIo, "generic-array", v)], "C").is_empty()
        };
        assert!(!hit("0.14.7"), "patched by >= 0.13.3");
        assert!(!hit("0.12.4"), "patched");
        assert!(hit("0.12.3"), "in the gap");
        assert!(hit("0.8.0"), "first affected");
        assert!(!hit("0.7.9"), "unaffected");
    }

    #[test]
    fn rustsec_no_patched_versions_affects_everything() {
        // An unmaintained-crate advisory: patched = [] and no unaffected list
        // means every version is affected, and no fix is advertised.
        let rs = "```toml\n[advisory]\nid = \"RUSTSEC-2025-0007\"\npackage = \"ring\"\ninformational = \"unmaintained\"\n\n[versions]\npatched = []\n```\n\n# *ring* is unmaintained\n";
        let mut db = AdvisoryDb::default();
        db.insert(parse_rustsec(rs).unwrap());
        let f = match_packages(&db, &[pkg(Ecosystem::CratesIo, "ring", "0.17.14")], "C");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].invariant_id, "sca_unmaintained_dependency");
        assert!(!f[0].message.contains("fixed version exists"));
    }

    #[test]
    fn requirement_operators() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(req_matches(&v("1.5.0"), "^1.2"));
        assert!(!req_matches(&v("2.0.0"), "^1.2"));
        assert!(req_matches(&v("0.3.9"), "^0.3.1"));
        assert!(!req_matches(&v("0.4.0"), "^0.3.1"));
        assert!(req_matches(&v("1.2.9"), "~1.2.3"));
        assert!(!req_matches(&v("1.3.0"), "~1.2.3"));
        assert!(req_matches(&v("0.8.5"), ">= 0.8.4, < 0.9.0"));
        assert!(!req_matches(&v("0.9.0"), ">= 0.8.4, < 0.9.0"));
        assert!(req_matches(&v("1.0.0"), "= 1.0.0"));
        assert!(!req_matches(&v("1.0.1"), "= 1.0.0"));
    }

    #[test]
    fn rustsec_patched_bound() {
        let rs = "```toml\n[advisory]\nid = \"RUSTSEC-2018-0005\"\npackage = \"serde_yaml\"\n\n[versions]\npatched = [\">= 0.8.4\"]\nunaffected = [\"< 0.6.0-rc1\"]\n```\n\n# Uncontrolled recursion\n";
        let mut db = AdvisoryDb::default();
        db.insert(parse_rustsec(rs).unwrap());
        assert_eq!(
            match_packages(&db, &[pkg(Ecosystem::CratesIo, "serde_yaml", "0.8.0")], "C").len(),
            1
        );
        assert!(
            match_packages(&db, &[pkg(Ecosystem::CratesIo, "serde_yaml", "0.8.4")], "C").is_empty()
        );
        assert!(
            match_packages(&db, &[pkg(Ecosystem::CratesIo, "serde_yaml", "0.5.0")], "C").is_empty(),
            "unaffected lower bound"
        );
    }
}
