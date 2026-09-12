#![deny(unsafe_code)]

//! Software composition analysis.
//!
//! Three questions about a repository's dependencies, answered from its
//! manifests and lockfiles without running anything:
//!
//! 1. **Is any pinned version known-vulnerable?** — [`advisory`] matches
//!    every locked package against an OSV or RustSec database.
//! 2. **Is the dependency set actually pinned?** — [`pinning`] flags floating
//!    requirements and manifests with no lockfile.
//! 3. **What is in it?** — [`sbom`] emits CycloneDX so the answer can be
//!    handed to anyone.
//!
//! Every finding carries its taxonomy row and the advisory ID that justifies
//! it. A missing advisory database is reported as such, never as "no
//! vulnerabilities".

pub mod advisory;
pub mod integrity;
pub mod lockfile;
pub mod pinning;
pub mod sbom;
pub mod version;

use std::path::Path;
use truent_core::Finding;

pub use advisory::{Advisory, AdvisoryDb};
pub use lockfile::{discover_lockfiles, parse_lockfile, Ecosystem, Package};

/// Everything a run produces.
#[derive(Debug, Default)]
pub struct ScaReport {
    /// Packages resolved from every lockfile found.
    pub packages: Vec<Package>,
    /// Lockfiles that were parsed, relative to the scan root.
    pub lockfiles: Vec<String>,
    /// Findings: vulnerable, unpinned, unlocked.
    pub findings: Vec<Finding>,
    /// Advisory database summary, if one was used.
    pub advisory_source: Option<String>,
    /// Number of advisories in the database.
    pub advisory_count: usize,
}

/// Run the whole analysis over a directory.
pub fn analyze(root: &Path, db: Option<&AdvisoryDb>) -> ScaReport {
    let mut report = ScaReport::default();

    for lock in discover_lockfiles(root) {
        let rel = lock
            .strip_prefix(root)
            .unwrap_or(&lock)
            .to_string_lossy()
            .replace('\\', "/");
        match std::fs::read_to_string(&lock) {
            Ok(text) => {
                let pkgs = parse_lockfile(&lock, &text);
                report.lockfiles.push(rel.clone());
                report
                    .findings
                    .extend(integrity::lockfile_checks(&lock, &text, &rel));
                if let Some(db) = db {
                    report
                        .findings
                        .extend(advisory::match_packages(db, &pkgs, &rel));
                }
                report.packages.extend(pkgs);
            }
            Err(_) => continue,
        }
    }

    report.findings.extend(pinning::detect(root));
    report.findings.extend(integrity::confusion(root));
    report
        .findings
        .extend(integrity::typosquats(&report.packages));

    if let Some(db) = db {
        report.advisory_source = Some(db.source.clone());
        report.advisory_count = db.len();
    }

    report.packages.sort_by(|a, b| {
        (a.ecosystem.as_str(), &a.name, &a.version).cmp(&(
            b.ecosystem.as_str(),
            &b.name,
            &b.version,
        ))
    });
    report
        .packages
        .dedup_by(|a, b| a.ecosystem == b.ecosystem && a.name == b.name && a.version == b.version);
    report
}

/// Errors from loading advisory data.
#[derive(Debug, thiserror::Error)]
pub enum ScaError {
    #[error("{0}: {1}")]
    Io(std::path::PathBuf, String),
    #[error("{0}: {1}")]
    Malformed(std::path::PathBuf, String),
}
