//! Dependency analysis, advisory matching, and SBOM output.

use super::{FormatArg, SeverityArg};
use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;
use std::path::PathBuf;

/// Arguments for `deps`.
#[derive(Parser)]
pub(crate) struct DepsArgs {
    /// Repository root.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Directory of OSV JSON and/or RustSec advisories for vulnerability matching.
    #[arg(long, value_name = "DIR")]
    advisory_db: Option<PathBuf>,
    /// Write a CycloneDX 1.5 SBOM here.
    #[arg(long, value_name = "FILE")]
    sbom: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,
    /// Fail if findings at or above this severity exist.
    #[arg(long, value_enum, default_value = "critical")]
    fail_on: SeverityArg,
}

/// Handle `deps`.
pub(crate) fn run(args: DepsArgs, quiet: bool) -> Result<()> {
    let db = match &args.advisory_db {
        Some(dir) => Some(
            truent_sca::AdvisoryDb::load_dir(dir)
                .with_context(|| format!("loading advisories from {}", dir.display()))?,
        ),
        None => None,
    };
    let report = truent_sca::analyze(&args.path, db.as_ref());

    if let Some(out) = &args.sbom {
        let name = args
            .path
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "project".into());
        let doc = truent_sca::sbom::cyclonedx(&report.packages, &name, env!("CARGO_PKG_VERSION"));
        std::fs::write(out, serde_json::to_string_pretty(&doc)?)
            .with_context(|| format!("writing {}", out.display()))?;
        if !quiet {
            eprintln!(
                "✓ SBOM written to {} ({} components)",
                out.display(),
                report.packages.len()
            );
        }
    }

    match args.format {
        FormatArg::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "lockfiles": report.lockfiles,
                    "packages": report.packages.len(),
                    "advisory_source": report.advisory_source,
                    "advisory_count": report.advisory_count,
                    "findings": report.findings,
                }))?
            );
        }
        _ => {
            println!(
                "Dependencies: {} package(s) from {} lockfile(s)",
                report.packages.len(),
                report.lockfiles.len()
            );
            for l in &report.lockfiles {
                println!("  {l}");
            }
            match &report.advisory_source {
                Some(src) => println!("Advisories: {} from {src}", report.advisory_count),
                None => println!("Advisories: none loaded — pass --advisory-db to match against OSV/RustSec. No vulnerability claims are made without one."),
            }
            println!();
            if report.findings.is_empty() {
                println!("No dependency findings.");
            } else {
                for f in &report.findings {
                    println!(
                        "[{}] {}  {}:{}",
                        f.severity.name(),
                        f.invariant_id,
                        f.file,
                        f.line
                    );
                    println!("    {}", f.message);
                }
            }
        }
    }

    let fail_rank = super::severity_arg_rank(&args.fail_on);
    if report
        .findings
        .iter()
        .any(|f| super::severity_rank(f.severity.name()) >= fail_rank)
    {
        std::process::exit(1);
    }
    Ok(())
}
