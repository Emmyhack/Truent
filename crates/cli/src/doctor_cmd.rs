//! Installation health checks and `doctor` output.

use super::FormatArg;
use crate::ui::{render_doctor_results, HealthCheck};
use anyhow::Result;
use clap::Parser;
use serde_json::json;
use std::path::PathBuf;

/// Arguments for the `doctor` subcommand.
#[derive(Parser)]
pub(crate) struct DoctorArgs {
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,

    /// Output file.
    #[arg(long)]
    output: Option<PathBuf>,
}

pub(crate) fn run(args: DoctorArgs, quiet: bool) -> Result<()> {
    use super::doctor_fixtures as fx;

    let checks = vec![
        super::core_health_check(),
        super::detector_health_check(
            "EVM analyzer",
            truent_analyzer_evm::detectors::run_all_detectors(fx::EVM, "self-test.sol").len(),
        ),
        super::detector_health_check(
            "Solana analyzer",
            truent_analyzer_solana::run_all_detectors(fx::SOLANA, "self-test.rs").len(),
        ),
        super::detector_health_check(
            "Move analyzer",
            truent_analyzer_move::run_all_detectors(fx::MOVE, "self-test.move").len(),
        ),
        super::detector_health_check(
            "Soroban analyzer",
            truent_analyzer_soroban::run_all_detectors(fx::SOROBAN, "self-test.rs").len(),
        ),
        super::detector_health_check(
            "General analyzer",
            truent_analyzer_general::run_all_detectors(fx::GENERAL, "self-test.py").len(),
        ),
        super::sca_health_check(),
        super::runtime_health_check(),
        HealthCheck {
            component: "Exposure & remediation".to_string(),
            passed: truent_core::all_metadata().len() == truent_core::taxonomy::all().len()
                && !truent_pathways::chains().is_empty(),
            message: format!(
                "{} detectors have an attack profile, fix and verify step; {} attack chains known",
                truent_core::exposure::all().len(),
                truent_pathways::chains().len()
            ),
        },
        symbolic_health_check(),
        HealthCheck {
            component: "Release checklist".to_string(),
            passed: truent_pathways::SECTIONS.len() == 33
                && truent_pathways::Signal::all().len() >= 20,
            message: format!(
                "{} sections, {} items, {} repository signals",
                truent_pathways::SECTIONS.len(),
                truent_pathways::SECTIONS
                    .iter()
                    .map(|s| s.items.len())
                    .sum::<usize>(),
                truent_pathways::Signal::all().len()
            ),
        },
        HealthCheck {
            component: "Security pathways".to_string(),
            passed: truent_pathways::pathways().len() >= 21,
            message: format!(
                "{} pathways mapped to native detectors, hosted skills and assessment controls",
                truent_pathways::pathways().len()
            ),
        },
        super::dsl_health_check(),
        HealthCheck {
            component: "Invariant library".to_string(),
            passed: super::builtin_invariant_count() > 0,
            message: format!(
                "{} built-in invariants loaded",
                super::builtin_invariant_count()
            ),
        },
        HealthCheck {
            component: "Detector taxonomy".to_string(),
            passed: !truent_core::taxonomy::all().is_empty(),
            message: format!(
                "{} detectors mapped to CWE/SWC/OWASP/DASP",
                truent_core::taxonomy::all().len()
            ),
        },
        super::report_health_check(),
        super::skills_health_check(),
    ];

    match args.format {
        FormatArg::Text => {
            if !quiet {
                println!("{}", render_doctor_results(&checks));
            }
        }
        FormatArg::Json => write_json_report(&checks, args.output.as_ref(), quiet)?,
        FormatArg::Html => anyhow::bail!(
            "HTML output is not supported by `truent doctor`; use --format text or --format json"
        ),
    }

    if checks.iter().any(|check| !check.passed) {
        std::process::exit(1);
    }
    Ok(())
}

fn symbolic_health_check() -> HealthCheck {
    let (findings, stats) = truent_symbolic::halmos::parse(
        r#"{"exitcode":1,"test_results":{"t/A.t.sol:A":[{"name":"check_x(uint256)","exitcode":1,"num_models":1,"models":[{"model":{"p":{"variable_name":"x","solidity_type":"uint256","value":1}},"is_valid":true}]}]}}"#,
        "p",
    );
    let installed = truent_symbolic::detect();
    let installed = if installed.is_empty() {
        "none (pip install halmos)".to_string()
    } else {
        installed
            .iter()
            .map(|item| format!("{} {}", item.tool.name(), item.version))
            .collect::<Vec<_>>()
            .join(", ")
    };

    HealthCheck {
        component: "Symbolic execution".to_string(),
        passed: stats.failed == 1 && findings.len() == 1 && findings[0].is_proven(),
        message: format!(
            "halmos/hevm/mythril parsers turn counterexamples into proven findings; installed: {installed}"
        ),
    }
}

fn write_json_report(checks: &[HealthCheck], output: Option<&PathBuf>, quiet: bool) -> Result<()> {
    let mut components = serde_json::Map::new();
    for check in checks {
        components.insert(
            check.component.clone(),
            json!({
                "status": if check.passed { "ok" } else { "error" },
                "message": &check.message,
            }),
        );
    }

    let report = json!({
        "status": if checks.iter().all(|check| check.passed) { "healthy" } else { "error" },
        "components": components,
    });
    let output_json = serde_json::to_string_pretty(&report)?;

    if let Some(output_path) = output {
        std::fs::write(output_path, output_json)?;
        if !quiet {
            eprintln!("✓ Report written to {}", output_path.display());
        }
    } else {
        println!("{output_json}");
    }
    Ok(())
}
