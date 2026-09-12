#![deny(unsafe_code)]
#![allow(dead_code)] // Functions used in future feature development
#![allow(missing_docs)] // CLI is self-documenting via clap help

//! Truent CLI: Multi-chain smart contract invariant enforcement tool.
//!
//! Production-grade terminal UI with professional styling and comprehensive
//! analysis capabilities for smart contract security.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Instant;

// UI module
mod ui;
use ui::*;

mod skills_cmd;

// Import analyzers
use truent_analyzer_evm::EvmAnalyzer;
use truent_analyzer_general as general;
use truent_analyzer_move::MoveAnalyzer;
use truent_analyzer_solana::SolanaAnalyzer;
use truent_analyzer_soroban::SorobanAnalyzer;
use truent_core::taxonomy::taxonomy_for;
use truent_core::traits::ChainAnalyzer;
use truent_core::{CodeFuzzer, Finding};
use truent_library::InvariantLibrary;
use truent_report::html_escape;

// ============================================================================
// CLI STRUCTURE
// ============================================================================

/// Truent: Production-grade multi-chain invariant analysis tool.
#[derive(Parser)]
#[command(
    name = "truent",
    about = "Enforce invariants on smart contracts across Solana, EVM, Move, and Soroban",
    version = env!("CARGO_PKG_VERSION"),
    author = "Truent Contributors"
)]
struct Cli {
    /// Enable verbose output.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress all non-error output.
    #[arg(long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze contracts for invariant violations (recommended: use 'scan' instead).
    Check(CheckArgs),
    /// Scan contracts with full invariant enforcement (primary command).
    Scan(ScanArgs),
    /// Generate a report from analysis results.
    Report(ReportArgs),
    /// Initialize a .truent.toml configuration file.
    Init(InitArgs),
    /// Check that all Truent components are working correctly.
    Doctor(DoctorArgs),
    /// Display exploit registry.
    Registry(RegistryArgs),
    /// Display compiled invariants.
    Invariants(InvariantsArgs),
    /// Run fuzzer on contract invariants.
    Fuzz(FuzzArgs),
    /// Show how detectors map to CWE, SWC, OWASP SC Top 10 and DASP.
    Taxonomy(TaxonomyArgs),
    /// Discover, inspect and run external security skill libraries.
    Skills(skills_cmd::SkillsArgs),
    /// Dependency analysis: vulnerable, unpinned and unlocked dependencies; SBOM.
    Deps(DepsArgs),
    /// The security-pathway map: how every class of security is covered.
    Pathways(PathwaysArgs),
    /// Assess a repository against the whole security model.
    Assess(AssessArgs),
    /// Generate a STRIDE threat model from discovered structure.
    ThreatModel(ThreatModelArgs),
    /// Probe a live target you are authorized to test: TLS, security headers, exposed paths, open ports.
    Probe(ProbeArgs),
    /// How exploitable each finding is, which findings compose into attack chains, and the fix for each.
    Exposure(ExposureArgs),
    /// Generate preventive controls for this repository (gitignore, Dependabot, pre-commit, CI gate, security headers).
    Harden(HardenArgs),
    /// Walk the 33-section codebase safety & security checklist and report what is verified, what is missing, and what needs a person.
    ReleaseCheck(ReleaseCheckArgs),
    /// Symbolic execution: drive halmos / hevm / Mythril on a Foundry project; counterexamples become proven findings.
    Symbolic(SymbolicArgs),
}

/// Arguments for `deps`.
#[derive(Parser)]
struct DepsArgs {
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

/// Arguments for `pathways`.
#[derive(Parser)]
struct PathwaysArgs {
    /// Show one pathway by id (e.g. api-security).
    id: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,
}

/// Arguments for `probe`.
#[derive(Parser)]
struct ProbeArgs {
    /// Target: `example.com`, `https://example.com:8443`, `http://10.0.0.5`.
    target: String,
    /// Assert that you are authorized to test this target. Required: the probe
    /// refuses to send anything without it.
    #[arg(long)]
    authorized: bool,
    /// Per-connection timeout in seconds.
    #[arg(long, default_value_t = 8)]
    timeout: u64,
    /// Comma-separated ports to check (default: 20 common ports); `none` disables.
    #[arg(long, value_name = "LIST")]
    ports: Option<String>,
    /// Skip the exposed-path checks (/.git/config, /.env, …).
    #[arg(long)]
    no_paths: bool,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,
    /// Also write a SARIF 2.1.0 report here.
    #[arg(long, value_name = "FILE")]
    sarif: Option<PathBuf>,
    /// Fail if findings at or above this severity exist.
    #[arg(long, value_enum, default_value = "critical")]
    fail_on: SeverityArg,
}

/// Arguments for `exposure`.
#[derive(Parser)]
struct ExposureArgs {
    /// Repository root.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Advisory database for the dependency half.
    #[arg(long, value_name = "DIR")]
    advisory_db: Option<PathBuf>,
    /// A `truent probe --format json` report to fold in (live findings raise exploitability).
    #[arg(long, value_name = "FILE")]
    probe_report: Option<PathBuf>,
    /// Only findings rated at or above this exploitability.
    #[arg(long, value_enum, default_value = "theoretical")]
    min: ExploitabilityArg,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,
    /// Write the report here (default: stdout).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ExploitabilityArg {
    Theoretical,
    Unlikely,
    Possible,
    Likely,
}

/// Arguments for `release-check`.
#[derive(Parser)]
struct ReleaseCheckArgs {
    /// Repository root.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Advisory database for the dependency half.
    #[arg(long, value_name = "DIR")]
    advisory_db: Option<PathBuf>,
    /// A `truent probe --format json` report; resolves the DAST/header/cookie items.
    #[arg(long, value_name = "FILE")]
    probe_report: Option<PathBuf>,
    /// A `truent symbolic --format json` report; resolves the symbolic-execution item.
    #[arg(long, value_name = "FILE")]
    symbolic_report: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,
    /// Write the report here (default: stdout).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Exit non-zero unless the verdict is READY.
    #[arg(long)]
    strict: bool,
}

/// Arguments for `symbolic`.
#[derive(Parser)]
struct SymbolicArgs {
    /// Foundry project root (has foundry.toml and check_*/prove_* tests).
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Executor to use (default: the first of halmos, hevm, mythril found on PATH).
    #[arg(long, value_enum)]
    tool: Option<SymbolicToolArg>,
    /// Overall timeout in seconds.
    #[arg(long, default_value_t = 900)]
    timeout: u64,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,
    /// Write the report here (default: stdout).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Fail if a proven counterexample is found.
    #[arg(long)]
    strict: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum SymbolicToolArg {
    Halmos,
    Hevm,
    Mythril,
}

/// Arguments for `harden`.
#[derive(Parser)]
struct HardenArgs {
    /// Repository root.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Write the files (never overwrites; `.gitignore` gets missing lines appended). Default: print the plan.
    #[arg(long)]
    write: bool,
    /// Output format for the plan.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,
}

/// Arguments for `assess`.
#[derive(Parser)]
struct AssessArgs {
    /// Repository root.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Advisory database for the dependency half.
    #[arg(long, value_name = "DIR")]
    advisory_db: Option<PathBuf>,
    /// Write the Markdown report here (default: stdout).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,
}

/// Arguments for `threat-model`.
#[derive(Parser)]
struct ThreatModelArgs {
    /// Repository root.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Write the Markdown report here (default: stdout).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,
}

/// Arguments for the `taxonomy` subcommand.
#[derive(Parser)]
struct TaxonomyArgs {
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: TaxonomyFormat,

    /// Only show detectors for this chain.
    #[arg(long, value_enum)]
    chain: Option<ChainArg>,

    /// Only show detectors mapped to this taxonomy ID (e.g. CWE-841, SWC-107,
    /// SC01, DASP-1). Matched case-insensitively against every registry.
    #[arg(long)]
    id: Option<String>,

    /// Output file.
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Output formats for `truent taxonomy`.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum TaxonomyFormat {
    /// Human-readable table.
    Text,
    /// Machine-readable JSON.
    Json,
    /// Markdown table, as committed to `docs/COVERAGE.md`.
    Markdown,
}

/// Arguments for the `doctor` subcommand.
#[derive(Parser)]
struct DoctorArgs {
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,

    /// Output file.
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Arguments for the `check` subcommand.
#[derive(Parser)]
struct CheckArgs {
    /// Path to analyze (file or directory).
    path: PathBuf,

    /// Blockchain to analyze.
    #[arg(long, value_enum, default_value = "evm")]
    chain: ChainArg,

    /// Fail if violations at or above this severity are found.
    #[arg(long, value_enum, default_value = "low")]
    fail_on: SeverityArg,

    /// Also fail on unproven leads, not just results reproduced by execution.
    ///
    /// Off by default: a lead is a pattern match that was never executed, and
    /// blocking a deploy on one trains teams to bypass the gate.
    #[arg(long, default_value_t = false)]
    fail_on_leads: bool,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,

    /// Output file (for non-text formats).
    #[arg(long)]
    output: Option<PathBuf>,

    /// Write a SARIF 2.1.0 report to this path, in addition to the normal
    /// output.
    ///
    /// SARIF is what GitHub code scanning ingests. Truent's findings carry a
    /// real CWE taxonomy, so uploading this file makes them filterable by
    /// weakness class alongside every other scanner's results.
    #[arg(long, value_name = "PATH")]
    sarif: Option<PathBuf>,

    /// Configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Random seed for reproducible analysis (default: 42).
    #[arg(long)]
    seed: Option<u64>,
}

/// Arguments for the `scan` subcommand (enhanced version of check).
#[derive(Parser)]
struct ScanArgs {
    /// Path to analyze (file or directory).
    path: PathBuf,

    /// Blockchain to analyze.
    #[arg(long, value_enum, default_value = "evm")]
    chain: ChainArg,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    output: FormatArg,

    /// Output file (for non-text formats).
    #[arg(long)]
    file: Option<PathBuf>,

    /// Write a SARIF 2.1.0 report to this path, in addition to the normal
    /// output.
    ///
    /// SARIF is what GitHub code scanning ingests. Truent's findings carry a
    /// real CWE taxonomy, so uploading this file makes them filterable by
    /// weakness class alongside every other scanner's results.
    #[arg(long, value_name = "PATH")]
    sarif: Option<PathBuf>,

    /// Minimum severity to report.
    #[arg(long, value_enum)]
    severity: Option<SeverityArg>,

    /// Filter by specific invariant ID (can be used multiple times).
    #[arg(long)]
    invariant: Vec<String>,

    /// RPC URL for on-chain verification (e.g., bridge config checks).
    #[arg(long)]
    rpc: Option<String>,

    /// Fail the scan if any issues at or above this severity are found.
    #[arg(long, value_enum, default_value = "critical")]
    fail_on: SeverityArg,

    /// Also fail on unproven leads, not just results reproduced by execution.
    ///
    /// Off by default: a lead is a pattern match that was never executed, and
    /// blocking a deploy on one trains teams to bypass the gate.
    #[arg(long, default_value_t = false)]
    fail_on_leads: bool,

    /// Use parallel scanning with rayon (thread pool).
    #[arg(long)]
    parallel: bool,

    /// Disable ANSI color output.
    #[arg(long)]
    no_color: bool,

    /// Configuration file.
    #[arg(long)]
    config: Option<PathBuf>,
}

/// Arguments for the `registry` subcommand.
#[derive(Parser)]
struct RegistryArgs {
    /// Subcommand for registry operations.
    #[command(subcommand)]
    action: RegistryAction,
}

#[derive(Subcommand)]
enum RegistryAction {
    /// List all known exploits in the registry.
    List {
        /// Filter by chain (evm, solana, move).
        #[arg(long)]
        chain: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: FormatArg,
    },
    /// Show details of a specific exploit.
    Show {
        /// Exploit ID (e.g., "euler-finance-2023").
        id: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: FormatArg,
    },
}

/// Arguments for the `invariants` subcommand.
#[derive(Parser)]
struct InvariantsArgs {
    /// Subcommand for invariants operations.
    #[command(subcommand)]
    action: InvariantsAction,
}

#[derive(Subcommand)]
enum InvariantsAction {
    /// List all compiled invariants.
    List {
        /// Filter by chain (evm, solana, move).
        #[arg(long)]
        chain: Option<String>,
        /// Filter by severity.
        #[arg(long)]
        severity: Option<SeverityArg>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: FormatArg,
    },
    /// Show details of a specific invariant.
    Show {
        /// Invariant ID (e.g., "evm_reentrancy_classic").
        id: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: FormatArg,
    },
}

/// Arguments for the `fuzz` subcommand.
#[derive(Parser)]
struct FuzzArgs {
    /// Contract file or directory to fuzz. Omit when using --address to
    /// fuzz an already-deployed contract by fetching its bytecode instead
    /// of reading local source.
    path: Option<PathBuf>,

    /// Blockchain to fuzz for.
    #[arg(long, value_enum, default_value = "evm")]
    chain: ChainArg,

    /// Maximum call sequence depth for fuzzer.
    #[arg(long, default_value = "10")]
    depth: usize,

    /// Number of iterations to run.
    #[arg(long, default_value = "10000")]
    iterations: u32,

    /// Random seed for reproducibility.
    #[arg(long)]
    seed: Option<u64>,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    output: FormatArg,

    /// Output file.
    #[arg(long)]
    file: Option<PathBuf>,

    /// Run the dynamic/coverage-guided invariant fuzzer (deploys the
    /// contract in-memory via revm, generates call sequences, and checks
    /// auto-detected invariants after every call) instead of the default
    /// source-mutation crash fuzzer. EVM only for now.
    #[arg(long)]
    dynamic: bool,

    /// Fuzz an already-deployed contract by address instead of local
    /// source: fetches its bytecode via --rpc-url and probes it against
    /// known ERC20/Ownable selectors (no ABI available for an unverified
    /// contract). Only valid with --dynamic; requires --rpc-url. Does not
    /// fork the contract's on-chain storage — only its code.
    #[arg(long, conflicts_with = "path")]
    address: Option<String>,

    /// JSON-RPC endpoint to fetch bytecode from when using --address.
    #[arg(long, requires = "address")]
    rpc_url: Option<String>,

    /// Solana fuzz plan (JSON): the genesis accounts, account pool, pins and
    /// invariants that an IDL cannot express. Required for
    /// `--dynamic --chain solana`, where `path` is the program's Anchor IDL.
    #[arg(long)]
    plan: Option<PathBuf>,

    /// Truent DSL file (`.invar`) of properties to check after every call.
    ///
    /// Auto-detection only recognises shapes it already knows, so the
    /// properties that decide whether a specific protocol is correct — is it
    /// solvent, can a provider always exit — have to be stated. Each free
    /// variable binds to a zero-argument view of the same name on the
    /// contract; a variable that cannot be bound is an error, never a
    /// silently skipped check.
    #[arg(long)]
    invariants: Option<PathBuf>,
}

/// Arguments for the `report` subcommand.
#[derive(Parser)]
struct ReportArgs {
    /// Input results file.
    #[arg(long)]
    input: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,

    /// Output file.
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Arguments for the `init` subcommand.
#[derive(Parser)]
struct InitArgs {
    /// Project directory.
    #[arg(default_value = ".")]
    path: PathBuf,
}

/// Supported blockchain networks.
#[derive(ValueEnum, Clone, Debug)]
enum ChainArg {
    /// Ethereum and EVM-compatible chains.
    Evm,
    /// Solana.
    Solana,
    /// Move (Aptos, Sui).
    Move,
    /// Soroban (Stellar).
    Soroban,
    /// Any repository: secrets, CI workflows, containers, application code.
    General,
    /// Every applicable engine, chosen per file by content and path.
    Auto,
}

/// Violation severity levels.
#[derive(ValueEnum, Clone, Debug)]
enum SeverityArg {
    /// Low severity issues.
    Low,
    /// Medium severity issues.
    Medium,
    /// High severity issues.
    High,
    /// Critical severity issues.
    Critical,
}

/// Output format options.
#[derive(ValueEnum, Clone, Debug)]
enum FormatArg {
    /// Human-readable text with colors and boxes.
    Text,
    /// JSON (one object per line).
    Json,
    /// HTML report.
    Html,
}

// ============================================================================
// MAIN
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Show banner on first launch if TTY
    if is_tty() {
        eprintln!("{}", render_banner(env!("CARGO_PKG_VERSION")));
    }

    match cli.command {
        Commands::Check(args) => cmd_check(args, cli.quiet, cli.verbose)?,
        Commands::Scan(args) => cmd_scan(args, cli.quiet, cli.verbose)?,
        Commands::Report(args) => cmd_report(args, cli.quiet)?,
        Commands::Init(args) => cmd_init(args, cli.quiet)?,
        Commands::Doctor(args) => cmd_doctor(args, cli.quiet)?,
        Commands::Registry(args) => cmd_registry(args, cli.quiet)?,
        Commands::Invariants(args) => cmd_invariants(args, cli.quiet)?,
        Commands::Fuzz(args) => cmd_fuzz(args, cli.quiet, cli.verbose)?,
        Commands::Taxonomy(args) => cmd_taxonomy(args)?,
        Commands::Skills(args) => skills_cmd::run(args, cli.quiet)?,
        Commands::Deps(args) => cmd_deps(args, cli.quiet)?,
        Commands::Pathways(args) => cmd_pathways(args)?,
        Commands::Assess(args) => cmd_assess(args, cli.quiet)?,
        Commands::ThreatModel(args) => cmd_threat_model(args)?,
        Commands::Probe(args) => cmd_probe(args, cli.quiet)?,
        Commands::Exposure(args) => cmd_exposure(args, cli.quiet)?,
        Commands::Harden(args) => cmd_harden(args, cli.quiet)?,
        Commands::ReleaseCheck(args) => cmd_release_check(args, cli.quiet)?,
        Commands::Symbolic(args) => cmd_symbolic(args, cli.quiet)?,
    }

    Ok(())
}

// ============================================================================
// COMMAND HANDLERS
// ============================================================================

/// Handle the `check` subcommand.
fn cmd_check(args: CheckArgs, quiet: bool, verbose: bool) -> Result<()> {
    let start_time = Instant::now();

    // Set random seed for reproducibility
    let seed = args.seed.unwrap_or(42);
    if verbose && !quiet {
        eprintln!("Setting random seed to: {}", seed);
    }

    let chain_name = match &args.chain {
        ChainArg::Evm => "EVM",
        ChainArg::Solana => "Solana",
        ChainArg::Move => "Move",
        ChainArg::Soroban => "Soroban",
        ChainArg::General => "General",
        ChainArg::Auto => "Auto",
    };

    // Convert config path to String for header
    let config_str = args
        .config
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());
    let config_ref = config_str.as_deref();

    // Display header (only for text format)
    if !quiet && matches!(args.format, FormatArg::Text) {
        println!(
            "{}",
            render_check_header(
                &args.path.display().to_string(),
                chain_name,
                config_ref,
                args.config.as_ref().map(|p| p.exists()).unwrap_or(false)
            )
        );
    }

    // Create spinner (only for text format)
    let spinner = if !quiet && matches!(args.format, FormatArg::Text) {
        Some(Spinner::start(&format!(
            "Analyzing {}...",
            args.path.display()
        )))
    } else {
        None
    };

    // Run actual analysis. Findings are kept alongside the display-shaped
    // violations because SARIF needs the raw form.
    let findings = match run_analysis_findings(&args.path, &args.chain, verbose) {
        Ok(f) => f,
        Err(e) => {
            if let Some(s) = spinner {
                s.stop_with_failure(&e.to_string());
            }
            return Err(e);
        }
    };
    let total_findings = findings.len();
    let violations: Vec<Violation> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| finding_to_violation(f, i + 1, total_findings))
        .collect();

    if let Some(sarif_path) = &args.sarif {
        write_sarif(&findings, sarif_path, quiet)?;
    }

    let duration_secs = start_time.elapsed().as_secs_f64();

    // Count violations by severity
    let (critical, high, medium, low) = count_violations_by_severity(&violations);
    // Approximate count of live detectors for this chain (a single detector can produce
    // multiple findings, so this is a lower bound, not an exact "checks run" count).
    let detector_count = match args.chain {
        ChainArg::Evm => 44,
        ChainArg::Solana => 11,
        ChainArg::Move => 7,
        ChainArg::Soroban => 9,
        ChainArg::General => 18,
        ChainArg::Auto => 100,
    };
    let total_checks = detector_count.max(violations.len());
    let passed = total_checks.saturating_sub(violations.len());

    // Build summary
    let proven = violations.iter().filter(|v| v.evidence.is_proven()).count();
    let leads = violations.len() - proven;

    let summary = AnalysisSummary {
        target: args.path.display().to_string(),
        chain: chain_name.to_string(),
        total_checks,
        violations: violations.len(),
        passed,
        proven,
        leads,
        suppressed: 0,
        duration_secs,
        severity_breakdown: SeverityBreakdown {
            critical,
            high,
            medium,
            low,
        },
    };

    // Stop spinner with success
    if let Some(s) = spinner {
        s.stop_with_success(&format!("{} checks in {:.1}s", total_checks, duration_secs));
    }

    // Handle different output formats
    match args.format {
        FormatArg::Text => {
            // Build text report
            let mut report_text = String::new();

            // Display violations
            if !violations.is_empty() {
                report_text.push_str(&render_violations(&violations));
                report_text.push('\n');
            }

            // Display passed checks (verbose mode)
            if verbose {
                let passed_check_names = vec![
                    "balance_conservation".to_string(),
                    "no_integer_overflow".to_string(),
                    "owner_only_withdraw".to_string(),
                    "access_control_present".to_string(),
                    "arithmetic_overflow".to_string(),
                    "missing_signer_check".to_string(),
                ];
                report_text.push_str(&render_passed_checks(&passed_check_names));
                report_text.push('\n');
            }

            // Display summary
            report_text.push_str(&render_summary(&summary));

            if let Some(output_path) = args.output {
                // Write to file
                std::fs::write(&output_path, &report_text)?;
                if !quiet {
                    eprintln!("✓ Report written to {}", output_path.display());
                }
            } else {
                // Write to stdout
                if !quiet {
                    println!("{}", report_text);
                }
            }
        }
        FormatArg::Json => {
            // Create JSON report
            let report = json!({
                "version": env!("CARGO_PKG_VERSION"),
                "chain": summary.chain,
                "target": summary.target,
                "duration_ms": (summary.duration_secs * 1000.0) as u64,
                "summary": {
                    "total_checks": summary.total_checks,
                    "violations": summary.violations,
                    "critical": summary.severity_breakdown.critical,
                    "high": summary.severity_breakdown.high,
                    "medium": summary.severity_breakdown.medium,
                    "low": summary.severity_breakdown.low,
                    "passed": summary.passed,
                    "suppressed": summary.suppressed,
                },
                "violations": violations,
            });

            let output_json = serde_json::to_string_pretty(&report)?;

            if let Some(output_path) = args.output {
                // Write to file
                std::fs::write(&output_path, &output_json)?;
                if !quiet {
                    eprintln!("✓ Report written to {}", output_path.display());
                }
            } else {
                // Write to stdout
                println!("{}", output_json);
            }
        }
        FormatArg::Html => {
            // Generate HTML report
            let html_report = generate_html_report(&summary, &violations);

            if let Some(output_path) = args.output {
                // Write to file
                std::fs::write(&output_path, &html_report)?;
                if !quiet {
                    eprintln!("✓ HTML report written to {}", output_path.display());
                }
            } else {
                // Write to stdout
                println!("{}", html_report);
            }
        }
    }

    // Exit non-zero only for results that were actually reproduced, at or
    // above --fail-on.
    //
    // A lead is a pattern match nobody executed; failing a build on one asks
    // the team to treat a guess as a defect, and the first false positive
    // teaches them to bypass the gate entirely. Leads are reported and
    // surfaced in the summary, but only a proven violation blocks. Pass
    // --fail-on-leads to gate on unproven results too.
    let fail_rank = severity_arg_rank(&args.fail_on);
    let blocking = violations.iter().any(|v| {
        severity_rank(&v.severity) >= fail_rank && (v.evidence.is_proven() || args.fail_on_leads)
    });
    if blocking {
        std::process::exit(1);
    }

    Ok(())
}

/// Generate an HTML report of the security analysis.
/// Render a violation's registry citations as HTML badges.
///
/// Empty when the invariant has no mapping, so the cell is blank rather than
/// showing a class Truent cannot stand behind.
fn violation_taxonomy_html(v: &Violation) -> String {
    let mut badges: Vec<String> = Vec::new();
    if let Some(cwe) = &v.cwe {
        // The label is "CWE-841 · Name"; the badge shows the ID, the tooltip
        // carries the full name.
        let id = cwe.split(' ').next().unwrap_or(cwe);
        badges.push(format!(
            "<span class=\"tax\" title=\"{}\">{}</span>",
            html_escape(cwe),
            html_escape(id)
        ));
    }
    for values in [&v.swc, &v.owasp_sc, &v.dasp] {
        for label in values {
            let id = label.split(' ').next().unwrap_or(label);
            badges.push(format!(
                "<span class=\"tax\" title=\"{}\">{}</span>",
                html_escape(label),
                html_escape(id)
            ));
        }
    }
    badges.join(" ")
}

fn generate_html_report(summary: &AnalysisSummary, violations: &[Violation]) -> String {
    // Every value below is attacker-influenceable — `location` carries a file
    // path, `message` can quote contract source — and a report is a document
    // people open in a browser and forward. Escape all of them with the same
    // helper the report crate uses; the previous hand-rolled `<`/`>` pass on
    // `message` alone left `&`, quotes, and every other column raw.
    let violation_rows = violations
        .iter()
        .map(|v| {
            let taxonomy = violation_taxonomy_html(v);
            format!(
                "<tr><td><code>{}</code></td><td class=\"severity-{}\">{}</td>\
                 <td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&v.invariant_id),
                html_escape(&v.severity),
                html_escape(&v.severity.to_uppercase()),
                html_escape(&v.location),
                taxonomy,
                html_escape(&v.message),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    #[allow(clippy::useless_vec)]
    let severity_colors = vec![
        format!(
            "<li><strong>Critical:</strong> {} findings</li>",
            summary.severity_breakdown.critical
        ),
        format!(
            "<li><strong>High:</strong> {} findings</li>",
            summary.severity_breakdown.high
        ),
        format!(
            "<li><strong>Medium:</strong> {} findings</li>",
            summary.severity_breakdown.medium
        ),
        format!(
            "<li><strong>Low:</strong> {} findings</li>",
            summary.severity_breakdown.low
        ),
    ];

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Truent Security Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            margin: 20px;
            background-color: #f6f8fb;
            color: #24292e;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #0366d6;
            border-bottom: 2px solid #e1e4e8;
            padding-bottom: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-box {{
            background: #f6f8fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #0366d6;
        }}
        .summary-box strong {{
            font-size: 18px;
            color: #0366d6;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background-color: #f6f8fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #e1e4e8;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #e1e4e8;
        }}
        tr:hover {{
            background-color: #f6f8fa;
        }}
        .severity-critical {{
            color: #d73a49;
            font-weight: 600;
        }}
        .severity-high {{
            color: #fd7e14;
            font-weight: 600;
        }}
        .severity-medium {{
            color: #ffc107;
            font-weight: 600;
        }}
        .severity-low {{
            color: #6f42c1;
            font-weight: 600;
        }}
        .tax {{
            display: inline-block;
            background: #eef2f7;
            border: 1px solid #d6dde6;
            border-radius: 4px;
            padding: 1px 6px;
            margin: 1px 2px 1px 0;
            font-size: 11px;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            color: #3a4652;
            white-space: nowrap;
        }}
        .timestamp {{
            color: #6a737d;
            font-size: 12px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Truent Security Analysis Report</h1>
        
        <div class="summary">
            <div class="summary-box">
                <strong>Target:</strong> {}<br>
                <strong>Chain:</strong> {}<br>
                <strong>Duration:</strong> {:.2}s
            </div>
            <div class="summary-box">
                <strong>Total Checks:</strong> {}<br>
                <strong>Violations Found:</strong> {}<br>
                <strong>Passed:</strong> {}
            </div>
        </div>

        <h2>Severity Breakdown</h2>
        <ul>
            {}
        </ul>

        <h2>Findings</h2>
        {}
        
        <table>
            <thead>
                <tr>
                    <th>Invariant</th>
                    <th>Severity</th>
                    <th>Location</th>
                    <th>Classification</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>

        <div class="timestamp">
            Generated by Truent v{}
        </div>
    </div>
</body>
</html>"#,
        html_escape(&summary.target),
        html_escape(&summary.chain),
        summary.duration_secs,
        summary.total_checks,
        summary.violations,
        summary.passed,
        severity_colors.join("\n"),
        if violations.is_empty() {
            "<p style=\"color: #28a745; font-weight: 600;\">✓ No security violations found!</p>"
                .to_string()
        } else {
            format!(
                "<p style=\"color: #d73a49;\">⚠️ {} security violations detected</p>",
                violations.len()
            )
        },
        violation_rows,
        env!("CARGO_PKG_VERSION"),
    )
}

/// File extension associated with each chain's source files.
fn chain_extension(chain: &ChainArg) -> &'static str {
    match chain {
        ChainArg::Evm => "sol",
        ChainArg::Solana => "rs",
        ChainArg::Move => "move",
        ChainArg::Soroban => "rs",
        // General and Auto do not select by a single extension; see
        // `engines_for_file`.
        ChainArg::General | ChainArg::Auto => "",
    }
}

/// Which engines should run over `path`, given the requested chain.
///
/// A single chain runs its engine over files with its extension. `General`
/// runs the repository analyzer over everything it applies to. `Auto` does
/// both, sniffing `.rs` files for Anchor or Soroban markers so a mixed
/// repository gets every engine that is relevant to each file.
fn engines_for_file(chain: &ChainArg, path: &Path, source: &str) -> Vec<ChainArg> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let file = path.to_string_lossy().to_string();
    let mut out = Vec::new();
    match chain {
        ChainArg::Evm | ChainArg::Solana | ChainArg::Move | ChainArg::Soroban => {
            if ext == chain_extension(chain) {
                out.push(chain.clone());
            }
        }
        ChainArg::General => {
            if general::applies_to(&file) {
                out.push(ChainArg::General);
            }
        }
        ChainArg::Auto => {
            match ext {
                "sol" => out.push(ChainArg::Evm),
                "move" => out.push(ChainArg::Move),
                "rs" if source.contains("anchor_lang") || source.contains("#[program]") => {
                    out.push(ChainArg::Solana)
                }
                "rs" if source.contains("soroban_sdk") => out.push(ChainArg::Soroban),
                _ => {}
            }
            if general::applies_to(&file) {
                out.push(ChainArg::General);
            }
        }
    }
    out
}

/// Recursively collect every regular file under `dir`, skipping dependency
/// and build trees. Binary-looking files are dropped when read.
fn collect_all_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory {}", dir.display()))?
    {
        let path = entry?.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                name,
                "node_modules"
                    | "target"
                    | ".git"
                    | "build"
                    | "dist"
                    | "out"
                    | "vendor"
                    | ".venv"
                    | "venv"
                    | "__pycache__"
            ) {
                continue;
            }
            collect_all_files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Recursively collect source files matching the chain's extension under `dir`.
fn collect_source_files(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // Skip common non-source directories to avoid scanning dependency trees.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                name,
                "node_modules" | "target" | ".git" | "build" | "dist" | "out"
            ) {
                continue;
            }
            collect_source_files(&path, extension, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some(extension) {
            out.push(path);
        }
    }
    Ok(())
}

/// Run every live pattern detector for `chain` against one file's source text.
fn run_detectors_on_source(chain: &ChainArg, source: &str, path: &Path) -> Vec<Finding> {
    let file_path = path.to_string_lossy().to_string();
    match chain {
        ChainArg::Evm => truent_analyzer_evm::detectors::run_all_detectors(source, &file_path),
        ChainArg::Solana => truent_analyzer_solana::run_all_detectors(source, &file_path),
        ChainArg::Move => truent_analyzer_move::run_all_detectors(source, &file_path),
        ChainArg::Soroban => truent_analyzer_soroban::run_all_detectors(source, &file_path),
        ChainArg::General => general::run_all_detectors(source, &file_path),
        // Auto never reaches here: it is expanded per file by `engines_for_file`.
        ChainArg::Auto => Vec::new(),
    }
}

/// Convert a title-cased, human-readable name out of a detector's invariant_id,
/// e.g. "evm_missing_post_state_health_check" -> "Missing Post State Health Check".
fn invariant_id_to_title(invariant_id: &str) -> String {
    let stripped = invariant_id
        .strip_prefix("evm_")
        .or_else(|| invariant_id.strip_prefix("sol_"))
        .or_else(|| invariant_id.strip_prefix("move_"))
        .unwrap_or(invariant_id);

    stripped
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Pull one registry's labels out of an invariant's taxonomy entry.
///
/// Empty when the invariant is unmapped, or when the registry genuinely has no
/// entry for it (SWC is Solidity-only, so Move and Solana findings carry none).
fn taxonomy_labels(
    invariant_id: &str,
    pick: impl Fn(&truent_core::Taxonomy) -> Vec<String>,
) -> Vec<String> {
    taxonomy_for(invariant_id).map(pick).unwrap_or_default()
}

/// Convert a detector `Finding` into a display/report-ready `Violation`.
fn finding_to_violation(finding: &Finding, index: usize, total: usize) -> Violation {
    let reference = get_vulnerability_reference(&finding.invariant_id);
    let exposure = finding.exposure();
    let rating = finding.exploitability();
    let taxonomy = truent_core::taxonomy::taxonomy_for(&finding.invariant_id);
    Violation {
        file: finding.file.clone(),
        line: finding.line,
        chain: taxonomy.and_then(|t| t.chain()).map(str::to_string),
        exploitability: rating
            .as_ref()
            .map(|r| r.exploitability.label().to_ascii_lowercase()),
        exploit_reasons: rating.map(|r| r.reasons).unwrap_or_default(),
        fix: exposure.map(|e| e.fix.to_string()),
        verify: exposure.map(|e| e.verify.to_string()),
        attack: taxonomy
            .map(|t| t.attack.iter().map(|a| a.id.to_string()).collect())
            .unwrap_or_default(),
        nist_csf: taxonomy
            .map(|t| t.nist_csf.iter().map(|n| n.id.to_string()).collect())
            .unwrap_or_default(),
        index,
        total,
        severity: finding.severity.name().to_lowercase(),
        title: invariant_id_to_title(&finding.invariant_id),
        invariant_id: finding.invariant_id.clone(),
        location: format!("{}:{}", finding.file, finding.line),
        cwe: cwe_label(&finding.invariant_id),
        swc: taxonomy_labels(&finding.invariant_id, |t| {
            t.swc.iter().map(|s| s.label()).collect()
        }),
        owasp_sc: taxonomy_labels(&finding.invariant_id, |t| {
            t.owasp_sc.iter().map(|o| o.label()).collect()
        }),
        dasp: taxonomy_labels(&finding.invariant_id, |t| {
            t.dasp.iter().map(|d| d.label()).collect()
        }),
        message: finding.message.clone(),
        // The exposure table's fix is the recommendation; the generic search
        // link is only the fallback for a user-authored `.sinv` rule.
        recommendation: match exposure {
            Some(e) => e.fix.to_string(),
            None => format!(
                "Review this finding and apply the recommended fix. Details: {}",
                reference
            ),
        },
        reference,
        code_snippet: finding
            .source_fragment
            .clone()
            .unwrap_or_else(|| finding.snippet.clone()),
        evidence: finding.evidence,
    }
}

/// Run actual analysis on the source file or directory, returning display-ready violations.
fn run_analysis(source_path: &Path, chain: &ChainArg, verbose: bool) -> Result<Vec<Violation>> {
    let findings = run_analysis_findings(source_path, chain, verbose)?;
    let total = findings.len();
    Ok(findings
        .iter()
        .enumerate()
        .map(|(i, f)| finding_to_violation(f, i + 1, total))
        .collect())
}

/// Run the detectors and return the raw [`Finding`]s.
///
/// SARIF output needs these rather than display-shaped `Violation`s: the
/// taxonomy is keyed on `invariant_id`, and SARIF wants a deduplicated rule
/// catalogue, which the flattened per-finding view cannot reconstruct.
fn run_analysis_findings(
    source_path: &Path,
    chain: &ChainArg,
    verbose: bool,
) -> Result<Vec<Finding>> {
    // Check if path exists
    if !source_path.exists() {
        return Err(anyhow::anyhow!("Path not found: {}", source_path.display()));
    }

    let extension = chain_extension(chain);
    let files = if source_path.is_dir() {
        let mut files = Vec::new();
        if extension.is_empty() {
            collect_all_files(source_path, &mut files)?;
        } else {
            collect_source_files(source_path, extension, &mut files)?;
        }
        files
    } else {
        vec![source_path.to_path_buf()]
    };

    if files.is_empty() {
        if verbose {
            eprintln!(
                "⚠ No .{} files found under {}",
                extension,
                source_path.display()
            );
        }
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    // Sources the general analyzer applies to, kept for the repository-level
    // pass that looks across files.
    let mut general_sources: Vec<(String, String)> = Vec::new();
    for file in &files {
        // Non-UTF-8 content is binary; nothing here reads binaries.
        let Ok(source) = std::fs::read_to_string(file) else {
            continue;
        };
        let engines = engines_for_file(chain, file, &source);
        if engines.iter().any(|e| matches!(e, ChainArg::General)) {
            general_sources.push((file.to_string_lossy().to_string(), source.clone()));
        }
        for engine in engines {
            findings.extend(run_detectors_on_source(&engine, &source, file));
        }
    }
    if !general_sources.is_empty() {
        findings.extend(general::run_repo_detectors(&general_sources));
    }

    if verbose {
        eprintln!(
            "✓ Scanned {} file(s), {} findings from pattern detectors",
            files.len(),
            findings.len()
        );
    }

    // Best-effort structural analysis (function/state-var counts) for diagnostics only.
    // This requires solc (EVM) to be installed; never let its absence block detection,
    // since the detectors above operate on raw source text and don't need it.
    if verbose {
        if let Some(first_file) = files.first() {
            // The repository analyzer has no program model; contract chains do.
            let structural = match chain {
                ChainArg::Evm => Some(EvmAnalyzer.analyze(first_file)),
                ChainArg::Solana => Some(SolanaAnalyzer.analyze(first_file)),
                ChainArg::Move => Some(MoveAnalyzer.analyze(first_file)),
                ChainArg::Soroban => Some(SorobanAnalyzer.analyze(first_file)),
                ChainArg::General | ChainArg::Auto => None,
            };
            match structural {
                Some(Ok(program)) => eprintln!(
                    "✓ Structural analysis: {} functions in {}",
                    program.functions.len(),
                    first_file.display()
                ),
                Some(Err(e)) => {
                    eprintln!("⚠ Structural analysis unavailable ({e}); detectors still ran")
                }
                None => eprintln!(
                    "ℹ Structural analysis is per-chain; skipped for the repository analyzer"
                ),
            }
        }

        // Load real built-in invariants for this chain (informational for now; the
        // invariant library's default expressions aren't yet wired into detection).
        let chain_name = match chain {
            ChainArg::Evm => "evm",
            ChainArg::Solana => "solana",
            ChainArg::Move => "move",
            ChainArg::Soroban => "soroban",
            ChainArg::General => "general",
            ChainArg::Auto => "auto",
        };
        let lib = InvariantLibrary::with_defaults(chain_name);
        eprintln!(
            "✓ Loaded {} built-in invariant definitions for {}",
            lib.all().len(),
            chain_name
        );
    }

    Ok(findings)
}

/// Generate detailed violation information with actionable recommendations.
fn generate_detailed_violation_info(
    program: &truent_core::model::ProgramModel,
    invariant: &truent_core::model::Invariant,
    confidence: f64,
) -> (String, String) {
    let invariant_lower = invariant.name.to_lowercase();
    let is_solana = program.chain.to_lowercase().contains("solana");

    // Solana-specific violation details
    if is_solana {
        if invariant_lower.contains("lamport") {
            let message = format!(
                "Detected unsafe lamport manipulation with {:.0}% confidence. Direct arithmetic on account lamports without validation or safety checks detected.",
                confidence * 100.0
            );
            let recommendation =
                "CRITICAL: Never directly manipulate lamports without proper validation.\n\
                 Fix: Use checked arithmetic and validate account signer status before modifying lamports:\n\
                 ✓ Require account to be a signer: #[account(mut, signer)]\n\
                 ✓ Use checked_add/checked_sub instead of saturating_add/sub\n\
                 ✓ Validate minimum balance after transfer\n\
                 ✓ Consider using Solana's system program for transfers\n\
                 Reference: https://docs.solana.com/developing/programming-model/transactions"
                    .to_string();
            return (message, recommendation);
        }

        if invariant_lower.contains("overflow") || invariant_lower.contains("integer_overflow") {
            let message = format!(
                "Detected unchecked arithmetic operation with {:.0}% confidence. Potential integer overflow/underflow risk found.",
                confidence * 100.0
            );
            let recommendation =
                "Use overflow-checked arithmetic for all calculations:\n\
                 Available options:\n\
                 1. Use checked_add/checked_sub/checked_mul/checked_div that return Option<T>\n\
                 2. Use wrapping_add/wrapping_sub for intentional wrapping behavior (rare, always document)\n\
                 3. For Solana tokens, use SPL Token's u128 multiplication internally\n\
                 4. Add overflow checks with: require!(value <= MAX_ALLOWED, ErrorCode::Overflow)\n\
                 Example fix:\n\
                   let result = amount.checked_add(fee).ok_or(ErrorCode::Overflow)?;\n\
                 Reference: https://github.com/solana-labs/spl-token/blob/master/program/src/instruction.rs"
                    .to_string();
            return (message, recommendation);
        }

        if invariant_lower.contains("signer") {
            let message = format!(
                "Detected missing signer verification with {:.0}% confidence. Function may accept unauthorized callers.",
                confidence * 100.0
            );
            let recommendation =
                "Ensure all sensitive operations require proper signer verification:\n\
                 Required fixes:\n\
                 1. Mark sensitive account parameters as signers: #[account(mut, signer)]\n\
                 2. Add explicit checks: require!(account.is_signer, ErrorCode::MissingSigner)\n\
                 3. For specific authorities, validate: require!(authority.key == EXPECTED_AUTH, ...)\n\
                 4. Use require_keys_eq! macro for owner validation\n\
                 Security: This prevents unauthorized account ownership transfers and fund theft.\n\
                 Reference: https://docs.rs/anchor-lang/latest/anchor_lang/require_keys_eq/index.html"
                    .to_string();
            return (message, recommendation);
        }

        if invariant_lower.contains("account_validation") || invariant_lower.contains("account") {
            let message = format!(
                "Detected missing account validation with {:.0}% confidence. Accounts may not be properly owned or validated.",
                confidence * 100.0
            );
            let recommendation =
                "Implement comprehensive account validation:\n\
                 Required checks for each account:\n\
                 1. Owner verification: require!(account.owner == &system_program::ID, ...)\n\
                 2. Account type validation: Verify account data layout matches expected structure\n\
                 3. Signer checks: require!(account.is_signer, ...) for authority accounts\n\
                 4. Mint validation: For token accounts, verify mint matches expected\n\
                 Anchor example:\n\
                   #[account(mut, owner = system_program::ID)]\n\
                   pub account: UncheckedAccount<'info>,\n\
                 Better approach: Use Account<'info, YourDataType> for automatic validation\n\
                 Reference: https://docs.anchor-lang.com/frequently-asked-questions/security#how-do-i-validate-accounts"
                    .to_string();
            return (message, recommendation);
        }

        if invariant_lower.contains("rent") {
            let message = format!(
                "Detected potential rent exemption issue with {:.0}% confidence. Account may not maintain required minimum balance.",
                confidence * 100.0
            );
            let recommendation = "Ensure accounts maintain rent exemption:\n\
                 Solana requires accounts to maintain a minimum lamport balance.\n\
                 Best practices:\n\
                 1. Allocate sufficient space for account data\n\
                 2. Set initial balance >= rent_exempt_minimum\n\
                 3. When withdrawing lamports: verify_account_rent_exemption!(account, rent)\n\
                 4. Use system_program::create_account for proper initialization\n\
                 5. For PDAs, ensure bump seed doesn't affect rent calculation\n\
                 Implementation:\n\
                   let rent = Rent::get()?;\n\
                   let required_lamports = rent.minimum_balance(data_len);\n\
                 Reference: https://docs.solana.com/developing/programming-model/accounts"
                .to_string();
            return (message, recommendation);
        }

        if invariant_lower.contains("pda") {
            let message = format!(
                "Detected PDA derivation issue with {:.0}% confidence. Bump seed or seed derivation may be incorrect.",
                confidence * 100.0
            );
            let recommendation =
                "Fix PDA derivation security issues:\n\
                 Common problems and fixes:\n\
                 1. Hardcoded bump seed: WRONG - use find_program_address instead\n\
                 2. Missing bump storage: Always store bump in account data for verification\n\
                 3. Seed ordering: Order seeds consistently \n\
                 4. Seed validation: Verify derived PDA in instrumentation\n\
                 Correct pattern:\n\
                   let (pda, bump) = Pubkey::find_program_address(&[seed], program_id);\n\
                   require_keys_eq!(expected_account, pda, ErrorCode::InvalidPDA);\n\
                 Store bump and re-derive for verification, never trust the bump argument\n\
                 Reference: https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses"
                    .to_string();
            return (message, recommendation);
        }

        if invariant_lower.contains("deserial") || invariant_lower.contains("instruction") {
            let message = format!(
                "Detected unsafe deserialization with {:.0}% confidence. Account data not properly validated before parsing.",
                confidence * 100.0
            );
            let recommendation =
                "Implement safe deserialization practices:\n\
                 Never assume account data layout matches expectations.\n\
                 Best practices:\n\
                 1. Use try_from_slice with error handling (not unwrap)\n\
                 2. Validate account size before deserializing: require!(account.data_len() >= EXPECTED_SIZE, ...)\n\
                 3. Use Anchor's Account<T> type which handles validation\n\
                 4. For raw deserialization: let data = account.data.borrow();\n\
                             let parsed = MyData::try_from_slice(&data)?;\n\
                 5. Add version checks for account data migrations\n\
                 Never use: \n\
                   let data = from_slice::<MyData>(&account.data).unwrap(); ❌\n\
                 Reference: https://docs.anchor-lang.com/frequently-asked-questions/security#how-do-i-validate-data"
                    .to_string();
            return (message, recommendation);
        }

        if invariant_lower.contains("token") {
            let message = format!(
                "Detected unchecked token operation with {:.0}% confidence. Token transfers may overflow or lose precision.",
                confidence * 100.0
            );
            let recommendation =
                "Use SPL Token's checked arithmetic for all transfers:\n\
                 Security issues with unchecked token math:\n\
                 1. Overflow in token amounts (rare but possible with custom decimals)\n\
                 2. Fee rounding attacks\n\
                 3. Solana Token program has internal overflow checks, but verify your math\n\
                 Best practice:\n\
                   // For SPL Token transfers, the program validates\n\
                   spl_token::instruction::transfer(...)?\n\
                 For custom math:\n\
                   let amount = tokens.checked_mul(price).ok_or(ErrorCode::Overflow)?;\n\
                 Testing:\n\
                   - Test with amounts near u64::MAX\n\
                   - Test with high-decimal tokens\n\
                 Reference: https://github.com/solana-labs/solana-program-library/tree/master/token"
                    .to_string();
            return (message, recommendation);
        }
    }

    // Generic/cross-platform violations
    if invariant_lower.contains("reentrancy") {
        let message = format!(
            "Detected potential reentrancy risk with {:.0}% confidence. Complex state interactions without guards.",
            confidence * 100.0
        );
        let recommendation = "Implement reentrancy protections:\n\
             1. Use checks-effects-interactions pattern\n\
             2. Apply state changes before external calls\n\
             3. Use reentrancy guards (mutex-style locking)\n\
             4. For EVM: use OpenZeppelin's ReentrancyGuard\n\
             5. For Solana: No reentrancy risk by design (sequential execution)\n\
             Reference: https://ethereumbook.org/code/vulnerabilities/"
            .to_string();
        return (message, recommendation);
    }

    // Fallback for unknown violations
    let message = format!(
        "Detected violation of '{}' invariant with {:.0}% confidence.",
        invariant.name,
        confidence * 100.0
    );
    let recommendation = format!(
        "Review the '{}' invariant documentation at https://docs.truent.dev/invariants/{} and apply recommended fixes.",
        invariant.name, invariant.name
    );

    (message, recommendation)
}

/// Find the approximate line where a vulnerability marker appears in the program.
fn find_vulnerability_line(
    program: &truent_core::model::ProgramModel,
    invariant_name: &str,
) -> Option<usize> {
    let invariant_lower = invariant_name.to_lowercase();

    // Search all markers for any embedded line number
    for func in program.functions.values() {
        for marker in &func.mutates {
            // Look for embedded line numbers in format: MARKER:LINE_NUMBER
            if let Some(colon_pos) = marker.rfind(':') {
                if let Ok(line_num) = marker[colon_pos + 1..].parse::<usize>() {
                    // We found a marker with an embedded line number
                    // Check if this marker is relevant to the invariant
                    let marker_upper = marker.to_uppercase();

                    #[allow(clippy::if_same_then_else)]
                    // Match based on invariant type
                    if invariant_lower.contains("signer") && marker_upper.contains("SIGNER") {
                        return Some(line_num);
                    } else if invariant_lower.contains("lamport")
                        && marker_upper.contains("LAMPORT")
                    {
                        return Some(line_num);
                    } else if (invariant_lower.contains("overflow")
                        || invariant_lower.contains("arithmetic"))
                        && marker_upper.contains("ARITHMETIC")
                    {
                        return Some(line_num);
                    } else if invariant_lower.contains("account")
                        && (marker_upper.contains("ACCOUNT") || marker_upper.contains("VALIDATION"))
                    {
                        return Some(line_num);
                    } else if invariant_lower.contains("rent") && marker_upper.contains("RENT") {
                        return Some(line_num);
                    } else if invariant_lower.contains("pda") && marker_upper.contains("PDA") {
                        return Some(line_num);
                    } else if (invariant_lower.contains("deserialization")
                        || invariant_lower.contains("instruction"))
                        && (marker_upper.contains("DESERIAL")
                            || marker_upper.contains("INSTRUCTION"))
                    {
                        return Some(line_num);
                    } else if invariant_lower.contains("token") && marker_upper.contains("TOKEN") {
                        return Some(line_num);
                    } else if invariant_lower.contains("reentrancy")
                        && marker_upper.contains("REENTRANCY")
                    {
                        return Some(line_num);
                    }
                }
            }
        }
    }

    None
}

/// Extract code snippet from source file at the given line number.
/// Shows the target line plus 2 lines of context before and after.
fn extract_code_snippet(
    source_path: &std::path::Path,
    line_number: usize,
) -> std::io::Result<String> {
    use std::fs;
    use std::io::BufRead;

    let file = fs::File::open(source_path)?;
    let reader = std::io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<Vec<_>, _>>()?;

    // Calculate context range (2 lines before and after)
    let start_line = if line_number > 2 { line_number - 3 } else { 0 };
    let end_line = std::cmp::min(line_number + 1, lines.len());

    if line_number == 0 || line_number > lines.len() {
        return Ok(format!(
            "Line {} is out of range in {}",
            line_number,
            source_path.display()
        ));
    }

    let mut snippet = String::new();
    for (idx, line) in lines[start_line..end_line].iter().enumerate() {
        let actual_line_num = start_line + idx + 1;
        let marker = if actual_line_num == line_number {
            ">>> "
        } else {
            "    "
        };
        snippet.push_str(&format!("{}{:3} | {}\n", marker, actual_line_num, line));
    }

    Ok(snippet.trim().to_string())
}

/// Get proper reference documentation links for each vulnerability type.
/// Map invariant IDs to documentation anchors in INVARIANT_LIBRARY.md
/// Handles 50+ detected invariants by mapping to canonical documentation
fn get_vulnerability_reference(invariant_id: &str) -> String {
    // Map of detected invariant IDs to documentation section anchors
    // Format: full_id -> anchor_in_library_md
    let invariant_mapping: &[(&str, &str)] = &[
        // Balance & Arithmetic (IDs 1-5 in docs)
        ("reentrancy_classic", "#1-balance_conservation"),
        ("overflow", "#2-no_integer_overflow"),
        ("underflow", "#3-no_integer_underflow"),
        ("balance_check", "#4-positive_balance"),
        ("conservation_check", "#5-supply_tracking"),
        ("conservation_check_absent", "#5-supply_tracking"),
        // Access Control (IDs 6-9 in docs)
        ("missing_signer", "#6-owner_only_function"),
        ("access_control", "#7-role_based_access"),
        ("shallow_auth", "#7-role_based_access"),
        ("single_eoa_admin", "#8-admin_override_safe"),
        ("permission", "#9-permission_consistency"),
        // State Consistency (IDs 10-13 in docs)
        ("state_transition", "#11-state_transition_valid"),
        ("reentrancy", "#12-no_reentrancy"),
        ("paused", "#13-paused_state_valid"),
        // Cross-Chain (IDs 14-16 in docs)
        ("bridge", "#14-bridge_conservation"),
        ("oracle", "#15-oracle_freshness"),
        ("oracle_spot_price", "#15-oracle_freshness"),
        ("oracle_self_trade", "#15-oracle_freshness"),
        ("oracle_rate", "#15-oracle_freshness"),
        ("canonical", "#16-canonical_state"),
        // Transaction Safety (IDs 17-22 in docs)
        ("signature", "#17-signature_validation"),
        ("nonce", "#18-nonce_ordering"),
        ("gas", "#19-gas_efficiency"),
        ("delegatecall", "#20-safe_delegatecall"),
        ("selfdestruct", "#21-safe_selfdestruct"),
        ("timestamp", "#22-no_timestamp_dependence"),
        // Additional EVM-specific invariants
        ("flash_loan", "#12-no_reentrancy"),
        ("dvn", "#15-oracle_freshness"),
        ("merkle_root", "#11-state_transition_valid"),
        ("precision_loss", "#2-no_integer_overflow"),
        ("zero_challenge", "#11-state_transition_valid"),
        ("public_relay", "#6-owner_only_function"),
        ("aa_entropy", "#17-signature_validation"),
        ("bridge_address", "#14-bridge_conservation"),
        ("synthetic_collateral", "#16-canonical_state"),
        ("dvn_single_point", "#15-oracle_freshness"),
        ("lst_depeg", "#5-supply_tracking"),
        ("erc4626_inflation", "#5-supply_tracking"),
        ("token_balance_manipulation", "#1-balance_conservation"),
        ("arbitrary_call_msg_value", "#20-safe_delegatecall"),
        ("router_slippage", "#15-oracle_freshness"),
        ("health_check", "#11-state_transition_valid"),
        ("state_mutation_ordering", "#11-state_transition_valid"),
        ("unbacked_synthetic_mint", "#5-supply_tracking"),
        ("upgrade_path", "#20-safe_delegatecall"),
        ("constructor_race", "#11-state_transition_valid"),
        ("proxy_storage", "#11-state_transition_valid"),
        ("arithmetic_rounding", "#2-no_integer_overflow"),
        // Solana-specific
        ("signer", "#6-owner_only_function"),
        ("account_validation", "#6-owner_only_function"),
        ("rent_exemption", "#10-state_immutability"),
        ("pda_authority", "#11-state_transition_valid"),
        ("sysvar_account", "#6-owner_only_function"),
        ("admin_timelock", "#8-admin_override_safe"),
        ("treasury_authority", "#8-admin_override_safe"),
        ("durable_nonce", "#18-nonce_ordering"),
        // Move-specific
        ("liquidity_conservation", "#1-balance_conservation"),
        ("type_safety", "#11-state_transition_valid"),
        ("resource_destruction", "#1-balance_conservation"),
    ];

    let id_lower = invariant_id.to_lowercase();

    // Strip chain prefix (evm_, sol_, move_)
    let clean_id = id_lower
        .strip_prefix("evm_")
        .unwrap_or(&id_lower)
        .strip_prefix("sol_")
        .unwrap_or(&id_lower)
        .strip_prefix("move_")
        .unwrap_or(&id_lower);

    // Try to find a mapping for any substring match
    for (pattern, anchor) in invariant_mapping.iter() {
        if clean_id.contains(pattern) {
            return format!(
                "https://github.com/geekstrancend/Truent/blob/main/docs/INVARIANT_LIBRARY.md{}",
                anchor
            );
        }
    }

    // Fallback to GitHub search if no mapping found
    format!(
        "https://github.com/geekstrancend/Truent/search?q={}",
        id_lower.replace("_", "%20")
    )
}

/// Detect which invariants were actually violated based on program structure.
fn detect_violated_invariants(
    program: &truent_core::model::ProgramModel,
    invariants: &[truent_core::model::Invariant],
) -> Vec<(truent_core::model::Invariant, f64)> {
    let mut violated = Vec::new();

    // Heuristic: check invariants based on program characteristics
    for invariant in invariants {
        let confidence = calculate_violation_confidence(program, invariant);
        if confidence > 0.3 {
            // Threshold for reporting
            violated.push((invariant.clone(), confidence));
        }
    }

    violated
}

/// Calculate confidence score for an invariant violation based on program analysis.
fn calculate_violation_confidence(
    program: &truent_core::model::ProgramModel,
    invariant: &truent_core::model::Invariant,
) -> f64 {
    let mut confidence = 0.0;
    let invariant_lower = invariant.name.to_lowercase();
    let chain_lower = program.chain.to_lowercase();

    // === SOLANA-SPECIFIC DETECTIONS ===
    if chain_lower.contains("solana") {
        if (invariant_lower.contains("lamport") || invariant_lower.contains("sol_lamport"))
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("SOLANA_LAMPORT_UNSAFE"))
            })
        {
            return 0.95;
        }
        if (invariant_lower.contains("overflow")
            || invariant_lower.contains("sol_integer_overflow"))
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("SOLANA_UNCHECKED_ARITHMETIC"))
            })
        {
            return 0.90;
        }
        if (invariant_lower.contains("signer") || invariant_lower.contains("sol_signer_checks"))
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("SOLANA_MISSING_SIGNER"))
            })
        {
            return 0.88;
        }
        if (invariant_lower.contains("account")
            || invariant_lower.contains("sol_account_validation"))
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("SOLANA__MISSING_VALIDATION"))
            })
        {
            return 0.85;
        }
        if (invariant_lower.contains("rent") || invariant_lower.contains("sol_rent_exemption"))
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("SOLANA_RENT_EXEMPTION"))
            })
        {
            return 0.82;
        }
        if (invariant_lower.contains("pda") || invariant_lower.contains("sol_pda_derivation"))
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("SOLANA_PDA_DERIVATION"))
            })
        {
            return 0.80;
        }
    }

    // === EVM-SPECIFIC DETECTIONS ===
    if chain_lower.contains("evm") {
        if invariant_lower.contains("reentrancy")
            && program
                .functions
                .iter()
                .any(|f| f.1.mutates.iter().any(|m| m.contains("EVM_REENTRANCY")))
        {
            return 0.93;
        }
        if (invariant_lower.contains("call") || invariant_lower.contains("external"))
            && program
                .functions
                .iter()
                .any(|f| f.1.mutates.iter().any(|m| m.contains("EVM_UNCHECKED_CALL")))
        {
            return 0.91;
        }
        if (invariant_lower.contains("overflow") || invariant_lower.contains("arithmetic"))
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("EVM_UNCHECKED_ARITHMETIC"))
            })
        {
            return 0.89;
        }
        if invariant_lower.contains("delegatecall")
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("EVM_DELEGATECALL_ABUSE"))
            })
        {
            return 0.92;
        }
        if invariant_lower.contains("timestamp")
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("EVM_TIMESTAMP_DEPENDENCY"))
            })
        {
            return 0.85;
        }
        if (invariant_lower.contains("front") || invariant_lower.contains("ordering"))
            && program
                .functions
                .iter()
                .any(|f| f.1.mutates.iter().any(|m| m.contains("EVM_FRONT_RUNNING")))
        {
            return 0.80;
        }
        if invariant_lower.contains("access")
            && program
                .functions
                .iter()
                .any(|f| f.1.mutates.iter().any(|m| m.contains("EVM_ACCESS_CONTROL")))
        {
            return 0.87;
        }
        if invariant_lower.contains("validation")
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("EVM_INPUT_VALIDATION"))
            })
        {
            return 0.83;
        }
    }

    // === MOVE-SPECIFIC DETECTIONS ===
    if chain_lower.contains("move") {
        if invariant_lower.contains("resource")
            && program
                .functions
                .iter()
                .any(|f| f.1.mutates.iter().any(|m| m.contains("MOVE_RESOURCE_LEAK")))
        {
            return 0.89;
        }
        if invariant_lower.contains("ability")
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("MOVE_MISSING_ABILITY"))
            })
        {
            return 0.86;
        }
        if (invariant_lower.contains("overflow") || invariant_lower.contains("arithmetic"))
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("MOVE_UNCHECKED_ARITHMETIC"))
            })
        {
            return 0.88;
        }
        if invariant_lower.contains("signer")
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("MOVE_MISSING_SIGNER"))
            })
        {
            return 0.84;
        }
        if invariant_lower.contains("mutation")
            || invariant_lower.contains("unguarded")
                && program.functions.iter().any(|f| {
                    f.1.mutates
                        .iter()
                        .any(|m| m.contains("MOVE_UNGUARDED_MUTATION"))
                })
        {
            return 0.82;
        }
        if invariant_lower.contains("privilege")
            && program.functions.iter().any(|f| {
                f.1.mutates
                    .iter()
                    .any(|m| m.contains("MOVE_PRIVILEGE_ESCALATION"))
            })
        {
            return 0.81;
        }
        if invariant_lower.contains("abort")
            && program
                .functions
                .iter()
                .any(|f| f.1.mutates.iter().any(|m| m.contains("MOVE_UNSAFE_ABORT")))
        {
            return 0.79;
        }
    }

    // Check for reentrancy patterns
    if invariant_lower.contains("reentrancy") && program.functions.len() > 2 {
        confidence += 0.3;
    }

    // Check for arithmetic issues
    if (invariant_lower.contains("overflow") || invariant_lower.contains("underflow"))
        && program.functions.iter().any(|f| {
            f.1.name.contains("add") || f.1.name.contains("mul") || f.1.name.contains("increment")
        })
    {
        confidence += 0.35;
    }

    // Check for access control
    if invariant_lower.contains("access")
        && program.functions.iter().any(|f| f.1.is_entry_point)
        && program.functions.len() > 1
    {
        confidence += 0.25;
    }

    // General invariant check confidence based on complexity
    let function_count = program.functions.len() as f64;
    let state_var_count = program.state_vars.len() as f64;

    confidence += (function_count / 15.0).min(0.25);
    confidence += (state_var_count / 30.0).min(0.20);

    // Ensure minimum confidence of 0.5 for detected violations to improve visibility
    if confidence > 0.35 {
        confidence = confidence.max(0.65);
    }

    confidence.min(1.0)
}

/// Write a SARIF 2.1.0 report to `path`.
///
/// Emitted alongside the normal output rather than instead of it: a CI job
/// usually wants both the human-readable result in the log and the SARIF
/// artifact to upload.
fn write_sarif(findings: &[Finding], path: &Path, quiet: bool) -> Result<()> {
    let sarif = truent_report::format_sarif(findings, env!("CARGO_PKG_VERSION"));
    let rendered = serde_json::to_string_pretty(&sarif)?;
    std::fs::write(path, rendered)
        .with_context(|| format!("writing SARIF report to {}", path.display()))?;
    if !quiet {
        eprintln!("✓ SARIF report written to {}", path.display());
    }
    Ok(())
}

/// Handle `deps`.
fn cmd_deps(args: DepsArgs, quiet: bool) -> Result<()> {
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

    let fail_rank = severity_arg_rank(&args.fail_on);
    if report
        .findings
        .iter()
        .any(|f| severity_rank(f.severity.name()) >= fail_rank)
    {
        std::process::exit(1);
    }
    Ok(())
}

/// Handle `exposure`.
fn cmd_exposure(args: ExposureArgs, quiet: bool) -> Result<()> {
    use truent_core::exposure::Exploitability;
    let mut findings = all_native_findings(&args.path, args.advisory_db.as_deref())?;
    if let Some(p) = &args.probe_report {
        let text = std::fs::read_to_string(p)
            .with_context(|| format!("reading probe report {}", p.display()))?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        let live: Vec<Finding> = serde_json::from_value(v["findings"].clone())
            .context("probe report has no `findings` array")?;
        findings.extend(live);
    }
    let min = match args.min {
        ExploitabilityArg::Theoretical => Exploitability::Theoretical,
        ExploitabilityArg::Unlikely => Exploitability::Unlikely,
        ExploitabilityArg::Possible => Exploitability::Possible,
        ExploitabilityArg::Likely => Exploitability::Likely,
    };
    let acceptances =
        truent_pathways::load_acceptances(&args.path).map_err(|e| anyhow::anyhow!(e))?;
    let (findings, accepted, _expired) = truent_pathways::apply_acceptances(findings, &acceptances);
    let chains = truent_pathways::detect_chains(&findings);
    let mut rated: Vec<(Finding, truent_core::exposure::Rating)> = findings
        .into_iter()
        .filter_map(|f| f.exploitability().map(|r| (f, r)))
        .filter(|(_, r)| r.exploitability >= min)
        .collect();
    rated.sort_by(|a, b| {
        b.1.exploitability
            .cmp(&a.1.exploitability)
            .then(b.0.severity.cmp(&a.0.severity))
    });

    let rendered = match args.format {
        FormatArg::Json => serde_json::to_string_pretty(&json!({
            "target": args.path.display().to_string(),
            "chains": chains,
            // The full catalogue of chains the engine knows, so a consumer can
            // show what is checked as well as what fired.
            "known_chains": truent_pathways::chains(),
            "accepted": accepted,
            "findings": rated.iter().map(|(f, r)| json!({
                "finding": f,
                "exploitability": r.exploitability,
                "reasons": r.reasons,
                "fix": f.exposure().map(|e| e.fix),
                "verify": f.exposure().map(|e| e.verify),
            })).collect::<Vec<_>>(),
        }))?,
        _ => {
            let mut s = String::new();
            s.push_str(&format!(
                "# Exposure — {}

",
                args.path.display()
            ));
            s.push_str("How possible each finding is to exploit, judged from its attack profile and evidence — never by exploiting it — and what closes it.

");
            if chains.is_empty() {
                s.push_str(
                    "## Attack chains

No known attack chain is completed by these findings.

",
                );
            } else {
                s.push_str(&format!(
                    "## Attack chains ({})

",
                    chains.len()
                ));
                for h in &chains {
                    s.push_str(&format!(
                        "### {} `{}`{}

{}

",
                        h.chain.name,
                        h.chain.id,
                        h.exploitability
                            .map(|e| format!(" — {}", e.label()))
                            .unwrap_or_default(),
                        h.chain.narrative
                    ));
                    for (i, step) in h.chain.steps.iter().enumerate() {
                        let by: Vec<String> = h.satisfied_by[i]
                            .iter()
                            .map(|(id, n)| format!("`{id}` ×{n}"))
                            .collect();
                        let brk = if i == h.chain.break_at {
                            "  ← break here"
                        } else {
                            ""
                        };
                        s.push_str(&format!(
                            "{}. {} — {}{brk}
",
                            i + 1,
                            step.role,
                            by.join(", ")
                        ));
                    }
                    if let Some(id) = h.chain.steps[h.chain.break_at].any_of.first() {
                        if let Some(e) = truent_core::exposure::exposure_for(id) {
                            s.push_str(&format!(
                                "
**Prevent:** {}
",
                                e.fix
                            ));
                        }
                    }
                    s.push_str(&format!(
                        "
ATT&CK: {}

",
                        h.chain.tactics.join(" → ")
                    ));
                }
            }
            if !accepted.is_empty() {
                s.push_str(&format!("## Accepted ({})\n\n", accepted.len()));
                for a in &accepted {
                    s.push_str(&format!(
                        "- `{}` {}:{} — until {} ({}): {}\n",
                        a.finding.invariant_id,
                        a.finding.file,
                        a.finding.line,
                        a.acceptance.until,
                        a.acceptance.owner,
                        a.acceptance.reason
                    ));
                }
                s.push('\n');
            }
            s.push_str(&format!(
                "## Findings ({})

",
                rated.len()
            ));
            let mut last: Option<Exploitability> = None;
            for (f, r) in &rated {
                if last != Some(r.exploitability) {
                    s.push_str(&format!(
                        "### {}

",
                        r.exploitability.label()
                    ));
                    last = Some(r.exploitability);
                }
                s.push_str(&format!(
                    "- **{}** [{}] {}:{}{}
  {}
  - why: {}
",
                    f.invariant_id,
                    f.severity.name(),
                    f.file,
                    f.line,
                    if f.is_proven() { " (proven)" } else { "" },
                    f.message,
                    r.reasons.join("; ")
                ));
                if let Some(e) = f.exposure() {
                    s.push_str(&format!(
                        "  - fix: {}
  - verify: {}
",
                        e.fix, e.verify
                    ));
                }
            }
            s
        }
    };
    match &args.out {
        Some(p) => {
            std::fs::write(p, &rendered)?;
            if !quiet {
                eprintln!("✓ Exposure report written to {}", p.display());
            }
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

/// Handle `symbolic`.
fn cmd_symbolic(args: SymbolicArgs, quiet: bool) -> Result<()> {
    use truent_symbolic::{run, Tool};
    let prefer = args.tool.map(|t| match t {
        SymbolicToolArg::Halmos => Tool::Halmos,
        SymbolicToolArg::Hevm => Tool::Hevm,
        SymbolicToolArg::Mythril => Tool::Mythril,
    });
    let report = run(
        &args.path,
        prefer,
        std::time::Duration::from_secs(args.timeout),
    );
    let rendered = match args.format {
        FormatArg::Json => serde_json::to_string_pretty(&report)?,
        _ => {
            let mut s = String::new();
            s.push_str(&format!("Symbolic execution — {}\n", report.project));
            match (&report.tool, &report.version) {
                (Some(t), Some(v)) => s.push_str(&format!("  tool     {} {}\n", t.name(), v)),
                _ => s.push_str("  tool     none found\n"),
            }
            s.push_str(&format!(
                "  ran      {}   checks {}  passed {}  counterexamples {}  unresolved {}   ({} ms)\n",
                report.ran, report.stats.checks, report.stats.passed, report.stats.failed, report.stats.unresolved, report.duration_ms
            ));
            for e in &report.errors {
                s.push_str(&format!("  !        {e}\n"));
            }
            s.push('\n');
            if report.findings.is_empty() {
                s.push_str(if report.ran {
                    "Every check passed.\n"
                } else {
                    "No result: the executor did not run.\n"
                });
            } else {
                for f in &report.findings {
                    s.push_str(&format!(
                        "[{}] {}  {}{}\n    {}\n    witness: {}\n",
                        f.severity.name(),
                        f.invariant_id,
                        f.file,
                        if f.is_proven() { "  (PROVEN)" } else { "" },
                        f.message,
                        f.snippet
                    ));
                }
            }
            s
        }
    };
    match &args.out {
        Some(p) => {
            std::fs::write(p, &rendered)?;
            if !quiet {
                eprintln!("✓ Symbolic report written to {}", p.display());
            }
        }
        None => println!("{rendered}"),
    }
    if args.strict && report.findings.iter().any(|f| f.is_proven()) {
        std::process::exit(1);
    }
    if !report.ran {
        std::process::exit(2);
    }
    Ok(())
}

/// Handle `release-check`.
fn cmd_release_check(args: ReleaseCheckArgs, quiet: bool) -> Result<()> {
    let root = &args.path;
    let mut findings = all_native_findings(root, args.advisory_db.as_deref())?;
    let probe_loaded = if let Some(p) = &args.probe_report {
        let text = std::fs::read_to_string(p)
            .with_context(|| format!("reading probe report {}", p.display()))?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        let live: Vec<Finding> = serde_json::from_value(v["findings"].clone())
            .context("probe report has no `findings` array")?;
        findings.extend(live);
        true
    } else {
        false
    };
    let symbolic_loaded = if let Some(p) = &args.symbolic_report {
        let text = std::fs::read_to_string(p)
            .with_context(|| format!("reading symbolic report {}", p.display()))?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        if v["ran"].as_bool() != Some(true) {
            anyhow::bail!(
                "symbolic report {} records a run that did not complete: {}",
                p.display(),
                v["errors"]
            );
        }
        let sym: Vec<Finding> = serde_json::from_value(v["findings"].clone())
            .context("symbolic report has no `findings` array")?;
        findings.extend(sym);
        true
    } else {
        false
    };
    // Test corpora and fixtures are deliberately vulnerable; they are not
    // the repository's exposure.
    findings.retain(|f| !f.file.contains("/corpus/") && !f.file.contains("/fixtures/"));
    // Risk acceptances: known, owned, dated. A malformed file is an error —
    // a typo must not silently un-accept anything.
    let acceptances = truent_pathways::load_acceptances(root).map_err(|e| anyhow::anyhow!(e))?;
    let (findings, accepted, expired) = truent_pathways::apply_acceptances(findings, &acceptances);

    let mut files = Vec::new();
    collect_all_files(root, &mut files)?;
    let rel: Vec<String> = files
        .iter()
        .map(|f| {
            f.strip_prefix(root)
                .unwrap_or(f)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    let texts: Vec<(String, String)> = rel
        .iter()
        .filter(|p| {
            p.starts_with(".github/workflows/")
                || p.ends_with(".gitlab-ci.yml")
                || p.ends_with("Jenkinsfile")
                || p.ends_with(".circleci/config.yml")
                || p.ends_with("package.json")
                || p.ends_with("Cargo.toml")
                || p.ends_with("pyproject.toml")
                || p.ends_with("foundry.toml")
                || p.contains("hardhat.config")
                || p.ends_with("Makefile")
                || p.ends_with("go.mod")
                || p.contains("/migrations/")
                || p.contains("alembic")
                || p.ends_with(".tf")
        })
        .filter_map(|p| {
            std::fs::read_to_string(root.join(p))
                .ok()
                .map(|t| (p.clone(), t))
        })
        .collect();
    let signals = truent_pathways::repo_signals(&truent_pathways::RepoView {
        files: &rel,
        texts: &texts,
    });
    let scope = truent_pathways::RepoScope::from_files(&rel);
    let report = truent_pathways::release_check(
        &findings,
        &signals,
        &scope,
        &truent_pathways::ReleaseInputs {
            probe_loaded,
            symbolic_loaded,
            accepted,
            expired,
        },
    );

    let rendered = match args.format {
        FormatArg::Json => serde_json::to_string_pretty(&json!({
            "target": root.display().to_string(),
            "scope": scope,
            "signals": signals,
            "report": report,
        }))?,
        _ => report.to_markdown(&root.display().to_string()),
    };
    match &args.out {
        Some(p) => {
            std::fs::write(p, &rendered)?;
            if !quiet {
                eprintln!("✓ Release check written to {}", p.display());
            }
        }
        None => println!("{rendered}"),
    }
    if args.strict && !report.ready {
        std::process::exit(1);
    }
    Ok(())
}

/// Handle `harden`.
fn cmd_harden(args: HardenArgs, quiet: bool) -> Result<()> {
    let root = &args.path;
    let mut files = Vec::new();
    collect_all_files(root, &mut files)?;
    let rel: Vec<String> = files
        .iter()
        .map(|f| {
            f.strip_prefix(root)
                .unwrap_or(f)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    let read = |p: &str| std::fs::read_to_string(root.join(p)).ok();
    let profile = truent_pathways::harden_profile(&rel, &read);
    let plan = truent_pathways::harden_plan(&profile);

    if matches!(args.format, FormatArg::Json) && !args.write {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "profile": profile, "artifacts": plan }))?
        );
        return Ok(());
    }

    println!(
        "Harden — {}
",
        root.display()
    );
    let mut written = 0;
    for a in &plan {
        let target = root.join(&a.path);
        let action = if a.append && target.exists() {
            let existing = std::fs::read_to_string(&target).unwrap_or_default();
            let missing = truent_pathways::harden::missing_lines(&existing, &a.content);
            if missing.is_empty() {
                "up to date".to_string()
            } else if args.write {
                let mut out = existing.clone();
                if !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
                out.push_str("\n# --- truent harden ---\n");
                out.push_str(&missing.join("\n"));
                out.push('\n');
                std::fs::write(&target, out)?;
                written += 1;
                format!("appended {} line(s)", missing.len())
            } else {
                format!("would append {} line(s)", missing.len())
            }
        } else if target.exists() {
            "exists — left untouched".to_string()
        } else if args.write {
            if let Some(dir) = target.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&target, &a.content)?;
            written += 1;
            "written".to_string()
        } else {
            "would create".to_string()
        };
        println!("  {:<44} {action}", a.path);
        println!("      {}", a.reason);
        if !a.prevents.is_empty() {
            println!("      prevents: {}", a.prevents.join(", "));
        }
    }
    println!();
    if args.write {
        if !quiet {
            eprintln!("✓ {written} file(s) written. Review and commit them; nothing existing was overwritten.");
        }
    } else {
        println!("Dry run. Re-run with --write to create these files (existing files are never overwritten).");
    }
    Ok(())
}

/// Handle `probe`.
fn cmd_probe(args: ProbeArgs, quiet: bool) -> Result<()> {
    use truent_runtime::{ports::DEFAULT_PORTS, probe, ProbeOptions, Target};
    let target = Target::parse(&args.target)?;
    let ports = match args.ports.as_deref() {
        None => DEFAULT_PORTS.to_vec(),
        Some("none") => Vec::new(),
        Some(list) => list
            .split(',')
            .map(|p| {
                p.trim()
                    .parse::<u16>()
                    .with_context(|| format!("bad port `{p}`"))
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let opts = ProbeOptions {
        authorized: args.authorized,
        timeout: std::time::Duration::from_secs(args.timeout),
        ports,
        check_paths: !args.no_paths,
    };
    let report = probe(&target, &opts)?;

    if let Some(path) = &args.sarif {
        write_sarif(&report.findings, path, quiet)?;
    }

    match args.format {
        FormatArg::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        _ => {
            println!("Probe: {}", target.origin());
            if let Some(t) = &report.tls {
                println!(
                    "  TLS    {} {}  chain verified: {}  expires in {} day(s)  subject: {}",
                    t.protocol,
                    t.cipher,
                    t.chain_verified,
                    (t.not_after - truent_runtime::unix_now()) / 86_400,
                    t.subject
                );
            }
            if let Some(h) = &report.http {
                println!(
                    "  HTTP   {} → {}  ({} header(s))",
                    h.status,
                    h.final_url,
                    h.headers.len()
                );
            }
            if !report.exposed.is_empty() {
                println!(
                    "  Paths  {} probed, {} exposed",
                    report.exposed.len(),
                    report.exposed.iter().filter(|p| p.matched).count()
                );
            }
            if !report.ports.is_empty() {
                let open: Vec<String> = report
                    .ports
                    .iter()
                    .filter(|p| p.open)
                    .map(|p| format!("{}/{}", p.port, p.service))
                    .collect();
                println!(
                    "  Ports  {} checked, open: {}",
                    report.ports.len(),
                    if open.is_empty() {
                        "none".to_string()
                    } else {
                        open.join(", ")
                    }
                );
            }
            for e in &report.errors {
                println!("  !      {e}");
            }
            println!();
            if report.findings.is_empty() {
                println!("No runtime findings.");
            } else {
                for f in &report.findings {
                    println!("[{}] {}  {}", f.severity.name(), f.invariant_id, f.file);
                    println!("    {}", f.message);
                    println!("    evidence: {}", f.snippet);
                }
                println!();
                println!(
                    "{} finding(s), all PROVEN — each records what the target returned.",
                    report.findings.len()
                );
            }
        }
    }

    let fail_rank = severity_arg_rank(&args.fail_on);
    if report
        .findings
        .iter()
        .any(|f| severity_rank(f.severity.name()) >= fail_rank)
    {
        std::process::exit(1);
    }
    Ok(())
}

/// Handle `pathways`.
fn cmd_pathways(args: PathwaysArgs) -> Result<()> {
    use truent_pathways::{pathway, pathways, Coverage};
    let selected: Vec<&truent_pathways::Pathway> = match &args.id {
        Some(id) => {
            vec![pathway(id).with_context(|| format!("no pathway '{id}'. Try: truent pathways"))?]
        }
        None => pathways().iter().collect(),
    };
    if matches!(args.format, FormatArg::Json) {
        println!("{}", serde_json::to_string_pretty(&selected)?);
        return Ok(());
    }
    for p in selected {
        let native = p
            .controls
            .iter()
            .filter(|c| matches!(c, Coverage::Native(_)))
            .count();
        let hosted = p
            .controls
            .iter()
            .filter(|c| matches!(c, Coverage::Hosted(_)))
            .count();
        let manual = p
            .controls
            .iter()
            .filter(|c| matches!(c, Coverage::Assess(_)))
            .count();
        println!("{}  [{}]  — {}", p.name, p.id, p.purpose);
        println!("  stage: {:?}   native detectors: {native}   hosted subdomains: {hosted}   manual controls: {manual}", p.stage);
        if args.id.is_some() {
            for c in p.controls {
                match c {
                    Coverage::Native(d) => println!("    native   {d}"),
                    Coverage::Hosted(s) => {
                        println!("    hosted   {s}  (truent skills search --subdomain {s})")
                    }
                    Coverage::Assess(t) => println!("    verify   {t}"),
                }
            }
        }
        println!();
    }
    Ok(())
}

/// Findings from every native engine over a tree, plus the dependency half.
fn all_native_findings(root: &Path, advisory_db: Option<&Path>) -> Result<Vec<Finding>> {
    let mut findings = run_analysis_findings(root, &ChainArg::Auto, false)?;
    let db = match advisory_db {
        Some(dir) => Some(truent_sca::AdvisoryDb::load_dir(dir)?),
        None => None,
    };
    findings.extend(truent_sca::analyze(root, db.as_ref()).findings);
    Ok(findings)
}

/// Installed skills per subdomain, when a catalog is reachable.
fn installed_skills_by_subdomain() -> Option<std::collections::BTreeMap<String, usize>> {
    let root = truent_skills::default_root();
    let catalog =
        truent_skills::Catalog::load(&root, truent_skills::builtin_skills_dir().as_deref()).ok()?;
    let mut m = std::collections::BTreeMap::new();
    for s in catalog.skills() {
        if let Some(sd) = &s.subdomain {
            *m.entry(sd.clone()).or_default() += 1;
        }
    }
    Some(m)
}

/// Handle `assess`.
fn cmd_assess(args: AssessArgs, quiet: bool) -> Result<()> {
    let findings = all_native_findings(&args.path, args.advisory_db.as_deref())?;
    let skills = installed_skills_by_subdomain();
    let a = truent_pathways::assess(&findings, skills.as_ref());
    let target = args.path.display().to_string();
    let rendered = match args.format {
        FormatArg::Json => serde_json::to_string_pretty(&a)?,
        _ => a.to_markdown(&target),
    };
    match &args.out {
        Some(p) => {
            std::fs::write(p, &rendered)?;
            if !quiet {
                eprintln!("✓ Assessment written to {}", p.display());
            }
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

/// Handle `threat-model`.
fn cmd_threat_model(args: ThreatModelArgs) -> Result<()> {
    let mut files = Vec::new();
    if args.path.is_dir() {
        collect_all_files(&args.path, &mut files)?;
    } else {
        files.push(args.path.clone());
    }
    let mut pairs = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(&args.path)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        if !general::applies_to(&rel) && !rel.ends_with(".sol") {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(&f) {
            pairs.push((rel, src));
        }
    }
    let m = truent_pathways::threat_model(&pairs);
    let rendered = match args.format {
        FormatArg::Json => serde_json::to_string_pretty(&m)?,
        _ => m.to_markdown(&args.path.display().to_string()),
    };
    match &args.out {
        Some(p) => {
            std::fs::write(p, &rendered)?;
            eprintln!("✓ Threat model written to {}", p.display());
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

/// Handle the `taxonomy` subcommand.
///
/// Answers "what does Truent actually detect, and what is it called elsewhere?"
/// — the question a security lead asks before adopting a scanner, and the
/// question `docs/COVERAGE.md` is generated from so the answer cannot go stale.
fn cmd_taxonomy(args: TaxonomyArgs) -> Result<()> {
    let chain_filter = args.chain.map(|c| match c {
        ChainArg::Evm => "evm",
        ChainArg::Solana => "solana",
        ChainArg::Move => "move",
        ChainArg::Soroban => "soroban",
        ChainArg::General => "general",
        ChainArg::Auto => "auto",
    });

    let needle = args.id.as_ref().map(|s| s.to_uppercase());

    let entries: Vec<&truent_core::Taxonomy> = truent_core::taxonomy::all()
        .iter()
        .filter(|t| match chain_filter {
            Some(c) => t.chain() == Some(c),
            None => true,
        })
        .filter(|t| match &needle {
            Some(n) => t.tags().iter().any(|tag| tag.to_uppercase() == *n),
            None => true,
        })
        .collect();

    let rendered = match args.format {
        TaxonomyFormat::Json => serde_json::to_string_pretty(&json!({
            "total": entries.len(),
            "detectors": entries.iter().map(|t| {
                let e = truent_core::exposure::exposure_for(t.invariant_id);
                json!({
                    "invariant_id": t.invariant_id,
                    "chain": t.chain(),
                    "cwe": t.cwe.iter().map(|c| c.id_str()).collect::<Vec<_>>(),
                    "cwe_names": t.cwe.iter().map(|c| c.name).collect::<Vec<_>>(),
                    "swc": t.swc.iter().map(|x| x.id_str()).collect::<Vec<_>>(),
                    "owasp_sc": t.owasp_sc.iter().map(|o| o.id_str()).collect::<Vec<_>>(),
                    "dasp": t.dasp.iter().map(|d| d.id_str()).collect::<Vec<_>>(),
                    "attack": t.attack.iter().map(|a| a.id).collect::<Vec<_>>(),
                    "attack_names": t.attack.iter().map(|a| a.name).collect::<Vec<_>>(),
                    "nist_csf": t.nist_csf.iter().map(|n| n.id).collect::<Vec<_>>(),
                    // Exposure profile: how the weakness is reached and closed.
                    "vector": e.map(|e| e.vector),
                    "prereq": e.map(|e| e.prereq),
                    "interaction": e.map(|e| e.interaction),
                    "impact": e.map(|e| e.impact),
                    "fix": e.map(|e| e.fix),
                    "verify": e.map(|e| e.verify),
                })
            }).collect::<Vec<_>>(),
        }))?,
        TaxonomyFormat::Markdown => render_taxonomy_markdown(&entries),
        TaxonomyFormat::Text => render_taxonomy_text(&entries),
    };

    match args.output {
        Some(path) => {
            std::fs::write(&path, &rendered)
                .with_context(|| format!("writing {}", path.display()))?;
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

/// Render the coverage matrix as the Markdown committed to `docs/COVERAGE.md`.
fn render_taxonomy_markdown(entries: &[&truent_core::Taxonomy]) -> String {
    // A raw string: a backslash-continued literal bakes this function's own
    // indentation into the generated Markdown.
    let mut out = String::from(
        r#"# Detector coverage

<!-- Generated by `truent taxonomy --format markdown`. Do not edit by hand.
     Regenerate with: truent taxonomy --format markdown --output docs/COVERAGE.md -->

Every detector Truent ships, and the industry identifiers it maps to. A blank
cell means no honest mapping exists — SWC, OWASP SC and DASP are contract
registries, so repository rows leave them empty, and MITRE ATT&CK / NIST CSF
are populated only for repository findings, where they are precise.

"#,
    );

    out.push_str(&format!("**{} detectors.**\n\n", entries.len()));

    for (chain, label) in [
        (Some("evm"), "EVM"),
        (Some("solana"), "Solana"),
        (Some("move"), "Move"),
        (Some("soroban"), "Soroban"),
        (Some("general"), "General (any repository)"),
        (Some("supply-chain"), "Supply chain (dependencies)"),
        (Some("runtime"), "Runtime (live probe, proven)"),
        (None, "Chain-agnostic"),
    ] {
        let rows: Vec<&&truent_core::Taxonomy> =
            entries.iter().filter(|t| t.chain() == chain).collect();
        if rows.is_empty() {
            continue;
        }
        let noun = if rows.len() == 1 {
            "detector"
        } else {
            "detectors"
        };
        out.push_str(&format!("## {label} ({} {noun})\n\n", rows.len()));
        out.push_str(
            "| Detector | CWE | SWC | OWASP SC Top 10 | DASP | MITRE ATT&CK | NIST CSF |\n",
        );
        out.push_str("|---|---|---|---|---|---|---|\n");
        for t in rows {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} |\n",
                t.invariant_id,
                t.cwe
                    .iter()
                    .map(|c| format!("[{}]({})", c.id_str(), c.url()))
                    .collect::<Vec<_>>()
                    .join("<br>"),
                t.swc
                    .iter()
                    .map(|x| format!("[{}]({})", x.id_str(), x.url()))
                    .collect::<Vec<_>>()
                    .join("<br>"),
                t.owasp_sc
                    .iter()
                    .map(|o| o.id_str().to_string())
                    .collect::<Vec<_>>()
                    .join("<br>"),
                t.dasp
                    .iter()
                    .map(|d| d.id_str())
                    .collect::<Vec<_>>()
                    .join("<br>"),
                t.attack
                    .iter()
                    .map(|a| format!("[{}]({})", a.id, a.url()))
                    .collect::<Vec<_>>()
                    .join("<br>"),
                t.nist_csf
                    .iter()
                    .map(|n| n.id.to_string())
                    .collect::<Vec<_>>()
                    .join("<br>"),
            ));
        }
        out.push('\n');
    }
    out
}

/// Render the coverage matrix for a terminal.
fn render_taxonomy_text(entries: &[&truent_core::Taxonomy]) -> String {
    let mut out = format!("{} detector(s)\n\n", entries.len());
    for t in entries {
        out.push_str(&format!(
            "{}  [{}]\n",
            t.invariant_id,
            t.chain().unwrap_or("all chains")
        ));
        for (label, values) in [
            ("CWE  ", t.cwe.iter().map(|c| c.label()).collect::<Vec<_>>()),
            ("SWC  ", t.swc.iter().map(|x| x.label()).collect::<Vec<_>>()),
            (
                "OWASP",
                t.owasp_sc.iter().map(|o| o.label()).collect::<Vec<_>>(),
            ),
            (
                "DASP ",
                t.dasp.iter().map(|d| d.label()).collect::<Vec<_>>(),
            ),
        ] {
            if !values.is_empty() {
                out.push_str(&format!("  {label}  {}\n", values.join(", ")));
            }
        }
        out.push('\n');
    }
    out
}

/// CWE label for an invariant, from the shared taxonomy table.
///
/// Previously this guessed by substring-matching the invariant ID and fell
/// back to `CWE-676 · Use of Potentially Dangerous Function` for anything it
/// did not recognise — which was most detectors, so most reports carried a
/// wrong CWE. The mapping now lives in `truent_core::taxonomy`, where a test
/// fails the build if a detector ships without one.
///
/// Returns `None` when there is genuinely no mapping (a user-authored `.sinv`
/// invariant); the renderer omits the line rather than inventing a class.
fn cwe_label(invariant_id: &str) -> Option<String> {
    taxonomy_for(invariant_id).map(|t| t.primary_cwe().label())
}

/// Count violations by severity level.
fn count_violations_by_severity(violations: &[Violation]) -> (usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for v in violations {
        match v.severity.to_lowercase().as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => low += 1,
        }
    }

    (critical, high, medium, low)
}

/// Handle the `report` subcommand.
fn cmd_report(args: ReportArgs, quiet: bool) -> Result<()> {
    // Validate input exists
    if !args.input.exists() {
        return Err(anyhow::anyhow!(
            "Input file not found: {}",
            args.input.display()
        ));
    }

    // Read input file
    let input_content = std::fs::read_to_string(&args.input)
        .map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))?;

    // Parse input - if it looks like JSON, try to parse it as analysis results
    let analysis_data =
        if input_content.trim().starts_with('{') || input_content.trim().starts_with('[') {
            serde_json::from_str::<serde_json::Value>(&input_content)
                .unwrap_or_else(|_| json!({"content": input_content}))
        } else {
            // If it's not JSON, treat it as raw content
            json!({"content": input_content})
        };

    // Generate report based on format
    let report_output = match args.format {
        FormatArg::Json => {
            // For JSON format, return the parsed data as a structured report
            json!({
                "report_type": "analysis",
                "source": args.input.display().to_string(),
                "data": analysis_data,
                "format": "json"
            })
            .to_string()
        }
        FormatArg::Html => {
            // For HTML format, generate a simple HTML wrapper around the data
            format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Report</title>
    <style>
        body {{ font-family: monospace; margin: 20px; }}
        pre {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Report</h1>
    <p><strong>Source:</strong> {}</p>
    <pre>{}</pre>
</body>
</html>"#,
                args.input.display(),
                serde_json::to_string_pretty(&analysis_data).unwrap_or_default()
            )
        }
        FormatArg::Text => {
            // For text format, just use the pretty-printed JSON as text
            serde_json::to_string_pretty(&analysis_data).unwrap_or_default()
        }
    };

    if !quiet {
        eprintln!(
            "✓ Generating {} report from {}",
            match args.format {
                FormatArg::Text => "text",
                FormatArg::Json => "JSON",
                FormatArg::Html => "HTML",
            },
            args.input.display()
        );
    }

    // Output the report
    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &report_output)
            .map_err(|e| anyhow::anyhow!("Failed to write report: {}", e))?;
        if !quiet {
            eprintln!("✓ Report written to {}", output_path.display());
        }
    } else {
        println!("{}", report_output);
    }

    if !quiet {
        eprintln!("✓ Report generated successfully");
    }

    Ok(())
}

/// Generate an HTML report from analysis data
/// Generate a text report from analysis data
fn generate_text_report(data: &serde_json::Value, source: &std::path::Path) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{} seconds since epoch", d.as_secs()))
        .unwrap_or_else(|_| "unknown time".to_string());

    format!(
        r#"================================================================================
                        TRUENT ANALYSIS REPORT
================================================================================

Generated: {}
Source:    {}

================================================================================
                          ANALYSIS SUMMARY
================================================================================

{}

================================================================================
                            END OF REPORT
================================================================================
"#,
        timestamp,
        source.display(),
        serde_json::to_string_pretty(data).unwrap_or_default()
    )
}

/// Handle the `init` subcommand.
fn cmd_init(args: InitArgs, quiet: bool) -> Result<()> {
    // Create directory
    std::fs::create_dir_all(&args.path)?;

    // Create .truent.toml
    let config_path = args.path.join(".truent.toml");
    let config_content = r#"# Truent Configuration
[project]
name = "my_contracts"
version = "0.1.0"

[chains]
enabled = ["evm"]

[invariants]
# Add your invariant checks here
"#;

    std::fs::write(&config_path, config_content)?;

    if !quiet {
        println!("{}", render_init_success(&args.path));
    }

    Ok(())
}

/// Handle the `doctor` subcommand.
/// Total built-in invariants across every supported chain.
fn builtin_invariant_count() -> usize {
    ["evm", "solana", "move", "soroban"]
        .iter()
        .map(|c| InvariantLibrary::with_defaults(c).all().len())
        .sum()
}

/// Health of the skill runtime.
///
/// Reports what is actually registered rather than asserting success: having
/// no sources is a perfectly healthy state, and saying so is more useful than
/// a check that cannot fail.
fn skills_health_check() -> HealthCheck {
    let root = truent_skills::default_root();
    match truent_skills::SourceRegistry::load(&root) {
        Ok(reg) if reg.sources.is_empty() => HealthCheck {
            component: "Skill runtime".to_string(),
            passed: true,
            message: "ready — no sources registered (truent skills source suggest)".to_string(),
        },
        Ok(reg) => {
            let catalog = truent_skills::Catalog::load(&root, None)
                .map(|c| c.len())
                .unwrap_or(0);
            HealthCheck {
                component: "Skill runtime".to_string(),
                passed: true,
                message: format!(
                    "{} source(s), {} skill(s) indexed",
                    reg.sources.len(),
                    catalog
                ),
            }
        }
        Err(e) => HealthCheck {
            component: "Skill runtime".to_string(),
            passed: false,
            message: format!("source registry unreadable: {e}"),
        },
    }
}

/// Known-vulnerable snippets used to prove each analyzer actually detects.
///
/// A health check that constructs a struct and reports success proves only
/// that the struct exists. These drive each chain's real detector pipeline and
/// assert it finds the bug — so the check fails if detection regresses.
///
/// They are text-only: `run_all_detectors` works on source text, so no `solc`
/// or other toolchain is needed and `doctor` cannot fail for want of one.
mod doctor_fixtures {
    /// Checks-effects-interactions violation: external call before the state
    /// update.
    pub const EVM: &str = r#"
pragma solidity ^0.8.0;
contract V {
    mapping(address => uint256) public balanceOf;
    function withdraw(uint256 a) public {
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok);
        balanceOf[msg.sender] -= a;
    }
}
"#;

    /// Privileged lamport mutation with no signer check.
    pub const SOLANA: &str = r#"
use anchor_lang::prelude::*;
#[program]
pub mod p {
    use super::*;
    pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        Ok(())
    }
}
#[derive(Accounts)]
pub struct W<'info> {
    #[account(mut)]
    pub vault: AccountInfo<'info>,
}
"#;

    /// Global state mutated with no signer requirement, unchecked subtraction.
    pub const MOVE: &str = r#"
module demo::vault {
    struct Coin has key { value: u64 }
    public fun withdraw(amount: u64) acquires Coin {
        let c = borrow_global_mut<Coin>(@demo);
        c.value = c.value - amount;
    }
}
"#;

    /// A committed AWS key and a shell-injected subprocess call.
    // The key is synthetic; the marker keeps a self-scan honest.
    pub const GENERAL: &str = r#"
import subprocess
// truent:allow
AWS_KEY = "AKIAJ4X7Z2K9M1P3Q5R7"  # synthetic
def ping(host):
    subprocess.run(f"ping -c 1 {host}", shell=True)
"#;

    /// Transfer with no `require_auth`, and an unprotected upgrade.
    pub const SOROBAN: &str = r#"
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        let b: i128 = env.storage().instance().get(&to).unwrap_or(0);
        env.storage().instance().set(&to, &(b + amount));
    }
    pub fn upgrade(env: Env, hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(hash);
    }
}
"#;
}

/// Build a health check from a detector self-test.
///
/// Reports the number of findings rather than "initialized": a count of zero
/// means the pipeline is wired but detecting nothing, which is a failure worth
/// seeing rather than a silent pass.
fn detector_health_check(component: &str, findings: usize) -> HealthCheck {
    HealthCheck {
        component: component.to_string(),
        passed: findings > 0,
        message: if findings > 0 {
            format!("{findings} finding(s) on the built-in self-test")
        } else {
            "self-test produced no findings — detection is not working".to_string()
        },
    }
}

/// Health of `truent-core`: the compiled-in invariants and the finding type.
fn core_health_check() -> HealthCheck {
    let compiled = truent_core::invariant_count();
    // Round-trip a finding through the taxonomy table: proves the type, the
    // table and the lookup all agree.
    let probe = Finding::new(
        "evm_reentrancy_classic".to_string(),
        truent_core::Severity::Critical,
        "self-test".to_string(),
        1,
        0,
        "self-test".to_string(),
        String::new(),
    );
    let mapped = probe.taxonomy().map(|t| t.primary_cwe().id);

    match mapped {
        Some(841) => HealthCheck {
            component: "truent-core".to_string(),
            passed: true,
            message: format!("{compiled} compiled invariants, taxonomy lookup OK"),
        },
        other => HealthCheck {
            component: "truent-core".to_string(),
            passed: false,
            message: format!("taxonomy lookup returned {other:?}, expected CWE-841"),
        },
    }
}

/// Health of the DSL parser: actually parse an invariant.
fn dsl_health_check() -> HealthCheck {
    const SOURCE: &str = "invariant BalancePositive { balance >= 0 }";
    match truent_dsl_parser::parse_invariant(SOURCE) {
        Ok(inv) if inv.name == "BalancePositive" => HealthCheck {
            component: "DSL parser".to_string(),
            passed: true,
            message: "parsed and named a test invariant".to_string(),
        },
        Ok(inv) => HealthCheck {
            component: "DSL parser".to_string(),
            passed: false,
            message: format!(
                "parsed, but named it '{}' instead of 'BalancePositive'",
                inv.name
            ),
        },
        Err(e) => HealthCheck {
            component: "DSL parser".to_string(),
            passed: false,
            message: format!("failed to parse a test invariant: {e}"),
        },
    }
}

/// Health of the report generator: render a report and inspect it.
fn report_health_check() -> HealthCheck {
    let finding = Finding::new(
        "evm_reentrancy_classic".to_string(),
        truent_core::Severity::Critical,
        "self-test.sol".to_string(),
        1,
        0,
        "self-test".to_string(),
        String::new(),
    );
    let report = truent_report::SecurityReport::new(
        "self-test".to_string(),
        vec!["self-test.sol".to_string()],
        vec![finding],
        "self-test".to_string(),
    );
    let json = report.generate(truent_report::ReportFormat::Json);

    // The report must parse, and must carry the taxonomy — the part most
    // likely to silently regress, since it is assembled rather than derived.
    match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(v) if v["findings"][0]["taxonomy"]["cwe"][0]["id"] == "CWE-841" => HealthCheck {
            component: "Report generator".to_string(),
            passed: true,
            message: "rendered a report with taxonomy attached".to_string(),
        },
        Ok(_) => HealthCheck {
            component: "Report generator".to_string(),
            passed: false,
            message: "rendered a report, but the taxonomy is missing".to_string(),
        },
        Err(e) => HealthCheck {
            component: "Report generator".to_string(),
            passed: false,
            message: format!("produced invalid JSON: {e}"),
        },
    }
}

/// Health of the SCA engine: parse a lockfile and match a known-bad pin.
fn sca_health_check() -> HealthCheck {
    let lock = "version = 4\n\n[[package]]\nname = \"lodash-rs\"\nversion = \"1.0.0\"\n";
    let pkgs = truent_sca::parse_lockfile(std::path::Path::new("Cargo.lock"), lock);
    let mut db = truent_sca::AdvisoryDb::default();
    if let Some(a) = truent_sca::advisory::parse_osv(
        r#"{"id":"SELF-1","affected":[{"package":{"ecosystem":"crates.io","name":"lodash-rs"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]}"#,
    ) {
        db.insert(a);
    }
    let hits = truent_sca::advisory::match_packages(&db, &pkgs, "Cargo.lock").len();
    HealthCheck {
        component: "Dependency analysis".to_string(),
        passed: pkgs.len() == 1 && hits == 1,
        message: if pkgs.len() == 1 && hits == 1 {
            "parsed a lockfile and matched a known-vulnerable pin".to_string()
        } else {
            format!("self-test parsed {} package(s), matched {hits}", pkgs.len())
        },
    }
}

fn runtime_health_check() -> HealthCheck {
    // Pure evaluators over fixtures — the probe's network layer is never
    // touched by doctor.
    let bare = truent_runtime::http::HttpObservation {
        url: "https://self/".into(),
        final_url: "https://self/".into(),
        status: 200,
        headers: vec![("content-type".into(), "text/html".into())],
        first_hop_status: None,
        first_hop_location: None,
    };
    let headers = truent_runtime::http::analyze(&bare, "https://self").len();
    let weak = truent_runtime::tls::analyze_failure(
        &truent_runtime::tls::TlsFailure::Incompatible("fixture".into()),
        "self:443",
    )
    .len();
    let passed = headers >= 4 && weak == 1;
    HealthCheck {
        component: "Runtime probe".to_string(),
        passed,
        message: if passed {
            "header and TLS evaluators produce findings from fixtures (no network used)".to_string()
        } else {
            format!("self-test: {headers} header finding(s), {weak} TLS finding(s)")
        },
    }
}

fn cmd_doctor(args: DoctorArgs, quiet: bool) -> Result<()> {
    use doctor_fixtures as fx;

    let checks = vec![
        core_health_check(),
        detector_health_check(
            "EVM analyzer",
            truent_analyzer_evm::detectors::run_all_detectors(fx::EVM, "self-test.sol").len(),
        ),
        detector_health_check(
            "Solana analyzer",
            truent_analyzer_solana::run_all_detectors(fx::SOLANA, "self-test.rs").len(),
        ),
        detector_health_check(
            "Move analyzer",
            truent_analyzer_move::run_all_detectors(fx::MOVE, "self-test.move").len(),
        ),
        detector_health_check(
            "Soroban analyzer",
            truent_analyzer_soroban::run_all_detectors(fx::SOROBAN, "self-test.rs").len(),
        ),
        detector_health_check(
            "General analyzer",
            general::run_all_detectors(fx::GENERAL, "self-test.py").len(),
        ),
        sca_health_check(),
        runtime_health_check(),
        HealthCheck {
            component: "Exposure & remediation".to_string(),
            passed: truent_core::taxonomy::all()
                .iter()
                .all(|t| truent_core::exposure::exposure_for(t.invariant_id).is_some())
                && !truent_pathways::chains().is_empty(),
            message: format!(
                "{} detectors have an attack profile, fix and verify step; {} attack chains known",
                truent_core::exposure::all().len(),
                truent_pathways::chains().len()
            ),
        },
        HealthCheck {
            component: "Symbolic execution".to_string(),
            passed: {
                let (f, s) = truent_symbolic::halmos::parse(
                    r#"{"exitcode":1,"test_results":{"t/A.t.sol:A":[{"name":"check_x(uint256)","exitcode":1,"num_models":1,"models":[{"model":{"p":{"variable_name":"x","solidity_type":"uint256","value":1}},"is_valid":true}]}]}}"#,
                    "p",
                );
                s.failed == 1 && f.len() == 1 && f[0].is_proven()
            },
            message: format!(
                "halmos/hevm/mythril parsers turn counterexamples into proven findings; installed: {}",
                {
                    let t = truent_symbolic::detect();
                    if t.is_empty() { "none (pip install halmos)".to_string() } else { t.iter().map(|i| format!("{} {}", i.tool.name(), i.version)).collect::<Vec<_>>().join(", ") }
                }
            ),
        },
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
        dsl_health_check(),
        HealthCheck {
            component: "Invariant library".to_string(),
            passed: builtin_invariant_count() > 0,
            message: format!("{} built-in invariants loaded", builtin_invariant_count()),
        },
        HealthCheck {
            component: "Detector taxonomy".to_string(),
            passed: !truent_core::taxonomy::all().is_empty(),
            message: format!(
                "{} detectors mapped to CWE/SWC/OWASP/DASP",
                truent_core::taxonomy::all().len()
            ),
        },
        report_health_check(),
        skills_health_check(),
    ];

    match args.format {
        FormatArg::Text => {
            if !quiet {
                println!("{}", render_doctor_results(&checks));
            }
        }
        FormatArg::Json => {
            // Build components map
            let mut components = serde_json::Map::new();
            for check in &checks {
                components.insert(
                    check.component.clone(),
                    json!({
                        "status": if check.passed { "ok" } else { "error" },
                        "message": &check.message,
                    }),
                );
            }

            let report = json!({
                "status": if checks.iter().all(|c| c.passed) { "healthy" } else { "error" },
                "components": components,
            });

            let output_json = serde_json::to_string_pretty(&report)?;

            if let Some(output_path) = args.output {
                std::fs::write(&output_path, &output_json)?;
                if !quiet {
                    eprintln!("✓ Report written to {}", output_path.display());
                }
            } else {
                println!("{}", output_json);
            }
        }
        FormatArg::Html => {
            if !quiet {
                eprintln!("ℹ HTML format is not yet implemented");
            }
            // Fall back to JSON
            let report = json!({
                "status": if checks.iter().all(|c| c.passed) { "healthy" } else { "error" },
                "components": checks,
            });

            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    // Exit non-zero when a component is unhealthy.
    //
    // Every check used to be a hardcoded `passed: true`, so the return value
    // was academic. Now that checks report real state, `truent doctor` is only
    // usable as an install gate — which is exactly how the release workflow
    // uses it — if a failure actually fails.
    if checks.iter().any(|c| !c.passed) {
        std::process::exit(1);
    }

    Ok(())
}

/// Handle the `scan` subcommand (enhanced version of check).
/// Rank a violation/finding severity string for threshold comparisons (higher = more severe).
fn severity_rank(name: &str) -> u32 {
    match name.to_lowercase().as_str() {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0, // low / info
    }
}

/// Rank a `SeverityArg` CLI value using the same scale as `severity_rank`.
fn severity_arg_rank(arg: &SeverityArg) -> u32 {
    match arg {
        SeverityArg::Critical => 3,
        SeverityArg::High => 2,
        SeverityArg::Medium => 1,
        SeverityArg::Low => 0,
    }
}

fn cmd_scan(args: ScanArgs, quiet: bool, verbose: bool) -> Result<()> {
    let start_time = Instant::now();

    let chain_name = match args.chain {
        ChainArg::Evm => "EVM",
        ChainArg::Solana => "Solana",
        ChainArg::Move => "Move",
        ChainArg::Soroban => "Soroban",
        ChainArg::General => "General",
        ChainArg::Auto => "Auto",
    };

    if !quiet {
        eprintln!("▶ Scanning {} on {}...", args.path.display(), chain_name);
        if args.rpc.is_some() {
            eprintln!("⚠ --rpc is not yet implemented; on-chain verification will be skipped");
        }
        if args.parallel {
            eprintln!("⚠ --parallel is not yet implemented; scanning sequentially");
        }
        if args.no_color {
            eprintln!("⚠ --no-color is not yet implemented; output may still include ANSI codes");
        }
    }

    // Run detectors. Filters are applied to the findings rather than to the
    // display-shaped violations, so every output — terminal, JSON, SARIF —
    // describes exactly the same set. Filtering twice, once per shape, is how
    // a SARIF artifact ends up disagreeing with the log above it.
    let mut findings = run_analysis_findings(&args.path, &args.chain, verbose)?;

    // Apply minimum-severity filter.
    if let Some(min_severity) = &args.severity {
        let min_rank = severity_arg_rank(min_severity);
        // Rank through `severity_rank` rather than `Severity::value()`: the
        // CLI's scale is 4-level (low..critical == 0..3) while the core enum's
        // is 5-level (info..critical == 0..4), so comparing across them lets
        // High pass a `--severity critical` filter.
        findings.retain(|f| severity_rank(f.severity.name()) >= min_rank);
    }

    // Apply invariant ID filter (may be repeated on the CLI).
    if !args.invariant.is_empty() {
        findings.retain(|f| {
            args.invariant
                .iter()
                .any(|id| f.invariant_id.contains(id.as_str()))
        });
    }

    if let Some(sarif_path) = &args.sarif {
        write_sarif(&findings, sarif_path, quiet)?;
    }

    // Index/total are assigned after filtering so they stay consistent.
    let total = findings.len();
    let violations: Vec<Violation> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| finding_to_violation(f, i + 1, total))
        .collect();

    let duration_secs = start_time.elapsed().as_secs_f64();
    let (critical, high, medium, low) = count_violations_by_severity(&violations);

    let proven = violations.iter().filter(|v| v.evidence.is_proven()).count();
    let leads = violations.len() - proven;

    let summary = AnalysisSummary {
        target: args.path.display().to_string(),
        chain: chain_name.to_string(),
        total_checks: violations.len(),
        violations: violations.len(),
        passed: 0,
        proven,
        leads,
        suppressed: 0,
        duration_secs,
        severity_breakdown: SeverityBreakdown {
            critical,
            high,
            medium,
            low,
        },
    };

    match args.output {
        FormatArg::Text => {
            let mut report_text = String::new();
            if !violations.is_empty() {
                report_text.push_str(&render_violations(&violations));
                report_text.push('\n');
            }
            report_text.push_str(&render_summary(&summary));

            if let Some(output_path) = &args.file {
                std::fs::write(output_path, &report_text)?;
                if !quiet {
                    eprintln!("✓ Report written to {}", output_path.display());
                }
            } else if !quiet {
                println!("{}", report_text);
            }
        }
        FormatArg::Json => {
            let report = json!({
                "version": env!("CARGO_PKG_VERSION"),
                "chain": summary.chain,
                "target": summary.target,
                "duration_ms": (summary.duration_secs * 1000.0) as u64,
                "summary": {
                    "violations": summary.violations,
                    "critical": summary.severity_breakdown.critical,
                    "high": summary.severity_breakdown.high,
                    "medium": summary.severity_breakdown.medium,
                    "low": summary.severity_breakdown.low,
                },
                "violations": violations,
            });
            let output_json = serde_json::to_string_pretty(&report)?;

            if let Some(output_path) = &args.file {
                std::fs::write(output_path, &output_json)?;
                if !quiet {
                    eprintln!("✓ Report written to {}", output_path.display());
                }
            } else {
                println!("{}", output_json);
            }
        }
        FormatArg::Html => {
            let html_report = generate_html_report(&summary, &violations);

            if let Some(output_path) = &args.file {
                std::fs::write(output_path, &html_report)?;
                if !quiet {
                    eprintln!("✓ HTML report written to {}", output_path.display());
                }
            } else {
                println!("{}", html_report);
            }
        }
    }

    if !quiet {
        eprintln!("✓ Scan complete");
    }

    // Exit non-zero only for results that were actually reproduced, at or
    // above --fail-on.
    //
    // A lead is a pattern match nobody executed; failing a build on one asks
    // the team to treat a guess as a defect, and the first false positive
    // teaches them to bypass the gate entirely. Leads are reported and
    // surfaced in the summary, but only a proven violation blocks. Pass
    // --fail-on-leads to gate on unproven results too.
    let fail_rank = severity_arg_rank(&args.fail_on);
    let blocking = violations.iter().any(|v| {
        severity_rank(&v.severity) >= fail_rank && (v.evidence.is_proven() || args.fail_on_leads)
    });
    if blocking {
        std::process::exit(1);
    }

    Ok(())
}

/// Handle the `registry` subcommand.
fn cmd_registry(args: RegistryArgs, quiet: bool) -> Result<()> {
    use truent_core::EXPLOIT_REGISTRY;

    match args.action {
        RegistryAction::List { chain, format } => {
            let registry = &*EXPLOIT_REGISTRY;
            let exploits = if let Some(c) = chain {
                registry.by_chain(&c)
            } else {
                registry.all()
            };

            match format {
                FormatArg::Text => {
                    if !quiet {
                        println!(
                            "\n{} Historical DeFi Exploits Mapped to Truent Invariants",
                            exploits.len()
                        );
                        println!("{}", "=".repeat(80));
                        for exploit in &exploits {
                            println!(
                                "\n  {} | {} | {} | ${} loss",
                                exploit.id, exploit.protocol, exploit.date, exploit.loss_usd
                            );
                            println!("    Invariants: {}", exploit.invariant_ids.join(", "));
                        }
                        println!("\n{}", "=".repeat(80));
                        println!("Total loss: ${}", registry.total_loss());
                    }
                }
                FormatArg::Json => {
                    let json_exploits: Vec<_> = exploits.iter().map(|e| json!(e)).collect();
                    println!("{}", serde_json::to_string_pretty(&json_exploits)?);
                }
                _ => {
                    if !quiet {
                        eprintln!("ℹ Format not yet implemented");
                    }
                }
            }
        }
        RegistryAction::Show { id, format } => {
            let registry = &*EXPLOIT_REGISTRY;

            match registry.get(&id) {
                Some(exploit) => match format {
                    FormatArg::Text => {
                        if !quiet {
                            println!("\n{} - {} ({})", exploit.id, exploit.protocol, exploit.date);
                            println!("{}", "=".repeat(80));
                            println!("Loss: ${}", exploit.loss_usd);
                            println!("Chain: {}", exploit.chain);
                            println!("\nAttack Summary:\n{}\n", exploit.attack_summary);
                            println!("Invariants Violated:");
                            for inv_id in &exploit.invariant_ids {
                                println!("  - {}", inv_id);
                            }
                            println!("\nTx Hash: {}", exploit.tx_hash);
                            println!("Postmortem: {}\n", exploit.postmortem_url);
                        }
                    }
                    FormatArg::Json => {
                        println!("{}", serde_json::to_string_pretty(&exploit)?);
                    }
                    _ => {
                        if !quiet {
                            eprintln!("ℹ Format not yet implemented");
                        }
                    }
                },
                None => {
                    if !quiet {
                        eprintln!("✗ Exploit not found: {}", id);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle the `invariants` subcommand.
fn cmd_invariants(args: InvariantsArgs, quiet: bool) -> Result<()> {
    use truent_core::{get_invariant, invariant_count, invariants_for_chain};

    match args.action {
        InvariantsAction::List {
            chain,
            severity: _,
            format,
        } => match format {
            FormatArg::Text => {
                if !quiet {
                    // Count what is actually listed. Printing the global total
                    // above a filtered list reads as "9 invariants" over six
                    // rows.
                    let count = match &chain {
                        Some(c) => invariants_for_chain(c).len(),
                        None => invariant_count(),
                    };
                    println!("\n {} Compiled Invariants", count);
                    println!("{}", "=".repeat(80));

                    if let Some(c) = &chain {
                        let invariants = invariants_for_chain(c);
                        println!("Chain: {}\n", c);
                        for inv in &invariants {
                            println!("  {} | {} | {}", inv.id, inv.severity, inv.description);
                        }
                    } else {
                        println!("(Total across all chains)\n");
                        println!("  Use --chain evm|solana|move to filter\n");
                    }
                    println!("{}", "=".repeat(80));
                }
            }
            FormatArg::Json => {
                if let Some(c) = chain {
                    let invariants = invariants_for_chain(&c);
                    let json_invs: Vec<_> = invariants
                        .iter()
                        .map(|i| json!({"id": i.id, "severity": i.severity, "chain": i.chain}))
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&json_invs)?);
                }
            }
            _ => {
                if !quiet {
                    eprintln!("ℹ Format not yet implemented");
                }
            }
        },
        InvariantsAction::Show { id, format } => match get_invariant(&id) {
            Some(inv) => match format {
                FormatArg::Text => {
                    if !quiet {
                        println!("\n{}", inv.id);
                        println!("{}", "=".repeat(80));
                        println!("Severity: {}", inv.severity);
                        println!("Chain: {}", inv.chain);
                        println!("\nDescription:\n{}\n", inv.description);
                        println!("Message Template: {}\n", inv.message);
                    }
                }
                FormatArg::Json => {
                    println!("{}", serde_json::to_string_pretty(&json!(inv))?);
                }
                _ => {
                    if !quiet {
                        eprintln!("ℹ Format not yet implemented");
                    }
                }
            },
            None => {
                if !quiet {
                    eprintln!("✗ Invariant not found: {}", id);
                }
            }
        },
    }

    Ok(())
}

/// Handle the `fuzz` subcommand.
/// Apply `depth` random line-level mutations (delete/duplicate/truncate/swap)
/// to `source`, driven by `fuzzer`'s seeded RNG so a run is fully reproducible
/// given the same `--seed`. This is deliberately dumb/structural rather than
/// language-aware: the goal is to stress-test the detectors' robustness
/// against malformed, truncated, or reordered input, not to produce valid
/// programs.
fn mutate_source(fuzzer: &mut truent_core::CodeFuzzer, source: &str, depth: usize) -> String {
    let mut lines: Vec<String> = source.lines().map(|l| l.to_string()).collect();
    if lines.is_empty() {
        return source.to_string();
    }

    for _ in 0..depth {
        if lines.is_empty() {
            break;
        }
        match fuzzer.next_index(4) {
            0 => {
                // Delete a random line.
                let idx = fuzzer.next_index(lines.len());
                lines.remove(idx);
            }
            1 => {
                // Duplicate a random line.
                let idx = fuzzer.next_index(lines.len());
                let line = lines[idx].clone();
                lines.insert(idx, line);
            }
            2 => {
                // Truncate a random line at a random (char-boundary-safe) point.
                let idx = fuzzer.next_index(lines.len());
                let line = lines[idx].clone();
                if !line.is_empty() {
                    let mut cut = fuzzer.next_index(line.len());
                    while cut > 0 && !line.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    lines[idx] = line[..cut].to_string();
                }
            }
            _ => {
                // Swap two random lines.
                let a = fuzzer.next_index(lines.len());
                let b = fuzzer.next_index(lines.len());
                lines.swap(a, b);
            }
        }
    }

    lines.join("\n")
}

/// Run every EVM-specific precision/recall self-test fuzzer and combine their
/// results. These generate wholly synthetic vulnerable/safe patterns (not the
/// user's file) to measure how well the pattern detectors distinguish the two,
/// independent of the crash-robustness fuzzing above.
fn run_detector_precision_fuzzers(iterations_per_fuzzer: usize) -> truent_core::FuzzResult {
    use truent_core::dvn_fuzzer::DVNSinglePointFuzzer;
    use truent_core::health_check_fuzzer::HealthCheckFuzzer;
    use truent_core::merkle_root_fuzzer::MerkleRootFuzzer;
    use truent_core::synthetic_mint_fuzzer::SyntheticMintFuzzer;

    let mut combined = truent_core::FuzzResult {
        true_positives: 0,
        false_positives: 0,
        false_negatives: 0,
        total: 0,
    };

    macro_rules! accumulate {
        ($fuzzer:expr) => {
            let r = $fuzzer.fuzz(iterations_per_fuzzer);
            combined.true_positives += r.true_positives;
            combined.false_positives += r.false_positives;
            combined.false_negatives += r.false_negatives;
            combined.total += r.total;
        };
    }

    accumulate!(DVNSinglePointFuzzer::new(Some(1)));
    accumulate!(HealthCheckFuzzer::new(Some(2)));
    accumulate!(MerkleRootFuzzer::new(Some(3)));
    accumulate!(SyntheticMintFuzzer::new(Some(4)));

    combined
}

/// Handle `truent fuzz --dynamic`: real revm-backed execution instead of
/// the source-mutation crash fuzzer above. Deploys each contract,
/// auto-detects invariants from its ABI (ERC20-shaped conservation,
/// monotonic accumulator getters), generates random call sequences, and on
/// the first violation, shrinks it to a minimal reproduction and prints a
/// Handle `truent fuzz --dynamic --chain solana`.
///
/// The Solana instruction-surface and fuzz-plan front-ends ship in this
/// release, so a plan is parsed and validated here — but the execution backend
/// that runs real BPF bytecode is held out of 0.4.0 (its Solana VM pulls
/// dependencies with unpatched RUSTSEC advisories, and a security tool must not
/// ship known-vulnerable crypto). So this validates inputs and then reports,
/// clearly, that execution is not available in this build rather than silently
/// doing nothing.
fn cmd_dynamic_fuzz_solana(args: FuzzArgs, _quiet: bool) -> Result<()> {
    let idl_path = args.path.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--dynamic --chain solana needs the program's Anchor IDL as the path argument"
        )
    })?;
    let plan_path = args.plan.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--dynamic --chain solana requires --plan <plan.json>: the genesis accounts and \
             invariants to check. An IDL describes instructions, not what must stay true."
        )
    })?;

    // Validate what we can, so a broken IDL/plan is reported now rather than
    // masked behind the "backend unavailable" notice.
    let idl_src = std::fs::read_to_string(idl_path)
        .with_context(|| format!("reading IDL {}", idl_path.display()))?;
    let program = truent_dynamic_solana::parse_idl(&idl_src)
        .with_context(|| format!("parsing IDL {}", idl_path.display()))?;
    let plan_src = std::fs::read_to_string(plan_path)
        .with_context(|| format!("reading fuzz plan {}", plan_path.display()))?;
    truent_dynamic_solana::parse_plan(&plan_src)
        .with_context(|| format!("parsing fuzz plan {}", plan_path.display()))?;

    Err(anyhow::anyhow!(
        "IDL and plan are valid ({} fuzzable instruction(s)), but this release cannot execute \
         them.\n\n\
         Running real Solana bytecode needs an in-process Solana VM, whose dependencies \
         currently carry unpatched security advisories. Truent will not ship known-vulnerable \
         crypto, so the dynamic Solana backend is deferred to a later version.\n\n\
         Static Solana analysis is fully available:\n\n    truent scan <path> --chain solana",
        program.instructions.len(),
    ))
}

fn cmd_dynamic_fuzz(args: FuzzArgs, quiet: bool, verbose: bool) -> Result<()> {
    if matches!(args.chain, ChainArg::Solana) {
        return cmd_dynamic_fuzz_solana(args, quiet);
    }
    if !matches!(args.chain, ChainArg::Evm) {
        return Err(anyhow::anyhow!(
            "--dynamic fuzzing currently only supports --chain evm (Move/Soroban need their own execution backends, not yet built)"
        ));
    }

    // Fixed actor pool: address arguments and callers are drawn only from
    // here (see truent_dynamic_core::abi_encode's random_word for why an
    // unbounded address universe breaks conservation-style invariants).
    let actors: Vec<[u8; 20]> = (1u8..=4).map(|i| [i; 20]).collect();
    let config = truent_dynamic_core::FuzzConfig {
        seed: args.seed.unwrap_or(0),
        max_runs: args.iterations as usize,
        sequence_depth: args.depth,
        actors,
    };

    if let Some(address_str) = &args.address {
        let rpc_url = args
            .rpc_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--rpc-url is required when using --address"))?;
        let address = parse_evm_address(address_str)?;

        if !quiet {
            eprintln!(
                "▶ Fetching bytecode for {address_str} from {rpc_url} and dynamically fuzzing it ({} runs, depth {})...",
                config.max_runs, config.sequence_depth
            );
        }

        return match truent_dynamic_evm::fuzz_deployed_contract(rpc_url, address, config.clone()) {
            Ok(Some(violation)) => {
                // Reproduced by execution — the reproduction below is the
                // proof, so this is a finding rather than a lead.
                println!("\n✗ [PROVEN] {address_str}");
                println!("{}", truent_dynamic_core::format_poc(&violation));
                std::process::exit(1);
            }
            Ok(None) => {
                if !quiet {
                    eprintln!("  ✓ no violation found in {} runs", config.max_runs);
                }
                Ok(())
            }
            Err(e) => Err(e),
        };
    }

    let path = args.path.clone().ok_or_else(|| {
        anyhow::anyhow!("either a contract path or --address (with --rpc-url) is required")
    })?;
    if !path.exists() {
        return Err(anyhow::anyhow!("Path not found: {}", path.display()));
    }

    let files = if path.is_dir() {
        let mut files = Vec::new();
        collect_source_files(&path, "sol", &mut files)?;
        files
    } else {
        vec![path.clone()]
    };
    if files.is_empty() {
        if !quiet {
            eprintln!(
                "⚠ No .sol files found under {}; nothing to fuzz",
                path.display()
            );
        }
        return Ok(());
    }

    // Load user-stated properties before doing any work, so a bad file fails
    // immediately rather than after a long fuzzing run.
    let dsl_specs: Vec<truent_core::model::Invariant> = match &args.invariants {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
            let specs = parse_invariant_file(&text)
                .map_err(|e| anyhow::anyhow!("in {}: {e}", path.display()))?;
            if !quiet {
                eprintln!(
                    "▶ Loaded {} propert{} from {}",
                    specs.len(),
                    if specs.len() == 1 { "y" } else { "ies" },
                    path.display()
                );
            }
            specs
        }
        None => Vec::new(),
    };

    let mut found_violation = false;
    // A contract the engine could not analyse is not a contract that passed.
    // These used to be printed as "skipped" and then exit 0, so a broken
    // toolchain — an unavailable solc, say — looked exactly like a clean run
    // and sailed through CI.
    let mut skipped: Vec<(String, String)> = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", file.display()))?;

        if !quiet {
            eprintln!(
                "▶ Dynamically fuzzing {} (revm, {} runs, depth {})...",
                file.display(),
                config.max_runs,
                config.sequence_depth
            );
        }

        match truent_dynamic_evm::fuzz_solidity_source_with(&source, config.clone(), &dsl_specs) {
            Ok(Some(violation)) => {
                found_violation = true;
                // Reproduced by execution — the call sequence below is the
                // proof, so this is a finding rather than a lead.
                println!("\n✗ [PROVEN] {}", file.display());
                println!("{}", truent_dynamic_core::format_poc(&violation));
            }
            Ok(None) => {
                if !quiet {
                    eprintln!("  ✓ no violation found in {} runs", config.max_runs);
                }
            }
            Err(e) => {
                let detail = if verbose {
                    format!("{e:#}")
                } else {
                    format!("{e}")
                };
                if !quiet {
                    eprintln!("  ⚠ not analysed: {detail}");
                }
                skipped.push((file.display().to_string(), detail));
            }
        }
    }

    if found_violation {
        std::process::exit(1);
    }

    if !skipped.is_empty() {
        eprintln!(
            "\n✗ {} of {} contract(s) could not be analysed — this is not a pass:",
            skipped.len(),
            files.len()
        );
        for (file, err) in &skipped {
            eprintln!("    {file}: {err}");
        }
        eprintln!(
            "\nThe dynamic engine proves findings by execution; when it cannot run, nothing\n\
             was verified. Re-run with --verbose for detail, or set SOLC_PATH / \n\
             TRUENT_SOLC_VERSION if this is a compiler problem."
        );
        // Distinct from 1 (violation found) so CI can tell "insecure" apart
        // from "inconclusive".
        std::process::exit(2);
    }

    Ok(())
}

/// Parses a `0x`-prefixed (or bare) 40-hex-character EVM address.
fn parse_evm_address(s: &str) -> Result<[u8; 20]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| anyhow::anyhow!("invalid address '{s}': {e}"))?;
    if bytes.len() != 20 {
        return Err(anyhow::anyhow!(
            "invalid address '{s}': expected 20 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn cmd_fuzz(args: FuzzArgs, quiet: bool, verbose: bool) -> Result<()> {
    if args.dynamic {
        return cmd_dynamic_fuzz(args, quiet, verbose);
    }

    let path = args.path.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "a contract path is required for the mutation fuzzer (--address/--rpc-url live-fetch mode is only available with --dynamic)"
        )
    })?;

    let chain_name = match args.chain {
        ChainArg::Evm => "EVM",
        ChainArg::Solana => "Solana",
        ChainArg::Move => "Move",
        ChainArg::Soroban => "Soroban",
        ChainArg::General => "General",
        ChainArg::Auto => "Auto",
    };

    if !quiet {
        eprintln!(
            "▶ Fuzzing {} on {} for {} iterations (depth: {})...",
            path.display(),
            chain_name,
            args.iterations,
            args.depth
        );
    }

    if !path.exists() {
        return Err(anyhow::anyhow!("Path not found: {}", path.display()));
    }

    let extension = chain_extension(&args.chain);
    let files = if path.is_dir() {
        let mut files = Vec::new();
        collect_source_files(&path, extension, &mut files)?;
        files
    } else {
        vec![path.clone()]
    };

    if files.is_empty() {
        if !quiet {
            eprintln!(
                "⚠ No .{} files found under {}; nothing to fuzz",
                extension,
                path.display()
            );
        }
        return Ok(());
    }

    let sources: Vec<(String, String)> = files
        .iter()
        .map(|f| {
            let content = std::fs::read_to_string(f)
                .with_context(|| format!("Failed to read {}", f.display()))?;
            Ok((f.to_string_lossy().to_string(), content))
        })
        .collect::<Result<Vec<_>>>()?;

    let seed = args.seed.unwrap_or(42);
    let mut fuzzer = CodeFuzzer::new(Some(seed));
    let start = Instant::now();

    // Suppress the default panic handler's stderr spam for the duration of
    // the fuzzing loop - a caught panic is an expected, reported outcome
    // here, not an unhandled crash the user needs a backtrace for.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut crashes: Vec<(u32, String, String)> = Vec::new();
    let mut finding_counts: Vec<usize> = Vec::new();

    for i in 0..args.iterations {
        let (file_path, source) = &sources[i as usize % sources.len()];
        let mutated = mutate_source(&mut fuzzer, source, args.depth);

        let chain = args.chain.clone();
        let result = std::panic::catch_unwind(|| match chain {
            ChainArg::Evm => truent_analyzer_evm::detectors::run_all_detectors(&mutated, file_path),
            ChainArg::Solana => truent_analyzer_solana::run_all_detectors(&mutated, file_path),
            ChainArg::Move => truent_analyzer_move::run_all_detectors(&mutated, file_path),
            ChainArg::Soroban => truent_analyzer_soroban::run_all_detectors(&mutated, file_path),
            ChainArg::General | ChainArg::Auto => general::run_all_detectors(&mutated, file_path),
        });

        match result {
            Ok(findings) => finding_counts.push(findings.len()),
            Err(panic_payload) => {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic payload>".to_string());
                crashes.push((i, file_path.clone(), msg));
            }
        }
    }

    std::panic::set_hook(original_hook);

    let duration_secs = start.elapsed().as_secs_f64();

    if !quiet {
        eprintln!(
            "✓ Ran {} iterations across {} file(s) in {:.2}s",
            args.iterations,
            sources.len(),
            duration_secs
        );

        if !finding_counts.is_empty() {
            let min = finding_counts.iter().min().copied().unwrap_or(0);
            let max = finding_counts.iter().max().copied().unwrap_or(0);
            let avg = finding_counts.iter().sum::<usize>() as f64 / finding_counts.len() as f64;
            eprintln!("  Findings per mutated variant: min {min}, max {max}, avg {avg:.1}");
        }

        if crashes.is_empty() {
            eprintln!("✓ No crashes found - detectors held up across all mutated inputs");
        } else {
            eprintln!(
                "✗ {} crash(es) found - detectors panicked on mutated input:",
                crashes.len()
            );
            for (iter, file, msg) in crashes.iter().take(10) {
                eprintln!("  iteration {iter} ({file}): {msg}");
            }
            if crashes.len() > 10 {
                eprintln!("  ... and {} more", crashes.len() - 10);
            }
        }

        // Bonus: EVM-specific detector precision/recall self-test, reusing
        // the existing synthetic-pattern fuzzers rather than leaving them
        // permanently disconnected from the CLI.
        if matches!(args.chain, ChainArg::Evm) && verbose {
            let precision_result = run_detector_precision_fuzzers(args.iterations as usize / 4);
            eprintln!(
                "  Detector precision self-test: precision {:.2}, recall {:.2}, F1 {:.2} ({} synthetic cases)",
                precision_result.precision(),
                precision_result.recall(),
                precision_result.f1_score(),
                precision_result.total,
            );
        }
    }

    if !crashes.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

/// Parse a `.invar` file into individual invariant specs.
///
/// Blocks are split by brace depth rather than by blank lines so a property
/// may span as many lines as it needs, and `//` comments are stripped.
fn parse_invariant_file(text: &str) -> anyhow::Result<Vec<truent_core::model::Invariant>> {
    let mut specs = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;

    for line in text.lines() {
        let code = line.split("//").next().unwrap_or("");
        if current.is_empty() && !code.trim_start().starts_with("invariant") {
            continue;
        }
        current.push_str(code);
        current.push('\n');
        depth += code.matches('{').count();
        depth -= code.matches('}').count().min(depth);
        if depth == 0 && !current.trim().is_empty() {
            let block = current.trim().to_string();
            let spec = truent_dsl_parser::parse_invariant(&block)
                .map_err(|e| anyhow::anyhow!("could not parse:\n{block}\n  {e}"))?;
            specs.push(spec);
            current.clear();
        }
    }

    if depth != 0 {
        anyhow::bail!("unbalanced braces — an invariant block is not closed");
    }
    if specs.is_empty() {
        anyhow::bail!("no `invariant NAME {{ ... }}` blocks found");
    }
    Ok(specs)
}
