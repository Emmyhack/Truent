#![deny(unsafe_code)]

//! Symbolic execution, settled honestly.
//!
//! Truent's engines are pattern- and dataflow-based; they do not solve
//! constraints. A symbolic executor does, and three good ones exist. This
//! crate does not reimplement them — it *drives* them and owns the result:
//!
//! - it finds which executor is installed ([`detect`]),
//! - runs it on a Foundry project ([`run`]),
//! - parses its output into [`Finding`]s with Truent's honesty contract: a
//!   **counterexample is a concrete witness**, so it is recorded as
//!   [`Finding::proven`]; a timeout, an unknown result or a test whose every
//!   path reverted is an *unresolved* lead, never a pass.
//!
//! Supported executors:
//!
//! | Tool | Invocation | Output parsed |
//! |---|---|---|
//! | [halmos](https://github.com/a16z/halmos) | `halmos --root <p> --json-output <f>` | JSON `test_results` with per-check `models` |
//! | [Mythril](https://github.com/Consensys/mythril) | `myth analyze <src> -o json` | JSON `issues` with `tx_sequence` |
//! | [hevm](https://github.com/ethereum/hevm) | `hevm test --root <p>` | `[PASS]` / `[FAIL]` + `Counterexample` text |
//!
//! The parsers are pure and tested against captured real output; only
//! [`run`] touches the filesystem and the process table.

pub mod halmos;
pub mod hevm;
pub mod mythril;

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use truent_core::{Finding, Severity};

/// A supported executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tool {
    Halmos,
    Mythril,
    Hevm,
}

impl Tool {
    pub fn binary(&self) -> &'static str {
        match self {
            Tool::Halmos => "halmos",
            Tool::Mythril => "myth",
            Tool::Hevm => "hevm",
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Tool::Halmos => "halmos",
            Tool::Mythril => "mythril",
            Tool::Hevm => "hevm",
        }
    }
    pub fn all() -> &'static [Tool] {
        &[Tool::Halmos, Tool::Hevm, Tool::Mythril]
    }
    pub fn install_hint(&self) -> &'static str {
        match self {
            Tool::Halmos => "pip install halmos   (needs Foundry's `forge` on PATH)",
            Tool::Mythril => "pip install mythril   (needs solc)",
            Tool::Hevm => "download a release from github.com/ethereum/hevm and put `hevm` on PATH",
        }
    }
}

/// An executor found on `PATH`.
#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub tool: Tool,
    pub path: PathBuf,
    pub version: String,
}

/// Which executors are installed.
pub fn detect() -> Vec<ToolInfo> {
    Tool::all()
        .iter()
        .filter_map(|t| {
            let path = which(t.binary())?;
            let version = Command::new(&path)
                .arg("--version")
                .output()
                .ok()
                .map(|o| {
                    String::from_utf8_lossy(if o.stdout.is_empty() {
                        &o.stderr
                    } else {
                        &o.stdout
                    })
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string()
                })
                .unwrap_or_default();
            Some(ToolInfo {
                tool: *t,
                path,
                version,
            })
        })
        .collect()
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

/// Per-check outcome counts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    pub checks: usize,
    pub passed: usize,
    /// Counterexample found.
    pub failed: usize,
    /// Timeout, unknown, or every path reverted.
    pub unresolved: usize,
}

/// The result of one run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SymbolicReport {
    pub project: String,
    pub tool: Option<Tool>,
    pub version: Option<String>,
    /// The executor actually ran to completion (findings are meaningful).
    pub ran: bool,
    pub stats: Stats,
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
    pub duration_ms: u128,
}

/// Build a finding. Counterexamples are proven — the executor handed us a
/// concrete input; everything else stays a lead.
pub(crate) fn finding(
    id: &str,
    sev: Severity,
    file: &str,
    line: usize,
    message: String,
    evidence: String,
    proven: bool,
) -> Finding {
    let f = Finding::new(
        id.to_string(),
        sev,
        file.to_string(),
        line.max(1),
        0,
        message,
        evidence,
    )
    .with_metadata("chain".to_string(), "evm".to_string());
    if proven {
        f.proven()
    } else {
        f
    }
}

/// What a Foundry project looks like: `foundry.toml` at the root.
pub fn is_foundry_project(root: &Path) -> bool {
    root.join("foundry.toml").is_file()
}

/// Run the preferred (or first installed) executor on `project`.
pub fn run(project: &Path, prefer: Option<Tool>, timeout: Duration) -> SymbolicReport {
    let started = Instant::now();
    let mut report = SymbolicReport {
        project: project.display().to_string(),
        ..Default::default()
    };
    let installed = detect();
    let chosen = match prefer {
        Some(t) => installed.iter().find(|i| i.tool == t).cloned(),
        None => installed.first().cloned(),
    };
    let Some(info) = chosen else {
        let want = prefer
            .map(|t| t.name())
            .unwrap_or("halmos, hevm or mythril");
        report.errors.push(format!(
            "no symbolic executor found on PATH ({want}). Install one: {}",
            Tool::all()
                .iter()
                .map(|t| format!("{} — {}", t.name(), t.install_hint()))
                .collect::<Vec<_>>()
                .join("; ")
        ));
        report.duration_ms = started.elapsed().as_millis();
        return report;
    };
    report.tool = Some(info.tool);
    report.version = Some(info.version.clone());

    let outcome = match info.tool {
        Tool::Halmos => run_halmos(&info.path, project, timeout),
        Tool::Hevm => run_hevm(&info.path, project, timeout),
        Tool::Mythril => run_mythril(&info.path, project, timeout),
    };
    match outcome {
        Ok((findings, stats)) => {
            report.ran = true;
            report.stats = stats;
            report.findings = findings;
        }
        Err(e) => report.errors.push(e),
    }
    report.duration_ms = started.elapsed().as_millis();
    report
}

/// Spawn, wait up to `timeout`, kill on expiry. Returns (stdout, stderr, code).
fn run_with_timeout(
    mut cmd: Command,
    timeout: Duration,
) -> Result<(String, String, Option<i32>), String> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("wait: {e}")),
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("output: {e}"))?;
    Ok((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code(),
    ))
}

fn run_halmos(
    bin: &Path,
    project: &Path,
    timeout: Duration,
) -> Result<(Vec<Finding>, Stats), String> {
    if !is_foundry_project(project) {
        return Err(format!(
            "{} is not a Foundry project (no foundry.toml); halmos needs one with check_* tests",
            project.display()
        ));
    }
    let json_path = std::env::temp_dir().join(format!("truent-halmos-{}.json", std::process::id()));
    let mut cmd = Command::new(bin);
    cmd.arg("--root")
        .arg(project)
        .arg("--json-output")
        .arg(&json_path)
        .arg("--solver-timeout-assertion")
        .arg("60000");
    let (stdout, stderr, _code) = run_with_timeout(cmd, timeout)?;
    let text = std::fs::read_to_string(&json_path).map_err(|_| {
        format!(
            "halmos produced no JSON output. stdout: {} stderr: {}",
            stdout.lines().last().unwrap_or(""),
            stderr.lines().last().unwrap_or("")
        )
    })?;
    let _ = std::fs::remove_file(&json_path);
    Ok(halmos::parse(&text, &project.display().to_string()))
}

fn run_hevm(
    bin: &Path,
    project: &Path,
    timeout: Duration,
) -> Result<(Vec<Finding>, Stats), String> {
    if !is_foundry_project(project) {
        return Err(format!("{} is not a Foundry project", project.display()));
    }
    let mut cmd = Command::new(bin);
    cmd.arg("test").arg("--root").arg(project);
    let (stdout, stderr, _code) = run_with_timeout(cmd, timeout)?;
    let text = format!("{stdout}\n{stderr}");
    Ok(hevm::parse(&text, &project.display().to_string()))
}

fn run_mythril(
    bin: &Path,
    project: &Path,
    timeout: Duration,
) -> Result<(Vec<Finding>, Stats), String> {
    let src = if project.join("src").is_dir() {
        project.join("src")
    } else {
        project.to_path_buf()
    };
    let mut files = Vec::new();
    collect_sol(&src, &mut files);
    if files.is_empty() {
        return Err(format!("no .sol files under {}", src.display()));
    }
    let mut cmd = Command::new(bin);
    cmd.arg("analyze").args(&files).arg("-o").arg("json");
    let (stdout, _stderr, _code) = run_with_timeout(cmd, timeout)?;
    Ok(mythril::parse(&stdout, &project.display().to_string()))
}

fn collect_sol(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_sol(&p, out);
        } else if p.extension().map(|x| x == "sol").unwrap_or(false) {
            out.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tool_is_an_error_not_a_pass() {
        // Point PATH at an empty dir so nothing is found.
        let d = tempfile::tempdir().unwrap();
        let old = std::env::var_os("PATH");
        std::env::set_var("PATH", d.path());
        let r = run(d.path(), None, Duration::from_secs(1));
        if let Some(p) = old {
            std::env::set_var("PATH", p);
        }
        assert!(!r.ran);
        assert!(r.findings.is_empty());
        assert!(r.errors[0].contains("no symbolic executor"));
    }

    #[test]
    fn foundry_detection() {
        let d = tempfile::tempdir().unwrap();
        assert!(!is_foundry_project(d.path()));
        std::fs::write(d.path().join("foundry.toml"), "[profile.default]\n").unwrap();
        assert!(is_foundry_project(d.path()));
    }
}
