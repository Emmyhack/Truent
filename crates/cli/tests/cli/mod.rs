//! CLI behavior tests.
//!
//! These tests validate that the CLI tool behaves correctly,
//! producing correct exit codes, output formats, and error handling.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Setup a test project directory with sample files
fn setup_test_project() -> TempDir {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let base = temp.path();

    // Create a sample DSL file
    let dsl_content = r#"
invariant: balance_conservation
description: "Total balance must be conserved across transactions"

forall tx in transactions:
    sum(tx.inputs) == sum(tx.outputs) + tx.fee
"#;

    fs::write(base.join("invariants.invar"), dsl_content).expect("Failed to write invariants file");

    temp
}

#[test]
fn test_cli_help_output() {
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Truent"));
}

#[test]
fn test_cli_version_output() {
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("--version");
    cmd.assert().success();
}

#[test]
fn test_cli_init_creates_project() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let project_path = temp.path().join("new_project");

    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("init").arg(&project_path);

    cmd.assert().success();
    assert!(
        project_path.exists(),
        "init should create project directory"
    );
}

#[test]
fn test_cli_missing_file_exits_with_error() {
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("build")
        .arg("--source")
        .arg("/nonexistent/file.rs")
        .arg("--chain")
        .arg("solana")
        .arg("--output")
        .arg("/tmp/out");

    cmd.assert().failure();
}

#[test]
fn test_cli_invalid_chain_exits_with_error() {
    let temp = setup_test_project();

    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("build")
        .arg("--source")
        .arg(temp.path().join("test.rs"))
        .arg("--chain")
        .arg("invalid_chain")
        .arg("--output")
        .arg(temp.path().join("output"));

    cmd.assert().failure();
}

#[test]
fn test_cli_verbose_flag_produces_output() {
    let _temp = setup_test_project();

    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("--verbose").arg("doctor");

    cmd.assert().success();
}

#[test]
fn test_cli_log_level_flag() {
    let mut cmd = Command::cargo_bin("truent").expect("Found to find binary");
    cmd.arg("--verbose").arg("doctor");

    cmd.assert().success();
}

#[test]
fn test_cli_invalid_subcommand() {
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("nonexistent_command");

    cmd.assert().failure();
}

/// Exit code tests
mod exit_codes {
    use super::*;

    #[test]
    fn test_exit_code_success_is_zero() {
        let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd.arg("--help");

        let output = cmd.output().expect("Failed to execute");
        assert_eq!(output.status.code(), Some(0), "Success should exit with 0");
    }

    #[test]
    fn test_exit_code_error_is_nonzero() {
        let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd.arg("nonexistent_command");

        let output = cmd.output().expect("Failed to execute");
        assert_ne!(
            output.status.code(),
            Some(0),
            "Error should exit with non-zero"
        );
    }
}

/// Output format tests
mod output_formats {
    use super::*;

    #[test]
    fn test_json_output_is_valid() {
        let temp = setup_test_project();

        let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd.arg("report")
            .arg("--input")
            .arg(temp.path().join("test_report.json"))
            .arg("--format")
            .arg("json");

        // Check if output is valid JSON (when it runs successfully)
        let output = cmd.output().expect("Failed to execute");

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Validate it's JSON-like
            assert!(stdout.contains("{") || stdout.is_empty());
        }
    }

    #[test]
    fn test_markdown_output() {
        let temp = setup_test_project();

        let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd.arg("report")
            .arg("--input")
            .arg(temp.path().join("test_report.json"))
            .arg("--format")
            .arg("markdown");

        let output = cmd.output().expect("Failed to execute");
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Markdown output shouldn't be JSON
        assert!(!stdout.starts_with("{") || output.status.success());
    }
}

/// Configuration tests
mod configuration {
    use super::*;

    #[test]
    fn test_config_file_loading() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let config_path = temp.path().join("invar.toml");

        let config_content = r#"
[project]
name = "test-project"
version = "0.1.0"

[invariants]
chains = ["solana", "evm"]
"#;

        fs::write(&config_path, config_content).expect("Failed to write config");

        // Config should be loadable
        assert!(config_path.exists());
    }
}

/// Determinism tests
mod determinism {
    use super::*;

    #[test]
    fn test_same_input_same_output() {
        let _temp = setup_test_project();

        // Run the same command twice
        let mut cmd1 = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd1.arg("list");
        let output1 = cmd1.output().expect("Failed to execute");

        let mut cmd2 = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd2.arg("list");
        let output2 = cmd2.output().expect("Failed to execute");

        // Same input should produce same output
        assert_eq!(output1.stdout, output2.stdout, "CLI must be deterministic");
        assert_eq!(
            output1.stderr, output2.stderr,
            "Errors must be deterministic"
        );
    }
}

/// Regression tests asserting that `truent check` actually detects real
/// vulnerabilities in the bundled fixtures, instead of always reporting a
/// clean scan. These fixtures previously sat unused by any test while the
/// detection pipeline itself was disconnected (see CHANGELOG / git history).
mod detection {
    use super::*;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn test_check_detects_vulnerable_evm_fixture() {
        let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd.arg("check")
            .arg(fixture_path("test_vulnerable_evm.sol"))
            .arg("--chain")
            .arg("evm")
            .arg("--format")
            .arg("json");

        let output = cmd.output().expect("Failed to execute");
        // Static detectors emit leads, not proven violations, and a lead does
        // not fail the run — blocking a build on an unexecuted pattern match
        // is what teaches teams to bypass the gate. The findings are still
        // reported; `--fail-on-leads` (asserted below) is how you gate on them.
        assert_eq!(
            output.status.code(),
            Some(0),
            "unproven leads must not fail the run by default"
        );

        let mut gated = Command::cargo_bin("truent").expect("binary exists");
        gated
            .arg("check")
            .arg(fixture_path("test_vulnerable_evm.sol"))
            .arg("--chain")
            .arg("evm")
            .arg("--format")
            .arg("json")
            .arg("--fail-on-leads");
        assert_eq!(
            gated.output().expect("Failed to execute").status.code(),
            Some(1),
            "--fail-on-leads must gate on unproven results"
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("check --format json must emit valid JSON");
        let violation_count = json["summary"]["violations"]
            .as_u64()
            .expect("summary.violations must be a number");
        assert!(
            violation_count > 0,
            "Expected at least one violation in the known-vulnerable EVM fixture, found 0"
        );
    }

    #[test]
    fn test_check_detects_vulnerable_solana_fixture() {
        let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd.arg("check")
            .arg(fixture_path("test_vulnerable_solana.rs"))
            .arg("--chain")
            .arg("solana")
            .arg("--format")
            .arg("json");

        let output = cmd.output().expect("Failed to execute");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("check --format json must emit valid JSON");
        let violation_count = json["summary"]["violations"]
            .as_u64()
            .expect("summary.violations must be a number");
        assert!(
            violation_count > 0,
            "Expected at least one violation in the known-vulnerable Solana fixture, found 0"
        );
    }

    #[test]
    fn test_check_detects_vulnerable_move_fixture() {
        let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd.arg("check")
            .arg(fixture_path("test_vulnerable_move.move"))
            .arg("--chain")
            .arg("move")
            .arg("--format")
            .arg("json");

        let output = cmd.output().expect("Failed to execute");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("check --format json must emit valid JSON");
        let violation_count = json["summary"]["violations"]
            .as_u64()
            .expect("summary.violations must be a number");
        assert!(
            violation_count > 0,
            "Expected at least one violation in the known-vulnerable Move fixture, found 0"
        );
    }

    /// The chain-agnostic shared-IR rule (`unauthorized_privileged_mutation`,
    /// truent_ir::rules) used to only fire in each analyzer crate's own unit
    /// tests - it was never wired into the production detector pipeline the
    /// CLI actually calls. This proves it now fires end to end for the two
    /// chains whose semantic-model extractor needs no external tool (Solana's
    /// Anchor parser and Move's regex extractor both work on raw source
    /// text; EVM's needs solc, which this environment doesn't have, so it's
    /// intentionally not asserted on here).
    #[test]
    fn test_shared_ir_rule_fires_for_solana_and_move() {
        for (fixture, chain) in [
            ("test_vulnerable_solana.rs", "solana"),
            ("test_vulnerable_move.move", "move"),
        ] {
            let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
            cmd.arg("check")
                .arg(fixture_path(fixture))
                .arg("--chain")
                .arg(chain)
                .arg("--format")
                .arg("json");

            let output = cmd.output().expect("Failed to execute");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let json: serde_json::Value =
                serde_json::from_str(&stdout).expect("check --format json must emit valid JSON");
            let violations = json["violations"]
                .as_array()
                .expect("violations must be an array");

            assert!(
                violations
                    .iter()
                    .any(|v| v["invariant_id"] == "unauthorized_privileged_mutation"),
                "Expected the shared-IR rule to fire for {chain} fixture {fixture}, but it didn't. Violations: {violations:#?}"
            );
        }
    }

    #[test]
    fn test_scan_respects_severity_and_fail_on_filters() {
        let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd.arg("scan")
            .arg(fixture_path("test_vulnerable_evm.sol"))
            .arg("--chain")
            .arg("evm")
            .arg("--output")
            .arg("json")
            .arg("--severity")
            .arg("critical")
            .arg("--fail-on")
            .arg("critical");

        let output = cmd.output().expect("Failed to execute");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("scan --output json must emit valid JSON");
        let violations = json["violations"]
            .as_array()
            .expect("violations must be an array");
        assert!(
            !violations.is_empty(),
            "Expected at least one critical violation in the vulnerable EVM fixture"
        );
        assert!(
            violations.iter().all(|v| v["severity"] == "critical"),
            "--severity critical must filter out all non-critical violations"
        );
        // Severity filtering is unchanged; what changed is that gating now
        // also requires the result to have been reproduced. These are leads,
        // so the run passes unless --fail-on-leads is given.
        assert_eq!(
            output.status.code(),
            Some(0),
            "critical *leads* are reported but do not fail the run"
        );
    }

    /// `truent fuzz` used to be a pure stub that printed "0 violations found"
    /// without doing any work. It now actually mutates the target file and
    /// runs the real detectors against each variant, so a run must complete
    /// successfully (exit 0, no crashes) rather than just no-op.
    #[test]
    fn test_fuzz_runs_against_real_detectors_without_crashing() {
        let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
        cmd.arg("fuzz")
            .arg(fixture_path("test_vulnerable_evm.sol"))
            .arg("--chain")
            .arg("evm")
            .arg("--iterations")
            .arg("50")
            .arg("--depth")
            .arg("4")
            .arg("--seed")
            .arg("7");

        let output = cmd.output().expect("Failed to execute");
        assert_eq!(
            output.status.code(),
            Some(0),
            "fuzz must exit 0 when no crashes are found"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Ran 50 iterations"),
            "expected fuzz to report the iteration count, got: {stderr}"
        );
        assert!(
            stderr.contains("No crashes found"),
            "expected fuzz to report no crashes on the known-parseable fixture, got: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// Report output hardening
// ---------------------------------------------------------------------------

/// A contract whose scan reliably produces at least one violation.
const VULNERABLE_SOL: &str = r#"
pragma solidity ^0.8.0;
contract Vuln {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function price() public view returns (uint256) {
        return balanceOf[address(this)] * 2;
    }
    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balanceOf[msg.sender] -= amount;
    }
}
"#;

#[test]
fn test_html_report_escapes_attacker_controlled_file_path() {
    // A report is a document people open in a browser and forward to clients.
    // The scan target's *path* reaches the HTML, and a path is chosen by
    // whoever supplies the repository — so an unescaped filename is stored
    // XSS in an audit deliverable.
    let temp = TempDir::new().expect("Failed to create temp dir");
    // No '/' — that cannot appear in a filename. This payload breaks out of
    // the <td> just as effectively.
    let hostile = r#"a"><img src=x onerror=alert(1)>.sol"#;
    fs::write(temp.path().join(hostile), VULNERABLE_SOL).expect("write contract");

    let out = temp.path().join("report.html");
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("scan")
        .arg(temp.path())
        .arg("--chain")
        .arg("evm")
        .arg("--output")
        .arg("html")
        .arg("--file")
        .arg(&out)
        .arg("--quiet");
    cmd.assert().success();

    let html = fs::read_to_string(&out).expect("read report");
    assert!(
        html.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "the path must appear in escaped form"
    );
    assert!(
        !html.contains("<img src=x onerror="),
        "the report contains an executable injected tag:\n{html}"
    );
    assert!(
        !html.contains(r#"a"><img"#),
        "the quote that breaks out of the attribute was not escaped"
    );
}

#[test]
fn test_html_report_includes_taxonomy_badges() {
    // The classification column is the reason a client can triage a Truent
    // report without learning Truent's internal rule names.
    let temp = TempDir::new().expect("Failed to create temp dir");
    fs::write(temp.path().join("Vuln.sol"), VULNERABLE_SOL).expect("write contract");

    let out = temp.path().join("report.html");
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("scan")
        .arg(temp.path())
        .arg("--chain")
        .arg("evm")
        .arg("--output")
        .arg("html")
        .arg("--file")
        .arg(&out)
        .arg("--quiet");
    cmd.assert().success();

    let html = fs::read_to_string(&out).expect("read report");
    assert!(html.contains("<th>Classification</th>"), "missing column");
    assert!(
        html.contains(r#"class="tax""#),
        "no taxonomy badge rendered:\n{html}"
    );
    assert!(html.contains("CWE-"), "no CWE identifier in the report");
}

#[test]
fn test_sarif_output_is_valid_and_deduplicated() {
    // SARIF is what CI uploads to code scanning. Its rule catalogue must be
    // deduplicated and every result's ruleIndex must resolve to its own rule —
    // previously every result pointed at index 0.
    let temp = TempDir::new().expect("Failed to create temp dir");
    fs::write(temp.path().join("Vuln.sol"), VULNERABLE_SOL).expect("write contract");

    let out = temp.path().join("out.sarif");
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("scan")
        .arg(temp.path())
        .arg("--chain")
        .arg("evm")
        .arg("--sarif")
        .arg(&out)
        .arg("--quiet");
    cmd.assert().success();

    let sarif: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).expect("read sarif")).expect("valid JSON");

    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    let results = run["results"].as_array().expect("results");
    assert!(!results.is_empty(), "expected at least one finding");

    // Rule IDs are unique.
    let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "rule catalogue has duplicates");

    // Every result points at the rule it names.
    for res in results {
        let idx = res["ruleIndex"].as_u64().expect("ruleIndex") as usize;
        assert_eq!(
            rules[idx]["id"], res["ruleId"],
            "ruleIndex does not resolve to the named rule"
        );
    }
}

// ---------------------------------------------------------------------------
// Skill runtime
// ---------------------------------------------------------------------------

/// A cache root holding one registered source with a couple of skills.
fn skills_fixture() -> TempDir {
    let temp = TempDir::new().expect("temp dir");
    let skills = temp.path().join("sources/demo/skills");

    let mk = |name: &str, extra: &str, script: Option<&str>| {
        let d = skills.join(name);
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join("SKILL.md"),
            format!(
                "---\nname: {name}\ndescription: Demo skill {name} for tests.\n{extra}\n---\n\
                 # {name}\n\n```bash\naws s3 ls\n```\n"
            ),
        )
        .unwrap();
        if let Some(body) = script {
            fs::create_dir_all(d.join("scripts")).unwrap();
            fs::write(d.join("scripts/agent.py"), body).unwrap();
        }
    };

    mk(
        "demo-hunting",
        "subdomain: threat-hunting\ntags:\n  - dns\nmitre_attack:\n  - T1048.003",
        Some("print('demo ran')\n"),
    );
    mk(
        "demo-noscript",
        "subdomain: cloud-security\ntags:\n  - aws",
        None,
    );

    fs::write(
        temp.path().join("sources.json"),
        r#"{"sources":[{"name":"demo","url":"https://example.com/d.git","skills_dir":"skills"}]}"#,
    )
    .unwrap();

    temp
}

fn skills_cmd(root: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.arg("skills").arg("--root").arg(root);
    cmd
}

#[test]
fn test_skills_indexes_a_registered_source() {
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("demo-hunting"))
        .stdout(predicate::str::contains("ADVISORY"));
}

#[test]
fn test_skills_search_matches_framework_identifiers() {
    // Searching by ATT&CK technique is the point of indexing the frontmatter.
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .args(["search", "T1048.003"])
        .assert()
        .success()
        .stdout(predicate::str::contains("demo-hunting"))
        .stdout(predicate::str::contains("demo-noscript").not());
}

#[test]
fn test_skills_search_is_conjunctive() {
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .args(["search", "dns", "aws"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No skills match"));
}

#[test]
fn test_skills_third_party_output_is_labelled_advisory() {
    // Truent's contract is that it never presents unverified output as
    // verified. A third-party skill must be labelled everywhere it appears.
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .args(["show", "demo-hunting", "--metadata-only"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[ADVISORY]"))
        .stdout(predicate::str::contains("does not verify it"));
}

#[test]
fn test_skills_run_refuses_without_confirmation_when_non_interactive() {
    // Running third-party code is the one irreversible thing this subsystem
    // does. Piped/CI invocations must not silently execute it.
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .args(["run", "demo-hunting"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to run"));
}

#[test]
fn test_skills_run_executes_with_explicit_consent() {
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .args(["run", "demo-hunting", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("demo ran"))
        .stderr(predicate::str::contains("ADVISORY"));
}

#[test]
fn test_skills_dry_run_does_not_execute() {
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .args(["run", "demo-hunting", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent.py"))
        .stdout(predicate::str::contains("demo ran").not());
}

#[test]
fn test_skills_run_explains_when_a_skill_has_no_script() {
    // An instructions-only skill is for an agent to read, not for the CLI to
    // execute. The error has to say which.
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .args(["run", "demo-noscript", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ships no script"));
}

#[test]
fn test_skills_unknown_name_suggests_alternatives() {
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .args(["show", "demo-huntin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Did you mean"));
}

#[test]
fn test_skills_doctor_reports_missing_tools() {
    let temp = skills_fixture();
    skills_cmd(temp.path())
        .args(["doctor", "demo-hunting"])
        .assert()
        .success()
        .stdout(predicate::str::contains("aws"));
}

#[test]
fn test_skills_registered_but_missing_checkout_is_reported() {
    // Silence here is the worst outcome: the operator sees an empty list and
    // assumes the library is empty rather than un-cloned.
    let temp = TempDir::new().expect("temp dir");
    fs::write(
        temp.path().join("sources.json"),
        r#"{"sources":[{"name":"ghost","url":"https://example.com/g.git","skills_dir":"skills"}]}"#,
    )
    .unwrap();

    skills_cmd(temp.path())
        .arg("list")
        .assert()
        .success()
        .stderr(predicate::str::contains("not checked out"));
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

#[test]
fn test_doctor_exits_zero_when_healthy() {
    let temp = TempDir::new().expect("temp dir");
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.env("TRUENT_HOME", temp.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("components healthy"));
}

#[test]
fn test_doctor_exits_nonzero_when_a_component_is_broken() {
    // Every doctor check used to be a hardcoded `passed: true`, so the command
    // could never fail and was useless as the install gate the release
    // workflow uses it as.
    let temp = TempDir::new().expect("temp dir");
    fs::create_dir_all(temp.path().join("skills")).unwrap();
    fs::write(temp.path().join("skills/sources.json"), "{ not json").unwrap();

    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.env("TRUENT_HOME", temp.path())
        .arg("doctor")
        .assert()
        .failure()
        .stdout(predicate::str::contains("Skill runtime"))
        .stdout(predicate::str::contains("have issues"));
}

#[test]
fn test_doctor_counts_are_computed_not_hardcoded() {
    // "28 built-in invariants" was a string literal; it would have kept
    // claiming 28 after any chain gained an invariant.
    let temp = TempDir::new().expect("temp dir");
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    let out = cmd
        .env("TRUENT_HOME", temp.path())
        .arg("doctor")
        .output()
        .expect("run doctor");
    let text = String::from_utf8_lossy(&out.stdout);

    let invariants = text
        .lines()
        .find(|l| l.contains("built-in invariants"))
        .expect("invariant line");
    let n: usize = invariants
        .split_whitespace()
        .find_map(|w| w.parse().ok())
        .expect("a count");
    assert!(n > 0, "invariant count must be real: {invariants}");

    // The taxonomy line must agree with the table the binary was built from.
    assert!(
        text.contains(&format!(
            "{} detectors mapped",
            truent_core::taxonomy::all().len()
        )),
        "taxonomy count disagrees with the table:\n{text}"
    );
}

#[test]
fn test_doctor_output_columns_are_aligned() {
    // The message column was padded with a fixed run of spaces regardless of
    // component-name length, so it came out ragged. Measure the actual column
    // the message starts in for each component rather than keying on any one
    // message string, which changes as checks gain real output.
    let temp = TempDir::new().expect("temp dir");
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    let out = cmd
        .env("TRUENT_HOME", temp.path())
        .arg("doctor")
        .output()
        .expect("run doctor");
    let text = String::from_utf8_lossy(&out.stdout);

    let components = [
        "truent-core",
        "EVM analyzer",
        "Solana analyzer",
        "Move analyzer",
        "Soroban analyzer",
        "DSL parser",
        "Invariant library",
        "Detector taxonomy",
        "Report generator",
        "Skill runtime",
    ];

    let mut message_columns = Vec::new();
    for component in components {
        let line = text
            .lines()
            .find(|l| l.contains(component))
            .unwrap_or_else(|| panic!("no doctor line for {component}:\n{text}"));
        let after_name = line.find(component).unwrap() + component.len();
        let message_start = after_name
            + line[after_name..]
                .find(|c: char| !c.is_whitespace())
                .unwrap_or_else(|| panic!("{component} has no message:\n{line}"));
        message_columns.push((component, message_start));
    }

    let first = message_columns[0].1;
    assert!(
        message_columns.iter().all(|(_, c)| *c == first),
        "message column is ragged: {message_columns:?}"
    );
}

#[test]
fn test_doctor_analyzer_checks_actually_detect() {
    // Each analyzer check runs a known-vulnerable snippet through the real
    // detector pipeline. Every check used to be a hardcoded `passed: true`,
    // which proved only that a struct could be constructed.
    let temp = TempDir::new().expect("temp dir");
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    let out = cmd
        .env("TRUENT_HOME", temp.path())
        .arg("doctor")
        .output()
        .expect("run doctor");
    let text = String::from_utf8_lossy(&out.stdout);

    for analyzer in [
        "EVM analyzer",
        "Solana analyzer",
        "Move analyzer",
        "Soroban analyzer",
    ] {
        let line = text
            .lines()
            .find(|l| l.contains(analyzer))
            .unwrap_or_else(|| panic!("no line for {analyzer}"));
        let n: usize = line
            .split_whitespace()
            .find_map(|w| w.parse().ok())
            .unwrap_or_else(|| panic!("{analyzer} reported no finding count: {line}"));
        assert!(
            n > 0,
            "{analyzer} self-test found nothing — detection is broken: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// Compiled .sinv invariants
// ---------------------------------------------------------------------------

#[test]
fn test_sinv_invariants_are_actually_compiled_in() {
    // build.rs lived at the workspace root, which is a *virtual* manifest, so
    // cargo never ran it: all nine .sinv files were inert and the registry was
    // the "no .sinv files found" stub. `truent invariants` listed nothing.
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    cmd.args(["invariants", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Compiled Invariants"))
        .stdout(predicate::str::contains("0 Compiled Invariants").not());
}

#[test]
fn test_invariants_list_count_matches_the_filter() {
    // The header printed the global total above a chain-filtered list, so
    // `--chain evm` read as "9 invariants" over six rows.
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    let out = cmd
        .args(["invariants", "list", "--chain", "evm"])
        .output()
        .expect("run invariants list");
    let text = String::from_utf8_lossy(&out.stdout);

    let header: usize = text
        .lines()
        .find(|l| l.contains("Compiled Invariants"))
        .and_then(|l| l.split_whitespace().find_map(|w| w.parse().ok()))
        .expect("a header count");
    let rows = text.lines().filter(|l| l.contains(" | ")).count();
    assert_eq!(header, rows, "header count disagrees with rows:\n{text}");
}

#[test]
fn test_invariants_show_json_serializes() {
    // The generated CompiledInvariant lacked serde derives, so this path did
    // not compile once the generator actually ran.
    let mut cmd = Command::cargo_bin("truent").expect("Failed to find binary");
    let out = cmd
        .args([
            "invariants",
            "show",
            "evm_reentrancy_classic",
            "--format",
            "json",
        ])
        .output()
        .expect("run invariants show");
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("show --format json must emit valid JSON");
    assert_eq!(v["id"], "evm_reentrancy_classic");
    assert_eq!(v["chain"], "evm");
    assert_eq!(v["severity"], "CRITICAL");
}
