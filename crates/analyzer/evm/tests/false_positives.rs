//! False-positive and true-positive regression corpus.
//!
//! Truent's detectors are pattern matchers over source text, and the failure
//! mode that costs users most is not a missed bug — it is a confident CRITICAL
//! on correct code. A scanner that reports eleven criticals on a plain ERC-20
//! teaches its users to ignore it, which is worse than reporting nothing.
//!
//! The corpus lives in `tests/corpus/`:
//!
//! - `good/*.sol` — contracts correct by construction. Each **must produce
//!   zero findings.**
//! - `bad/*.sol` — contracts with a real bug. Each carries one or more
//!   `// EXPECT: <invariant_id>` header lines naming the detector that must
//!   still fire, so a detector can never be "fixed" by switching it off.
//!
//! A third test asserts every finding points at a real source line whose text
//! is what the finding reports, which makes a line-1 phantom finding with a
//! fabricated snippet impossible.
//!
//! To add a case, drop a `.sol` file in the right directory. No code change.

use std::fs;
use std::path::{Path, PathBuf};
use truent_analyzer_evm::detectors::run_all_detectors;

fn corpus(sub: &str) -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(sub);
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "sol").unwrap_or(false))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .sol files under {}", dir.display());
    files
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            let src = fs::read_to_string(&p).unwrap();
            (name, src)
        })
        .collect()
}

fn expectations(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|l| l.trim().strip_prefix("// EXPECT:"))
        .map(|s| s.trim().to_string())
        .collect()
}

#[test]
fn known_good_contracts_produce_no_findings() {
    let mut failures = Vec::new();

    for (name, source) in corpus("good") {
        let findings = run_all_detectors(&source, &name);
        if !findings.is_empty() {
            let detail: Vec<String> = findings
                .iter()
                .map(|f| {
                    format!(
                        "      [{}] {} at line {}: {}",
                        f.severity, f.invariant_id, f.line, f.snippet
                    )
                })
                .collect();
            failures.push(format!(
                "  {name}: {} false positive(s)\n{}",
                findings.len(),
                detail.join("\n")
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "correct contracts produced findings:\n{}",
        failures.join("\n")
    );
}

#[test]
fn known_bad_contracts_are_still_detected() {
    let mut failures = Vec::new();

    for (name, source) in corpus("bad") {
        let expected = expectations(&source);
        assert!(
            !expected.is_empty(),
            "{name} has no `// EXPECT:` header naming the detector that must fire"
        );
        let findings = run_all_detectors(&source, &name);
        let got: Vec<&str> = findings.iter().map(|f| f.invariant_id.as_str()).collect();
        for e in expected {
            if !got.contains(&e.as_str()) {
                failures.push(format!("  {name}: expected {e}, got {got:?}"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "vulnerable contracts were not detected:\n{}",
        failures.join("\n")
    );
}

#[test]
fn findings_point_at_real_source_lines() {
    for (name, source) in corpus("bad").into_iter().chain(corpus("good")) {
        let lines: Vec<&str> = source.lines().collect();
        for f in run_all_detectors(&source, &name) {
            assert!(
                f.line >= 1 && f.line <= lines.len(),
                "{name}: {} reports line {} of {}",
                f.invariant_id,
                f.line,
                lines.len()
            );
            let actual = lines[f.line - 1].trim();
            assert_eq!(
                f.snippet.trim(),
                actual,
                "{name}: {} at line {} reports a snippet that is not the source there",
                f.invariant_id,
                f.line
            );
        }
    }
}

#[test]
fn bad_corpus_headers_name_real_detectors() {
    // A typo in an EXPECT header would make the true-positive test pass
    // vacuously for that file. Every expectation must be a mapped detector.
    for (name, source) in corpus("bad") {
        for e in expectations(&source) {
            assert!(
                truent_core::taxonomy::taxonomy_for(&e).is_some(),
                "{name}: `// EXPECT: {e}` names no known detector"
            );
        }
    }
}
