//! Regression corpus for the general analyzer.
//!
//! `corpus/good/**` are correct files and must produce **zero findings**;
//! `corpus/bad/**` carry `# EXPECT:` / `// EXPECT:` headers naming detectors
//! that must still fire. Paths are preserved relative to the corpus root
//! because this analyzer dispatches on them (`.github/workflows/`,
//! `Dockerfile`, extensions).

use std::fs;
use std::path::{Path, PathBuf};
use truent_analyzer_general::{run_all_detectors, run_repo_detectors};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn corpus(sub: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(sub);
    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();
    assert!(!files.is_empty(), "no files under {}", root.display());
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, fs::read_to_string(&p).unwrap())
        })
        .collect()
}

fn expectations(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            t.strip_prefix("# EXPECT:")
                .or_else(|| t.strip_prefix("// EXPECT:"))
        })
        .map(|s| s.trim().to_string())
        .collect()
}

#[test]
fn known_good_files_produce_no_findings() {
    let mut failures = Vec::new();
    // The repository-level pass sees the whole good corpus as one repository:
    // a login route in one file is covered by the limiter in another.
    let whole: Vec<(String, String)> = corpus("good");
    for f in run_repo_detectors(&whole) {
        failures.push(format!(
            "  {} (repository-level): {} at line {}: {}",
            f.file, f.invariant_id, f.line, f.snippet
        ));
    }
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
        "correct files produced findings:\n{}",
        failures.join("\n")
    );
}

#[test]
fn known_bad_files_are_still_detected() {
    let mut failures = Vec::new();
    for (name, source) in corpus("bad") {
        let expected = expectations(&source);
        assert!(!expected.is_empty(), "{name} has no EXPECT header");
        let mut findings = run_all_detectors(&source, &name);
        // Each bad file is its own repository for the cross-file detectors.
        findings.extend(run_repo_detectors(&[(name.clone(), source.clone())]));
        let got: Vec<&str> = findings.iter().map(|f| f.invariant_id.as_str()).collect();
        for e in expected {
            if !got.contains(&e.as_str()) {
                failures.push(format!("  {name}: expected {e}, got {got:?}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "vulnerable files were not detected:\n{}",
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
            assert_eq!(
                f.snippet.trim(),
                lines[f.line - 1].trim(),
                "{name}: {} at line {}",
                f.invariant_id,
                f.line
            );
        }
    }
}

#[test]
fn bad_corpus_headers_name_real_detectors() {
    for (name, source) in corpus("bad") {
        for e in expectations(&source) {
            assert!(
                truent_core::taxonomy::taxonomy_for(&e).is_some(),
                "{name}: EXPECT {e} names no known detector"
            );
        }
    }
}
