//! Differential (golden) tests: the detector engines' complete output over
//! the regression corpora, snapshotted.
//!
//! The corpus tests assert *presence* (a bad file still trips its detector)
//! and *absence* (a good file stays silent). This test asserts *identity*:
//! every finding — id, file, line, severity — over every corpus file must
//! match the committed snapshot exactly. A detector change that moves a
//! finding by one line, changes a severity, or adds a second finding to a
//! file shows up here as a diff to be reviewed, never silently accepted.
//!
//! Update deliberately: `INSTA_UPDATE=always cargo test -p truent-cli --test golden`
//! then review the `.snap` diff like code.

use std::path::Path;

fn corpus(rel: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    let mut out = Vec::new();
    fn walk(d: &Path, base: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(d).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let p = e.path();
            if p.is_dir() {
                walk(&p, base, out);
            } else if let Ok(s) = std::fs::read_to_string(&p) {
                let rel = p
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, s));
            }
        }
    }
    walk(&root, &root, &mut out);
    out
}

/// `(file, id, line, severity)` rows, sorted, for a stable snapshot.
fn rows(findings: Vec<truent_core::Finding>) -> Vec<(String, String, usize, String)> {
    let mut v: Vec<_> = findings
        .into_iter()
        .map(|f| {
            (
                f.file,
                f.invariant_id,
                f.line,
                f.severity.name().to_string(),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn general_corpus_output_is_unchanged() {
    let files = corpus("crates/analyzer/general/tests/corpus");
    let mut all = Vec::new();
    for (p, s) in &files {
        all.extend(truent_analyzer_general::run_all_detectors(s, p));
        all.extend(truent_analyzer_general::run_repo_detectors(&[(
            p.clone(),
            s.clone(),
        )]));
    }
    insta::assert_json_snapshot!("general_corpus", rows(all));
}

#[test]
fn evm_corpus_output_is_unchanged() {
    let files = corpus("crates/analyzer/evm/tests/corpus");
    let mut all = Vec::new();
    for (p, s) in &files {
        all.extend(truent_analyzer_evm::detectors::run_all_detectors(s, p));
    }
    insta::assert_json_snapshot!("evm_corpus", rows(all));
}

#[test]
fn solana_corpus_output_is_unchanged() {
    let files = corpus("crates/analyzer/solana/tests/corpus");
    let mut all = Vec::new();
    for (p, s) in &files {
        all.extend(truent_analyzer_solana::run_all_detectors(s, p));
    }
    insta::assert_json_snapshot!("solana_corpus", rows(all));
}

#[test]
fn taxonomy_ids_are_unchanged() {
    // Renaming or removing a detector id is a breaking change for every
    // SARIF consumer and every `.truent.toml` acceptance; make it visible.
    let ids: Vec<&str> = truent_core::taxonomy::all()
        .iter()
        .map(|t| t.invariant_id)
        .collect();
    insta::assert_json_snapshot!("detector_ids", ids);
}
