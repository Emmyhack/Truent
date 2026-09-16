#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Move (Aptos / Sui) program analyzer.
//!
//! One grammar, two object models. Files are parsed with the vendored Sui
//! Move tree-sitter grammar extended for Aptos (`acquires`, `inline`, `for`
//! loops, scripts, address blocks); every detector then reads the AST model
//! in [`ast`], with the dialect-specific rules for what counts as shared
//! state and what counts as authorization living in [`privilege`].

pub mod analyzer;
/// Structural model of a Move file, both dialects.
pub mod ast;
/// Vulnerability detectors for Move modules.
pub mod detectors;
pub mod move_manual_overflow_check;
/// Reachability, shared state and authorization analysis.
pub mod privilege;
/// Chain-agnostic semantic-model extraction (shared IR).
pub mod semantic_model;
/// Real structural parsing via the vendored tree-sitter grammar.
pub mod tree_sitter_grammar;

pub use analyzer::MoveAnalyzer;
pub use ast::Dialect;
pub use detectors::*;
pub use move_manual_overflow_check::detect_move_manual_overflow_check;
pub use semantic_model::build_semantic_model;

/// Run every live Move detector against the given source text.
///
/// This is the single entry point the CLI uses for Move analysis. When the
/// grammar cannot parse a file cleanly, only the text-based detectors run
/// and the result is labelled so a reader knows the AST detectors were
/// skipped rather than silent.
pub fn run_all_detectors(source: &str, file_path: &str) -> Vec<truent_core::Finding> {
    let mut findings = Vec::new();

    // Line-based detector sees code only — comments and string contents
    // removed — so prose can neither raise nor suppress a finding.
    let code = truent_core::text::normalize(source, truent_core::text::CommentPolicy::StripAll);
    findings.extend(detect_move_manual_overflow_check(&code, file_path));

    match ast::parse(source) {
        Some(file) => {
            findings.extend(detectors::detect_all(&file, file_path));
            let model = semantic_model::build_from_ast(&file, file_path);
            findings.extend(
                truent_ir::rules::find_unauthorized_privileged_mutations(&model)
                    .into_iter()
                    .map(|f| {
                        f.with_metadata("dialect".to_string(), file.dialect.label().to_string())
                    }),
            );
        }
        None => {
            let model = build_semantic_model(source, file_path);
            findings.extend(
                truent_ir::rules::find_unauthorized_privileged_mutations(&model)
                    .into_iter()
                    .map(|f| {
                        f.with_metadata("extraction".to_string(), "regex-fallback".to_string())
                    }),
            );
        }
    }

    truent_core::text::restore_snippets(source, &mut findings);

    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.dedup_key()));

    findings.sort_by(|a, b| match b.severity.cmp(&a.severity) {
        std::cmp::Ordering::Equal => a.line.cmp(&b.line),
        other => other,
    });

    findings
}
