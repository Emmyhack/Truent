#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Move (Aptos/Sui) program analyzer.

pub mod analyzer;
/// Vulnerability detectors for Move modules
pub mod detectors;
pub mod move_manual_overflow_check;
pub mod move_resource_destruction;
pub mod move_type_safety_violation;
/// Chain-agnostic semantic-model extraction (Epic 6.1 shared IR)
pub mod semantic_model;
/// Real structural parsing via a vendored Sui Move tree-sitter grammar
pub mod tree_sitter_grammar;

pub use analyzer::MoveAnalyzer;
pub use detectors::*;
pub use move_manual_overflow_check::detect_move_manual_overflow_check;
pub use move_resource_destruction::detect_move_resource_destruction;
pub use move_type_safety_violation::detect_move_type_safety_violation;
pub use semantic_model::build_semantic_model;

/// Run every live Move detector against the given source text.
///
/// This is the single entry point the CLI should use for Move analysis: each
/// detector operates directly on raw source text, no Move AST parse is required.
pub fn run_all_detectors(source: &str, file_path: &str) -> Vec<truent_core::Finding> {
    // Line-based detectors see code only — comments and string contents
    // removed — so prose can neither raise nor suppress a finding. The
    // tree-sitter semantic model still receives the raw source.
    let code = truent_core::text::normalize(source, truent_core::text::CommentPolicy::StripAll);
    let mut findings = detectors::detect_all(&code, file_path);

    findings.extend(detect_move_resource_destruction(&code, file_path));
    findings.extend(detect_move_type_safety_violation(&code, file_path));
    findings.extend(detect_move_manual_overflow_check(&code, file_path));

    // Chain-agnostic shared-IR rule (Epic 6.1): flags privileged mutations
    // with no authorization guard, using the same rule EVM and Solana share.
    let model = build_semantic_model(source, file_path);
    findings.extend(truent_ir::rules::find_unauthorized_privileged_mutations(
        &model,
    ));

    truent_core::text::restore_snippets(source, &mut findings);

    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.dedup_key()));

    findings.sort_by(|a, b| match b.severity.cmp(&a.severity) {
        std::cmp::Ordering::Equal => a.line.cmp(&b.line),
        other => other,
    });

    findings
}
