#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Solana program analyzer: Extracts program model from Rust source.

pub mod analyzer;
/// Data models for parsed Anchor account structures and security analysis
pub mod anchor_model;
/// Parser for extracting account information from Anchor source code
pub mod anchor_parser;
/// Vulnerability detectors for Solana programs
pub mod detectors;
/// Chain-agnostic semantic-model extraction (Epic 6.1 shared IR)
pub mod semantic_model;
pub mod solana_durable_nonce;
pub mod solana_fake_sysvar_instruction;
pub mod solana_pda_authority_validation;
pub mod solana_rent_exemption;
pub mod solana_unchecked_token_account;

pub use analyzer::SolanaAnalyzer;
pub use anchor_model::{
    AccountSecurity, AnchorAccountField, AnchorAccountStruct, AnchorConstraint,
};
pub use anchor_parser::parse_anchor_accounts;
pub use detectors::*;
pub use semantic_model::build_semantic_model;
pub use solana_durable_nonce::detect_solana_durable_nonce_validation;
pub use solana_fake_sysvar_instruction::detect_fake_sysvar_instruction_account;
pub use solana_pda_authority_validation::detect_solana_pda_authority_validation;
pub use solana_rent_exemption::detect_solana_rent_exemption;
pub use solana_unchecked_token_account::detect_unchecked_token_account_type;

/// Run every live Solana detector against the given source text.
///
/// This is the single entry point the CLI should use for Solana analysis: each
/// detector operates directly on raw source text, no syn/AST parse is required.
pub fn run_all_detectors(source: &str, file_path: &str) -> Vec<truent_core::Finding> {
    // Line-based detectors see code only: string literals emptied and plain
    // comments removed, so a `msg!("no signer check")` or a commented-out
    // instruction cannot raise a finding. Only `/// CHECK:` lines are kept,
    // because Anchor treats that annotation as semantic; other doc comments
    // are prose. The semantic-model builder and
    // the Anchor parser still receive the raw source.
    // Multi-line raw strings are blanked first: a vulnerable fixture held
    // in a `#[cfg(test)]` module is a string, not the program under test.
    let without_raw = truent_core::text::strip_raw_strings(source);
    let code = truent_core::text::normalize(
        &without_raw,
        truent_core::text::CommentPolicy::KeepCheckAnnotations,
    );
    let mut findings = detectors::detect_all(&code, file_path);

    findings.extend(detect_solana_durable_nonce_validation(&code, file_path));
    findings.extend(detect_solana_pda_authority_validation(&code, file_path));
    findings.extend(detect_solana_rent_exemption(&code, file_path));
    findings.extend(detect_unchecked_token_account_type(&code, file_path));
    findings.extend(detect_fake_sysvar_instruction_account(&code, file_path));

    // Chain-agnostic shared-IR rule (Epic 6.1): flags privileged mutations
    // with no authorization guard, using the same rule EVM and Move share.
    // Best-effort: a source file the Anchor-account parser can't handle
    // simply contributes nothing from this rule rather than failing the scan.
    if let Ok(model) = build_semantic_model(&without_raw, file_path) {
        findings.extend(truent_ir::rules::find_unauthorized_privileged_mutations(
            &model,
        ));
    }

    // Detectors recorded stripped text; report what the user wrote.
    truent_core::text::restore_snippets(source, &mut findings);

    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.dedup_key()));

    findings.sort_by(|a, b| match b.severity.cmp(&a.severity) {
        std::cmp::Ordering::Equal => a.line.cmp(&b.line),
        other => other,
    });

    findings
}
