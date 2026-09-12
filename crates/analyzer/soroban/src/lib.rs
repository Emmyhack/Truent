#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Soroban (Stellar) contract analyzer: extracts a program model and runs
//! vulnerability detectors over `#[contract]`/`#[contractimpl]` Rust source.

pub mod analyzer;
/// Vulnerability detectors for Soroban contracts
pub mod detectors;
/// Chain-agnostic semantic-model extraction (shared cross-chain IR)
pub mod semantic_model;
/// Data model for parsed `#[contractimpl]` function facts
pub mod soroban_model;
/// `syn`-based parser extracting function facts from contract source
pub mod soroban_parser;

pub use analyzer::SorobanAnalyzer;
pub use detectors::*;
pub use semantic_model::build_semantic_model;
pub use soroban_model::ContractFunction;
pub use soroban_parser::parse_contract_functions;

/// Run every live Soroban detector against the given source text.
///
/// This is the single entry point the CLI should use for Soroban analysis:
/// contract functions are parsed once via `syn` and every detector reads
/// off that shared fact set.
pub fn run_all_detectors(source: &str, file_path: &str) -> Vec<truent_core::Finding> {
    let functions = match parse_contract_functions(source) {
        Ok(functions) => functions,
        // A source file `syn` can't parse contributes no findings rather
        // than failing the whole scan, matching the other chain analyzers'
        // best-effort behavior.
        Err(_) => return Vec::new(),
    };

    let mut findings = detectors::detect_all(&functions, file_path);

    // Chain-agnostic shared-IR rule: flags privileged mutations with no
    // authorization guard, using the same rule EVM/Solana/Move share.
    if let Ok(model) = build_semantic_model(source, file_path) {
        findings.extend(truent_ir::rules::find_unauthorized_privileged_mutations(
            &model,
        ));
    }

    // Findings are built from the parsed function model and record the
    // function name; the report should show the source line.
    truent_core::text::restore_snippets(source, &mut findings);

    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.dedup_key()));

    findings.sort_by(|a, b| match b.severity.cmp(&a.severity) {
        std::cmp::Ordering::Equal => a.line.cmp(&b.line),
        other => other,
    });

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const VULNERABLE: &str = r#"
#[contract]
pub struct VaultContract;

#[contractimpl]
impl VaultContract {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let balance: i128 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap();
        let new_balance = balance - amount;
        env.storage().persistent().set(&DataKey::Balance(to), &new_balance);
    }
}
"#;

    #[test]
    fn run_all_detectors_includes_shared_and_chain_specific_findings() {
        let findings = run_all_detectors(VULNERABLE, "vault.rs");
        let ids: std::collections::HashSet<_> =
            findings.iter().map(|f| f.invariant_id.as_str()).collect();

        assert!(ids.contains("sor_missing_require_auth"));
        assert!(ids.contains("sor_reinitialization"));
        assert!(ids.contains(truent_ir::rules::UNAUTHORIZED_PRIVILEGED_MUTATION));
    }

    #[test]
    fn run_all_detectors_never_panics_on_unparseable_source() {
        let findings = run_all_detectors("this is not valid rust {{{", "bad.rs");
        assert!(findings.is_empty());
    }
}
