//! Which detector implements each built-in invariant.
//!
//! The invariant library declares what Truent checks for; the detectors are
//! what actually runs. Before this table existed the two had drifted apart:
//! every one of the 28 library invariants was declared, listed by
//! `truent invariants`, and **emitted by nothing** — some because the
//! implementing detector used a different name (`sol_signer_checks` is
//! implemented by `sol_missing_signer`), some because no detector existed.
//!
//! Every library invariant must now resolve to one of:
//!
//! - [`Coverage::Detector`] — the `invariant_id` a detector emits for it, or
//! - [`Coverage::AdvisoryOnly`] — an explicit, written reason why no static
//!   detector can honestly implement it.
//!
//! `tests::every_library_invariant_is_accounted_for` fails the build if an
//! invariant is added without a row, and `referenced_detectors_exist` fails
//! it if a row names a detector the taxonomy does not know. The list of
//! "declared but never fires" can therefore never silently grow again.

/// How a library invariant is realised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Implemented: findings carry this detector's `invariant_id`.
    Detector(&'static str),
    /// Deliberately not implemented statically, with the reason.
    AdvisoryOnly(&'static str),
}

/// Library invariant → implementation.
pub static COVERAGE: &[(&str, Coverage)] = &[
    // ---- EVM -------------------------------------------------------------
    (
        "evm_access_control",
        Coverage::Detector("evm_missing_signer_check"),
    ),
    (
        "evm_delegatecall_injection",
        Coverage::Detector("evm_arbitrary_function_selector_dispatch"),
    ),
    (
        "evm_division_by_zero",
        Coverage::Detector("evm_division_by_zero"),
    ),
    (
        "evm_frontrunning",
        Coverage::AdvisoryOnly(
            "Front-running is a property of the transaction ordering a function is exposed \
             to, not of its text; the slippage and commit-reveal shapes that mitigate it are \
             covered by evm_router_slippage_validation and evm_constructor_race_condition.",
        ),
    ),
    (
        "evm_integer_overflow",
        Coverage::Detector("evm_legacy_unsafe_math"),
    ),
    (
        "evm_integer_underflow",
        Coverage::Detector("evm_legacy_unsafe_math"),
    ),
    (
        "evm_reentrancy_protection",
        Coverage::Detector("evm_reentrancy_classic"),
    ),
    (
        "evm_timestamp_dependence",
        Coverage::Detector("evm_timestamp_dependence"),
    ),
    (
        "evm_unchecked_returns",
        Coverage::Detector("evm_unchecked_returns"),
    ),
    (
        "evm_uninitialized_pointers",
        Coverage::AdvisoryOnly(
            "Uninitialised storage pointers were a compiler bug class fixed in Solidity 0.5; \
             the compiler rejects them, so a static detector would only ever fire on code \
             that does not compile.",
        ),
    ),
    // ---- Solana ----------------------------------------------------------
    (
        "sol_account_validation",
        Coverage::Detector("sol_unchecked_token_account_type"),
    ),
    (
        "sol_instruction_parsing",
        Coverage::AdvisoryOnly(
            "Instruction-data parsing correctness is decided by the Borsh/Anchor layout, \
             which the IDL front-end of `truent fuzz` exercises; there is no textual shape \
             for a malformed parse.",
        ),
    ),
    (
        "sol_integer_overflow",
        Coverage::Detector("sol_lamport_balance"),
    ),
    (
        "sol_lamport_balance",
        Coverage::Detector("sol_lamport_balance"),
    ),
    (
        "sol_pda_derivation",
        Coverage::Detector("sol_pda_authority_validation"),
    ),
    (
        "sol_rent_exemption",
        Coverage::Detector("sol_rent_exemption_check"),
    ),
    (
        "sol_signer_checks",
        Coverage::Detector("sol_missing_signer"),
    ),
    // ---- Move ------------------------------------------------------------
    (
        "move_access_control",
        Coverage::Detector("move_access_control_missing"),
    ),
    (
        "move_integer_overflow",
        Coverage::Detector("move_manual_overflow_check"),
    ),
    (
        "move_resource_leaks",
        Coverage::Detector("move_resource_destruction"),
    ),
    (
        "move_signer_requirement",
        Coverage::Detector("move_access_control_missing"),
    ),
    (
        "move_type_safety",
        Coverage::Detector("move_type_safety_violation"),
    ),
    // ---- Soroban ---------------------------------------------------------
    (
        "sor_checked_arithmetic",
        Coverage::Detector("sor_unchecked_arithmetic"),
    ),
    ("sor_init_guard", Coverage::Detector("sor_reinitialization")),
    (
        "sor_no_reentrancy",
        Coverage::Detector("sor_reentrancy_external_call"),
    ),
    (
        "sor_no_unprotected_upgrade",
        Coverage::Detector("sor_unprotected_upgrade"),
    ),
    (
        "sor_require_auth_checks",
        Coverage::Detector("sor_missing_require_auth"),
    ),
    (
        "sor_storage_ttl_extended",
        Coverage::Detector("sor_storage_ttl_not_extended"),
    ),
];

/// How `library_id` is realised, if it is a known library invariant.
pub fn coverage_for(library_id: &str) -> Option<Coverage> {
    COVERAGE
        .iter()
        .find(|(id, _)| *id == library_id)
        .map(|(_, c)| *c)
}

/// Every library invariant that no detector implements, with its reason.
pub fn advisory_only() -> Vec<(&'static str, &'static str)> {
    COVERAGE
        .iter()
        .filter_map(|(id, c)| match c {
            Coverage::AdvisoryOnly(why) => Some((*id, *why)),
            Coverage::Detector(_) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InvariantLibrary;
    use truent_core::taxonomy::taxonomy_for;

    fn all_library_ids() -> Vec<String> {
        ["evm", "solana", "move", "soroban"]
            .iter()
            .flat_map(|c| {
                InvariantLibrary::with_defaults(c)
                    .all()
                    .into_iter()
                    .map(|i| i.name.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn every_library_invariant_is_accounted_for() {
        // The ratchet. Adding an invariant to the library without saying how
        // it is implemented fails here.
        let missing: Vec<String> = all_library_ids()
            .into_iter()
            .filter(|id| coverage_for(id).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "library invariants with no coverage row: {missing:?}"
        );
    }

    #[test]
    fn no_stale_coverage_rows() {
        let ids = all_library_ids();
        let stale: Vec<&str> = COVERAGE
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| !ids.iter().any(|l| l == id))
            .collect();
        assert!(
            stale.is_empty(),
            "coverage rows for unknown invariants: {stale:?}"
        );
    }

    #[test]
    fn referenced_detectors_exist() {
        // A row may only point at a detector the taxonomy knows, and the
        // taxonomy is itself pinned to what the engine emits — so a row can
        // only name something that actually fires.
        for (id, c) in COVERAGE {
            if let Coverage::Detector(d) = c {
                assert!(
                    taxonomy_for(d).is_some(),
                    "{id} claims to be implemented by {d}, which is not a known detector"
                );
            }
        }
    }

    #[test]
    fn advisory_only_rows_carry_a_real_reason() {
        for (id, why) in advisory_only() {
            assert!(
                why.len() > 60,
                "{id}: reason is not an explanation: {why:?}"
            );
        }
        // These are the only two it is honest to leave unimplemented.
        assert_eq!(advisory_only().len(), 3);
    }
}
