//! The release checklist: every section of the codebase safety & security
//! test model, item by item, with what Truent can say about each.
//!
//! Each [`Item`] carries one kind of [`Evidence`]:
//!
//! - [`Evidence::Detectors`] — native detectors decide it: **PASS** when they
//!   ran over applicable files and found nothing, **FAIL** with counts
//!   otherwise, **N/A** when the repository has nothing they apply to.
//! - [`Evidence::Probe`] — runtime-probe detectors decide it, so a probe
//!   report must be supplied; without one the item is **NEEDS-PROBE**.
//! - [`Evidence::Signal`] — the repository must *carry* the thing (a test
//!   suite, a load test, a runbook) and CI must *run* it: **PASS** when both,
//!   **PARTIAL** when present but not wired, **MISSING** otherwise. This is
//!   the honest ceiling for tests only your own system can run.
//! - [`Evidence::Chains`] / [`Evidence::Exposure`] — no completed attack chain
//!   / no LIKELY finding.
//! - [`Evidence::Manual`] — only a person with the system can verify;
//!   **ASSESS**, never silently passed.
//!
//! The verdict is READY only when nothing is FAIL, MISSING or PARTIAL and
//! every ASSESS item has been listed for sign-off.

use serde::Serialize;
use std::collections::BTreeMap;
use truent_core::exposure::Exploitability;
use truent_core::Finding;

use crate::acceptance::{Acceptance, Accepted};
use crate::signals::{Signal, SignalResult};

/// What decides an item.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum Evidence {
    Detectors(&'static [&'static str]),
    Probe(&'static [&'static str]),
    Signal(Signal),
    Chains,
    Exposure,
    /// An external tool's report decides it (a symbolic executor). Without
    /// the report the item is NEEDS-TOOL.
    Tool(&'static [&'static str]),
    Manual(&'static str),
}

/// Which repositories an item applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Any,
    Contracts,
    Web,
    Deps,
    Ci,
    Containers,
    Iac,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Item {
    pub name: &'static str,
    pub scope: Scope,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Section {
    pub number: u8,
    pub name: &'static str,
    pub items: &'static [Item],
}

const fn d(name: &'static str, scope: Scope, ids: &'static [&'static str]) -> Item {
    Item {
        name,
        scope,
        evidence: Evidence::Detectors(ids),
    }
}
const fn p(name: &'static str, ids: &'static [&'static str]) -> Item {
    Item {
        name,
        scope: Scope::Web,
        evidence: Evidence::Probe(ids),
    }
}
const fn sig(name: &'static str, s: Signal) -> Item {
    Item {
        name,
        scope: Scope::Any,
        evidence: Evidence::Signal(s),
    }
}
const fn m(name: &'static str, how: &'static str) -> Item {
    Item {
        name,
        scope: Scope::Any,
        evidence: Evidence::Manual(how),
    }
}
use Scope::*;
use Signal as S;

const INJECTION_SINKS: &[&str] = &[
    "gen_sql_injection",
    "gen_command_injection",
    "gen_code_injection",
    "gen_xss_sink",
];
const ALL_AUTHZ_CONTRACT: &[&str] = &[
    "evm_access_control",
    "evm_shallow_auth",
    "evm_missing_signer_check",
    "evm_unprotected_initializer",
    "sol_missing_signer",
    "sol_signer_checks",
    "sol_account_validation",
    "sol_pda_authority_validation",
    "move_access_control",
    "move_access_control_missing",
    "move_signer_requirement",
    "sor_missing_require_auth",
    "sor_require_auth_checks",
    "unauthorized_privileged_mutation",
];
const REENTRANCY: &[&str] = &[
    "evm_reentrancy_classic",
    "evm_reentrancy_erc20",
    "evm_reentrancy_protection",
    "evm_reentrancy_via_whitelisted",
    "evm_readonly_reentrancy",
    "sor_no_reentrancy",
    "sor_reentrancy_external_call",
];
const OVERFLOW: &[&str] = &[
    "evm_integer_overflow",
    "evm_integer_underflow",
    "evm_legacy_unsafe_math",
    "sol_integer_overflow",
    "move_integer_overflow",
    "move_manual_overflow_check",
    "sor_checked_arithmetic",
    "sor_unchecked_arithmetic",
];
const PRECISION: &[&str] = &[
    "evm_precision_loss",
    "evm_arithmetic_rounding",
    "evm_division_by_zero",
];
const ORACLE: &[&str] = &[
    "evm_oracle_spot_price",
    "evm_oracle_self_trade",
    "evm_stale_oracle_price",
    "evm_token_balance_manipulation",
    "evm_unbounded_pricing_input",
    "evm_synthetic_collateral_oracle",
    "evm_lst_depeg",
    "sol_oracle_self_trade",
    "sol_oracle_rate_account",
    "move_oracle_spot_price",
    "sor_thin_liquidity_oracle_price",
];
const REPLAY: &[&str] = &[
    "evm_signature_replay_protection",
    "evm_cross_chain_replay_missing_chainid",
    "sol_durable_nonce_validation",
];
const UPGRADE: &[&str] = &[
    "evm_upgrade_path_verification",
    "evm_proxy_storage_collision",
    "evm_unprotected_initializer",
    "evm_constructor_race_condition",
    "sor_unprotected_upgrade",
    "sor_no_unprotected_upgrade",
    "sor_init_guard",
    "sor_reinitialization",
];
const CONSERVATION: &[&str] = &[
    "evm_conservation_check_absent",
    "evm_missing_post_state_health_check",
    "evm_state_mutation_ordering",
    "evm_unbacked_synthetic_mint",
    "move_liquidity_conservation",
    "sol_lamport_balance",
];
const SECRETS: &[&str] = &["gen_hardcoded_secret", "gen_private_key_committed"];
const HEADERS: &[&str] = &[
    "rt_missing_hsts",
    "rt_missing_csp",
    "rt_missing_frame_options",
    "rt_missing_content_type_options",
];
const COOKIES: &[&str] = &["rt_insecure_cookie"];
const CI_ATTACKS: &[&str] = &[
    "gen_ci_pwn_request",
    "gen_ci_script_injection",
    "gen_ci_secret_exposed",
    "gen_ci_unpinned_action",
];
const DOS_CONTRACT: &[&str] = &["evm_unbounded_loop", "evm_push_payment_in_loop"];
const DOS_WEB: &[&str] = &[
    "gen_regex_dos",
    "gen_unbounded_query_limit",
    "gen_graphql_unrestricted",
    "gen_upload_unvalidated",
    "gen_missing_rate_limit",
];

/// The whole model, section by section.
pub static SECTIONS: &[Section] = &[
    Section { number: 1, name: "Functional Testing", items: &[
        sig("Unit testing", S::UnitTests), sig("Integration testing", S::IntegrationTests), sig("End-to-end (E2E) testing", S::E2eTests), sig("API/endpoint testing", S::ApiTests),
        sig("Contract/interface testing", S::ApiTests),
        d("Input validation testing", Web, &["gen_mass_assignment", "gen_upload_unvalidated", "gen_unbounded_query_limit", "gen_xxe"]),
        d("Output validation testing", Web, &["gen_xss_sink", "gen_error_detail_exposed", "gen_open_redirect"]),
    ]},
    Section { number: 2, name: "Regression Testing", items: &[
        sig("Full regression test suite", S::UnitTests),
        m("Previously fixed vulnerability regression tests", "Every fixed vulnerability has a test that reproduces it; keep them in a `regressions/` corpus the way Truent keeps its own `tests/corpus/bad`"),
        m("Previously fixed bug regression tests", "Bug fixes land with a failing-then-passing test"),
        sig("Critical user-flow regression tests", S::E2eTests),
        d("Authentication regression tests", Web, &["gen_web_jwt_unverified", "gen_missing_rate_limit", "gen_insecure_randomness"]),
        d("Authorization regression tests", Any, &["gen_object_level_auth_missing", "unauthorized_privileged_mutation"]),
        d("Payment/withdrawal regression tests", Any, &["gen_non_atomic_multi_write", "evm_reentrancy_classic", "evm_unchecked_returns"]),
        d("Database-operation regression tests", Web, &["gen_sql_injection", "gen_non_atomic_multi_write"]),
        d("Smart-contract interaction regression tests", Contracts, REENTRANCY),
        d("State-transition regression tests", Contracts, UPGRADE),
    ]},
    Section { number: 3, name: "Static Application Security Testing (SAST)", items: &[
        d("SQL injection detection", Web, &["gen_sql_injection"]), d("Command injection detection", Web, &["gen_command_injection", "gen_pipe_to_shell"]),
        d("Cross-site scripting (XSS) detection", Web, &["gen_xss_sink"]), d("Server-side request forgery (SSRF) detection", Web, &["gen_web_ssrf"]),
        d("Path traversal detection", Web, &["gen_web_path_traversal"]), d("Insecure deserialization detection", Web, &["gen_unsafe_deserialization", "gen_xxe"]),
        d("Hardcoded secrets detection", Any, SECRETS), d("Weak/unsafe cryptography detection", Any, &["gen_weak_hash", "gen_insecure_randomness", "gen_tls_verification_disabled"]),
        d("Authentication flaws", Any, &["gen_web_jwt_unverified", "gen_missing_rate_limit", "evm_missing_signer_check", "sol_missing_signer", "sor_missing_require_auth"]),
        d("Authorization flaws", Any, ALL_AUTHZ_CONTRACT), d("Dangerous function/API usage", Web, &["gen_code_injection", "gen_unsafe_deserialization", "gen_insecure_temp_file", "gen_insecure_file_permissions"]),
        d("Unsafe configuration detection", Any, &["gen_web_debug_enabled", "gen_web_cors_wildcard", "gen_web_csrf_disabled", "gen_web_insecure_cookie", "gen_container_privileged", "gen_docker_root_user"]),
        d("Security-sensitive code pattern analysis", Any, &["gen_toctou_file", "gen_regex_dos", "gen_log_sensitive_data", "gen_mass_assignment"]),
    ]},
    Section { number: 4, name: "Dynamic Application Security Testing (DAST)", items: &[
        m("Authentication bypass testing", "Active bypass attempts are exploitation; Truent's exposure rating and the authentication detectors cover the static half — run authorized manual testing for the rest"),
        d("IDOR/BOLA testing", Web, &["gen_object_level_auth_missing"]),
        d("Privilege-escalation testing", Any, &["gen_mass_assignment", "gen_object_level_auth_missing", "unauthorized_privileged_mutation"]),
        p("Session-management testing", COOKIES), d("CORS testing", Web, &["gen_web_cors_wildcard"]), d("CSRF testing", Web, &["gen_web_csrf_disabled"]),
        d("Rate-limit testing", Web, &["gen_missing_rate_limit"]), d("Rate-limit bypass testing", Web, &["gen_missing_rate_limit"]),
        d("API abuse testing", Web, DOS_WEB), d("Malformed-request testing", Web, &["gen_xxe", "gen_regex_dos", "gen_upload_unvalidated"]),
        d("Injection testing", Web, INJECTION_SINKS), p("Security-header testing", HEADERS),
        p("Error-handling and information-disclosure testing", &["rt_server_banner", "rt_exposed_sensitive_path"]),
    ]},
    Section { number: 5, name: "Dependency & Supply-Chain Security Testing", items: &[
        d("Direct dependency vulnerability scanning", Deps, &["sca_vulnerable_dependency"]), d("Transitive dependency vulnerability scanning", Deps, &["sca_vulnerable_dependency"]),
        d("Known CVE detection", Deps, &["sca_vulnerable_dependency"]), d("Outdated dependency detection", Deps, &["sca_unmaintained_dependency"]),
        d("Malicious-package detection", Deps, &["sca_typosquat_candidate", "sca_install_script_dependency"]), d("Dependency-confusion checks", Deps, &["sca_dependency_confusion"]),
        d("Lockfile integrity checks", Deps, &["sca_missing_lockfile", "sca_lockfile_missing_integrity"]), sig("Dependency provenance verification", S::Sbom),
        d("Package integrity/signature verification", Deps, &["sca_lockfile_missing_integrity"]), d("Build-pipeline dependency checks", Ci, &["gen_ci_unpinned_action", "gen_docker_unpinned_base"]),
    ]},
    Section { number: 6, name: "Fuzz Testing", items: &[
        sig("Random-input fuzzing", S::Fuzzing), sig("Malformed-input fuzzing", S::Fuzzing), sig("Boundary-value fuzzing", S::Fuzzing), sig("Type-confusion fuzzing", S::Fuzzing),
        sig("Null/empty-value fuzzing", S::Fuzzing), sig("Extremely large input testing", S::Fuzzing), sig("Extremely small input testing", S::Fuzzing),
        d("Integer boundary testing", Contracts, OVERFLOW), d("Maximum-value testing", Contracts, OVERFLOW), d("Negative-value testing", Contracts, &["evm_integer_underflow"]),
        sig("Unicode/encoding fuzzing", S::Fuzzing), d("JSON/XML/parser fuzzing", Web, &["gen_xxe", "gen_regex_dos"]), sig("API parameter fuzzing", S::Fuzzing), sig("Transaction-input fuzzing", S::Fuzzing),
    ]},
    Section { number: 7, name: "Property-Based Testing", items: &[
        sig("Define security invariants", S::Invariants), d("Define financial invariants", Contracts, CONSERVATION), d("Define data-integrity invariants", Any, &["gen_non_atomic_multi_write", "move_liquidity_conservation"]),
        d("Define authorization invariants", Any, ALL_AUTHZ_CONTRACT), sig("Generate randomized test cases", S::PropertyTests), sig("Verify invariants across thousands of scenarios", S::Fuzzing),
        sig("Test edge cases automatically", S::PropertyTests), sig("Test state invariants after failures", S::Invariants),
    ]},
    Section { number: 8, name: "Business-Logic Testing", items: &[
        m("Business-rule validation", "Rules are specific to the product; encode them as invariants (`.sinv`) so `truent scan`/`fuzz` enforce them"),
        d("Unauthorized workflow testing", Any, ALL_AUTHZ_CONTRACT), d("Workflow-bypass testing", Contracts, UPGRADE),
        d("Price manipulation testing", Contracts, ORACLE), d("Quantity manipulation testing", Any, &["gen_mass_assignment", "evm_unbounded_pricing_input"]),
        m("Discount/coupon abuse testing", "Product-specific; test coupon reuse, stacking and negative totals in the E2E suite"),
        d("Fee manipulation testing", Contracts, &["evm_fee_on_transfer_incompatibility", "evm_router_slippage_validation"]), d("Balance manipulation testing", Any, &["evm_token_balance_manipulation", "gen_mass_assignment", "gen_non_atomic_multi_write"]),
        d("Duplicate-operation testing", Any, &["gen_non_atomic_multi_write", "evm_reentrancy_classic"]), d("Replay testing", Contracts, REPLAY), d("Double-spending testing", Any, REENTRANCY),
        d("Transaction-order manipulation testing", Contracts, &["evm_frontrunning", "evm_router_slippage_validation", "evm_timestamp_dependence"]),
        m("Trust-boundary testing", "Run `truent threat-model`; every boundary it lists needs a test that crosses it without credentials"),
        d("Privilege-boundary testing", Any, &["gen_object_level_auth_missing", "unauthorized_privileged_mutation", "evm_single_eoa_admin"]),
    ]},
    Section { number: 9, name: "State-Transition Testing", items: &[
        m("Test every valid state transition", "Enumerate the state machine and cover each edge in the unit suite"),
        d("Test every invalid state transition", Contracts, &["sor_init_guard", "sor_reinitialization", "evm_unprotected_initializer"]),
        d("Test unauthorized state transitions", Any, ALL_AUTHZ_CONTRACT), d("Test state-transition bypasses", Contracts, UPGRADE),
        sig("Test state rollback", S::MigrationRollback), d("Test repeated transitions", Contracts, &["evm_unprotected_initializer", "sor_reinitialization", "gen_non_atomic_multi_write"]),
        d("Test skipped states", Contracts, &["evm_zero_challenge_period", "evm_constructor_race_condition"]), sig("Test failed transitions", S::Invariants),
        d("Test partial transitions", Any, &["gen_non_atomic_multi_write", "evm_state_mutation_ordering"]), d("Test concurrent transitions", Any, REENTRANCY),
        d("Verify terminal states cannot be improperly reversed", Contracts, &["sor_storage_ttl_not_extended", "sor_temporary_storage_critical_state", "move_resource_destruction"]),
    ]},
    Section { number: 10, name: "Authorization & Access-Control Testing", items: &[
        d("Role-based access-control testing", Any, ALL_AUTHZ_CONTRACT), d("Permission testing", Any, &["gen_iac_wildcard_iam", "gen_insecure_file_permissions"]),
        d("Object-level authorization testing", Web, &["gen_object_level_auth_missing"]), d("Function-level authorization testing", Any, ALL_AUTHZ_CONTRACT),
        d("Horizontal privilege-escalation testing", Web, &["gen_object_level_auth_missing"]), d("Vertical privilege-escalation testing", Any, &["gen_mass_assignment", "unauthorized_privileged_mutation"]),
        d("Admin-access testing", Contracts, &["evm_single_eoa_admin", "evm_insufficient_multisig_threshold", "sol_admin_no_timelock", "move_admin_no_timelock"]),
        d("Owner-access testing", Contracts, &["evm_access_control", "evm_shallow_auth"]), d("Guest-access testing", Web, &["gen_object_level_auth_missing", "gen_web_jwt_unverified"]),
        d("Cross-user data-access testing", Web, &["gen_object_level_auth_missing"]), d("Tenant-isolation testing", Web, &["gen_object_level_auth_missing"]),
        d("API authorization matrix testing", Web, &["gen_object_level_auth_missing", "gen_web_jwt_unverified", "gen_mass_assignment"]), d("Smart-contract access-control testing", Contracts, ALL_AUTHZ_CONTRACT),
    ]},
    Section { number: 11, name: "Authentication & Session Security Testing", items: &[
        d("Login testing", Web, &["gen_missing_rate_limit", "gen_missing_security_logging"]), d("Logout testing", Web, &["gen_web_insecure_cookie"]),
        d("Password-reset testing", Web, &["gen_insecure_randomness", "gen_missing_rate_limit"]), m("MFA testing", "Verify enrolment, recovery codes and step-up on sensitive actions in the E2E suite"),
        p("Session-expiration testing", COOKIES), m("Session-revocation testing", "Logout and password change must invalidate every other session; test it"),
        p("Session-fixation testing", COOKIES), d("Token-reuse testing", Any, &["gen_web_jwt_unverified", "evm_signature_replay_protection"]),
        d("JWT validation testing", Web, &["gen_web_jwt_unverified"]), d("Refresh-token testing", Web, &["gen_insecure_randomness", "gen_log_sensitive_data"]),
        d("Credential-stuffing resistance testing", Web, &["gen_missing_rate_limit"]), d("Brute-force protection testing", Web, &["gen_missing_rate_limit"]),
        d("Account-enumeration testing", Web, &["gen_error_detail_exposed"]),
    ]},
    Section { number: 12, name: "Race-Condition & Concurrency Testing", items: &[
        d("Concurrent-request testing", Any, &["gen_non_atomic_multi_write"]), d("Race-condition testing", Any, &["gen_non_atomic_multi_write", "gen_toctou_file"]),
        d("TOCTOU testing", Any, &["gen_toctou_file", "evm_frontrunning"]), d("Double-spend testing", Any, REENTRANCY), d("Duplicate-transaction testing", Any, REPLAY),
        d("Concurrent withdrawal testing", Any, &["evm_reentrancy_classic", "gen_non_atomic_multi_write"]), d("Concurrent state-update testing", Any, &["gen_non_atomic_multi_write", "evm_state_mutation_ordering"]),
        d("Database race-condition testing", Web, &["gen_non_atomic_multi_write"]), m("Queue/message race testing", "Idempotency keys on consumers; test redelivery in the integration suite"),
        d("Replay-under-concurrency testing", Contracts, REPLAY), d("Locking/atomicity testing", Any, &["gen_non_atomic_multi_write"]),
    ]},
    Section { number: 13, name: "Data-Integrity Testing", items: &[
        d("Database integrity testing", Web, &["gen_non_atomic_multi_write", "gen_sql_injection"]), d("Transaction atomicity testing", Any, &["gen_non_atomic_multi_write"]),
        d("Consistency testing", Contracts, CONSERVATION), m("Duplicate-record testing", "Unique constraints and idempotent writes, tested"),
        m("Missing-record testing", "Referential integrity under deletes, tested"), d("Corrupted-state testing", Contracts, &["sor_storage_ttl_not_extended", "sor_temporary_storage_critical_state"]),
        sig("Rollback testing", S::MigrationRollback), m("Database constraint testing", "Constraints exist for every invariant the application relies on"),
        m("Referential-integrity testing", "Foreign keys with the intended on-delete behaviour"), sig("Backup restoration testing", S::DrRunbook),
        sig("Disaster-recovery testing", S::DrRunbook), sig("Data migration integrity testing", S::Migrations), d("Financial-balance reconciliation testing", Any, CONSERVATION),
    ]},
    Section { number: 14, name: "Financial / Value-Movement Testing", items: &[
        d("Deposit testing", Contracts, &["evm_erc4626_inflation_protection", "evm_fee_on_transfer_incompatibility", "sol_rent_exemption"]), d("Withdrawal testing", Contracts, REENTRANCY),
        d("Transfer testing", Any, &["evm_unchecked_returns", "gen_non_atomic_multi_write"]), m("Refund testing", "Refunds cannot exceed the original charge or be issued twice; test it"),
        d("Fee calculation testing", Contracts, &["evm_precision_loss", "evm_arithmetic_rounding", "evm_fee_on_transfer_incompatibility"]), d("Balance calculation testing", Any, CONSERVATION),
        d("Rounding/precision testing", Contracts, PRECISION), d("Negative-value testing", Contracts, &["evm_integer_underflow"]), d("Zero-value testing", Contracts, &["evm_division_by_zero", "evm_merkle_root_zero"]),
        d("Maximum-value testing", Contracts, OVERFLOW), d("Double-spending testing", Any, REENTRANCY), d("Replay testing", Contracts, REPLAY),
        d("Unauthorized transfer testing", Any, ALL_AUTHZ_CONTRACT), d("Transaction ordering testing", Contracts, &["evm_frontrunning", "evm_state_mutation_ordering"]),
        d("Partial-failure testing", Any, &["gen_non_atomic_multi_write", "evm_push_payment_in_loop"]), d("Atomicity testing", Any, &["gen_non_atomic_multi_write"]),
        d("Accounting/reconciliation testing", Contracts, CONSERVATION),
    ]},
    Section { number: 15, name: "Smart-Contract Security Testing", items: &[
        d("Reentrancy testing", Contracts, REENTRANCY), d("Access-control testing", Contracts, ALL_AUTHZ_CONTRACT), d("Integer overflow/underflow testing", Contracts, OVERFLOW),
        d("Precision/rounding testing", Contracts, PRECISION), d("Oracle manipulation testing", Contracts, ORACLE), d("Price manipulation testing", Contracts, ORACLE),
        d("Flash-loan attack testing", Contracts, &["evm_flash_loan_governance", "evm_oracle_spot_price", "evm_token_balance_manipulation"]), d("Front-running testing", Contracts, &["evm_frontrunning", "evm_router_slippage_validation"]),
        d("MEV-related attack testing", Contracts, &["evm_frontrunning", "evm_router_slippage_validation", "evm_oracle_self_trade"]), d("Replay-attack testing", Contracts, REPLAY),
        d("Signature-validation testing", Contracts, &["evm_signature_replay_protection", "evm_bridge_address_cryptographic_verify", "evm_aa_entropy_weakness"]),
        d("Initialization testing", Contracts, &["evm_unprotected_initializer", "evm_constructor_race_condition", "sor_init_guard"]), d("Uninitialized-contract testing", Contracts, &["evm_unprotected_initializer", "evm_uninitialized_pointers"]),
        d("Upgradeability testing", Contracts, UPGRADE), d("Proxy security testing", Contracts, &["evm_proxy_storage_collision", "evm_upgrade_path_verification", "evm_delegatecall_injection"]),
        d("Storage-collision testing", Contracts, &["evm_proxy_storage_collision"]), d("Emergency/pause mechanism testing", Contracts, &["evm_missing_pause_mechanism"]),
        d("Token-standard compatibility testing", Contracts, &["evm_fee_on_transfer_incompatibility", "evm_unchecked_returns", "sol_unchecked_token_account_type"]),
        d("Denial-of-service/gas-griefing testing", Contracts, DOS_CONTRACT), d("Gas-consumption testing", Contracts, DOS_CONTRACT),
        sig("Invariant testing", S::Invariants),
        Item { name: "Symbolic-execution testing", scope: Contracts, evidence: Evidence::Tool(&["evm_symbolic_counterexample", "evm_symbolic_unresolved"]) },
        sig("Smart-contract fuzzing", S::Fuzzing), d("Static-analysis testing", Contracts, REENTRANCY),
    ]},
    Section { number: 16, name: "API Security Testing", items: &[
        m("Endpoint discovery", "`truent threat-model` lists discovered routes; reconcile against the API inventory"),
        d("Authentication testing", Web, &["gen_web_jwt_unverified", "gen_missing_rate_limit"]), d("Authorization testing", Web, &["gen_object_level_auth_missing"]),
        d("BOLA/IDOR testing", Web, &["gen_object_level_auth_missing"]), d("Parameter tampering", Web, &["gen_mass_assignment", "gen_unbounded_query_limit"]),
        m("HTTP-method manipulation", "Every route rejects methods it does not implement (405); test with the API suite"),
        d("Mass-assignment testing", Web, &["gen_mass_assignment"]), d("Input validation testing", Web, &["gen_xxe", "gen_regex_dos", "gen_upload_unvalidated", "gen_sql_injection"]),
        d("Output encoding testing", Web, &["gen_xss_sink", "gen_error_detail_exposed"]), d("Rate-limit testing", Web, &["gen_missing_rate_limit"]),
        d("Pagination abuse testing", Web, &["gen_unbounded_query_limit"]), d("Resource-exhaustion testing", Web, DOS_WEB),
        m("API version compatibility testing", "Contract tests against the previous API version in CI"), d("GraphQL security testing (if applicable)", Web, &["gen_graphql_unrestricted"]),
        d("WebSocket security testing (if applicable)", Web, &["gen_websocket_no_origin_check"]),
    ]},
    Section { number: 17, name: "CORS & Browser Security Testing", items: &[
        d("CORS policy testing", Web, &["gen_web_cors_wildcard"]), d("Origin-validation testing", Web, &["gen_web_cors_wildcard", "gen_websocket_no_origin_check"]),
        d("Credentialed-CORS testing", Web, &["gen_web_cors_wildcard"]), d("Wildcard-origin testing", Web, &["gen_web_cors_wildcard"]), d("CSRF testing", Web, &["gen_web_csrf_disabled"]),
        p("Clickjacking testing", &["rt_missing_frame_options"]), p("Content-Security-Policy testing", &["rt_missing_csp"]), p("Security-header testing", HEADERS),
        p("Cookie security testing", COOKIES), d("SameSite testing", Web, &["gen_web_insecure_cookie"]), p("Secure/HttpOnly cookie testing", COOKIES),
    ]},
    Section { number: 18, name: "Load & Stress Testing", items: &[
        sig("Normal-load testing", S::LoadTests), sig("Peak-load testing", S::LoadTests), sig("High-concurrency testing", S::LoadTests), sig("Stress testing", S::LoadTests),
        sig("Spike testing", S::LoadTests), sig("Endurance/soak testing", S::LoadTests), d("CPU-exhaustion testing", Web, &["gen_regex_dos"]),
        d("Memory-exhaustion testing", Web, &["gen_unbounded_query_limit", "gen_upload_unvalidated"]), d("Database-exhaustion testing", Web, &["gen_unbounded_query_limit"]),
        sig("Connection-exhaustion testing", S::LoadTests), sig("Queue-overload testing", S::LoadTests), sig("API timeout testing", S::LoadTests), sig("Cascading-failure testing", S::ChaosTests),
    ]},
    Section { number: 19, name: "Chaos & Failure Testing", items: &[
        sig("Database failure testing", S::ChaosTests), sig("Cache failure testing", S::ChaosTests), sig("RPC-node failure testing", S::ChaosTests), sig("Network failure testing", S::ChaosTests),
        sig("Network-latency testing", S::ChaosTests), sig("Third-party-service failure testing", S::ChaosTests), sig("API timeout testing", S::ChaosTests), sig("Message-queue failure testing", S::ChaosTests),
        d("Transaction-revert testing", Contracts, &["evm_unchecked_returns", "evm_push_payment_in_loop", "sor_unhandled_panic"]), sig("Partial-service failure testing", S::ChaosTests),
        sig("Restart/recovery testing", S::ChaosTests), sig("Failover testing", S::DrRunbook), sig("Graceful-degradation testing", S::ChaosTests), sig("Recovery-state integrity testing", S::Invariants),
    ]},
    Section { number: 20, name: "Migration & Upgrade Testing", items: &[
        sig("Database migration testing", S::Migrations), sig("Schema migration testing", S::Migrations), sig("Migration rollback testing", S::MigrationRollback),
        sig("Partial-migration failure testing", S::MigrationRollback), sig("Existing-data compatibility testing", S::Migrations), sig("Version-upgrade testing", S::E2eTests),
        m("API backward-compatibility testing", "Contract tests against the previous client version"), d("Smart-contract upgrade testing", Contracts, UPGRADE),
        d("Proxy upgrade testing", Contracts, &["evm_upgrade_path_verification", "evm_proxy_storage_collision"]), d("Storage-layout compatibility testing", Contracts, &["evm_proxy_storage_collision"]),
        m("Configuration migration testing", "Config schema is versioned and validated at startup"),
    ]},
    Section { number: 21, name: "Performance Testing", items: &[
        sig("Response-time testing", S::LoadTests), sig("Throughput testing", S::LoadTests), sig("CPU profiling", S::Benchmarks), sig("Memory profiling", S::Benchmarks),
        d("Database-query performance testing", Web, &["gen_unbounded_query_limit"]), m("N+1 query detection", "Enable query logging in tests and assert query counts per request"),
        sig("RPC-call performance testing", S::Benchmarks), sig("Network-performance testing", S::LoadTests), sig("Cache-performance testing", S::Benchmarks),
        d("Smart-contract gas-usage testing", Contracts, DOS_CONTRACT), sig("Performance-regression testing", S::Benchmarks),
    ]},
    Section { number: 22, name: "Differential Testing", items: &[
        sig("Compare old and new implementations", S::SnapshotOrDifferentialTests), sig("Compare outputs for identical inputs", S::SnapshotOrDifferentialTests),
        sig("Compare financial calculations", S::SnapshotOrDifferentialTests), sig("Compare state transitions", S::SnapshotOrDifferentialTests),
        sig("Compare API responses", S::SnapshotOrDifferentialTests), sig("Compare serialization/deserialization", S::SnapshotOrDifferentialTests),
        m("Investigate unexpected behavioral differences", "Every snapshot change is reviewed, never blindly accepted"),
    ]},
    Section { number: 23, name: "Mutation Testing", items: &[
        sig("Mutate comparison operators", S::MutationTesting), sig("Mutate arithmetic operators", S::MutationTesting), sig("Mutate boolean conditions", S::MutationTesting),
        sig("Remove validation checks", S::MutationTesting), sig("Remove authorization checks", S::MutationTesting), sig("Change boundary conditions", S::MutationTesting),
        sig("Verify tests detect injected mutations", S::MutationTesting), sig("Measure test-suite mutation score", S::MutationTesting),
    ]},
    Section { number: 24, name: "Secrets & Configuration Testing", items: &[
        d("Hardcoded-secret scanning", Any, SECRETS), d("API-key scanning", Any, &["gen_hardcoded_secret"]), d("Private-key scanning", Any, &["gen_private_key_committed"]),
        d("Credential scanning", Any, SECRETS), d("Environment-variable security", Any, &["gen_hardcoded_secret", "gen_ci_secret_exposed"]),
        d("Production/debug configuration checks", Web, &["gen_web_debug_enabled", "gen_graphql_unrestricted"]), d("Insecure default configuration checks", Any, &["gen_web_cors_wildcard", "gen_web_csrf_disabled", "gen_container_privileged", "gen_iac_public_storage"]),
        p("Exposed configuration testing", &["rt_exposed_sensitive_path"]), m("Secret rotation testing", "Rotation is automated (or at least runbooked) and exercised on a schedule"),
        d("Secret-access authorization testing", Iac, &["gen_iac_wildcard_iam", "gen_ci_secret_exposed"]),
    ]},
    Section { number: 25, name: "Logging & Monitoring Security Testing", items: &[
        d("Sensitive-data logging checks", Web, &["gen_log_sensitive_data"]), d("Secret/token logging checks", Any, &["gen_log_sensitive_data", "gen_ci_secret_exposed"]),
        d("Security-event logging", Web, &["gen_missing_security_logging"]), d("Authentication-event logging", Web, &["gen_missing_security_logging"]),
        d("Authorization-event logging", Web, &["gen_missing_security_logging"]), m("Financial-transaction logging", "Every value movement writes an immutable audit record"),
        m("Audit-trail integrity", "Logs are append-only and shipped off-host; tampering is detectable"), d("Log-injection testing", Web, &["gen_log_injection"]),
        sig("Alerting verification", S::AlertingConfig), sig("Detection-rule testing", S::AlertingConfig),
    ]},
    Section { number: 26, name: "File & Resource Security Testing", items: &[
        d("File-upload testing", Web, &["gen_upload_unvalidated"]), d("Malicious-file testing", Web, &["gen_upload_unvalidated"]), d("File-type validation", Web, &["gen_upload_unvalidated"]),
        d("Path-traversal testing", Web, &["gen_web_path_traversal"]), d("File-size limit testing", Web, &["gen_upload_unvalidated"]), d("Resource-exhaustion testing", Web, DOS_WEB),
        d("Temporary-file security", Web, &["gen_insecure_temp_file", "gen_toctou_file"]), d("File-permission testing", Any, &["gen_insecure_file_permissions"]),
    ]},
    Section { number: 27, name: "Availability & Denial-of-Service Testing", items: &[
        d("Application-level DoS testing", Web, DOS_WEB), d("API resource-exhaustion testing", Web, DOS_WEB), d("Database resource-exhaustion testing", Web, &["gen_unbounded_query_limit"]),
        d("Memory-exhaustion testing", Web, &["gen_unbounded_query_limit", "gen_upload_unvalidated"]), d("CPU-exhaustion testing", Web, &["gen_regex_dos"]),
        d("Expensive-operation abuse testing", Web, &["gen_graphql_unrestricted", "gen_missing_rate_limit"]), d("Gas-griefing testing", Contracts, DOS_CONTRACT),
        sig("Queue exhaustion testing", S::LoadTests), sig("Connection exhaustion testing", S::LoadTests), d("Rate-limit bypass testing", Web, &["gen_missing_rate_limit"]),
    ]},
    Section { number: 28, name: "Supply-Chain & Build Security", items: &[
        d("CI/CD pipeline security testing", Ci, CI_ATTACKS), d("Build-script review", Ci, &["gen_ci_script_injection", "gen_pipe_to_shell"]),
        d("Dependency-lock verification", Deps, &["sca_missing_lockfile", "sca_lockfile_missing_integrity", "sca_unpinned_dependency"]), d("Artifact-integrity testing", Ci, &["gen_ci_unsigned_release"]),
        d("Container-image scanning", Containers, &["gen_docker_unpinned_base", "gen_docker_root_user"]), d("Base-image vulnerability scanning", Containers, &["gen_docker_unpinned_base"]),
        d("Secret exposure in CI/CD", Ci, &["gen_ci_secret_exposed"]), d("Build-environment isolation", Ci, &["gen_ci_pwn_request"]),
        d("Deployment-permission testing", Ci, &["gen_ci_pwn_request", "gen_iac_wildcard_iam"]), sig("Release-integrity verification", S::ReleaseSigning),
    ]},
    Section { number: 29, name: "Security Boundary Testing", items: &[
        d("User-to-user isolation", Web, &["gen_object_level_auth_missing"]), d("User-to-admin isolation", Any, &["gen_mass_assignment", "unauthorized_privileged_mutation"]),
        m("Service-to-service authorization", "Internal calls carry an identity (mTLS / signed tokens) and are authorized, tested"), d("API-to-database boundaries", Web, &["gen_sql_injection", "gen_iac_public_database"]),
        d("Frontend-to-backend trust boundaries", Web, &["gen_mass_assignment", "gen_web_jwt_unverified", "gen_web_cors_wildcard"]), d("Backend-to-RPC boundaries", Any, &["gen_tls_verification_disabled", "gen_web_ssrf"]),
        d("Smart-contract trust boundaries", Contracts, &["evm_bridge_address_cryptographic_verify", "evm_public_relay", "evm_delegatecall_injection", "evm_dvn_threshold"]),
        d("Third-party integration boundaries", Any, &["gen_web_ssrf", "gen_tls_verification_disabled", "sca_vulnerable_dependency"]),
        m("Internal-service authentication", "No internal service accepts unauthenticated calls from the network; verify with `truent probe --ports`"),
    ]},
    Section { number: 30, name: "Recovery & Disaster Testing", items: &[
        sig("Backup creation testing", S::BackupConfig), sig("Backup restoration testing", S::DrRunbook), sig("Database recovery testing", S::DrRunbook), sig("Service recovery testing", S::ChaosTests),
        m("Key recovery procedures", "Signing and encryption keys have a documented, rehearsed recovery path"), d("Failed-transaction recovery", Any, &["gen_non_atomic_multi_write", "evm_push_payment_in_loop"]),
        d("Interrupted-operation recovery", Any, &["gen_non_atomic_multi_write"]), sig("Disaster-recovery testing", S::DrRunbook), sig("Business-continuity testing", S::DrRunbook),
        sig("Recovery-time objective testing", S::DrRunbook), sig("Recovery-point objective testing", S::BackupConfig),
    ]},
    Section { number: 31, name: "Code Quality & Safety Testing", items: &[
        sig("Linting", S::Lint), sig("Type checking", S::TypeCheck), sig("Compiler/static type checks", S::TypeCheck), m("Dead-code detection", "Compiler warnings / `knip` / `vulture` run in CI with warnings denied"),
        d("Unsafe-code detection", Any, &["gen_code_injection", "gen_unsafe_deserialization", "gen_insecure_file_permissions"]), d("Error-handling analysis", Any, &["evm_unchecked_returns", "sor_unhandled_panic", "gen_error_detail_exposed"]),
        d("Exception-path testing", Any, &["gen_error_detail_exposed", "gen_non_atomic_multi_write"]), m("Null/undefined handling", "Strict null checks / Option types enforced by the type checker"),
        d("Boundary-condition testing", Contracts, OVERFLOW), m("Complexity analysis", "Cyclomatic complexity is measured and capped in CI"), sig("Code-coverage analysis", S::Coverage),
    ]},
    Section { number: 32, name: "Critical-Path Security Testing", items: &[
        Item { name: "No completed attack chain", scope: Any, evidence: Evidence::Chains },
        Item { name: "No LIKELY-exploitable finding", scope: Any, evidence: Evidence::Exposure },
        d("Move money or tokens", Any, REENTRANCY), d("Change balances", Any, CONSERVATION), d("Transfer ownership", Contracts, &["evm_access_control", "evm_shallow_auth", "evm_single_eoa_admin"]),
        d("Change permissions", Any, &["gen_mass_assignment", "gen_iac_wildcard_iam", "unauthorized_privileged_mutation"]), d("Execute privileged operations", Any, ALL_AUTHZ_CONTRACT),
        d("Modify critical configuration", Contracts, &["evm_upgrade_path_verification", "sol_admin_no_timelock", "move_admin_no_timelock"]), d("Access sensitive user data", Web, &["gen_object_level_auth_missing", "gen_log_sensitive_data", "gen_sql_injection"]),
        d("Delete or corrupt data", Web, &["gen_sql_injection", "gen_non_atomic_multi_write", "gen_insecure_file_permissions"]), d("Execute smart contracts", Contracts, &["evm_delegatecall_injection", "evm_arbitrary_function_selector_dispatch", "evm_arbitrary_call_msg_value"]),
        d("Sign transactions", Contracts, &["evm_signature_replay_protection", "evm_aa_entropy_weakness"]), d("Modify prices or exchange rates", Contracts, ORACLE), d("Control oracles", Contracts, ORACLE),
        d("Upgrade contracts", Contracts, UPGRADE), d("Pause/unpause systems", Contracts, &["evm_missing_pause_mechanism"]), d("Shut down or exhaust the application", Any, DOS_WEB),
        d("Bypass authentication", Web, &["gen_web_jwt_unverified", "gen_missing_rate_limit"]), d("Bypass authorization", Any, &["gen_object_level_auth_missing", "unauthorized_privileged_mutation"]),
        d("Cause permanent loss of funds", Contracts, &["evm_unbacked_synthetic_mint", "evm_erc4626_inflation_protection", "move_resource_leaks"]), d("Cause irreversible state changes", Contracts, &["evm_zero_challenge_period", "evm_unprotected_initializer", "sor_temporary_storage_critical_state"]),
    ]},
    Section { number: 33, name: "Final Security Validation", items: &[
        sig("All unit tests pass", S::UnitTests), sig("All integration tests pass", S::IntegrationTests), sig("All E2E tests pass", S::E2eTests), sig("Regression suite passes", S::UnitTests),
        d("SAST passes", Any, INJECTION_SINKS), p("DAST passes", HEADERS), d("Dependency scan passes", Deps, &["sca_vulnerable_dependency"]), sig("Fuzz tests pass", S::Fuzzing),
        sig("Property/invariant tests pass", S::Invariants), d("Business-logic tests pass", Contracts, ORACLE), d("Authorization matrix passes", Any, ALL_AUTHZ_CONTRACT),
        d("Race-condition tests pass", Any, &["gen_non_atomic_multi_write"]), d("Data-integrity tests pass", Any, CONSERVATION), d("Financial/value-movement tests pass", Any, REENTRANCY),
        d("Smart-contract security tests pass", Contracts, ALL_AUTHZ_CONTRACT), sig("Load/stress tests pass", S::LoadTests), sig("Failure/chaos tests pass", S::ChaosTests),
        sig("Migration tests pass", S::Migrations), sig("Performance regression checks pass", S::Benchmarks), sig("Mutation tests meet the required threshold", S::MutationTesting),
        d("Secrets/configuration scans pass", Any, SECRETS), d("Logging/monitoring checks pass", Web, &["gen_log_sensitive_data", "gen_missing_security_logging"]), sig("Recovery tests pass", S::DrRunbook),
        Item { name: "Critical-path security review completed", scope: Any, evidence: Evidence::Chains },
        Item { name: "No unresolved critical vulnerabilities", scope: Any, evidence: Evidence::Exposure },
        m("No unresolved high-severity vulnerabilities without explicit risk acceptance", "Every remaining HIGH has a written, dated risk acceptance"),
    ]},
];

/// Status of one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Pass,
    /// Findings exist but every one is covered by an in-force risk acceptance.
    Accepted,
    NotApplicable,
    Assess,
    NeedsProbe,
    Partial,
    Missing,
    Fail,
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Accepted => "ACCEPTED",
            Self::Fail => "FAIL",
            Self::Partial => "PARTIAL",
            Self::Missing => "MISSING",
            Self::Assess => "ASSESS",
            Self::NeedsProbe => "NEEDS-TOOL",
            Self::NotApplicable => "N/A",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ItemResult {
    pub name: &'static str,
    pub status: Status,
    /// What produced the status: counts, evidence paths, or the manual step.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionResult {
    pub number: u8,
    pub name: &'static str,
    pub items: Vec<ItemResult>,
    pub worst: Status,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub sections: Vec<SectionResult>,
    pub counts: BTreeMap<String, usize>,
    pub ready: bool,
    /// Findings carried under an in-force acceptance, with the acceptance.
    pub accepted: Vec<Accepted>,
    /// Acceptances whose date has passed; their findings are open again.
    pub expired: Vec<Acceptance>,
}

/// External inputs to the evaluation.
#[derive(Debug, Default, Clone)]
pub struct Inputs {
    /// A `truent probe` report was folded into the findings.
    pub probe_loaded: bool,
    /// A `truent symbolic` report was folded into the findings.
    pub symbolic_loaded: bool,
    /// Findings removed from the open set by risk acceptance.
    pub accepted: Vec<Accepted>,
    pub expired: Vec<Acceptance>,
}

/// What the repository contains, for scoping.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RepoScope {
    pub contracts: bool,
    pub web: bool,
    pub deps: bool,
    pub ci: bool,
    pub containers: bool,
    pub iac: bool,
}

impl RepoScope {
    pub fn from_files(files: &[String]) -> Self {
        let l: Vec<String> = files.iter().map(|f| f.to_ascii_lowercase()).collect();
        Self {
            contracts: l.iter().any(|f| {
                f.ends_with(".sol")
                    || f.ends_with(".move")
                    || (f.ends_with(".rs") && (f.contains("programs/") || f.contains("contracts/")))
            }),
            web: l.iter().any(|f| {
                f.ends_with(".py")
                    || f.ends_with(".js")
                    || f.ends_with(".ts")
                    || f.ends_with(".tsx")
                    || f.ends_with(".go")
                    || f.ends_with(".jsx")
                    || f.ends_with(".mjs")
            }),
            deps: l.iter().any(|f| {
                f.ends_with("cargo.lock")
                    || f.ends_with("package-lock.json")
                    || f.ends_with("yarn.lock")
                    || f.ends_with("pnpm-lock.yaml")
                    || f.ends_with("requirements.txt")
                    || f.ends_with("poetry.lock")
                    || f.ends_with("pipfile.lock")
                    || f.ends_with("go.sum")
                    || f.ends_with("package.json")
                    || f.ends_with("cargo.toml")
                    || f.ends_with("pyproject.toml")
                    || f.ends_with("go.mod")
            }),
            ci: l.iter().any(|f| {
                f.starts_with(".github/workflows/")
                    || f.ends_with(".gitlab-ci.yml")
                    || f.ends_with("jenkinsfile")
            }),
            containers: l.iter().any(|f| {
                f.ends_with("dockerfile")
                    || f.contains("dockerfile.")
                    || f.contains("docker-compose")
                    || f.contains("k8s/")
                    || f.contains("kubernetes/")
                    || f.contains("helm/")
            }),
            iac: l.iter().any(|f| {
                f.ends_with(".tf")
                    || f.contains("cloudformation")
                    || f.ends_with("template.yaml")
                    || f.ends_with("template.yml")
            }),
        }
    }
    fn applies(&self, s: Scope) -> bool {
        match s {
            Scope::Any => true,
            Scope::Contracts => self.contracts,
            Scope::Web => self.web,
            Scope::Deps => self.deps,
            Scope::Ci => self.ci,
            Scope::Containers => self.containers,
            Scope::Iac => self.iac,
        }
    }
}

/// Evaluate the whole checklist.
pub fn evaluate(
    findings: &[Finding],
    signals: &[SignalResult],
    scope: &RepoScope,
    inputs: &Inputs,
) -> Report {
    let probe_loaded = inputs.probe_loaded;
    // Informational findings (an install script to review, say) describe
    // the repository; they do not fail a checklist item.
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in findings
        .iter()
        .filter(|f| f.severity != truent_core::Severity::Info)
    {
        *counts.entry(f.invariant_id.as_str()).or_default() += 1;
    }
    let mut accepted_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for a in &inputs.accepted {
        *accepted_counts
            .entry(a.finding.invariant_id.as_str())
            .or_default() += 1;
    }
    let chains = crate::chains::detect(findings);
    let likely = findings
        .iter()
        .filter(|f| {
            f.exploitability()
                .map(|r| r.exploitability == Exploitability::Likely)
                .unwrap_or(false)
        })
        .count();
    let sig = |s: Signal| signals.iter().find(|r| r.signal == s);

    let mut sections = Vec::new();
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for sec in SECTIONS {
        let mut items = Vec::new();
        for it in sec.items {
            let (status, detail) = match it.evidence {
                Evidence::Detectors(ids) => {
                    if !scope.applies(it.scope) {
                        (Status::NotApplicable, "nothing in the repository these detectors apply to".into())
                    } else {
                        let hits: Vec<String> = ids
                            .iter()
                            .filter_map(|id| counts.get(id).map(|n| format!("{id} ×{n}")))
                            .collect();
                        if hits.is_empty() {
                            let acc: Vec<String> = ids
                                .iter()
                                .filter_map(|id| accepted_counts.get(id).map(|n| format!("{id} ×{n}")))
                                .collect();
                            if acc.is_empty() {
                                (Status::Pass, format!("{} detector(s) ran, no findings", ids.len()))
                            } else {
                                (Status::Accepted, format!("under risk acceptance: {}", acc.join(", ")))
                            }
                        } else {
                            (Status::Fail, hits.join(", "))
                        }
                    }
                }
                Evidence::Tool(ids) => {
                    if !scope.applies(it.scope) {
                        (Status::NotApplicable, "nothing in the repository this applies to".into())
                    } else if !inputs.symbolic_loaded {
                        (Status::NeedsProbe, "run `truent symbolic <foundry-project> --format json --out symbolic.json` and pass --symbolic-report".into())
                    } else {
                        let cex = counts.get(ids[0]).copied().unwrap_or(0);
                        let unresolved = ids.get(1).and_then(|i| counts.get(i)).copied().unwrap_or(0);
                        if cex > 0 {
                            (Status::Fail, format!("{cex} proven counterexample(s) — see `truent symbolic`"))
                        } else if unresolved > 0 {
                            (Status::Partial, format!("{unresolved} check(s) undecided (timeout / unknown / all paths reverted)"))
                        } else {
                            (Status::Pass, "every symbolic check passed".into())
                        }
                    }
                }
                Evidence::Probe(ids) => {
                    if !probe_loaded {
                        (Status::NeedsProbe, "run `truent probe <target> --authorized --format json` and pass --probe-report".into())
                    } else {
                        let hits: Vec<String> = ids
                            .iter()
                            .filter_map(|id| counts.get(id).map(|n| format!("{id} ×{n}")))
                            .collect();
                        if hits.is_empty() {
                            (Status::Pass, "probe observed no issue".into())
                        } else {
                            (Status::Fail, hits.join(", "))
                        }
                    }
                }
                Evidence::Signal(s) => match sig(s) {
                    Some(r) if r.present && r.wired => (Status::Pass, format!("{} present and run in CI ({})", s.label(), r.evidence.join(", "))),
                    Some(r) if r.present => (Status::Partial, format!("{} present ({}) but no CI workflow runs it", s.label(), r.evidence.join(", "))),
                    _ => (Status::Missing, format!("no {} found in the repository — `truent harden` can generate a starting point", s.label())),
                },
                Evidence::Chains => {
                    if chains.is_empty() {
                        (Status::Pass, "no known attack chain is completed by the findings".into())
                    } else {
                        (Status::Fail, chains.iter().map(|h| h.chain.id.to_string()).collect::<Vec<_>>().join(", "))
                    }
                }
                Evidence::Exposure => {
                    if likely == 0 {
                        (Status::Pass, "no finding rated LIKELY".into())
                    } else {
                        (Status::Fail, format!("{likely} finding(s) rated LIKELY — see `truent exposure`"))
                    }
                }
                Evidence::Manual(how) => (Status::Assess, how.to_string()),
            };
            *tally.entry(status.label().to_string()).or_default() += 1;
            items.push(ItemResult {
                name: it.name,
                status,
                detail,
            });
        }
        let worst = items.iter().map(|i| i.status).max().unwrap_or(Status::Pass);
        sections.push(SectionResult {
            number: sec.number,
            name: sec.name,
            items,
            worst,
        });
    }
    let ready = !sections
        .iter()
        .flat_map(|s| s.items.iter())
        .any(|i| matches!(i.status, Status::Fail | Status::Missing | Status::Partial));
    Report {
        sections,
        counts: tally,
        ready,
        accepted: inputs.accepted.clone(),
        expired: inputs.expired.clone(),
    }
}

impl Report {
    pub fn to_markdown(&self, target: &str) -> String {
        let mut s = String::new();
        s.push_str(&format!("# Release check — {target}\n\n"));
        s.push_str(&format!(
            "**Verdict: {}** — {}\n\n",
            if self.ready { "READY" } else { "NOT READY" },
            self.counts
                .iter()
                .map(|(k, v)| format!("{k} {v}"))
                .collect::<Vec<_>>()
                .join(" · ")
        ));
        s.push_str("PASS = an engine ran and found nothing · ACCEPTED = findings carried under a dated, owned risk acceptance · FAIL = findings · PARTIAL = the test exists but CI never runs it (or a check is undecided) · MISSING = nothing found (`truent harden` generates a start) · NEEDS-TOOL = pass a `truent probe` / `truent symbolic` report · ASSESS = a person must verify · N/A = nothing to apply to\n\n");
        if !self.accepted.is_empty() || !self.expired.is_empty() {
            s.push_str("## Risk acceptances\n\n");
            for a in &self.accepted {
                s.push_str(&format!(
                    "- **{}** {}:{} — accepted until {} by {}: {}\n",
                    a.finding.invariant_id,
                    a.finding.file,
                    a.finding.line,
                    a.acceptance.until,
                    a.acceptance.owner,
                    a.acceptance.reason
                ));
            }
            for e in &self.expired {
                s.push_str(&format!(
                    "- **EXPIRED** acceptance of `{}` ({}) on {} — its findings are open again\n",
                    e.id, e.owner, e.until
                ));
            }
            s.push('\n');
        }
        s.push_str("| # | Section | Worst | Pass | Fail | Partial | Missing | Assess |\n|---|---|---|---|---|---|---|---|\n");
        for sec in &self.sections {
            let c = |st: Status| sec.items.iter().filter(|i| i.status == st).count();
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                sec.number,
                sec.name,
                sec.worst.label(),
                c(Status::Pass) + c(Status::Accepted),
                c(Status::Fail),
                c(Status::Partial),
                c(Status::Missing),
                c(Status::Assess) + c(Status::NeedsProbe)
            ));
        }
        s.push('\n');
        for sec in &self.sections {
            s.push_str(&format!(
                "## {}. {} — {}\n\n",
                sec.number,
                sec.name,
                sec.worst.label()
            ));
            for i in &sec.items {
                let mark = match i.status {
                    Status::Pass | Status::Accepted => "[x]",
                    Status::NotApplicable => "[–]",
                    _ => "[ ]",
                };
                s.push_str(&format!(
                    "- {mark} **{}** — {}: {}\n",
                    i.name,
                    i.status.label(),
                    i.detail
                ));
            }
            s.push('\n');
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::{evaluate as signals_eval, RepoView};
    use truent_core::taxonomy::taxonomy_for;
    use truent_core::{Finding, Severity};

    #[test]
    fn every_detector_reference_is_real_and_every_section_is_present() {
        let mut nums: Vec<u8> = SECTIONS.iter().map(|s| s.number).collect();
        nums.sort();
        assert_eq!(nums, (1..=33).collect::<Vec<u8>>());
        for sec in SECTIONS {
            assert!(!sec.items.is_empty(), "section {} empty", sec.number);
            for it in sec.items {
                if let Evidence::Detectors(ids) | Evidence::Probe(ids) | Evidence::Tool(ids) =
                    it.evidence
                {
                    assert!(!ids.is_empty(), "{}: empty detector list", it.name);
                    for id in ids {
                        assert!(
                            taxonomy_for(id).is_some(),
                            "section {} `{}`: unknown detector {id}",
                            sec.number,
                            it.name
                        );
                    }
                }
                if let Evidence::Probe(ids) = it.evidence {
                    assert!(
                        ids.iter().all(|i| i.starts_with("rt_")),
                        "{}: probe items use rt_ detectors",
                        it.name
                    );
                }
            }
        }
    }

    #[test]
    fn every_native_detector_is_referenced_somewhere() {
        // A detector no checklist item uses is coverage the report cannot
        // show. Chain-agnostic and probe detectors count too.
        let mut used = std::collections::BTreeSet::new();
        for sec in SECTIONS {
            for it in sec.items {
                if let Evidence::Detectors(ids) | Evidence::Probe(ids) | Evidence::Tool(ids) =
                    it.evidence
                {
                    used.extend(ids.iter().copied());
                }
            }
        }
        let missing: Vec<&str> = truent_core::taxonomy::all()
            .iter()
            .map(|t| t.invariant_id)
            .filter(|id| !used.contains(id))
            .collect();
        assert!(
            missing.len() <= 20,
            "many detectors unreferenced by the checklist: {missing:?}"
        );
    }

    fn f(id: &str) -> Finding {
        Finding::new(
            id.into(),
            Severity::High,
            "x".into(),
            1,
            0,
            "m".into(),
            "s".into(),
        )
    }

    #[test]
    fn statuses_follow_evidence() {
        let files: Vec<String> = [
            "app.py",
            "tests/test_app.py",
            ".github/workflows/ci.yml",
            "requirements.txt",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let texts = vec![(
            ".github/workflows/ci.yml".to_string(),
            "run: pytest\n".to_string(),
        )];
        let sigs = signals_eval(&RepoView {
            files: &files,
            texts: &texts,
        });
        let scope = RepoScope::from_files(&files);
        assert!(scope.web && scope.deps && scope.ci && !scope.contracts);

        let r = evaluate(&[f("gen_sql_injection")], &sigs, &scope, &Inputs::default());
        let sast = r.sections.iter().find(|s| s.number == 3).unwrap();
        let sqli = sast
            .items
            .iter()
            .find(|i| i.name == "SQL injection detection")
            .unwrap();
        assert_eq!(sqli.status, Status::Fail);
        assert!(sqli.detail.contains("gen_sql_injection ×1"));
        let unit = r.sections[0]
            .items
            .iter()
            .find(|i| i.name == "Unit testing")
            .unwrap();
        assert_eq!(unit.status, Status::Pass);
        let load = r.sections.iter().find(|s| s.number == 18).unwrap();
        assert_eq!(load.items[0].status, Status::Missing);
        let contracts = r.sections.iter().find(|s| s.number == 15).unwrap();
        assert!(contracts
            .items
            .iter()
            .any(|i| i.status == Status::NotApplicable));
        let dast = r.sections.iter().find(|s| s.number == 4).unwrap();
        assert!(dast.items.iter().any(|i| i.status == Status::NeedsProbe));
        assert!(!r.ready);
    }

    #[test]
    fn probe_report_resolves_probe_items() {
        let files: Vec<String> = vec!["app.js".into()];
        let sigs = signals_eval(&RepoView {
            files: &files,
            texts: &[],
        });
        let scope = RepoScope::from_files(&files);
        let r = evaluate(
            &[f("rt_missing_hsts").proven()],
            &sigs,
            &scope,
            &Inputs {
                probe_loaded: true,
                ..Default::default()
            },
        );
        let dast = r.sections.iter().find(|s| s.number == 4).unwrap();
        let hdr = dast
            .items
            .iter()
            .find(|i| i.name == "Security-header testing")
            .unwrap();
        assert_eq!(hdr.status, Status::Fail);
        let ok = evaluate(
            &[],
            &sigs,
            &scope,
            &Inputs {
                probe_loaded: true,
                ..Default::default()
            },
        );
        let hdr = ok
            .sections
            .iter()
            .find(|s| s.number == 4)
            .unwrap()
            .items
            .iter()
            .find(|i| i.name == "Security-header testing")
            .unwrap();
        assert_eq!(hdr.status, Status::Pass);
    }

    #[test]
    fn accepted_findings_do_not_block_and_are_listed() {
        use crate::acceptance::{apply_on, parse};
        let files: Vec<String> = vec!["a.py".into()];
        let sigs = signals_eval(&RepoView {
            files: &files,
            texts: &[],
        });
        let scope = RepoScope::from_files(&files);
        let acc = parse("[[accept]]\nid = \"gen_sql_injection\"\nreason = \"legacy report endpoint, parameterised in Q4\"\nowner = \"@o\"\nuntil = \"2099-01-01\"\n").unwrap();
        let (open, accepted, expired) = apply_on(vec![f("gen_sql_injection")], &acc, (2026, 9, 12));
        assert!(open.is_empty());
        let r = evaluate(
            &open,
            &sigs,
            &scope,
            &Inputs {
                accepted,
                expired,
                ..Default::default()
            },
        );
        let sast = r.sections.iter().find(|s| s.number == 3).unwrap();
        let item = sast
            .items
            .iter()
            .find(|i| i.name == "SQL injection detection")
            .unwrap();
        assert_eq!(item.status, Status::Accepted);
        assert!(r.to_markdown("t").contains("## Risk acceptances"));
        let mut info = f("sca_install_script_dependency");
        info.severity = Severity::Info;
        let files2: Vec<String> = vec!["package-lock.json".into()];
        let r2 = evaluate(
            &[info],
            &sigs,
            &RepoScope::from_files(&files2),
            &Inputs::default(),
        );
        let dep = r2.sections.iter().find(|s| s.number == 5).unwrap();
        assert_eq!(
            dep.items
                .iter()
                .find(|i| i.name == "Malicious-package detection")
                .unwrap()
                .status,
            Status::Pass
        );
    }

    #[test]
    fn symbolic_report_resolves_the_symbolic_item() {
        let files: Vec<String> = vec!["src/V.sol".into()];
        let sigs = signals_eval(&RepoView {
            files: &files,
            texts: &[],
        });
        let scope = RepoScope::from_files(&files);
        let get = |r: &Report| {
            r.sections
                .iter()
                .find(|s| s.number == 15)
                .unwrap()
                .items
                .iter()
                .find(|i| i.name == "Symbolic-execution testing")
                .unwrap()
                .status
        };
        assert_eq!(
            get(&evaluate(&[], &sigs, &scope, &Inputs::default())),
            Status::NeedsProbe
        );
        assert_eq!(
            get(&evaluate(
                &[],
                &sigs,
                &scope,
                &Inputs {
                    symbolic_loaded: true,
                    ..Default::default()
                }
            )),
            Status::Pass
        );
        assert_eq!(
            get(&evaluate(
                &[f("evm_symbolic_counterexample").proven()],
                &sigs,
                &scope,
                &Inputs {
                    symbolic_loaded: true,
                    ..Default::default()
                }
            )),
            Status::Fail
        );
        assert_eq!(
            get(&evaluate(
                &[f("evm_symbolic_unresolved")],
                &sigs,
                &scope,
                &Inputs {
                    symbolic_loaded: true,
                    ..Default::default()
                }
            )),
            Status::Partial
        );
    }

    #[test]
    fn markdown_renders_every_section() {
        let files: Vec<String> = vec!["a.py".into()];
        let sigs = signals_eval(&RepoView {
            files: &files,
            texts: &[],
        });
        let md = evaluate(
            &[],
            &sigs,
            &RepoScope::from_files(&files),
            &Inputs::default(),
        )
        .to_markdown("t");
        for n in 1..=33 {
            assert!(
                md.contains(&format!("## {n}. ")),
                "section {n} missing from markdown"
            );
        }
        assert!(md.contains("NOT READY"));
    }
}
