//! Soroban detector implementations.
//!
//! Unlike the raw-line-matching style used for some Solana/EVM detectors,
//! every detector here reads pre-parsed [`ContractFunction`] facts (see
//! [`crate::soroban_parser`]) — precise per-function structure is required
//! for several of these checks (initializer-guard ordering, external-call
//! vs. storage-write ordering) that a single-line grep cannot express.

use crate::soroban_model::ContractFunction;
use truent_core::{Finding, Severity};

/// Function-name substrings that indicate a privileged mutation requiring
/// `require_auth`.
const SENSITIVE_VERBS: &[&str] = &[
    "withdraw",
    "transfer",
    "pay",
    "mint",
    "burn",
    "set_admin",
    "set_owner",
    "remove",
    "upgrade",
];

/// Detects privileged functions with no `require_auth`/`require_auth_for_args`
/// call anywhere in their body.
pub fn detect_missing_require_auth(
    functions: &[ContractFunction],
    file_path: &str,
) -> Vec<Finding> {
    functions
        .iter()
        .filter(|f| !f.has_require_auth)
        .filter(|f| {
            let lower = f.name.to_lowercase();
            SENSITIVE_VERBS.iter().any(|v| lower.contains(v))
        })
        .map(|f| {
            Finding::new(
                "sor_missing_require_auth".to_string(),
                Severity::Critical,
                file_path.to_string(),
                f.line,
                0,
                format!(
                    "Function '{}' performs a privileged action with no require_auth() call reaching it",
                    f.name
                ),
                f.name.clone(),
            )
            .with_metadata("chain".to_string(), "soroban".to_string())
        })
        .collect()
}

/// Detects `update_current_contract_wasm` (contract upgrade) with no
/// `require_auth` guarding it.
pub fn detect_unprotected_upgrade(functions: &[ContractFunction], file_path: &str) -> Vec<Finding> {
    functions
        .iter()
        .filter(|f| f.upgrades_wasm && !f.has_require_auth)
        .map(|f| {
            Finding::new(
                "sor_unprotected_upgrade".to_string(),
                Severity::Critical,
                file_path.to_string(),
                f.line,
                0,
                format!(
                    "Function '{}' upgrades the contract's WASM with no require_auth() call guarding it",
                    f.name
                ),
                f.name.clone(),
            )
            .with_metadata("chain".to_string(), "soroban".to_string())
        })
        .collect()
}

/// Detects `initialize`/`init` functions with no guard against being called
/// more than once (re-initialization lets anyone reset the admin/config
/// after deploy).
pub fn detect_reinitialization(functions: &[ContractFunction], file_path: &str) -> Vec<Finding> {
    functions
        .iter()
        .filter(|f| f.is_initialize && !f.has_init_guard)
        .map(|f| {
            Finding::new(
                "sor_reinitialization".to_string(),
                Severity::High,
                file_path.to_string(),
                f.line,
                0,
                format!(
                    "Initializer '{}' has no storage check guarding against being called more than once",
                    f.name
                ),
                f.name.clone(),
            )
            .with_metadata("chain".to_string(), "soroban".to_string())
        })
        .collect()
}

/// Detects raw `+`/`-`/`*` arithmetic with no `checked_add`/`checked_sub`/
/// `checked_mul`/`checked_div` call anywhere in the same function. Rust
/// release builds do not trap on integer overflow by default, so unchecked
/// arithmetic in a Soroban contract can silently wrap.
pub fn detect_unchecked_arithmetic(
    functions: &[ContractFunction],
    file_path: &str,
) -> Vec<Finding> {
    functions
        .iter()
        .filter(|f| f.uses_unchecked_arithmetic)
        .map(|f| {
            Finding::new(
                "sor_unchecked_arithmetic".to_string(),
                Severity::High,
                file_path.to_string(),
                f.line,
                0,
                format!(
                    "Function '{}' performs raw arithmetic with no checked_add/checked_sub/checked_mul/checked_div \
                     call in the same function; Rust release builds do not trap on overflow by default",
                    f.name
                ),
                f.name.clone(),
            )
            .with_metadata("chain".to_string(), "soroban".to_string())
        })
        .collect()
}

/// Detects `persistent()` storage writes with no `extend_ttl`/`.bump(` call
/// anywhere in the function — persistent entries archive/expire, so a
/// contract that never extends TTL risks its own state becoming
/// inaccessible.
pub fn detect_storage_ttl_not_extended(
    functions: &[ContractFunction],
    file_path: &str,
) -> Vec<Finding> {
    functions
        .iter()
        .filter(|f| f.writes_persistent_storage && !f.extends_ttl)
        .map(|f| {
            Finding::new(
                "sor_storage_ttl_not_extended".to_string(),
                Severity::Medium,
                file_path.to_string(),
                f.line,
                0,
                format!(
                    "Function '{}' writes persistent storage but never extends its TTL, risking \
                     archival/expiry of this state",
                    f.name
                ),
                f.name.clone(),
            )
            .with_metadata("chain".to_string(), "soroban".to_string())
        })
        .collect()
}

/// Detects durable-looking state (balance/admin/owner/supply/price) written
/// to `temporary()` storage, which does not persist.
pub fn detect_temporary_storage_critical_state(
    functions: &[ContractFunction],
    file_path: &str,
) -> Vec<Finding> {
    functions
        .iter()
        .filter(|f| f.writes_temporary_storage_of_sensitive_state)
        .map(|f| {
            Finding::new(
                "sor_temporary_storage_critical_state".to_string(),
                Severity::Medium,
                file_path.to_string(),
                f.line,
                0,
                format!(
                    "Function '{}' writes state that looks durable (balance/admin/owner/supply/price) \
                     to temporary() storage, which does not survive",
                    f.name
                ),
                f.name.clone(),
            )
            .with_metadata("chain".to_string(), "soroban".to_string())
        })
        .collect()
}

/// Detects a cross-contract call (`invoke_contract`/`Client::new`) followed
/// by a later storage write in the same function — a
/// checks-effects-interactions violation shape that can enable reentrancy.
pub fn detect_reentrancy_external_call(
    functions: &[ContractFunction],
    file_path: &str,
) -> Vec<Finding> {
    functions
        .iter()
        .filter(|f| f.external_call_before_storage_write)
        .map(|f| {
            Finding::new(
                "sor_reentrancy_external_call".to_string(),
                Severity::High,
                file_path.to_string(),
                f.line,
                0,
                format!(
                    "Function '{}' writes storage after a cross-contract call, violating \
                     checks-effects-interactions and risking reentrancy",
                    f.name
                ),
                f.name.clone(),
            )
            .with_metadata("chain".to_string(), "soroban".to_string())
        })
        .collect()
}

/// Detects a price read from what looks like a single spot-price call with
/// no TWAP/multi-source corroboration. A thin-liquidity venue's spot price
/// can be pumped by one large order, letting an attacker over-borrow
/// against manipulated collateral — the pattern behind YieldBlox ($10.2M,
/// Feb 2026, Stellar/Soroban), where a thin USTRY/USDC market let an
/// attacker inflate a VWAP oracle's reported price.
pub fn detect_thin_liquidity_oracle_price(
    functions: &[ContractFunction],
    file_path: &str,
) -> Vec<Finding> {
    functions
        .iter()
        .filter(|f| f.uses_single_source_price_oracle)
        .map(|f| {
            Finding::new(
                "sor_thin_liquidity_oracle_price".to_string(),
                Severity::High,
                file_path.to_string(),
                f.line,
                0,
                format!(
                    "Function '{}' reads a price from a single spot-price call with no TWAP/\
                     multi-source corroboration anywhere in the function — a thin-liquidity \
                     venue's price can be pumped by a single large order, the exact pattern \
                     behind YieldBlox ($10.2M, Feb 2026, Stellar/Soroban)",
                    f.name
                ),
                f.name.clone(),
            )
            .with_metadata("chain".to_string(), "soroban".to_string())
        })
        .collect()
}

/// Detects `.unwrap()`/`.expect(` calls, which abort the whole invocation on
/// failure.
pub fn detect_unhandled_panic(functions: &[ContractFunction], file_path: &str) -> Vec<Finding> {
    functions
        .iter()
        .filter(|f| f.unwrap_count > 0)
        .map(|f| {
            Finding::new(
                "sor_unhandled_panic".to_string(),
                Severity::Low,
                file_path.to_string(),
                f.line,
                0,
                format!(
                    "Function '{}' calls a bare unwrap() {} time(s): a missing storage key or \
                     failed conversion aborts with no reason; use expect(\"why\") or return a \
                     #[contracterror] Result",
                    f.name, f.unwrap_count
                ),
                f.name.clone(),
            )
            .with_metadata("chain".to_string(), "soroban".to_string())
        })
        .collect()
}

/// Run every Soroban detector against pre-parsed contract functions.
pub fn detect_all(functions: &[ContractFunction], file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_missing_require_auth(functions, file_path));
    findings.extend(detect_unprotected_upgrade(functions, file_path));
    findings.extend(detect_reinitialization(functions, file_path));
    findings.extend(detect_unchecked_arithmetic(functions, file_path));
    findings.extend(detect_storage_ttl_not_extended(functions, file_path));
    findings.extend(detect_temporary_storage_critical_state(
        functions, file_path,
    ));
    findings.extend(detect_reentrancy_external_call(functions, file_path));
    findings.extend(detect_thin_liquidity_oracle_price(functions, file_path));
    findings.extend(detect_unhandled_panic(functions, file_path));

    findings.sort_by(|a, b| match b.severity.cmp(&a.severity) {
        std::cmp::Ordering::Equal => a.line.cmp(&b.line),
        other => other,
    });

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soroban_parser::parse_contract_functions;

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
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &new_balance);
        env.storage().temporary().set(&DataKey::Balance(to), &new_balance);
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    pub fn payout(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
        env.storage().persistent().set(&DataKey::Paid(to), &true);
    }
}
"#;

    #[test]
    fn flags_every_vulnerable_pattern() {
        let functions = parse_contract_functions(VULNERABLE).unwrap();
        let findings = detect_all(&functions, "vault.rs");
        let ids: std::collections::HashSet<_> =
            findings.iter().map(|f| f.invariant_id.as_str()).collect();

        assert!(ids.contains("sor_missing_require_auth"));
        assert!(ids.contains("sor_unprotected_upgrade"));
        assert!(ids.contains("sor_reinitialization"));
        assert!(ids.contains("sor_unchecked_arithmetic"));
        assert!(ids.contains("sor_storage_ttl_not_extended"));
        assert!(ids.contains("sor_temporary_storage_critical_state"));
        assert!(ids.contains("sor_reentrancy_external_call"));
        assert!(ids.contains("sor_unhandled_panic"));
    }

    #[test]
    fn flags_single_source_spot_price_read() {
        let source = r#"
#[contract]
pub struct LendingContract;

#[contractimpl]
impl LendingContract {
    pub fn borrow(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let price = pool_client.get_price(&env);
        let collateral_value = price * amount;
        env.storage().persistent().set(&DataKey::Debt(from), &collateral_value);
    }
}
"#;
        let functions = parse_contract_functions(source).unwrap();
        let findings = detect_thin_liquidity_oracle_price(&functions, "lending.rs");
        assert!(findings
            .iter()
            .any(|f| f.invariant_id == "sor_thin_liquidity_oracle_price"));
    }

    #[test]
    fn does_not_flag_twap_price_read() {
        let source = r#"
#[contract]
pub struct LendingContract;

#[contractimpl]
impl LendingContract {
    pub fn borrow(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let price = pool_client.get_price(&env);
        let twap_price = compute_time_weighted_average(&env, price);
        let collateral_value = twap_price * amount;
        env.storage().persistent().set(&DataKey::Debt(from), &collateral_value);
    }
}
"#;
        let functions = parse_contract_functions(source).unwrap();
        let findings = detect_thin_liquidity_oracle_price(&functions, "safe_lending.rs");
        assert!(!findings
            .iter()
            .any(|f| f.invariant_id == "sor_thin_liquidity_oracle_price"));
    }
}
