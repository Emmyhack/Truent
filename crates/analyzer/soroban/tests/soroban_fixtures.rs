use truent_analyzer_soroban::run_all_detectors;

/// A contract that follows every Soroban best practice this analyzer
/// checks for: `require_auth` on every privileged function, an init guard,
/// checked arithmetic, and TTL extension on persistent writes. None of the
/// eight chain-specific detectors, nor the shared
/// `unauthorized_privileged_mutation` rule, should fire against it.
const WELL_GUARDED_CONTRACT: &str = r#"
#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn withdraw(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(from.clone()))
            .unwrap_or(0);
        let new_balance = balance.checked_sub(amount).expect("insufficient balance");
        env.storage()
            .persistent()
            .set(&DataKey::Balance(from.clone()), &new_balance);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Balance(from), 100, 200);
    }
}
"#;

#[test]
fn well_guarded_contract_has_no_critical_or_high_findings() {
    let findings = run_all_detectors(WELL_GUARDED_CONTRACT, "token.rs");
    let severe: Vec<_> = findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                truent_core::Severity::Critical | truent_core::Severity::High
            )
        })
        .collect();
    assert!(
        severe.is_empty(),
        "expected no critical/high findings, got: {:?}",
        severe
    );
}

#[test]
fn missing_require_auth_is_flagged_on_privileged_function() {
    let source = r#"
#[contract]
pub struct VaultContract;

#[contractimpl]
impl VaultContract {
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&DataKey::Balance(to), &amount);
    }
}
"#;
    let findings = run_all_detectors(source, "vault.rs");
    assert!(findings
        .iter()
        .any(|f| f.invariant_id == "sor_missing_require_auth"));
}

#[test]
fn state_write_before_external_call_is_not_flagged_as_reentrancy() {
    // Checks-effects-interactions done correctly: storage write happens
    // before the cross-contract call, not after.
    let source = r#"
#[contract]
pub struct PayoutContract;

#[contractimpl]
impl PayoutContract {
    pub fn payout(env: Env, token: Address, to: Address, amount: i128) {
        env.storage().persistent().set(&DataKey::Paid(to.clone()), &true);
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
"#;
    let findings = run_all_detectors(source, "payout.rs");
    assert!(!findings
        .iter()
        .any(|f| f.invariant_id == "sor_reentrancy_external_call"));
}

#[test]
fn ttl_extension_suppresses_storage_ttl_finding() {
    let source = r#"
#[contract]
pub struct VaultContract;

#[contractimpl]
impl VaultContract {
    pub fn deposit(env: Env, admin: Address, to: Address, amount: i128) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &amount);
        env.storage().persistent().extend_ttl(&DataKey::Balance(to), 100, 200);
    }
}
"#;
    let findings = run_all_detectors(source, "vault.rs");
    assert!(!findings
        .iter()
        .any(|f| f.invariant_id == "sor_storage_ttl_not_extended"));
}

#[test]
fn checked_arithmetic_suppresses_unchecked_arithmetic_finding() {
    let source = r#"
#[contract]
pub struct VaultContract;

#[contractimpl]
impl VaultContract {
    pub fn deposit(env: Env, admin: Address, to: Address, amount: i128) {
        admin.require_auth();
        let balance: i128 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        let new_balance = balance.checked_add(amount).unwrap();
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &new_balance);
        env.storage().persistent().extend_ttl(&DataKey::Balance(to), 100, 200);
    }
}
"#;
    let findings = run_all_detectors(source, "vault.rs");
    assert!(!findings
        .iter()
        .any(|f| f.invariant_id == "sor_unchecked_arithmetic"));
}

#[test]
fn saturating_arithmetic_suppresses_unchecked_arithmetic_finding() {
    let source = r#"
#[contract]
pub struct VaultContract;

#[contractimpl]
impl VaultContract {
    pub fn credit(env: Env, admin: Address, to: Address, amount: i128) {
        admin.require_auth();
        let balance: i128 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        let new_balance = balance.saturating_add(amount);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &new_balance);
        env.storage().persistent().extend_ttl(&DataKey::Balance(to), 100, 200);
    }
}
"#;
    let findings = run_all_detectors(source, "vault.rs");
    assert!(!findings
        .iter()
        .any(|f| f.invariant_id == "sor_unchecked_arithmetic"));
}
