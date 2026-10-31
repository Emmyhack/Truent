#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

/// A correct Soroban contract exercising checked and saturating arithmetic.
/// Confirms that using checked_add, checked_sub, checked_mul, checked_div,
/// saturating_add, saturating_sub, and saturating_mul produces zero
/// `sor_unchecked_arithmetic` false positives.
#[contracttype]
pub enum DataKey {
    Balance(Address),
    Admin,
    Points(Address),
}

const TTL_THRESHOLD: u32 = 100_000;
const TTL_EXTEND: u32 = 200_000;

#[contract]
pub struct SafeVault;

#[contractimpl]
impl SafeVault {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn deposit_checked(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.checked_add(amount).expect("overflow");
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }

    pub fn withdraw_checked(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.checked_sub(amount).expect("underflow");
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }

    pub fn multiply_yield_checked(env: Env, user: Address, factor: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.checked_mul(factor).expect("overflow");
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }

    pub fn divide_shares_checked(env: Env, user: Address, divisor: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.checked_div(divisor).expect("division by zero");
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }

    pub fn credit_saturating(env: Env, user: Address, reward: i128) {
        user.require_auth();
        let key = DataKey::Points(user.clone());
        let points: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = points.saturating_add(reward);
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }

    pub fn debit_saturating(env: Env, user: Address, penalty: i128) {
        user.require_auth();
        let key = DataKey::Points(user.clone());
        let points: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = points.saturating_sub(penalty);
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }

    pub fn scale_saturating(env: Env, user: Address, multiplier: i128) {
        user.require_auth();
        let key = DataKey::Points(user.clone());
        let points: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = points.saturating_mul(multiplier);
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }
}
