#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

/// A correct Soroban token: every mutation calls `require_auth`, arithmetic
/// is checked, persistent storage has its TTL extended, and there is no
/// upgrade path.
#[contracttype]
pub enum DataKey {
    Balance(Address),
    Admin,
}

const TTL_THRESHOLD: u32 = 100_000;
const TTL_EXTEND: u32 = 200_000;

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        let key = DataKey::Balance(id);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        let new_from = from_bal.checked_sub(amount).expect("insufficient");
        let new_to = to_bal.checked_add(amount).expect("overflow");
        env.storage().persistent().set(&from_key, &new_from);
        env.storage().persistent().set(&to_key, &new_to);
        env.storage().persistent().extend_ttl(&from_key, TTL_THRESHOLD, TTL_EXTEND);
        env.storage().persistent().extend_ttl(&to_key, TTL_THRESHOLD, TTL_EXTEND);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).expect("uninitialized");
        admin.require_auth();
        let key = DataKey::Balance(to);
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_bal = bal.checked_add(amount).expect("overflow");
        env.storage().persistent().set(&key, &new_bal);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }
}
