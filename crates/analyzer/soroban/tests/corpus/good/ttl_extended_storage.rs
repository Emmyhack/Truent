#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

/// A correct Soroban contract demonstrating persistent storage writes
/// accompanied by explicit TTL extensions. Exercises both single-key and
/// multi-key state writes where every persistent write is followed by an
/// `extend_ttl` call, ensuring zero `sor_storage_ttl_not_extended` findings.
#[contracttype]
pub enum StorageKey {
    Config,
    UserRecord(Address),
    Counter(Address),
}

const TTL_THRESHOLD: u32 = 100_000;
const TTL_EXTEND: u32 = 200_000;

#[contract]
pub struct TtlExtendedContract;

#[contractimpl]
impl TtlExtendedContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&StorageKey::Config) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&StorageKey::Config, &admin);
    }

    pub fn set_user_record(env: Env, user: Address, score: i128) {
        user.require_auth();
        let key = StorageKey::UserRecord(user.clone());
        env.storage().persistent().set(&key, &score);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }

    pub fn increment_counter(env: Env, user: Address) {
        user.require_auth();
        let key = StorageKey::Counter(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.checked_add(1).expect("overflow");
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }

    pub fn clear_record(env: Env, user: Address) {
        user.require_auth();
        let key = StorageKey::UserRecord(user.clone());
        env.storage().persistent().remove(&key);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
    }
}
