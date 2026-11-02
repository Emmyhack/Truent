// EXPECT: sor_storage_ttl_not_extended
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Registry;

#[contractimpl]
impl Registry {
    pub fn register(env: Env, user: Address, id: u32) {
        user.require_auth();
        env.storage().persistent().set(&user, &id);
    }
}
