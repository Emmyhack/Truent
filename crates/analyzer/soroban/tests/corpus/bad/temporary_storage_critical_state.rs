// EXPECT: sor_temporary_storage_critical_state
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn set_admin(env: Env, new_admin: Address) {
        new_admin.require_auth();
        env.storage().temporary().set(&DataKey::Admin, &new_admin);
    }
}
