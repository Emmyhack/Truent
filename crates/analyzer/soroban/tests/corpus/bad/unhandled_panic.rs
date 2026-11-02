// EXPECT: sor_unhandled_panic
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn get_value(env: Env, caller: Address) -> i128 {
        caller.require_auth();
        env.storage().instance().get(&caller).unwrap()
    }
}
