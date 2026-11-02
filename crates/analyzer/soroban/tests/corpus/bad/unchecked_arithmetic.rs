// EXPECT: sor_unchecked_arithmetic
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn calculate_fee(env: Env, caller: Address, amount: i128, rate: i128) -> i128 {
        caller.require_auth();
        (amount * rate) / 10000
    }
}
