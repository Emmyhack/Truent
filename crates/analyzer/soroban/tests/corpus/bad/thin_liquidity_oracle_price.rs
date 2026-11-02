// EXPECT: sor_thin_liquidity_oracle_price
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct LendingPool;

#[contractimpl]
impl LendingPool {
    pub fn borrow(env: Env, caller: Address, oracle: Address) {
        caller.require_auth();
        let price = oracle.get_price();
    }
}
