// EXPECT: sor_cross_contract_call_unauthorized
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Forwarder;

#[contractimpl]
impl Forwarder {
    pub fn forward_transfer(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
