// EXPECT: sor_event_without_version
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct EventContract;

#[contractimpl]
impl EventContract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let balance: i128 = env.storage().persistent().get(&from).unwrap_or(0);
        let new_bal = balance.checked_sub(amount).expect("insufficient");
        env.storage().persistent().set(&from, &new_bal);
        env.storage().persistent().extend_ttl(&from, 100, 200);
        env.events().publish((symbol_short!("transfer"), from, to), amount);
    }
}
