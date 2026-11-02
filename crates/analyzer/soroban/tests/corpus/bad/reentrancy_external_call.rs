// EXPECT: sor_reentrancy_external_call
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bridge;

#[contractimpl]
impl Bridge {
    pub fn bridge_out(env: Env, caller: Address, target: Address, amount: i128) {
        caller.require_auth();
        env.invoke_contract::<()>(&target, &Symbol::new(&env, "deposit"), (amount,));
        let balance: i128 = env.storage().persistent().get(&caller).unwrap_or(0);
        env.storage().persistent().set(&caller, &(balance - amount));
        env.storage().persistent().extend_ttl(&caller, 100, 200);
    }
}
