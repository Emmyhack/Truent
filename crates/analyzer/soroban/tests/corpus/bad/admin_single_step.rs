// EXPECT: sor_admin_single_step_transfer
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct SingleStepAdmin;

#[contractimpl]
impl SingleStepAdmin {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn set_admin(env: Env, new_admin: Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).expect("no admin");
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }
}
