// truent-fuzz Section D skeleton — Soroban property tests on soroban_sdk::testutils.
// FORMAT: adapt contract/client/function names; nothing here is engine output.
// Truent verifies Soroban statically only (`truent scan --chain soroban`);
// `cargo test` results are EXTERNAL evidence.
//
// Place as `src/fizz_properties.rs` with `#[cfg(test)] mod fizz_properties;` in lib.rs,
// or as `tests/fizz_properties.rs`. Add `proptest = "1"` under [dev-dependencies].
// Keep the Spec ID (GL-NN / SP-NN / ADV-NN / RT-NN) on the first line of every test.
#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env,
};

use crate::{Token, TokenClient};

// ───────────────────────── setup ─────────────────────────

fn setup() -> (Env, TokenClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(Token, ());
    let client = TokenClient::new(&env, &id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin, user)
}

// ───────────────────────── global invariant helpers ─────────────────────────

// GL-01 SHOULD-HOLD — sum of tracked balances == total_supply
fn gl_01_holds(client: &TokenClient, actors: &[Address]) -> bool {
    let sum: i128 = actors.iter().map(|a| client.balance(a)).sum();
    sum == client.total_supply()
}

// GL-02 EXPLORATORY — no balance is ever negative
fn gl_02_holds(client: &TokenClient, actors: &[Address]) -> bool {
    actors.iter().all(|a| client.balance(a) >= 0)
}

fn check_globals(client: &TokenClient, actors: &[Address], step: &str) {
    assert!(gl_01_holds(client, actors), "GL-01 violated after {step}");
    assert!(gl_02_holds(client, actors), "GL-02 violated after {step}");
}

// ───────────────────────── scripted sequences ─────────────────────────

#[test]
// SP-01 SHOULD-HOLD — mint credits exactly `amount` to the recipient
fn sp_01_mint_credits_amount() {
    let (_env, client, admin, user) = setup();
    let actors = [admin.clone(), user.clone()];
    let before = client.balance(&user);
    client.mint(&user, &1_000);
    assert_eq!(client.balance(&user), before + 1_000, "SP-01 violated");
    check_globals(&client, &actors, "mint");
}

#[test]
// GL-01 SHOULD-HOLD — conservation across a transfer sequence with ledger time passing
fn gl_01_conservation_over_sequence() {
    let (env, client, admin, user) = setup();
    let actors = [admin.clone(), user.clone()];
    client.mint(&user, &1_000);
    check_globals(&client, &actors, "mint");
    env.ledger().with_mut(|l| {
        l.timestamp += 3_600;
        l.sequence_number += 10;
    });
    client.transfer(&user, &admin, &400);
    check_globals(&client, &actors, "transfer");
}

#[test]
// ADV-02 SHOULD-HOLD — an unauthorised caller cannot mint (auth NOT mocked for the attempt)
fn adv_02_non_admin_cannot_mint() {
    let env = Env::default();
    let id = env.register(Token, ());
    let client = TokenClient::new(&env, &id);
    let admin = Address::generate(&env);
    let mallory = Address::generate(&env);
    env.mock_all_auths();
    client.initialize(&admin);
    env.set_auths(&[]); // drop blanket auth: the next call carries no authorisation
    assert!(client.try_mint(&mallory, &1).is_err(), "ADV-02 violated: mint succeeded without auth");
}

#[test]
// LIV-01 EXPLORATORY — every actor with a balance can move all of it
fn liv_01_every_holder_can_transfer_out() {
    let (_env, client, admin, user) = setup();
    client.mint(&user, &500);
    client.mint(&admin, &5);
    for holder in [&user, &admin] {
        let bal = client.balance(holder);
        if bal > 0 {
            assert!(client.try_transfer(holder, &user, &bal).is_ok(), "LIV-01 violated for a holder");
        }
    }
}

// ───────────────────────── input-shaped properties (proptest) ─────────────────────────

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

    // RT-01 EXPLORATORY — deposit then withdraw of the same amount never leaves the user richer
    #[test]
    fn rt_01_roundtrip_no_profit(amount in 1i128..1_000_000_000i128) {
        let (_env, client, _admin, user) = setup();
        client.mint(&user, &amount);
        let before = client.balance(&user);
        client.deposit(&user, &amount);
        client.withdraw(&user, &amount);
        proptest::prop_assert!(client.balance(&user) <= before, "RT-01 violated");
    }
}
