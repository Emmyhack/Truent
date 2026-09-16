/// A correct Aptos protocol: every write to global state at the module
/// address is gated on the stored admin, bounded, and delayed; user funds
/// are keyed by the caller's own address; prices come from an oracle with a
/// staleness check; randomness goes through the framework API from a private
/// entry function.
module vault_addr::vault {
    use std::signer;
    use std::error;
    use std::vector;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::timestamp;
    use aptos_framework::randomness;
    use aptos_framework::event;
    use pyth::pyth;
    use pyth::price_identifier;

    const E_NOT_ADMIN: u64 = 1;
    const E_FEE_TOO_HIGH: u64 = 2;
    const E_NOT_PENDING: u64 = 3;
    const E_TOO_EARLY: u64 = 4;
    const MAX_FEE_BPS: u64 = 1_000;
    const DELAY_SECONDS: u64 = 86_400;
    const MAX_AGE_SECONDS: u64 = 60;

    #[event]
    struct Deposited has drop, store { who: address, amount: u64 }

    struct Config has key {
        admin: address,
        pending_admin: address,
        fee_bps: u64,
        pending_fee_bps: u64,
        fee_effective_at: u64,
    }

    struct Vault has key { balance: Coin<AptosCoin>, total: u64 }

    struct UserAccount has key { balance: u64 }

    fun init_module(deployer: &signer) {
        let admin = signer::address_of(deployer);
        move_to(deployer, Config { admin, pending_admin: admin, fee_bps: 30, pending_fee_bps: 30, fee_effective_at: 0 });
        move_to(deployer, Vault { balance: coin::zero<AptosCoin>(), total: 0 });
    }

    #[view]
    public fun fee_bps(): u64 acquires Config {
        borrow_global<Config>(@vault_addr).fee_bps
    }

    /// Proposes a new fee; it becomes effective after the delay.
    public entry fun propose_fee(account: &signer, fee: u64) acquires Config {
        let c = borrow_global_mut<Config>(@vault_addr);
        assert!(signer::address_of(account) == c.admin, error::permission_denied(E_NOT_ADMIN));
        assert!(fee <= MAX_FEE_BPS, error::invalid_argument(E_FEE_TOO_HIGH));
        c.pending_fee_bps = fee;
        c.fee_effective_at = timestamp::now_seconds() + DELAY_SECONDS;
    }

    public entry fun apply_fee(account: &signer) acquires Config {
        let c = borrow_global_mut<Config>(@vault_addr);
        assert!(signer::address_of(account) == c.admin, error::permission_denied(E_NOT_ADMIN));
        assert!(timestamp::now_seconds() >= c.fee_effective_at, error::invalid_state(E_TOO_EARLY));
        c.fee_bps = c.pending_fee_bps;
    }

    /// Two-step admin transfer.
    public entry fun propose_admin(account: &signer, new_admin: address) acquires Config {
        let c = borrow_global_mut<Config>(@vault_addr);
        assert!(signer::address_of(account) == c.admin, error::permission_denied(E_NOT_ADMIN));
        c.pending_admin = new_admin;
    }

    public entry fun accept_admin(account: &signer) acquires Config {
        let c = borrow_global_mut<Config>(@vault_addr);
        assert!(signer::address_of(account) == c.pending_admin, error::permission_denied(E_NOT_PENDING));
        c.admin = c.pending_admin;
    }

    public entry fun deposit(account: &signer, amount: u64) acquires Vault, UserAccount {
        let who = signer::address_of(account);
        let c = coin::withdraw<AptosCoin>(account, amount);
        let v = borrow_global_mut<Vault>(@vault_addr);
        coin::merge(&mut v.balance, c);
        v.total = v.total + amount;
        if (!exists<UserAccount>(who)) {
            move_to(account, UserAccount { balance: 0 });
        };
        let u = borrow_global_mut<UserAccount>(who);
        u.balance = u.balance + amount;
        event::emit(Deposited { who, amount });
    }

    public entry fun withdraw(account: &signer, amount: u64) acquires Vault, UserAccount {
        let who = signer::address_of(account);
        let u = borrow_global_mut<UserAccount>(who);
        assert!(u.balance >= amount, error::invalid_argument(E_FEE_TOO_HIGH));
        u.balance = u.balance - amount;
        let v = borrow_global_mut<Vault>(@vault_addr);
        v.total = v.total - amount;
        coin::deposit(who, coin::extract(&mut v.balance, amount));
    }

    /// Price from Pyth with an explicit maximum age.
    public fun apt_usd_price(): u64 {
        let id = price_identifier::from_byte_vec(x"03ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d5");
        let p = pyth::get_price_no_older_than(id, MAX_AGE_SECONDS);
        pyth::price_value(&p)
    }

    /// Multiply before dividing so the fee rounds once.
    public fun fee_for(amount: u64): u64 acquires Config {
        let c = borrow_global<Config>(@vault_addr);
        (amount * c.fee_bps) / 10_000
    }

    #[randomness]
    entry fun draw(account: &signer) {
        let _winner_index = randomness::u64_range(0, 10);
        let _ = account;
    }

    public fun sum(v: &vector<u64>): u64 {
        let total = 0u64;
        for (i in 0..vector::length(v)) {
            total = total + *vector::borrow(v, i);
        };
        total
    }

    #[test_only]
    public fun init_for_test(deployer: &signer) { init_module(deployer); }

    #[test(admin = @vault_addr)]
    fun test_fee(admin: &signer) acquires Config {
        init_module(admin);
        propose_fee(admin, 50);
    }
}
