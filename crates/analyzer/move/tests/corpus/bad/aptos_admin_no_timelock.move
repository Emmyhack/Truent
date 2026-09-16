// EXPECT: move_admin_no_timelock
module demo::governed {
    use std::signer;

    struct Config has key { admin: address, oracle: address }

    const E_NOT_ADMIN: u64 = 1;

    /// Gated on the admin, but the new oracle takes effect immediately.
    public entry fun set_oracle(account: &signer, oracle: address) acquires Config {
        let c = borrow_global_mut<Config>(@demo);
        assert!(signer::address_of(account) == c.admin, E_NOT_ADMIN);
        c.oracle = oracle;
    }
}
