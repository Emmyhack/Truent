// EXPECT: move_admin_transfer_single_step
module demo::ownership {
    use std::signer;

    struct Config has key { admin: address }

    const E_NOT_ADMIN: u64 = 1;

    /// Gated correctly, but a typo in `new_admin` bricks the protocol.
    public entry fun set_admin(account: &signer, new_admin: address) acquires Config {
        let c = borrow_global_mut<Config>(@demo);
        assert!(signer::address_of(account) == c.admin, E_NOT_ADMIN);
        c.admin = new_admin;
    }
}
