// EXPECT: move_capability_transferred_to_caller
module demo::caps {
    struct AdminCap has key { dummy_field: bool }

    /// Any signer can give themselves the admin resource.
    public entry fun become_admin(account: &signer) {
        move_to(account, AdminCap { dummy_field: false });
    }
}
