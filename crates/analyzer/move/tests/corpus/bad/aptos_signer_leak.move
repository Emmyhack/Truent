// EXPECT: move_privileged_handle_exposed
module demo::resource_account {
    use aptos_framework::account::{Self, SignerCapability};

    struct Config has key { signer_cap: SignerCapability }

    /// Anyone can obtain the protocol's own signer.
    public fun get_resource_signer(): signer acquires Config {
        let c = borrow_global<Config>(@demo);
        account::create_signer_with_capability(&c.signer_cap)
    }
}
