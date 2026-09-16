// EXPECT: move_access_control_missing
// EXPECT: move_unbounded_parameter
module demo::config {
    struct Config has key { admin: address, fee_bps: u64 }

    /// Anyone can call this and the fee is written straight from the argument.
    public entry fun set_fee(_account: &signer, fee: u64) acquires Config {
        let c = borrow_global_mut<Config>(@demo);
        c.fee_bps = fee;
    }
}
