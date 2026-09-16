// EXPECT: move_oracle_spot_price
module demo::pricing {
    struct Pool has key { reserve_a: u64, reserve_b: u64 }

    /// The price is the live reserve ratio; a flash loan moves both.
    public fun spot_price(): u64 acquires Pool {
        let p = borrow_global<Pool>(@demo);
        (p.reserve_b * 1_000_000) / p.reserve_a
    }
}
