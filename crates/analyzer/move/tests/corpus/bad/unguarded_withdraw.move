// EXPECT: move_access_control_missing
module demo::treasury {
    struct Treasury has key {
        admin: address,
        balance: u64,
    }

    public entry fun withdraw(amount: u64) acquires Treasury {
        let t = borrow_global_mut<Treasury>(@demo);
        t.balance = t.balance - amount;
    }
}
