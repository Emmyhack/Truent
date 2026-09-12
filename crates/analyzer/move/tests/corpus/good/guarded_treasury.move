module demo::treasury {
    use std::signer;

    /// A correct Move treasury: every mutation takes a `&signer` and asserts
    /// it is the admin; arithmetic relies on Move's native abort-on-overflow.
    struct Treasury has key {
        admin: address,
        balance: u64,
    }

    const E_NOT_ADMIN: u64 = 1;
    const E_INSUFFICIENT: u64 = 2;

    public entry fun initialize(account: &signer) {
        move_to(account, Treasury { admin: signer::address_of(account), balance: 0 });
    }

    public entry fun deposit(account: &signer, amount: u64) acquires Treasury {
        let t = borrow_global_mut<Treasury>(@demo);
        assert!(signer::address_of(account) == t.admin, E_NOT_ADMIN);
        t.balance = t.balance + amount;
    }

    public entry fun withdraw(account: &signer, amount: u64) acquires Treasury {
        let t = borrow_global_mut<Treasury>(@demo);
        assert!(signer::address_of(account) == t.admin, E_NOT_ADMIN);
        assert!(t.balance >= amount, E_INSUFFICIENT);
        t.balance = t.balance - amount;
    }

    public fun balance(): u64 acquires Treasury {
        borrow_global<Treasury>(@demo).balance
    }
}
