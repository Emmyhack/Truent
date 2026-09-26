// truent-fuzz Section D skeleton — Sui Move unit tests with test_scenario.
// FORMAT: adapt package/module/function names; nothing here is engine output.
// Truent verifies Move statically only (`truent scan --chain move`); results of
// `sui move test` are EXTERNAL evidence. Sui has no Move Prover in the standard
// toolchain, so every property is an executable test.
//
// Keep the Spec ID (GL-NN / SP-NN / ADV-NN) in a comment on the first line of
// every test so PROPERTIES.md bookkeeping still applies.
#[test_only]
module fizz_target::fizz_properties {
    use sui::test_scenario as ts;
    use sui::coin;
    use sui::sui::SUI;
    use fizz_target::pool::{Self, Pool, AdminCap};

    const ADMIN: address = @0xA;
    const USER: address = @0xB;
    const MALLORY: address = @0xC;

    // GL-01 SHOULD-HOLD — pool reserve equals total_shares while price is 1:1
    fun gl_01_holds(p: &Pool): bool {
        pool::reserve_value(p) == pool::total_shares(p)
    }

    #[test]
    // SP-01 SHOULD-HOLD — deposit credits exactly `amount`; GL-01 holds after every step
    fun sp_01_deposit_credits_amount() {
        let mut s = ts::begin(ADMIN);
        pool::init_for_testing(ts::ctx(&mut s));

        ts::next_tx(&mut s, USER);
        {
            let mut p = ts::take_shared<Pool>(&s);
            let before = pool::reserve_value(&p);
            let c = coin::mint_for_testing<SUI>(100, ts::ctx(&mut s));
            pool::deposit(&mut p, c, ts::ctx(&mut s));
            assert!(pool::reserve_value(&p) == before + 100, 0);
            assert!(gl_01_holds(&p), 1);
            ts::return_shared(p);
        };
        ts::end(s);
    }

    #[test]
    // RT-01 EXPLORATORY — deposit then withdraw of the same amount never leaves the user richer
    fun rt_01_roundtrip_no_profit() {
        let mut s = ts::begin(ADMIN);
        pool::init_for_testing(ts::ctx(&mut s));

        ts::next_tx(&mut s, USER);
        {
            let mut p = ts::take_shared<Pool>(&s);
            let c = coin::mint_for_testing<SUI>(1_000, ts::ctx(&mut s));
            let shares = pool::deposit(&mut p, c, ts::ctx(&mut s));
            let out = pool::withdraw(&mut p, shares, ts::ctx(&mut s));
            assert!(coin::value(&out) <= 1_000, 0);
            assert!(gl_01_holds(&p), 1);
            coin::burn_for_testing(out);
            ts::return_shared(p);
        };
        ts::end(s);
    }

    #[test]
    #[expected_failure(abort_code = pool::ENotAdmin)]
    // ADV-01 SHOULD-HOLD — a caller without AdminCap cannot set the fee
    fun adv_01_non_admin_cannot_set_fee() {
        let mut s = ts::begin(ADMIN);
        pool::init_for_testing(ts::ctx(&mut s));

        ts::next_tx(&mut s, MALLORY);
        {
            let mut p = ts::take_shared<Pool>(&s);
            // Mallory has no AdminCap; the unguarded path must abort.
            pool::set_fee_unchecked(&mut p, 50, ts::ctx(&mut s));
            ts::return_shared(p);
        };
        ts::end(s);
    }

    #[test]
    // ST-02 SHOULD-HOLD — AdminCap stays with ADMIN across user activity
    fun st_02_admin_cap_stable() {
        let mut s = ts::begin(ADMIN);
        pool::init_for_testing(ts::ctx(&mut s));
        ts::next_tx(&mut s, USER);
        assert!(ts::has_most_recent_for_address<AdminCap>(ADMIN), 0);
        assert!(!ts::has_most_recent_for_address<AdminCap>(USER), 1);
        ts::end(s);
    }
}
