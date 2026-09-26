// truent-fuzz Section D skeleton — Aptos Move Prover specs + unit tests.
// FORMAT: adapt module/resource/function names; nothing here is engine output.
// Truent verifies Move statically only (`truent scan --chain move`); results of
// `aptos move prove` / `aptos move test` are EXTERNAL evidence.
//
// Layout: keep the Spec ID (GL-NN / SP-NN) in a comment on the first line of
// every spec block and test so PROPERTIES.md bookkeeping still applies.
module fizz_target::pool {
    use std::signer;

    const ENOT_ADMIN: u64 = 1;
    const EZERO_AMOUNT: u64 = 2;

    struct Pool has key {
        admin: address,
        total_assets: u64,
        total_shares: u64,
        fee_bps: u64,
    }

    public entry fun init(admin: &signer) {
        move_to(admin, Pool { admin: signer::address_of(admin), total_assets: 0, total_shares: 0, fee_bps: 0 });
    }

    public entry fun deposit(_user: &signer, pool_addr: address, amount: u64) acquires Pool {
        assert!(amount > 0, EZERO_AMOUNT);
        let p = borrow_global_mut<Pool>(pool_addr);
        p.total_assets = p.total_assets + amount;
        p.total_shares = p.total_shares + amount; // 1:1 for the skeleton
    }

    public entry fun set_fee(caller: &signer, pool_addr: address, fee_bps: u64) acquires Pool {
        let p = borrow_global_mut<Pool>(pool_addr);
        assert!(signer::address_of(caller) == p.admin, ENOT_ADMIN);
        p.fee_bps = fee_bps;
    }

    #[view]
    public fun total_assets(pool_addr: address): u64 acquires Pool { borrow_global<Pool>(pool_addr).total_assets }

    // ───────────────────────── Move Prover specs (aptos move prove) ─────────────────────────

    spec module {
        pragma verify = true;
        // GL-01 SHOULD-HOLD — shares are always backed: total_shares <= total_assets
        invariant forall a: address where exists<Pool>(a): global<Pool>(a).total_shares <= global<Pool>(a).total_assets;
        // GL-02 EXPLORATORY — fee bounded (state predicate; replace 10000 with the documented cap)
        invariant forall a: address where exists<Pool>(a): global<Pool>(a).fee_bps <= 10000;
    }

    spec deposit {
        // SP-01 SHOULD-HOLD — deposit increases total_assets by exactly `amount`
        aborts_if amount == 0;
        aborts_if !exists<Pool>(pool_addr);
        aborts_if global<Pool>(pool_addr).total_assets + amount > MAX_U64;
        ensures global<Pool>(pool_addr).total_assets == old(global<Pool>(pool_addr).total_assets) + amount;
        // VT-01 SHOULD-HOLD — total_assets is monotonic under deposit
        ensures global<Pool>(pool_addr).total_assets >= old(global<Pool>(pool_addr).total_assets);
    }

    spec set_fee {
        // ADV-01 SHOULD-HOLD — only the admin can set the fee
        aborts_if !exists<Pool>(pool_addr);
        aborts_if signer::address_of(caller) != global<Pool>(pool_addr).admin;
        ensures global<Pool>(pool_addr).fee_bps == fee_bps;
        // ST-02 SHOULD-HOLD — admin is unchanged by set_fee
        ensures global<Pool>(pool_addr).admin == old(global<Pool>(pool_addr).admin);
    }

    // ───────────────────────── Unit tests (aptos move test) ─────────────────────────

    #[test(admin = @0xA, user = @0xB)]
    // SP-01 SHOULD-HOLD — deposit credits exactly `amount` (executable twin of the spec)
    fun sp_01_deposit_credits_amount(admin: &signer, user: &signer) acquires Pool {
        init(admin);
        let pool_addr = signer::address_of(admin);
        let before = total_assets(pool_addr);
        deposit(user, pool_addr, 100);
        assert!(total_assets(pool_addr) == before + 100, 0);
    }

    #[test(admin = @0xA, mallory = @0xC)]
    #[expected_failure(abort_code = ENOT_ADMIN, location = Self)]
    // ADV-01 SHOULD-HOLD — non-admin cannot set the fee
    fun adv_01_non_admin_cannot_set_fee(admin: &signer, mallory: &signer) acquires Pool {
        init(admin);
        set_fee(mallory, signer::address_of(admin), 50);
    }
}
