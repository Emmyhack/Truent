// EXPECT: move_unbounded_parameter
module demo::fees;

public struct AdminCap has key { id: UID }
public struct Config has key { id: UID, fee_bps: u64 }

fun init(ctx: &mut TxContext) {
    transfer::share_object(Config { id: object::new(ctx), fee_bps: 30 });
}

/// Gated on the capability, but nothing stops a 100% fee.
public fun set_fee(_: &AdminCap, c: &mut Config, fee_bps: u64) {
    c.fee_bps = fee_bps;
}
