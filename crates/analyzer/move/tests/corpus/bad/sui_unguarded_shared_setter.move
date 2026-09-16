// EXPECT: move_access_control_missing
module demo::pool;

use sui::balance::{Self, Balance};
use sui::sui::SUI;

public struct Pool has key { id: UID, balance: Balance<SUI>, paused: bool }

fun init(ctx: &mut TxContext) {
    transfer::share_object(Pool { id: object::new(ctx), balance: balance::zero(), paused: false });
}

/// The pool is shared, so any transaction can pass it in and flip the flag.
public fun set_paused(p: &mut Pool, paused: bool) {
    p.paused = paused;
}
