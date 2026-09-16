// EXPECT: unauthorized_privileged_mutation
module demo::treasury;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::sui::SUI;

public struct Treasury has key { id: UID, balance: Balance<SUI> }

fun init(ctx: &mut TxContext) {
    transfer::share_object(Treasury { id: object::new(ctx), balance: balance::zero() });
}

/// Shared treasury, no capability, no sender check: anyone drains it.
public fun withdraw(t: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<SUI> {
    coin::take(&mut t.balance, amount, ctx)
}
