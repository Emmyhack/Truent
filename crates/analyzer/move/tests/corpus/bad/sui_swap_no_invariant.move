// EXPECT: move_liquidity_conservation
module demo::amm;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};

public struct Pool<phantom X, phantom Y> has key { id: UID, reserve_x: Balance<X>, reserve_y: Balance<Y> }

/// Takes from one side and puts into the other with the amount computed
/// elsewhere; nothing checks x*y afterwards.
public fun swap_x_for_y<X, Y>(pool: &mut Pool<X, Y>, input: Coin<X>, amount_out: u64, ctx: &mut TxContext): Coin<Y> {
    pool.reserve_x.join(input.into_balance());
    coin::take(&mut pool.reserve_y, amount_out, ctx)
}
