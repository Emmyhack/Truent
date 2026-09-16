// EXPECT: move_unconstrained_type_argument
module demo::deposits;

use sui::coin::{Self, Coin};
use sui::balance::{Self, Balance};

public struct Ledger has key { id: UID, total_deposited: u64 }

/// Any coin type is accepted and its face value credited to one ledger.
public fun deposit<T>(ledger: &mut Ledger, c: Coin<T>, ctx: &mut TxContext) {
    let amount = coin::value(&c);
    ledger.total_deposited = ledger.total_deposited + amount;
    transfer::public_transfer(c, ctx.sender());
}
