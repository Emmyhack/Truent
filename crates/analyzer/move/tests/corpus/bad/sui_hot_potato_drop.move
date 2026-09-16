// EXPECT: move_hot_potato_has_abilities
module demo::flash;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::sui::SUI;

public struct Vault has key { id: UID, balance: Balance<SUI> }

/// The receipt can be dropped, so the borrower never has to repay.
public struct FlashReceipt has drop { amount: u64 }

public fun flash_borrow(v: &mut Vault, amount: u64, ctx: &mut TxContext): (Coin<SUI>, FlashReceipt) {
    (coin::take(&mut v.balance, amount, ctx), FlashReceipt { amount })
}

public fun flash_repay(v: &mut Vault, c: Coin<SUI>, receipt: FlashReceipt) {
    let FlashReceipt { amount } = receipt;
    assert!(c.value() >= amount, 1);
    v.balance.join(c.into_balance());
}
