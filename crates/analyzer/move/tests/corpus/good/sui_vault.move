/// A correct Sui protocol: the shared vault is only reconfigured by the
/// holder of a capability that carries no `store`; user balances are keyed
/// by sender; the flash-loan receipt has no abilities; randomness is consumed
/// from a private entry function; the price feed is checked for age.
module vault::vault;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin, TreasuryCap};
use sui::sui::SUI;
use sui::table::{Self, Table};
use sui::clock::Clock;
use sui::event;
use sui::random::{Self, Random};
use pyth::price_info::PriceInfoObject;
use pyth::pyth;

const E_FEE_TOO_HIGH: u64 = 1;
const E_INSUFFICIENT: u64 = 2;
const E_NOT_PENDING: u64 = 3;
const E_TOO_EARLY: u64 = 4;
const MAX_FEE_BPS: u64 = 1_000;
const DELAY_MS: u64 = 86_400_000;
const MAX_AGE_SECONDS: u64 = 60;

public struct VAULT has drop {}

public struct AdminCap has key { id: UID }

public struct Vault has key {
    id: UID,
    balance: Balance<SUI>,
    balances: Table<address, u64>,
    fee_bps: u64,
    pending_fee_bps: u64,
    fee_effective_at: u64,
    admin: address,
    pending_admin: address,
}

/// Hot potato: no abilities, so `repay` is the only way to get rid of it.
public struct FlashReceipt { amount: u64 }

public struct Deposited has copy, drop { who: address, amount: u64 }

fun init(otw: VAULT, ctx: &mut TxContext) {
    let (treasury, metadata) = coin::create_currency(otw, 6, b"VLT", b"Vault", b"", option::none(), ctx);
    transfer::public_freeze_object(metadata);
    transfer::public_transfer(treasury, ctx.sender());
    transfer::transfer(AdminCap { id: object::new(ctx) }, ctx.sender());
    transfer::share_object(Vault {
        id: object::new(ctx),
        balance: balance::zero(),
        balances: table::new(ctx),
        fee_bps: 30,
        pending_fee_bps: 30,
        fee_effective_at: 0,
        admin: ctx.sender(),
        pending_admin: ctx.sender(),
    });
}

public fun propose_fee(_: &AdminCap, v: &mut Vault, fee: u64, clock: &Clock) {
    assert!(fee <= MAX_FEE_BPS, E_FEE_TOO_HIGH);
    v.pending_fee_bps = fee;
    v.fee_effective_at = clock.timestamp_ms() + DELAY_MS;
}

public fun apply_fee(_: &AdminCap, v: &mut Vault, clock: &Clock) {
    assert!(clock.timestamp_ms() >= v.fee_effective_at, E_TOO_EARLY);
    v.fee_bps = v.pending_fee_bps;
}

public fun propose_admin(_: &AdminCap, v: &mut Vault, new_admin: address) {
    v.pending_admin = new_admin;
}

public fun accept_admin(v: &mut Vault, ctx: &TxContext) {
    assert!(ctx.sender() == v.pending_admin, E_NOT_PENDING);
    v.admin = v.pending_admin;
}

public fun deposit(v: &mut Vault, c: Coin<SUI>, ctx: &TxContext) {
    let who = ctx.sender();
    let amount = c.value();
    v.balance.join(c.into_balance());
    if (!v.balances.contains(who)) {
        v.balances.add(who, 0);
    };
    let b = v.balances.borrow_mut(who);
    *b = *b + amount;
    event::emit(Deposited { who, amount });
}

public fun withdraw(v: &mut Vault, amount: u64, ctx: &mut TxContext): Coin<SUI> {
    let who = ctx.sender();
    let b = v.balances.borrow_mut(who);
    assert!(*b >= amount, E_INSUFFICIENT);
    *b = *b - amount;
    coin::take(&mut v.balance, amount, ctx)
}

public fun flash_borrow(v: &mut Vault, amount: u64, ctx: &mut TxContext): (Coin<SUI>, FlashReceipt) {
    (coin::take(&mut v.balance, amount, ctx), FlashReceipt { amount })
}

public fun flash_repay(v: &mut Vault, c: Coin<SUI>, receipt: FlashReceipt) {
    let FlashReceipt { amount } = receipt;
    assert!(c.value() >= amount, E_INSUFFICIENT);
    v.balance.join(c.into_balance());
}

public fun mint(cap: &mut TreasuryCap<VAULT>, amount: u64, ctx: &mut TxContext): Coin<VAULT> {
    coin::mint(cap, amount, ctx)
}

/// Fee rounds once: multiply, then divide.
public fun fee_for(v: &Vault, amount: u64): u64 {
    (amount * v.fee_bps) / 10_000
}

public fun sui_usd_price(price_info: &PriceInfoObject, clock: &Clock): u64 {
    let p = pyth::get_price_no_older_than(price_info, clock, MAX_AGE_SECONDS);
    pyth::price_value(&p)
}

entry fun draw(r: &Random, ctx: &mut TxContext) {
    let mut g = random::new_generator(r, ctx);
    let _winner = g.generate_u64_in_range(0, 10);
}

#[test_only]
public fun init_for_test(ctx: &mut TxContext) { init(VAULT {}, ctx); }

#[test]
fun test_fee_math() { assert!((100 * 30) / 10_000 == 0); }
