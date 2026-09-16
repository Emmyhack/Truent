// EXPECT: move_divide_before_multiply
module demo::math;

/// Divides first, then multiplies: the truncation is scaled up.
public fun share_of(amount: u64, total: u64, supply: u64): u64 {
    (amount / total) * supply
}
