// EXPECT: move_manual_overflow_check
module demo::fixed_point;

/// A hand-rolled shift-and-mask overflow check (the Cetus pattern).
public fun checked_shlw(n: u256): (u256, bool) {
    let mask = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff << 192;
    if (n > mask) {
        (0, true)
    } else {
        (n << 64, false)
    }
}
