// EXPECT: move_randomness_public_function
module demo::dice;

use sui::random::{Self, Random};

/// Must be a private `entry fun`; as `public` the outcome can be inspected and aborted on.
public fun roll(r: &Random, ctx: &mut TxContext): u64 {
    let mut g = random::new_generator(r, ctx);
    g.generate_u64_in_range(1, 6)
}
