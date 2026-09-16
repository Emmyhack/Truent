// EXPECT: move_unbounded_vector_growth
module demo::registry;

public struct Registry has key { id: UID, members: vector<address> }

fun init(ctx: &mut TxContext) {
    transfer::share_object(Registry { id: object::new(ctx), members: vector[] });
}

/// Anyone can append, forever.
public fun join(r: &mut Registry, who: address) {
    r.members.push_back(who);
}

/// ...and every payout walks the whole list.
public fun count(r: &Registry): u64 {
    let mut i = 0;
    let mut n = 0;
    while (i < r.members.length()) { n = n + 1; i = i + 1; };
    n
}
