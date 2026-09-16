// EXPECT: move_capability_with_store
module demo::caps;

/// `store` lets this be wrapped and transferred by anyone holding it.
public struct AdminCap has key, store { id: UID }

fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, ctx.sender());
}
