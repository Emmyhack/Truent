// EXPECT: move_capability_transferred_to_caller
module demo::caps;

public struct AdminCap has key { id: UID }

/// Anyone can mint themselves an AdminCap.
public fun claim_admin(recipient: address, ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, recipient);
}
