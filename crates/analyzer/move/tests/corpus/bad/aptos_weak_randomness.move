// EXPECT: move_weak_randomness
module demo::lottery {
    use aptos_framework::timestamp;

    struct Lottery has key { players: vector<address>, winner: address }

    /// The "random" index is the block timestamp modulo the player count.
    public entry fun pick_winner() acquires Lottery {
        let l = borrow_global_mut<Lottery>(@demo);
        let n = std::vector::length(&l.players);
        let random_index = timestamp::now_microseconds() % n;
        l.winner = *std::vector::borrow(&l.players, random_index);
    }
}
