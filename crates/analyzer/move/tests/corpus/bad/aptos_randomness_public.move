// EXPECT: move_randomness_public_function
module demo::dice {
    use aptos_framework::randomness;

    /// A public function using randomness can be composed with a check-and-abort.
    #[randomness]
    public entry fun roll(_account: &signer): u64 {
        randomness::u64_range(1, 7)
    }
}
