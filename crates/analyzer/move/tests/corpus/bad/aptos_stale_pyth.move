// EXPECT: move_oracle_stale_price
module demo::oracle {
    use pyth::pyth;
    use pyth::price_identifier;

    /// `get_price_unsafe` returns whatever was last published, however old.
    public fun apt_usd(): u64 {
        let id = price_identifier::from_byte_vec(x"03ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d5");
        let p = pyth::get_price_unsafe(id);
        pyth::price_value(&p)
    }
}
