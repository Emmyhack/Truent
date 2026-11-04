//! Parsed-fact model for Soroban `#[contractimpl]` functions.
//!
//! [`crate::soroban_parser::parse_contract_functions`] populates this from
//! real `syn`-parsed source; [`crate::detectors`] and
//! [`crate::semantic_model`] read it to produce findings without
//! re-parsing.

/// One `pub fn` found inside a `#[contractimpl]` block, with the facts
/// extracted from its body.
#[derive(Debug, Clone)]
pub struct ContractFunction {
    /// Function name.
    pub name: String,
    /// 1-indexed source line of the `fn` declaration.
    pub line: usize,
    /// Whether the body calls `require_auth`/`require_auth_for_args` on any
    /// receiver.
    pub has_require_auth: bool,
    /// Whether this function is a contract initializer (`initialize`/`init`).
    pub is_initialize: bool,
    /// For initializers only: whether a storage `.has(` check appears
    /// before the first `.set(`, guarding against re-initialization.
    pub has_init_guard: bool,
    /// Whether the body calls `update_current_contract_wasm` (a contract
    /// upgrade).
    pub upgrades_wasm: bool,
    /// Whether the body performs raw `+`/`-`/`*` arithmetic without any
    /// `checked_add`/`checked_sub`/`checked_mul`/`checked_div` call
    /// anywhere in the same function.
    pub uses_unchecked_arithmetic: bool,
    /// Count of `.unwrap()`/`.expect(` calls in the body.
    pub unwrap_count: usize,
    /// Whether the body writes (`.set`/`.remove`) to `persistent()` storage.
    pub writes_persistent_storage: bool,
    /// Whether the body calls `extend_ttl`/`.bump(` anywhere.
    pub extends_ttl: bool,
    /// Whether the body writes to `temporary()` storage using a key/type
    /// name that looks like durable state (balance/admin/owner/supply/price).
    pub writes_temporary_storage_of_sensitive_state: bool,
    /// Whether a cross-contract call (`invoke_contract`/`Client::new`)
    /// appears before a later storage write in the same function — a
    /// checks-effects-interactions violation shape.
    pub external_call_before_storage_write: bool,
    /// Whether the body reads a price from what looks like a single spot-
    /// price call (`get_price`/`.price(`/`spot_price`/`exchange_rate`) with
    /// no TWAP/multi-source corroboration anywhere in the function.
    pub uses_single_source_price_oracle: bool,
    /// Whether the function sets an admin or owner storage key directly
    /// without a two-step propose/accept flow.
    pub sets_admin_single_step: bool,
}

/// Key/type-name substrings that indicate storage holding durable contract
/// state, used to flag that state being kept in non-durable `temporary()`
/// storage.
pub const SENSITIVE_STORAGE_KEYS: &[&str] = &["balance", "admin", "owner", "supply", "price"];
