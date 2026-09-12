//! `syn`-based extraction of [`ContractFunction`] facts from Soroban source.
//!
//! Follows the same technique [`truent_analyzer_solana`]'s `anchor_parser`
//! uses: parse real Rust syntax with `syn` to find the structural elements
//! (here, `#[contractimpl]` blocks and their `pub fn`s), then re-stringify
//! each function body via `quote!` and search the whitespace-stripped
//! token text for the patterns that indicate a given fact. Whitespace is
//! stripped because `quote!`'s `Display` impl inserts a space around every
//! token (`env . storage () . persistent ()`), which would otherwise break
//! substring checks like `.set(`.

use crate::soroban_model::{ContractFunction, SENSITIVE_STORAGE_KEYS};
use quote::quote;
use syn::{ImplItem, Item};

fn is_contractimpl_block(item_impl: &syn::ItemImpl) -> bool {
    item_impl
        .attrs
        .iter()
        .any(|attr| attr.path().is_ident("contractimpl"))
}

fn byte_offset_to_line(source: &str, byte_offset: usize) -> usize {
    let bound = byte_offset.min(source.len());
    source[..bound].matches('\n').count() + 1
}

fn line_of_fn(source: &str, fn_name: &str) -> usize {
    let needle = format!("fn {fn_name}");
    source
        .find(&needle)
        .map(|pos| byte_offset_to_line(source, pos))
        .unwrap_or(1)
}

/// Parse every `pub fn` inside a `#[contractimpl]` block and extract the
/// facts [`crate::detectors`] and [`crate::semantic_model`] need.
pub fn parse_contract_functions(source: &str) -> syn::Result<Vec<ContractFunction>> {
    let file = syn::parse_file(source)?;
    let mut functions = Vec::new();

    for item in &file.items {
        let Item::Impl(item_impl) = item else {
            continue;
        };
        if !is_contractimpl_block(item_impl) {
            continue;
        }
        for impl_item in &item_impl.items {
            let ImplItem::Fn(method) = impl_item else {
                continue;
            };
            if !matches!(method.vis, syn::Visibility::Public(_)) {
                continue;
            }
            functions.push(analyze_function(method, source));
        }
    }

    Ok(functions)
}

fn analyze_function(method: &syn::ImplItemFn, source: &str) -> ContractFunction {
    let name = method.sig.ident.to_string();
    let line = line_of_fn(source, &name);

    // Body only (not the signature) so a `->` return arrow can't be
    // mistaken for subtraction.
    let block = &method.block;
    let body = quote!(#block).to_string().replace(' ', "");
    let body_lower = body.to_lowercase();

    let has_require_auth = body.contains("require_auth");

    let is_initialize = name == "initialize" || name == "init" || name.starts_with("initialize");
    let has_init_guard = if is_initialize {
        matches!(
            (body.find(".has("), body.find(".set(")),
            (Some(has_pos), Some(set_pos)) if has_pos < set_pos
        )
    } else {
        // Not applicable to non-initializers; never flagged by the
        // re-initialization detector, which gates on `is_initialize`.
        true
    };

    let upgrades_wasm = body.contains("update_current_contract_wasm");

    let has_checked_math = body_lower.contains("checked_add")
        || body_lower.contains("checked_sub")
        || body_lower.contains("checked_mul")
        || body_lower.contains("checked_div");
    let has_raw_arithmetic = body.contains('+') || body.contains('-') || body.contains('*');
    let uses_unchecked_arithmetic = has_raw_arithmetic && !has_checked_math;

    // Only a *bare* `.unwrap()` is reported. `.expect("overflow")` on a
    // checked-arithmetic result is the Soroban idiom for a deliberate abort —
    // the equivalent of `require` — and counting it flagged every correctly
    // written token.
    let unwrap_count = body.matches(".unwrap(").count();

    let writes_persistent_storage =
        body.contains("persistent()") && (body.contains(".set(") || body.contains(".remove("));
    let extends_ttl = body.contains("extend_ttl") || body.contains(".bump(");

    let writes_temporary_storage_of_sensitive_state = body.contains("temporary()")
        && (body.contains(".set(") || body.contains(".remove("))
        && SENSITIVE_STORAGE_KEYS
            .iter()
            .any(|k| body_lower.contains(k));

    let external_call_before_storage_write = {
        let call_pos = body
            .find("invoke_contract")
            .or_else(|| body.find("Client::new"));
        matches!(
            (call_pos, body.rfind(".set(")),
            (Some(call_pos), Some(set_pos)) if call_pos < set_pos
        )
    };

    let uses_single_source_price_oracle = (body.contains("get_price(")
        || body.contains(".price(")
        || body.contains("spot_price(")
        || body.contains("exchange_rate("))
        && !body_lower.contains("twap")
        && !body_lower.contains("time_weighted")
        && !body_lower.contains("average_price")
        && !body_lower.contains("median");

    ContractFunction {
        name,
        line,
        has_require_auth,
        is_initialize,
        has_init_guard,
        upgrades_wasm,
        uses_unchecked_arithmetic,
        unwrap_count,
        writes_persistent_storage,
        extends_ttl,
        writes_temporary_storage_of_sensitive_state,
        external_call_before_storage_write,
        uses_single_source_price_oracle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: &str = r#"
#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let balance: i128 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap();
        let new_balance = balance - amount;
        env.storage().persistent().set(&DataKey::Balance(to), &new_balance);
    }

    pub fn safe_withdraw(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let balance: i128 = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap();
        let new_balance = balance.checked_sub(amount).unwrap();
        env.storage().persistent().set(&DataKey::Balance(from), &new_balance);
        env.storage().persistent().extend_ttl(&DataKey::Balance(from), 100, 200);
    }
}
"#;

    #[test]
    fn parses_contractimpl_functions_only() {
        let functions = parse_contract_functions(CONTRACT).unwrap();
        let names: Vec<_> = functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["initialize", "withdraw", "safe_withdraw"]);
    }

    #[test]
    fn detects_init_guard() {
        let functions = parse_contract_functions(CONTRACT).unwrap();
        let init = functions.iter().find(|f| f.name == "initialize").unwrap();
        assert!(init.is_initialize);
        assert!(init.has_init_guard);
    }

    #[test]
    fn detects_missing_require_auth_and_unchecked_arithmetic() {
        let functions = parse_contract_functions(CONTRACT).unwrap();
        let withdraw = functions.iter().find(|f| f.name == "withdraw").unwrap();
        assert!(!withdraw.has_require_auth);
        assert!(withdraw.uses_unchecked_arithmetic);
        assert!(withdraw.writes_persistent_storage);
        assert!(!withdraw.extends_ttl);
    }

    #[test]
    fn recognizes_safe_function() {
        let functions = parse_contract_functions(CONTRACT).unwrap();
        let safe = functions
            .iter()
            .find(|f| f.name == "safe_withdraw")
            .unwrap();
        assert!(safe.has_require_auth);
        assert!(!safe.uses_unchecked_arithmetic);
        assert!(safe.extends_ttl);
    }
}
