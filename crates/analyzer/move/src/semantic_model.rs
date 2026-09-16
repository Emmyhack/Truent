//! Chain-agnostic semantic model for Move, feeding the shared
//! `unauthorized_privileged_mutation` rule every chain analyzer contributes
//! to.
//!
//! Extraction is AST-based via [`crate::ast`] and [`crate::privilege`]: a
//! privileged mutation is a fund movement, authority change, upgrade or
//! resource removal traced through the body, on state the module shares
//! (Sui) or holds in global storage at a non-signer address (Aptos). Only
//! when the grammar fails to parse a file does the regex heuristic run — and
//! then it says so with `metadata["extraction"] = "regex-fallback"` on
//! whatever the rule reports.

use regex::Regex;
use truent_ir::semantic::{
    AuthCheckKind, AuthorizationCheck, MutationKind, PrivilegedMutation, SemanticModel,
};

use crate::ast::{self, MoveFile};
use crate::privilege::analyze;

/// Function-name heuristics for the regex fallback only.
const SENSITIVE_FUNCTIONS: &[(&str, MutationKind)] = &[
    ("withdraw", MutationKind::FundTransfer),
    ("transfer", MutationKind::FundTransfer),
    ("mint", MutationKind::FundTransfer),
    ("burn", MutationKind::FundTransfer),
    ("set_admin", MutationKind::AuthorityChange),
    ("set_owner", MutationKind::AuthorityChange),
    ("upgrade", MutationKind::Upgrade),
];

/// Build the model, preferring the AST and falling back to regex.
pub fn build_semantic_model(source: &str, file_path: &str) -> SemanticModel {
    match ast::parse(source) {
        Some(file) => build_from_ast(&file, file_path),
        None => build_semantic_model_regex(source, file_path),
    }
}

/// Whether the AST path applies to this source (exposed so the runner can
/// label fallback findings).
pub fn parses_cleanly(source: &str) -> bool {
    ast::parse(source).is_some()
}

pub fn build_from_ast(file: &MoveFile, file_path: &str) -> SemanticModel {
    let mut model = SemanticModel::new("move", file_path);
    for (m, f) in file.functions() {
        if !f.is_reachable() {
            continue;
        }
        let a = analyze(m, f, file.dialect);
        let Some(worst) = a.worst() else { continue };
        let Some(kind) = worst.ir_kind() else {
            continue;
        };
        model.mutations.push(PrivilegedMutation {
            entry_point: f.name.clone(),
            kind,
            line: f.line,
            guards: a.guards.clone(),
        });
    }
    model
}

/// Regex-based fallback, used only when the AST parse fails.
fn build_semantic_model_regex(source: &str, file_path: &str) -> SemanticModel {
    let mut model = SemanticModel::new("move", file_path);

    // Matched against the whole source: real-world signatures wrap their
    // parameter list across lines.
    let sig_re = Regex::new(r"public\s+(?:entry\s+)?fun\s+(\w+)\s*(?:<[^>]*>)?\s*\(([\s\S]*?)\)")
        .expect("valid regex");
    let cap_re = Regex::new(r"&(?:mut\s+)?(\w*Cap\w*)").expect("valid regex");

    for caps in sig_re.captures_iter(source) {
        let fn_name = &caps[1];
        let params = &caps[2];

        let lower = fn_name.to_lowercase();
        let Some((_, kind)) = SENSITIVE_FUNCTIONS
            .iter()
            .find(|(needle, _)| lower.contains(needle))
        else {
            continue;
        };

        let mut guards: Vec<AuthorizationCheck> = cap_re
            .captures_iter(params)
            .map(|c| AuthorizationCheck {
                kind: AuthCheckKind::RoleOrCapability,
                source: c[1].to_string(),
            })
            .collect();
        let whole = caps.get(0).expect("group 0");
        if let Some(check) = body_authority_guard(brace_body(source, whole.end())) {
            guards.push(check);
        }

        let name_match = caps.get(1).expect("group 1 always matches");
        model.mutations.push(PrivilegedMutation {
            entry_point: fn_name.to_string(),
            kind: kind.clone(),
            line: offset_to_line(source, name_match.start()),
            guards,
        });
    }

    model
}

fn offset_to_line(source: &str, byte_offset: usize) -> usize {
    source
        .get(..byte_offset.min(source.len()))
        .unwrap_or("")
        .matches('\n')
        .count()
        + 1
}

fn body_authority_guard(body: &str) -> Option<AuthorizationCheck> {
    let lower = body.to_lowercase();
    let asserts = lower.contains("assert!(") || lower.contains("abort");
    if asserts
        && (lower.contains("signer::address_of(") || lower.contains("sender("))
        && lower.contains("==")
    {
        return Some(AuthorizationCheck {
            kind: AuthCheckKind::Signer,
            source: "assert!(sender == ..)".to_string(),
        });
    }
    if asserts && lower.contains("== @") {
        return Some(AuthorizationCheck {
            kind: AuthCheckKind::Signer,
            source: "assert!(.. == @address)".to_string(),
        });
    }
    for helper in [
        "assert_admin(",
        "assert_owner(",
        "is_admin(",
        "only_admin(",
        "has_role(",
    ] {
        if lower.contains(helper) {
            return Some(AuthorizationCheck {
                kind: AuthCheckKind::RoleOrCapability,
                source: helper.trim_end_matches('(').to_string(),
            });
        }
    }
    None
}

fn brace_body(source: &str, from: usize) -> &str {
    let rest = &source[from..];
    let Some(open) = rest.find('{') else {
        return "";
    };
    let mut depth = 0i32;
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[open..open + i + 1];
                }
            }
            _ => {}
        }
    }
    &rest[open..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use truent_ir::rules::find_unauthorized_privileged_mutations;

    /// Sui: the vault is shared, so `withdraw` on it without a capability is
    /// a privileged mutation; `admin_withdraw` holds the capability.
    const SUI_FIXTURE: &str = r#"
module vault::vault {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    public struct AdminCap has key { id: UID }
    public struct Vault has key { id: UID, balance: Balance<SUI> }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Vault { id: object::new(ctx), balance: balance::zero() });
    }

    public fun withdraw(vault: &mut Vault, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::take(&mut vault.balance, amount, ctx)
    }

    public fun admin_withdraw(_: &AdminCap, vault: &mut Vault, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::take(&mut vault.balance, amount, ctx)
    }
}
"#;

    #[test]
    fn flags_withdraw_on_shared_vault_but_not_admin_withdraw() {
        let model = build_semantic_model(SUI_FIXTURE, "vault.move");
        assert_eq!(model.chain, "move");
        assert_eq!(model.mutations.len(), 2, "{:?}", model.mutations);

        let findings = find_unauthorized_privileged_mutations(&model);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("'withdraw'"));
        assert!(!findings[0].message.contains("admin_withdraw"));
    }

    /// Aptos: global storage at the module address is protocol state; the
    /// signer-scoped resource is the caller's own.
    const APTOS_FIXTURE: &str = r#"
module demo::treasury {
    use std::signer;

    struct Treasury has key { admin: address, balance: u64 }
    struct Account has key { balance: u64 }

    public entry fun withdraw(
        amount: u64
    ) acquires Treasury {
        let t = borrow_global_mut<Treasury>(@demo);
        t.balance = t.balance - amount;
    }

    public entry fun admin_withdraw(account: &signer, amount: u64) acquires Treasury {
        let t = borrow_global_mut<Treasury>(@demo);
        assert!(signer::address_of(account) == t.admin, 1);
        t.balance = t.balance - amount;
    }

    public entry fun withdraw_own(account: &signer, amount: u64) acquires Account {
        let a = borrow_global_mut<Account>(signer::address_of(account));
        a.balance = a.balance - amount;
    }
}
"#;

    #[test]
    fn aptos_global_storage_is_privileged_signer_scoped_is_not() {
        let model = build_semantic_model(APTOS_FIXTURE, "treasury.move");
        let names: Vec<&str> = model
            .mutations
            .iter()
            .map(|m| m.entry_point.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["withdraw", "admin_withdraw"],
            "{:?}",
            model.mutations
        );

        let findings = find_unauthorized_privileged_mutations(&model);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("'withdraw'"));

        // The multi-line signature reports its own line.
        let expected_line = APTOS_FIXTURE
            .lines()
            .position(|l| l.contains("fun withdraw("))
            .unwrap()
            + 1;
        assert_eq!(model.mutations[0].line, expected_line);
    }

    #[test]
    fn ast_extraction_is_engaged_for_both_dialects() {
        assert!(parses_cleanly(SUI_FIXTURE));
        assert!(parses_cleanly(APTOS_FIXTURE));
    }

    /// A comment or string containing a function-like shape must not become
    /// a mutation: only real `function_definition` nodes count.
    #[test]
    fn ast_extraction_ignores_lookalikes_in_comments_and_strings() {
        let source = r#"
module vault::vault {
    // withdraw(admin: &AdminCap, vault: &mut Vault, amount: u64) - not real code
    public fun log_note(): vector<u8> {
        b"fun withdraw(vault: &mut Vault, amount: u64) {}"
    }
}
"#;
        let model = build_semantic_model(source, "vault.move");
        assert!(model.mutations.is_empty(), "{:?}", model.mutations);
    }

    #[test]
    fn regex_fallback_still_reports_a_named_withdraw() {
        // Deliberately unparseable: a stray token after the signature.
        let source = "module a::b {\n    public fun withdraw(vault: &mut Vault) @@ {\n        let x = 1;\n    }\n}\n";
        assert!(!parses_cleanly(source));
        let model = build_semantic_model(source, "b.move");
        assert_eq!(model.mutations.len(), 1);
        assert_eq!(model.mutations[0].entry_point, "withdraw");
    }
}
