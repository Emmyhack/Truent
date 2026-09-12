//! Chain-agnostic semantic-model extraction for Move modules.
//!
//! Extraction is AST-based, via the vendored Sui Move tree-sitter grammar
//! (see [`crate::tree_sitter_grammar`]) - a real parse rather than
//! re-scanning source text, so multi-line signatures, nested generics, and
//! comments/strings that merely *look* like a function signature are all
//! handled correctly. If the grammar fails to produce an error-free parse
//! (it's an upstream work-in-progress grammar with no guarantee of covering
//! every valid Move construct), this falls back to the original per-source
//! regex heuristic rather than silently reporting nothing.

use regex::Regex;
use truent_ir::{
    AuthCheckKind, AuthorizationCheck, MutationKind, PrivilegedMutation, SemanticModel,
};

/// Function name substrings that indicate a privileged mutation, paired
/// with the mutation category they represent.
const SENSITIVE_FUNCTIONS: &[(&str, MutationKind)] = &[
    ("withdraw", MutationKind::FundTransfer),
    ("transfer", MutationKind::FundTransfer),
    ("mint", MutationKind::FundTransfer),
    ("burn", MutationKind::FundTransfer),
    ("upgrade", MutationKind::Upgrade),
];

/// Build a chain-agnostic semantic model from Move module source.
///
/// A capability-typed parameter (`&AdminCap`, `&Capability<...>`, ...) is
/// treated as the guard: Move's capability pattern is its equivalent of an
/// authorization check — possession of the typed value at the call site
/// stands in for a signer/role check.
pub fn build_semantic_model(source: &str, file_path: &str) -> SemanticModel {
    match build_semantic_model_ast(source, file_path) {
        Some(model) => model,
        None => build_semantic_model_regex(source, file_path),
    }
}

/// AST-based extraction. Returns `None` (rather than a possibly-wrong,
/// possibly-empty model) if the grammar can't produce a clean parse, so the
/// caller knows to fall back instead of silently trusting a broken tree.
fn build_semantic_model_ast(source: &str, file_path: &str) -> Option<SemanticModel> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(crate::tree_sitter_grammar::language())
        .expect("the vendored grammar must load - this is a static, compiled-in constant");

    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }

    let mut model = SemanticModel::new("move", file_path);
    let src_bytes = source.as_bytes();
    let text = |node: tree_sitter::Node| node.utf8_text(src_bytes).unwrap_or("");

    visit_function_definitions(root, &mut |func_node| {
        let Some(name_node) = func_node.child_by_field_name("name") else {
            return;
        };
        let fn_name = text(name_node);

        // Only functions actually reachable from outside the module (public,
        // public(package), or a transaction entry point) are relevant entry
        // points for this rule - a private helper isn't callable without
        // going through one of those anyway.
        let mut modifiers = vec![];
        for i in 0..func_node.child_count() {
            if let Some(child) = func_node.child(i) {
                if child.kind() == "modifier" {
                    modifiers.push(text(child));
                }
            }
        }
        let is_reachable = modifiers
            .iter()
            .any(|m| m.starts_with("public") || *m == "entry");
        if !is_reachable {
            return;
        }

        let lower = fn_name.to_lowercase();
        let Some((_, kind)) = SENSITIVE_FUNCTIONS
            .iter()
            .find(|(needle, _)| lower.contains(needle))
        else {
            return;
        };

        let guards = func_node
            .child_by_field_name("parameters")
            .map(|params_node| {
                let mut guards = Vec::new();
                for i in 0..params_node.child_count() {
                    let Some(param) = params_node.child(i) else {
                        continue;
                    };
                    if param.kind() != "function_parameter" {
                        continue;
                    }
                    let Some(type_node) = param.child_by_field_name("type") else {
                        continue;
                    };
                    let type_text = text(type_node);
                    // Find the innermost type identifier (e.g. `AdminCap` out
                    // of `&AdminCap` or `&Capability<AdminCap>`) by looking
                    // for any "Cap"-containing word, matching the same
                    // capability-pattern convention the regex fallback uses.
                    if let Some(cap_word) = type_text
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|w| w.contains("Cap") && !w.is_empty())
                    {
                        guards.push(AuthorizationCheck {
                            kind: AuthCheckKind::RoleOrCapability,
                            source: cap_word.to_string(),
                        });
                    }
                }
                guards
            })
            .unwrap_or_default();

        // Move's other authorisation idiom lives in the body: take a
        // `&signer` and assert who it is. Only capability parameters used to
        // count, so every `withdraw` guarded by
        // `assert!(signer::address_of(account) == t.admin)` was reported as
        // an unauthorised privileged mutation.
        let mut guards = guards;
        if let Some(check) = body_authority_guard(text(func_node)) {
            guards.push(check);
        }

        model.mutations.push(PrivilegedMutation {
            entry_point: fn_name.to_string(),
            kind: kind.clone(),
            line: func_node.start_position().row + 1,
            guards,
        });
    });

    Some(model)
}

/// Recursively visit every `function_definition` node in the tree, calling
/// `visit` on each. Function definitions can appear nested inside a
/// `module_body` (brace form) or directly under `source_file` (Move 2024's
/// semicolon module form), so this walks the whole tree rather than
/// assuming one specific shape.
fn visit_function_definitions<'a>(
    node: tree_sitter::Node<'a>,
    visit: &mut impl FnMut(tree_sitter::Node<'a>),
) {
    if node.kind() == "function_definition" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_function_definitions(child, visit);
    }
}

/// Regex-based fallback, used only when the AST parse fails. Kept as its own
/// function (rather than deleted) precisely for that degraded-but-still-useful
/// path — see the module doc comment.
fn build_semantic_model_regex(source: &str, file_path: &str) -> SemanticModel {
    let mut model = SemanticModel::new("move", file_path);

    // Matched against the whole source (not line-by-line): a real-world Move
    // function signature commonly wraps its parameter list across multiple
    // lines, which a per-line regex would silently never match at all.
    // `[\s\S]*?` (rather than `[^)]*`) lets the parameter capture span
    // newlines; it's non-greedy so it still stops at the first `)`.
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

        let name_match = caps
            .get(1)
            .expect("group 1 always matches with the outer regex");
        model.mutations.push(PrivilegedMutation {
            entry_point: fn_name.to_string(),
            kind: kind.clone(),
            line: offset_to_line(source, name_match.start()),
            guards,
        });
    }

    model
}

/// 1-indexed line number containing the given byte offset.
fn offset_to_line(source: &str, byte_offset: usize) -> usize {
    source
        .get(..byte_offset.min(source.len()))
        .unwrap_or("")
        .matches('\n')
        .count()
        + 1
}

/// An authority assertion in a function body, if present.
///
/// Recognises `assert!(signer::address_of(x) == ...)`, `assert!(x == @addr)`,
/// and `assert_admin`/`is_admin`/`has_role`-style helpers.
fn body_authority_guard(body: &str) -> Option<AuthorizationCheck> {
    let lower = body.to_lowercase();
    let asserts = lower.contains("assert!(") || lower.contains("abort");
    if asserts && lower.contains("signer::address_of(") && lower.contains("==") {
        return Some(AuthorizationCheck {
            kind: AuthCheckKind::Signer,
            source: "assert!(signer::address_of(..) == ..)".to_string(),
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

/// The brace-delimited block starting at or after byte offset `from`.
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

    const FIXTURE: &str = r#"
module vault::vault {
    public entry fun withdraw<T>(vault: &mut Vault<T>, amount: u64, ctx: &mut TxContext) {
        // no capability check
    }

    public entry fun admin_withdraw<T>(admin: &AdminCap, vault: &mut Vault<T>, amount: u64) {
        // guarded by capability
    }
}
"#;

    #[test]
    fn flags_withdraw_with_no_guard_but_not_admin_withdraw() {
        let model = build_semantic_model(FIXTURE, "vault.move");
        assert_eq!(model.chain, "move");
        assert_eq!(model.mutations.len(), 2);

        let findings = find_unauthorized_privileged_mutations(&model);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("withdraw"));
        assert!(!findings[0].message.contains("admin_withdraw"));
    }

    /// A per-line regex would never match this at all: real-world Move
    /// signatures commonly wrap a long parameter list across several lines.
    const MULTILINE_FIXTURE: &str = r#"
module vault::vault {
    public entry fun withdraw<T>(
        vault: &mut Vault<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // no capability check
    }

    public entry fun admin_withdraw<T>(
        admin: &AdminCap,
        vault: &mut Vault<T>,
        amount: u64
    ) {
        // guarded by capability
    }
}
"#;

    #[test]
    fn flags_multiline_signature_with_no_guard() {
        let model = build_semantic_model(MULTILINE_FIXTURE, "vault.move");
        assert_eq!(model.mutations.len(), 2);

        let findings = find_unauthorized_privileged_mutations(&model);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("withdraw"));
        assert!(!findings[0].message.contains("admin_withdraw"));

        // The reported line should point at `withdraw`'s own signature line,
        // not get thrown off by the multi-line parameter list.
        let withdraw_mutation = model
            .mutations
            .iter()
            .find(|m| m.entry_point == "withdraw")
            .unwrap();
        let expected_line = MULTILINE_FIXTURE
            .lines()
            .position(|l| l.contains("fun withdraw"))
            .unwrap()
            + 1;
        assert_eq!(withdraw_mutation.line, expected_line);
    }

    /// Proves the AST path is actually engaged for ordinary fixtures (not
    /// silently falling back to regex on every call, which would make the
    /// two tests above pass for the wrong reason).
    #[test]
    fn ast_extraction_succeeds_for_brace_style_module() {
        assert!(
            build_semantic_model_ast(FIXTURE, "vault.move").is_some(),
            "expected the vendored grammar to parse this fixture without error"
        );
    }

    /// A text like `// TODO: implement withdraw(admin: &AdminCap)` or a
    /// string literal containing that shape would fool the regex fallback
    /// into reporting a phantom function - real AST extraction only looks at
    /// actual `function_definition` nodes, so comments and strings can't
    /// masquerade as one.
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
        let model =
            build_semantic_model_ast(source, "vault.move").expect("fixture must parse cleanly");
        assert!(
            model.mutations.is_empty(),
            "a comment/string containing lookalike text must not be treated as a real \
             function definition, got: {:?}",
            model.mutations
        );
    }
}
