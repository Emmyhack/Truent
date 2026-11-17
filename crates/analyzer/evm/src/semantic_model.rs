//! Chain-agnostic semantic-model extraction for EVM/Solidity contracts.
//!
//! Builds a [`truent_ir::SemanticModel`] from the real solc-JSON-AST-derived
//! [`AstContract`] (see [`crate::ast::SolidityParser`]) — modifiers and
//! function bodies come from the parsed contract, not from re-scanning
//! source text with a second, weaker heuristic.

use crate::ast::{AstContract, AstFunction, Visibility};
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
    ("setowner", MutationKind::AuthorityChange),
    ("transferownership", MutationKind::AuthorityChange),
    ("upgradeto", MutationKind::Upgrade),
    ("selfdestruct", MutationKind::AccountClose),
];

/// Modifier name substrings recognized as authorization guards.
const GUARD_MODIFIERS: &[(&str, AuthCheckKind)] = &[
    ("onlyowner", AuthCheckKind::Signer),
    ("onlyadmin", AuthCheckKind::Signer),
    ("onlyrole", AuthCheckKind::RoleOrCapability),
    ("onlygovernance", AuthCheckKind::Multisig),
];

/// Build a chain-agnostic semantic model from a parsed Solidity contract.
///
/// Sensitive public/external, state-mutating functions (fund movement,
/// ownership/authority changes, upgrades, self-destruction) become
/// [`PrivilegedMutation`] entries; guards come from the function's actual
/// modifier list, plus an inline `require(msg.sender == owner)`-style check
/// found in its parsed body statements when no modifier is present.
pub fn build_semantic_model(
    contract: &AstContract,
    source: &str,
    file_path: &str,
) -> SemanticModel {
    let mut model = SemanticModel::new("evm", file_path);

    for func in &contract.functions {
        if !matches!(func.visibility, Visibility::Public | Visibility::External) {
            continue;
        }
        if !func.is_mutable {
            // pure/view functions don't mutate state.
            continue;
        }

        let lower = func.name.to_lowercase();
        let Some((_, kind)) = SENSITIVE_FUNCTIONS
            .iter()
            .find(|(needle, _)| lower.contains(needle))
        else {
            continue;
        };

        model.mutations.push(PrivilegedMutation {
            entry_point: func.name.clone(),
            kind: kind.clone(),
            line: find_line(source, &func.name),
            guards: extract_guards(func),
        });
    }

    model
}

fn extract_guards(func: &AstFunction) -> Vec<AuthorizationCheck> {
    let mut guards: Vec<AuthorizationCheck> = func
        .modifiers
        .iter()
        .filter_map(|m| {
            let m_lower = m.to_lowercase();
            GUARD_MODIFIERS
                .iter()
                .find(|(needle, _)| m_lower.contains(needle))
                .map(|(_, kind)| AuthorizationCheck {
                    kind: kind.clone(),
                    source: m.clone(),
                })
        })
        .collect();

    if guards.is_empty() && has_inline_sender_check(&func.body) {
        guards.push(AuthorizationCheck {
            kind: AuthCheckKind::Signer,
            source: "inline msg.sender check".to_string(),
        });
    }

    guards
}

fn has_inline_sender_check(body: &[String]) -> bool {
    body.iter().any(|stmt| {
        let s = stmt.replace(' ', "").to_lowercase();
        s.contains("msg.sender==owner") || s.contains("msg.sender==admin")
    })
}

fn find_line(source: &str, func_name: &str) -> usize {
    let needle = format!("function {func_name}");
    source
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains(&needle))
        .map(|(i, _)| i + 1)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{AstParam, Visibility};
    use truent_ir::rules::find_unauthorized_privileged_mutations;

    /// solc's JSON AST isn't available in this environment (no `solc`
    /// binary), so this hand-builds the `AstContract` the real
    /// `SolidityParser` would produce for the fixture source below —
    /// exercising the same conversion path production parsing feeds.
    const FIXTURE: &str = r#"
contract Vault {
    address owner;

    function withdraw(uint256 amount) public {
        // moves funds with no access control
    }

    function adminWithdraw(uint256 amount) public onlyOwner {
        // guarded by a real modifier
    }
}
"#;

    fn make_function(name: &str, modifiers: Vec<&str>) -> AstFunction {
        AstFunction {
            name: name.to_string(),
            parameters: vec![AstParam {
                name: "amount".to_string(),
                type_name: "uint256".to_string(),
            }],
            returns: vec![],
            visibility: Visibility::Public,
            is_mutable: true,
            is_pure: false,
            is_view: false,
            modifiers: modifiers.into_iter().map(String::from).collect(),
            body: vec![],
            id: 0,
        }
    }

    #[test]
    fn flags_withdraw_with_no_guard_but_not_admin_withdraw() {
        let contract = AstContract {
            name: "Vault".to_string(),
            id: 0,
            state_vars: vec![],
            functions: vec![
                make_function("withdraw", vec![]),
                make_function("adminWithdraw", vec!["onlyOwner"]),
            ],
            events: vec![],
            modifiers: vec![],
            base_contracts: vec![],
            bytecode: String::new(),
            runtime_bytecode: String::new(),
        };

        let model = build_semantic_model(&contract, FIXTURE, "Vault.sol");
        assert_eq!(model.chain, "evm");
        assert_eq!(model.mutations.len(), 2);

        let findings = find_unauthorized_privileged_mutations(&model);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("withdraw"));
        assert!(!findings[0].message.contains("adminWithdraw"));
    }
}
