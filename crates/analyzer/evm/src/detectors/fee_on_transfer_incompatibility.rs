//! Fee-on-transfer / rebasing token incompatibility.
//!
//! A token that takes a fee on transfer delivers less than the nominal amount.
//! Accounting that credits the parameter passed to `transferFrom`, rather than
//! the balance actually received, credits more than arrived — and the
//! difference is extractable.
//!
//! The risk only exists when the *caller* chooses the token. A vault whose
//! `asset` is an immutable set at deployment was pointed at a specific token
//! by its deployer; reporting every such vault — which is every ERC-4626 in
//! existence, OpenZeppelin's included — as fee-on-transfer-unsafe is noise,
//! not a finding. This detector fires when the token the call is made on is a
//! parameter of the enclosing function, and the received balance is not
//! measured.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

lazy_static! {
    static ref TRANSFER_FROM_CALL: Regex =
        Regex::new(r"(?i)\.(safeTransferFrom|transferFrom)\s*\(").unwrap();
    static ref BALANCE_DIFF_CHECK: Regex =
        Regex::new(r"(?i)balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)").unwrap();
}

pub fn detect_fee_on_transfer_incompatibility(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let lines: Vec<&str> = source.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("//") || !TRANSFER_FROM_CALL.is_match(line) {
            continue;
        }

        let window_start = i.saturating_sub(10);
        let window_end = lines.len().min(i + 10);
        let window = lines[window_start..window_end].join("\n");
        if BALANCE_DIFF_CHECK.is_match(&window) {
            continue;
        }

        if !token_is_caller_supplied(&lines, i) {
            continue;
        }

        findings.push(
            Finding::new(
                "evm_fee_on_transfer_incompatibility".to_string(),
                Severity::Medium,
                file_path.to_string(),
                i + 1,
                0,
                "transferFrom on a caller-supplied token is used without comparing this \
                 contract's balance before and after the transfer — a fee-on-transfer or \
                 rebasing token delivers less than the nominal amount, so accounting that \
                 trusts the parameter credits more than was actually received"
                    .to_string(),
                line.trim().to_string(),
            )
            .with_metadata("chain".to_string(), "evm".to_string()),
        );
    }

    findings
}

/// Whether the object `transferFrom` is called on at `line_idx` is a parameter
/// of the enclosing function (`function f(IERC20 token, ...) { token.transferFrom`)
/// rather than contract state.
fn token_is_caller_supplied(lines: &[&str], line_idx: usize) -> bool {
    let line = lines[line_idx];
    // Identifier immediately before `.transferFrom(` / `.safeTransferFrom(`,
    // unwrapping `IERC20(x)` to `x`.
    let Some(m) = TRANSFER_FROM_CALL.find(line) else {
        return false;
    };
    let before = line[..m.start()].trim_end();
    let callee = before
        .rsplit(|c: char| !(c.is_alphanumeric() || c == '_' || c == ')' || c == '('))
        .next()
        .unwrap_or("");
    let ident = callee
        .trim_end_matches(')')
        .rsplit('(')
        .next()
        .unwrap_or(callee)
        .trim();
    if ident.is_empty() {
        return false;
    }

    // Walk back to the enclosing declaration and read its parameter list.
    let decl = lines[..=line_idx]
        .iter()
        .rev()
        .find(|l| l.contains("function ") || l.contains("constructor"));
    let Some(decl) = decl else {
        return false;
    };
    let Some(open) = decl.find('(') else {
        return false;
    };
    let close = decl[open..]
        .find(')')
        .map(|p| open + p)
        .unwrap_or(decl.len());
    decl[open + 1..close]
        .split(',')
        .filter_map(|p| p.split_whitespace().last())
        .any(|name| name == ident)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_transfer_from_without_balance_diff_check() {
        // The token is chosen by the caller: this is the shape every real
        // fee-on-transfer drain took (a pool or bridge accepting any token
        // and crediting the nominal amount).
        let source = r#"
contract Pool {
    function deposit(IERC20 token, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender][address(token)] += amount;
    }
}
"#;
        let findings = detect_fee_on_transfer_incompatibility(source, "pool.sol");
        assert!(findings
            .iter()
            .any(|f| f.invariant_id == "evm_fee_on_transfer_incompatibility"));
    }

    #[test]
    fn does_not_flag_a_deployer_fixed_asset() {
        // Every ERC-4626 in existence, OpenZeppelin's included, transfers its
        // immutable `asset` and credits derived shares. That is a documented
        // limitation the deployer accepted when choosing the token, not a
        // finding — reporting it made the detector fire on every vault.
        let source = r#"
contract Vault {
    IERC20 public immutable asset;
    function deposit(uint256 assets) external {
        require(asset.transferFrom(msg.sender, address(this), assets));
        shares[msg.sender] += convert(assets);
    }
}
"#;
        let findings = detect_fee_on_transfer_incompatibility(source, "vault.sol");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn does_not_flag_when_balance_diff_checked() {
        let source = r#"
contract Vault {
    function deposit(IERC20 token, uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        balances[msg.sender] += received;
    }
}
"#;
        let findings = detect_fee_on_transfer_incompatibility(source, "safe_vault.sol");
        assert!(findings.is_empty(), "{findings:?}");
    }
}
