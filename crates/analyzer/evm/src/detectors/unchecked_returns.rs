//! Unchecked return values (CWE-252, SWC-104).
//!
//! A low-level `call`/`send`/`delegatecall` returns `false` on failure instead
//! of reverting, and an ERC-20 `transfer`/`transferFrom` returns a `bool` that
//! many tokens set rather than revert. A bare statement that discards that
//! value continues as if the operation succeeded: funds are recorded as sent
//! that never moved.
//!
//! Only *discarded* results are reported. `(bool ok, ) = x.call(...)`,
//! `require(token.transfer(...))`, `if (!x.send(...))` and SafeERC20's
//! `safeTransfer` all handle the result and are not findings.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

lazy_static! {
    /// A low-level call whose result is a bool that must be checked.
    static ref LOW_LEVEL_CALL: Regex =
        Regex::new(r"\.\s*(call|send|delegatecall|staticcall)\s*(\{[^}]*\})?\s*\(").unwrap();

    /// An ERC-20 bool-returning transfer. Two arguments distinguishes
    /// `token.transfer(to, amount)` from the one-argument ETH
    /// `payable(x).transfer(amount)`, which reverts on failure.
    static ref ERC20_TRANSFER: Regex =
        Regex::new(r"(?i)\.\s*(transfer|transferFrom|approve)\s*\(").unwrap();
}

pub fn detect_unchecked_returns(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in source.lines().enumerate() {
        let stmt = line.trim();
        if stmt.is_empty() || !is_bare_statement(stmt) {
            continue;
        }

        if LOW_LEVEL_CALL.is_match(stmt) {
            findings.push(finding(
                file_path,
                idx,
                stmt,
                Severity::High,
                "Low-level call result is discarded: a failed call returns false rather than \
                 reverting, so execution continues as if it succeeded",
            ));
            continue;
        }

        if ERC20_TRANSFER.is_match(stmt) && !stmt.to_lowercase().contains("safetransfer") {
            // ETH `x.transfer(amount)` reverts and needs no check; ERC-20
            // `token.transfer(to, amount)` returns a bool. Count arguments.
            if argument_count(stmt) >= 2 {
                findings.push(finding(
                    file_path,
                    idx,
                    stmt,
                    Severity::Medium,
                    "ERC-20 transfer result is discarded: tokens that return false instead of \
                     reverting leave accounting updated for a transfer that never happened",
                ));
            }
        }
    }

    findings
}

/// A statement whose value goes nowhere: not assigned, not wrapped in a
/// check, not returned, not negated.
fn is_bare_statement(stmt: &str) -> bool {
    let lower = stmt.to_lowercase();
    !(lower.starts_with("require(")
        || lower.starts_with("assert(")
        || lower.starts_with("if")
        || lower.starts_with("return")
        || lower.starts_with("while")
        || lower.starts_with('!')
        || lower.starts_with("bool ")
        || lower.starts_with('(')
        || lower.contains(" = ")
        || lower.contains("= ")
        || lower.starts_with("emit ")
        || lower.starts_with("function ")
        || lower.starts_with("modifier "))
}

/// Number of top-level arguments in the first call on the line.
fn argument_count(stmt: &str) -> usize {
    let Some(open) = stmt.find('(') else {
        return 0;
    };
    let mut depth = 0i32;
    let mut count = 0usize;
    let mut saw_any = false;
    for c in stmt[open + 1..].chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            ',' if depth == 0 => count += 1,
            c if !c.is_whitespace() => saw_any = true,
            _ => {}
        }
    }
    if saw_any {
        count + 1
    } else {
        0
    }
}

fn finding(file: &str, idx: usize, stmt: &str, sev: Severity, msg: &str) -> Finding {
    Finding::new(
        "evm_unchecked_returns".to_string(),
        sev,
        file.to_string(),
        idx + 1,
        0,
        msg.to_string(),
        stmt.to_string(),
    )
    .with_metadata("detector".to_string(), "return_value_analysis".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_low_level_call_is_flagged() {
        let src = "contract C { function f(address r) external { r.call{value: 1 ether}(\"\"); } }";
        let f = detect_unchecked_returns(src, "c.sol");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn checked_low_level_call_is_not() {
        for src in [
            "(bool ok, ) = r.call{value: 1}(\"\");",
            "require(r.send(1), \"failed\");",
            "if (!r.send(1)) revert();",
            "bool ok = r.send(1);",
        ] {
            assert!(detect_unchecked_returns(src, "c.sol").is_empty(), "{src}");
        }
    }

    #[test]
    fn erc20_bool_transfer_is_flagged_but_eth_transfer_is_not() {
        assert_eq!(
            detect_unchecked_returns("token.transfer(to, amount);", "c").len(),
            1
        );
        assert_eq!(
            detect_unchecked_returns("token.transferFrom(a, b, amount);", "c").len(),
            1
        );
        // One argument: ETH transfer, reverts on failure.
        assert!(detect_unchecked_returns("payable(to).transfer(amount);", "c").is_empty());
        // SafeERC20 reverts on false.
        assert!(detect_unchecked_returns("token.safeTransfer(to, amount);", "c").is_empty());
        assert!(detect_unchecked_returns("require(token.transfer(to, amount));", "c").is_empty());
    }
}
