//! Token-handling patterns drawn from the most frequent contest findings:
//! raw ERC-20 calls on caller-chosen tokens, hard-coded 18-decimal maths,
//! approvals that cannot be reset or are unlimited, and NFT transfers that
//! bypass the receiver check.
//!
//! Every rule here scopes to the *function* and, where the risk only exists
//! when the caller picks the token, to functions that take the token as a
//! parameter. A vault whose asset is fixed by its deployer is not reported.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use super::implementations::split_functions;
use super::textutil::code_lines;

lazy_static! {
    /// A function that takes a token the caller chooses.
    static ref TOKEN_PARAM: Regex =
        Regex::new(r"(?i)\b(?:IERC20(?:Metadata)?|ERC20|address)\s+(?:memory\s+|calldata\s+)?(\w*token\w*|\w*asset\w*|\w*currency\w*)\b").unwrap();
    static ref FUNCTION_DECL: Regex = Regex::new(r"(?i)\bfunction\s+(\w+)\s*\(([^)]*)\)").unwrap();
    static ref RAW_ERC20_CALL: Regex =
        Regex::new(r"(?i)\b(\w+)\s*\.\s*(transfer|transferFrom|approve)\s*\(").unwrap();
    static ref SAFE_WRAPPER: Regex = Regex::new(r"(?i)safeTransfer|safeTransferFrom|forceApprove|safeIncreaseAllowance|using\s+SafeERC20|SafeTransferLib|safeApprove").unwrap();
    static ref HARDCODED_1E18: Regex = Regex::new(r"(?:\b1e18\b|\b10\s*\*\*\s*18\b|\b1_?000_?000_?000_?000_?000_?000\b)").unwrap();
    static ref DECIMALS_CALL: Regex = Regex::new(r"(?i)\.decimals\s*\(\s*\)").unwrap();
    static ref SAFE_APPROVE_NONZERO: Regex = Regex::new(r"(?i)\.safeApprove\s*\(\s*[^,]+,\s*([^)]+)\)").unwrap();
    static ref UNLIMITED_APPROVE: Regex =
        Regex::new(r"(?i)\.(?:approve|safeApprove|forceApprove)\s*\(\s*(\w+)\s*,\s*type\s*\(\s*uint256\s*\)\s*\.max\s*\)").unwrap();
    static ref ERC721_CONTEXT: Regex = Regex::new(r"(?i)\bIERC721\b|\bERC721\b|\btokenId\b|\bnft\b").unwrap();
    static ref NFT_TRANSFER_FROM: Regex =
        Regex::new(r"(?i)\b(\w+)\s*\.\s*transferFrom\s*\(\s*([^,]+),\s*([^,]+),\s*([^,)]+)\)").unwrap();
    /// A *definition* with a body — an interface declaration ends in `;` and is not the token itself.
    static ref ERC721_IMPL: Regex = Regex::new(r"(?i)\bfunction\s+(?:safe)?transferFrom\s*\([^;{]*\)[^;{]*\{").unwrap();
    static ref ERC721_SIGNAL: Regex = Regex::new(r"(?i)\bIERC721\b|\bERC721\b|\bnft\b|\btokenId\b").unwrap();
}

fn params_of(decl: &str) -> Vec<(String, String)> {
    // (type, name) for each parameter of a declaration line.
    let Some(c) = FUNCTION_DECL.captures(decl) else {
        return Vec::new();
    };
    c[2].split(',')
        .filter_map(|p| {
            let parts: Vec<&str> = p.split_whitespace().collect();
            match parts.as_slice() {
                [ty, .., name] => Some((
                    ty.to_string(),
                    name.trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '_')
                        .to_string(),
                )),
                _ => None,
            }
        })
        .collect()
}

fn caller_chosen_tokens(decl: &str) -> Vec<String> {
    params_of(decl)
        .into_iter()
        .filter(|(ty, name)| {
            let ty = ty.to_ascii_lowercase();
            let n = name.to_ascii_lowercase();
            ty.starts_with("ierc20")
                || ty == "erc20"
                || (ty == "address"
                    && (n.contains("token") || n.contains("asset") || n.contains("currency")))
        })
        .map(|(_, n)| n)
        .collect()
}

fn finding(id: &str, file: &str, idx: usize, line: &str, sev: Severity, msg: &str) -> Finding {
    Finding::new(
        id.to_string(),
        sev,
        file.to_string(),
        idx + 1,
        0,
        msg.to_string(),
        line.trim().to_string(),
    )
    .with_metadata("detector".to_string(), "token_handling".to_string())
}

/// Raw `transfer`/`transferFrom`/`approve` on a token the caller chooses.
/// Tokens like USDT return nothing, so even `require(token.transfer(..))`
/// reverts on them; only the SafeERC20 wrappers work for every token.
pub fn detect_erc20_without_safe_wrapper(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((_, decl)) = span.lines.first() else {
            continue;
        };
        let tokens = caller_chosen_tokens(decl);
        if tokens.is_empty() {
            continue;
        }
        for (idx, line) in &span.lines {
            if SAFE_WRAPPER.is_match(line) {
                continue;
            }
            for c in RAW_ERC20_CALL.captures_iter(line) {
                let target = c[1].to_ascii_lowercase();
                if tokens.iter().any(|t| t.to_ascii_lowercase() == target) {
                    out.push(finding(
                        "evm_erc20_without_safe_wrapper", file_path, *idx, line, Severity::Medium,
                        "Raw ERC-20 call on a caller-supplied token: tokens that return no value (USDT) \
                         or `false` (some ZRX-era tokens) break this path; use SafeERC20 so every token behaves",
                    ));
                }
            }
        }
    }
    out
}

/// `1e18` baked into conversions in a function that accepts arbitrary tokens,
/// with `decimals()` never consulted anywhere in the file.
pub fn detect_hardcoded_token_decimals(source: &str, file_path: &str) -> Vec<Finding> {
    if DECIMALS_CALL.is_match(source) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((_, decl)) = span.lines.first() else {
            continue;
        };
        if caller_chosen_tokens(decl).is_empty() {
            continue;
        }
        for (idx, line) in &span.lines {
            if HARDCODED_1E18.is_match(line) && (line.contains('*') || line.contains('/')) {
                out.push(finding(
                    "evm_hardcoded_token_decimals", file_path, *idx, line, Severity::Medium,
                    "18 decimals assumed for a caller-supplied token: USDC and USDT have 6, WBTC has 8, \
                     so amounts and prices are off by a factor of 10^10 or more; read `decimals()`",
                ));
            }
        }
    }
    out
}

/// `safeApprove` to a non-zero amount (reverts when an allowance already
/// exists — OpenZeppelin deprecated it for that reason) and unlimited
/// approvals granted to a spender the caller names.
pub fn detect_unsafe_token_approval(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((_, decl)) = span.lines.first() else {
            continue;
        };
        let params: Vec<String> = params_of(decl)
            .into_iter()
            .map(|(_, n)| n.to_ascii_lowercase())
            .collect();
        for (idx, line) in &span.lines {
            if let Some(c) = SAFE_APPROVE_NONZERO.captures(line) {
                if c[1].trim() != "0" {
                    out.push(finding(
                        "evm_unsafe_token_approval", file_path, *idx, line, Severity::Low,
                        "`safeApprove` to a non-zero amount reverts whenever an allowance is already set, \
                         so the second call ever made here fails; use `forceApprove` or reset to zero first",
                    ));
                }
            }
            if let Some(c) = UNLIMITED_APPROVE.captures(line) {
                if params.contains(&c[1].to_ascii_lowercase()) {
                    out.push(finding(
                        "evm_unsafe_token_approval", file_path, *idx, line, Severity::Medium,
                        "Unlimited approval granted to a spender the caller names: whoever supplies that \
                         address can drain the contract's balance of the token at any later time",
                    ));
                }
            }
        }
    }
    out
}

/// An NFT sent with `transferFrom` to an address the caller supplies: if the
/// recipient is a contract without `onERC721Received`, the token is locked.
pub fn detect_erc721_unsafe_transfer(source: &str, file_path: &str) -> Vec<Finding> {
    if !ERC721_SIGNAL.is_match(source) || ERC721_IMPL.is_match(source) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((_, decl)) = span.lines.first() else {
            continue;
        };
        let params: Vec<String> = params_of(decl)
            .into_iter()
            .filter(|(t, _)| t.eq_ignore_ascii_case("address"))
            .map(|(_, n)| n)
            .collect();
        for (idx, line) in &span.lines {
            if line.to_ascii_lowercase().contains("safetransferfrom") {
                continue;
            }
            if let Some(c) = NFT_TRANSFER_FROM.captures(line) {
                let to = c[3].trim();
                if params.iter().any(|p| p == to) {
                    out.push(finding(
                        "evm_erc721_unsafe_transfer", file_path, *idx, line, Severity::Medium,
                        "NFT sent with `transferFrom` to a caller-supplied address: a contract recipient \
                         that lacks `onERC721Received` receives it anyway and can never move it; use `safeTransferFrom`",
                    ));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_transfer_on_caller_token_is_flagged_but_fixed_asset_is_not() {
        let bad = "contract C { function sweep(IERC20 token, uint256 amt) external { require(token.transfer(msg.sender, amt), \"x\"); } }";
        assert_eq!(detect_erc20_without_safe_wrapper(bad, "a.sol").len(), 1);
        let good = "contract C { IERC20 immutable asset; function w(uint256 amt) external { require(asset.transfer(msg.sender, amt), \"x\"); } }";
        assert!(detect_erc20_without_safe_wrapper(good, "a.sol").is_empty());
        let safe = "contract C { using SafeERC20 for IERC20; function sweep(IERC20 token, uint256 amt) external { token.safeTransfer(msg.sender, amt); } }";
        assert!(detect_erc20_without_safe_wrapper(safe, "a.sol").is_empty());
    }

    #[test]
    fn hardcoded_decimals_only_without_decimals_call() {
        let bad = "contract C { function value(address token, uint256 amt, uint256 price) external pure returns (uint256) { return amt * price / 1e18; } }";
        assert_eq!(detect_hardcoded_token_decimals(bad, "a.sol").len(), 1);
        let good = format!("{bad} contract D {{ function d(IERC20 t) external view returns (uint8) {{ return t.decimals(); }} }}");
        assert!(detect_hardcoded_token_decimals(&good, "a.sol").is_empty());
    }

    #[test]
    fn approvals() {
        let bad = "contract C {\n    function a(address spender) external {\n        token.safeApprove(spender, 100);\n        token.approve(spender, type(uint256).max);\n    }\n}";
        assert_eq!(detect_unsafe_token_approval(bad, "a.sol").len(), 2);
        let good = "contract C {\n    function a() external {\n        token.safeApprove(router, 0);\n        token.forceApprove(router, amount);\n    }\n}";
        assert!(detect_unsafe_token_approval(good, "a.sol").is_empty());
    }

    #[test]
    fn nft_transfer_to_param_is_flagged() {
        let bad = "contract Market { function buy(address to, uint256 tokenId) external { nft.transferFrom(address(this), to, tokenId); } }";
        assert_eq!(detect_erc721_unsafe_transfer(bad, "a.sol").len(), 1);
        let good = "contract Market { function buy(address to, uint256 tokenId) external { nft.safeTransferFrom(address(this), to, tokenId); } }";
        assert!(detect_erc721_unsafe_transfer(good, "a.sol").is_empty());
    }
}
