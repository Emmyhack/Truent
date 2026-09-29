//! Router swaps without real slippage protection.
//!
//! A swap is protected when its minimum-out (or maximum-in) comes from
//! outside the transaction: a value the caller chose off-chain, or a price
//! from an oracle or TWAP. It is *not* protected when the minimum is zero,
//! a bare literal, or derived from the pool's own spot quote in the same
//! transaction: an attacker who moves the spot price moves the "minimum"
//! with it, and 99% of a manipulated quote is still a manipulated quote.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use super::implementations::split_functions;
use super::textutil::code_lines;

lazy_static! {
    /// A V2-style router call; the capture is the function name.
    static ref ROUTER_SWAP: Regex = Regex::new(
        r"(?i)\.\s*(swapExactTokensForTokens|swapTokensForExactTokens|swapExactETHForTokens|swapTokensForExactETH|swapExactTokensForETH|swapETHForExactTokens)\s*\("
    ).unwrap();
    /// A V3-style call with a params struct carrying `amountOutMinimum`.
    static ref V3_MIN_FIELD: Regex =
        Regex::new(r"(?i)amount(OutMinimum|InMaximum)\s*:\s*([^,}]+)").unwrap();
    /// The minimum was read from the pool in this transaction.
    static ref SPOT_QUOTE: Regex = Regex::new(
        r"(?i)getAmountsOut|getAmountOut|getAmountsIn|getAmountIn|quoteExactInput|quoteExactOutput|\.quote\s*\(|getReserves|slot0|\.observe\s*\("
    ).unwrap();
    /// A price from outside the transaction.
    static ref EXTERNAL_PRICE: Regex =
        Regex::new(r"(?i)oracle|twap|latestRoundData|priceFeed|pyth|chainlink").unwrap();
    static ref FUNCTION_DECL: Regex = Regex::new(r"(?i)\bfunction\s+\w+\s*\(([^)]*)\)").unwrap();
}

/// Index of the slippage argument for each V2 router function.
fn min_arg_index(name: &str) -> usize {
    match name.to_ascii_lowercase().as_str() {
        "swapexactethfortokens" | "swapethforexacttokens" => 0,
        _ => 1,
    }
}

/// Top-level arguments of the call that starts at `open` (index of `(`).
fn call_args(text: &str, open: usize) -> Vec<String> {
    let mut depth = 0i32;
    let mut current = String::new();
    let mut args = Vec::new();
    for ch in text[open..].chars() {
        match ch {
            '(' | '[' | '{' => {
                if depth > 0 {
                    current.push(ch);
                }
                depth += 1;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                current.push(ch);
            }
            ',' if depth == 1 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        args.push(current.trim().to_string());
    }
    args
}

enum Verdict {
    Protected,
    Unprotected(&'static str),
}

/// Judge one minimum expression in the context of its function.
fn judge(min_expr: &str, params: &str, body: &str) -> Verdict {
    let expr = min_expr.trim();
    if expr.is_empty() {
        return Verdict::Unprotected("no minimum amount is passed at all");
    }
    let bare_literal = expr
        .chars()
        .all(|c| c.is_ascii_digit() || c == '_' || c == 'e');
    if bare_literal {
        return if expr.trim_matches('0').is_empty() {
            Verdict::Unprotected("the minimum is zero, so any output is accepted")
        } else {
            Verdict::Unprotected(
                "the minimum is a fixed literal that does not scale with the trade",
            )
        };
    }
    let ident: String = expr
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    let is_param = !ident.is_empty()
        && params
            .split(',')
            .filter_map(|p| p.split_whitespace().last())
            .any(|n| n == ident);
    if is_param {
        return Verdict::Protected;
    }
    // A local: see how it was computed.
    let assigned_from_spot = body.lines().any(|l| {
        let l = l.trim();
        (l.contains(&format!("{ident} ="))
            || l.contains(&format!(" {ident}="))
            || l.starts_with(&format!("uint256 {ident}"))
            || l.contains(&format!("uint {ident}")))
            && SPOT_QUOTE.is_match(l)
    });
    if assigned_from_spot || (SPOT_QUOTE.is_match(body) && !EXTERNAL_PRICE.is_match(body)) {
        return Verdict::Unprotected(
            "the minimum is derived from the pool's own quote in the same transaction, so it moves with a manipulated price",
        );
    }
    Verdict::Protected
}

pub fn detect_router_slippage_validation(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((_, decl)) = span.lines.first() else {
            continue;
        };
        let params = FUNCTION_DECL
            .captures(decl)
            .map(|c| c[1].to_string())
            .unwrap_or_default();
        let body: String = span
            .lines
            .iter()
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let mut reported = false;
        for (idx, line) in &span.lines {
            if reported {
                break;
            }
            if let Some(m) = ROUTER_SWAP.captures(line) {
                let open = m.get(0).unwrap().end() - 1;
                // The call may wrap lines; judge over the rest of the body from here.
                let from_here: String = span
                    .lines
                    .iter()
                    .filter(|(i, _)| *i >= *idx)
                    .map(|(_, l)| l.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                let start = from_here
                    .find(&line[..open])
                    .map(|p| p + open)
                    .unwrap_or(open);
                let args = call_args(&from_here, start);
                let min_expr = args.get(min_arg_index(&m[1])).cloned().unwrap_or_default();
                if let Verdict::Unprotected(why) = judge(&min_expr, &params, &body) {
                    findings.push(finding(file_path, *idx, line, why));
                    reported = true;
                }
            } else if let Some(m) = V3_MIN_FIELD.captures(line) {
                if let Verdict::Unprotected(why) = judge(&m[2], &params, &body) {
                    findings.push(finding(file_path, *idx, line, why));
                    reported = true;
                }
            }
        }
    }
    findings
}

fn finding(file: &str, idx: usize, line: &str, why: &str) -> Finding {
    Finding::new(
        "evm_router_slippage_validation".to_string(),
        Severity::Medium,
        file.to_string(),
        idx + 1,
        0,
        format!(
            "Swap without real slippage protection: {why}. Take the minimum from the caller \
             (computed off-chain) or from an oracle/TWAP, never from the pool's spot price"
        ),
        line.trim().to_string(),
    )
    .with_metadata("detector".to_string(), "router_slippage".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_supplied_minimum_is_protected() {
        let safe = "contract C {\n    function swap(uint256 amountIn, uint256 amountOutMin, address[] calldata path, uint256 deadline) external {\n        router.swapExactTokensForTokens(amountIn, amountOutMin, path, msg.sender, deadline);\n    }\n}";
        assert!(detect_router_slippage_validation(safe, "t.sol").is_empty());
    }

    #[test]
    fn zero_and_literal_minimums_are_flagged() {
        let zero = "contract C {\n    function swap(uint256 amountIn, address[] calldata path) external {\n        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);\n    }\n}";
        assert_eq!(detect_router_slippage_validation(zero, "t.sol").len(), 1);
        let literal = zero.replace(", 0,", ", 1000,");
        assert_eq!(
            detect_router_slippage_validation(&literal, "t.sol").len(),
            1
        );
    }

    #[test]
    fn spot_derived_minimum_is_flagged_even_when_scaled() {
        let spot = "contract C {\n    function swap(uint256 amountIn, address[] calldata path) external {\n        uint256[] memory quoted = router.getAmountsOut(amountIn, path);\n        uint256 minOut = (quoted[1] * 99) / 100;\n        router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, block.timestamp);\n    }\n}";
        assert_eq!(detect_router_slippage_validation(spot, "t.sol").len(), 1);
    }

    #[test]
    fn oracle_derived_minimum_is_protected() {
        let oracle = "contract C {\n    function swap(uint256 amountIn, address[] calldata path) external {\n        uint256 minOut = amountIn * oracle.price() * 99 / 100e18;\n        router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, block.timestamp);\n    }\n}";
        assert!(detect_router_slippage_validation(oracle, "t.sol").is_empty());
    }

    #[test]
    fn v3_struct_minimum_zero_is_flagged() {
        let v3 = "contract C {\n    function swap(uint256 amountIn) external {\n        router.exactInputSingle(ISwapRouter.ExactInputSingleParams({tokenIn: a, tokenOut: b, fee: 3000, recipient: msg.sender, deadline: block.timestamp, amountIn: amountIn, amountOutMinimum: 0, sqrtPriceLimitX96: 0}));\n    }\n}";
        assert_eq!(detect_router_slippage_validation(v3, "t.sol").len(), 1);
    }

    #[test]
    fn eth_swap_uses_first_argument() {
        let safe = "contract C {\n    function swap(uint256 amountOutMin, address[] calldata path) external payable {\n        router.swapExactETHForTokens{value: msg.value}(amountOutMin, path, msg.sender, block.timestamp);\n    }\n}";
        assert!(detect_router_slippage_validation(safe, "t.sol").is_empty());
    }
}
