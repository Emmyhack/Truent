//! Numeric and parameter hygiene: silent truncation on narrowing casts,
//! fee parameters with no upper bound, and address setters that accept zero.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use super::implementations::split_functions;
use super::textutil::code_lines;

lazy_static! {
    static ref NARROW_CAST: Regex =
        Regex::new(r"\b(u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248))\s*\(\s*([^()]+)\s*\)").unwrap();
    static ref SAFECAST: Regex = Regex::new(r"(?i)SafeCast|\.toUint\d+\s*\(|\.toInt\d+\s*\(").unwrap();
    static ref BOUND_CHECK: Regex = Regex::new(r"(?i)type\s*\(\s*u?int\d+\s*\)\s*\.max").unwrap();
    static ref FUNCTION_DECL: Regex = Regex::new(r"(?i)\bfunction\s+(\w+)\s*\(([^)]*)\)").unwrap();
    static ref FEE_NAME: Regex = Regex::new(r"(?i)fee|bps|basispoints|rate|percent|commission|slippage|penalty").unwrap();
    static ref STATE_ASSIGN: Regex = Regex::new(r"^\s*(\w+(?:\[[^\]]*\])*(?:\.\w+)*)\s*=\s*(\w+)\s*;").unwrap();
    /// A plain state variable, not a struct field or a two-step "pending" slot.
    static ref PLAIN_STATE_TARGET: Regex = Regex::new(r"^\w+$").unwrap();
    static ref UPPER_BOUND: Regex = Regex::new(r"(?i)require\s*\([^;]*(<=|<)[^;]*\)|if\s*\([^;]*(>|>=)[^;]*\)\s*revert|\bMAX_|_MAX\b|\bmax\w*\b").unwrap();
    static ref ADDRESS_PARAM: Regex = Regex::new(r"(?i)\baddress\s+(?:payable\s+)?(\w+)").unwrap();
    static ref ZERO_CHECK: Regex = Regex::new(r"(?i)address\s*\(\s*0\s*\)|address\s*\(\s*0x0+\s*\)").unwrap();
    static ref ONLY_VIEW: Regex = Regex::new(r"(?i)\b(view|pure)\b").unwrap();
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
    .with_metadata("detector".to_string(), "numeric_and_params".to_string())
}

/// A narrowing cast of a non-literal, non-address expression with no
/// SafeCast and no explicit bound check in the function: high bits are
/// silently dropped, which is how packed accounting under-counts.
pub fn detect_unsafe_downcast(source: &str, file_path: &str) -> Vec<Finding> {
    if SAFECAST.is_match(source) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        if body.iter().any(|l| BOUND_CHECK.is_match(l)) {
            continue;
        }
        for (idx, line) in &span.lines {
            for c in NARROW_CAST.captures_iter(line) {
                let arg = c[2].trim();
                let literal = arg
                    .chars()
                    .all(|ch| ch.is_ascii_digit() || ch == '_' || ch == 'e');
                let lower = arg.to_ascii_lowercase();
                if literal
                    || lower.contains("address")
                    || lower.contains("msg.sender")
                    || lower.contains("this")
                {
                    continue;
                }
                out.push(finding(
                    "evm_unsafe_downcast", file_path, *idx, line, Severity::Medium,
                    "Narrowing cast truncates silently: a value above the target type's maximum wraps \
                     rather than reverting, corrupting the stored amount; use SafeCast or bound the value first",
                ));
                break;
            }
        }
    }
    out
}

/// A fee-like parameter written to state with no upper bound: an admin
/// mistake, or a compromised key, sets the fee to 100% or more.
pub fn detect_fee_parameter_unbounded(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((_, decl)) = span.lines.first() else {
            continue;
        };
        let Some(c) = FUNCTION_DECL.captures(decl) else {
            continue;
        };
        if ONLY_VIEW.is_match(decl) {
            continue;
        }
        let params: Vec<String> = c[2]
            .split(',')
            .filter_map(|p| p.split_whitespace().last())
            .map(|s| s.to_string())
            .collect();
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        if body.iter().any(|l| UPPER_BOUND.is_match(l)) {
            continue;
        }
        for (idx, line) in span.lines.iter().skip(1) {
            let Some(a) = STATE_ASSIGN.captures(line) else {
                continue;
            };
            let target = &a[1];
            let value = &a[2];
            if params.iter().any(|p| p == value)
                && FEE_NAME.is_match(target)
                && !target.contains("Recipient")
                && !target.to_ascii_lowercase().contains("address")
            {
                out.push(finding(
                    "evm_fee_parameter_unbounded", file_path, *idx, line, Severity::Medium,
                    "Fee-like parameter stored with no maximum: a typo or a compromised admin key can \
                     set it to 100% or beyond, taking every user's funds on the next operation; \
                     require it below a declared cap",
                ));
            }
        }
    }
    out
}

/// An address parameter written straight to state with no zero check.
/// A mis-sent transaction then points the protocol at nothing: fees burn,
/// an oracle reads `address(0)`, ownership is lost.
pub fn detect_missing_zero_address_check(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((_, decl)) = span.lines.first() else {
            continue;
        };
        let is_decl =
            FUNCTION_DECL.is_match(decl) || decl.to_ascii_lowercase().contains("constructor");
        if !is_decl || ONLY_VIEW.is_match(decl) {
            continue;
        }
        let addr_params: Vec<String> = ADDRESS_PARAM
            .captures_iter(decl)
            .map(|c| c[1].to_string())
            .collect();
        if addr_params.is_empty() {
            continue;
        }
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        if body.iter().any(|l| ZERO_CHECK.is_match(l)) {
            continue;
        }
        for (idx, line) in span.lines.iter().skip(1) {
            let Some(a) = STATE_ASSIGN.captures(line) else {
                continue;
            };
            let target = &a[1];
            if !PLAIN_STATE_TARGET.is_match(target)
                || target.to_ascii_lowercase().starts_with("pending")
            {
                continue;
            }
            if addr_params.iter().any(|p| *p == a[2]) {
                out.push(finding(
                    "evm_missing_zero_address_check",
                    file_path,
                    *idx,
                    line,
                    Severity::Low,
                    "Address stored without a zero check: one mistaken call leaves the protocol \
                     pointing at `address(0)` (lost ownership, burned fees, a dead oracle); \
                     require the parameter to be non-zero",
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downcast() {
        let bad =
            "contract C { function set(uint256 amount) external { stored = uint128(amount); } }";
        assert_eq!(detect_unsafe_downcast(bad, "a.sol").len(), 1);
        let bounded = "contract C { function set(uint256 amount) external { require(amount <= type(uint128).max, \"o\"); stored = uint128(amount); } }";
        assert!(detect_unsafe_downcast(bounded, "a.sol").is_empty());
        assert!(detect_unsafe_downcast("x = uint160(address(this));", "a.sol").is_empty());
    }

    #[test]
    fn fee_bounds() {
        let bad = "contract C {\n    function setFee(uint256 _fee) external onlyOwner {\n        fee = _fee;\n    }\n}";
        assert_eq!(detect_fee_parameter_unbounded(bad, "a.sol").len(), 1);
        let good = "contract C {\n    function setFee(uint256 _fee) external onlyOwner {\n        require(_fee <= MAX_FEE, \"cap\");\n        fee = _fee;\n    }\n}";
        assert!(detect_fee_parameter_unbounded(good, "a.sol").is_empty());
    }

    #[test]
    fn zero_address() {
        let bad = "contract C {\n    function setOracle(address _oracle) external onlyOwner {\n        oracle = _oracle;\n    }\n}";
        assert_eq!(detect_missing_zero_address_check(bad, "a.sol").len(), 1);
        let good = "contract C {\n    function setOracle(address _oracle) external onlyOwner {\n        require(_oracle != address(0), \"zero\");\n        oracle = _oracle;\n    }\n}";
        assert!(detect_missing_zero_address_check(good, "a.sol").is_empty());
        let mapping = "contract C {\n    function grant(address who) external {\n        roles[who] = true;\n    }\n}";
        assert!(detect_missing_zero_address_check(mapping, "a.sol").is_empty());
    }
}
