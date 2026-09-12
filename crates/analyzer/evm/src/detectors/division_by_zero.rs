//! Unguarded division (CWE-369).
//!
//! On Solidity ≥ 0.8 a zero divisor reverts with a panic rather than
//! producing a silent wrong result, so the consequence is a denial of
//! service: any function that divides by an externally-influenced quantity —
//! a pool reserve, a total supply, a caller-supplied parameter — can be made
//! to revert by driving that quantity to zero, and everything that depends on
//! the function stops working.
//!
//! Only divisions by a *bare* variable with no guard in the same function are
//! reported. A literal, a constant, a parenthesised expression with an
//! additive offset (`/ (total + 1)`) and a divisor covered by a `require`
//! or `if` check are all left alone.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::detectors::implementations::split_functions;

lazy_static! {
    /// `... / <bare identifier>` — a name, a member access or an index, not
    /// followed by an operator that would make it part of a larger expression.
    static ref BARE_DIVISOR: Regex = Regex::new(
        r"/\s*([A-Za-z_]\w*(?:\.\w+)*(?:\[[^\]]+\])?)\s*(?:[;,)\]]|$)"
    ).unwrap();

    /// Numeric literal or SCREAMING_CASE constant.
    static ref LITERAL_OR_CONST: Regex = Regex::new(r"^(\d|[A-Z][A-Z0-9_]{2,}$)").unwrap();
}

pub fn detect_division_by_zero(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<String> = source.lines().map(str::to_string).collect();

    for func in split_functions(&lines) {
        let body = func
            .lines
            .iter()
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        for (idx, line) in &func.lines {
            // `//` comments are already stripped by the entry point; `/=` and
            // `*/` are not divisions.
            let scan = line.replace("/=", "  ").replace("*/", "  ");
            for cap in BARE_DIVISOR.captures_iter(&scan) {
                let divisor = cap[1].to_string();
                if LITERAL_OR_CONST.is_match(&divisor) {
                    continue;
                }
                if is_guarded(&body, &divisor) {
                    continue;
                }
                findings.push(
                    Finding::new(
                        "evm_division_by_zero".to_string(),
                        Severity::Low,
                        file_path.to_string(),
                        idx + 1,
                        0,
                        format!(
                            "Division by `{divisor}` with no non-zero guard in this function: \
                             if it reaches zero the call reverts, and every path through \
                             this function becomes a denial of service"
                        ),
                        line.trim().to_string(),
                    )
                    .with_metadata("detector".to_string(), "arithmetic_analysis".to_string()),
                );
            }
        }
    }

    findings
}

/// Whether the function checks `name` against zero before dividing by it.
fn is_guarded(body: &str, name: &str) -> bool {
    let n = regex::escape(name);
    let guard = Regex::new(&format!(
        r"(?x)
          require\s*\(\s*{n}\s*(>|!=)\s*0
        | require\s*\(\s*{n}\s*>=\s*1
        | assert\s*\(\s*{n}\s*(>|!=)\s*0
        | if\s*\(\s*{n}\s*(==|<=|<)\s*0[^)]*\)\s*(revert|return)
        | if\s*\(\s*{n}\s*(>|!=)\s*0
        | {n}\s*(>|!=)\s*0\s*\?"
    ))
    .expect("guard regex");
    guard.is_match(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unguarded_state_divisor_is_flagged() {
        let src = "contract C {\n uint r0; uint r1;\n function p() external view returns (uint) {\n  return r1 * 1e18 / r0;\n }\n}";
        let f = detect_division_by_zero(src, "c");
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("`r0`"));
    }

    #[test]
    fn guarded_divisor_is_not_flagged() {
        let src = "contract C {\n function p(uint a, uint d) external pure returns (uint) {\n  require(d > 0, \"zero\");\n  return a / d;\n }\n}";
        assert!(detect_division_by_zero(src, "c").is_empty());
    }

    #[test]
    fn literals_constants_and_offset_expressions_are_not_flagged() {
        for src in [
            "function f(uint a) pure returns (uint) { return a / 2; }",
            "function f(uint a) pure returns (uint) { return a / 1e18; }",
            "function f(uint a) pure returns (uint) { return a / PRECISION; }",
            "function f(uint a) view returns (uint) { return a / (total + VIRTUAL); }",
            "function f(uint a) view returns (uint) { return a / (10 ** feed.decimals()); }",
        ] {
            assert!(detect_division_by_zero(src, "c").is_empty(), "{src}");
        }
    }
}
