//! Detector for missing post-state health checks in lending protocols.
//!
//! This detector identifies when state-modifying functions in lending/collateral
//! contracts don't verify account health after state updates. This pattern was
//! exploited in H19 Euler Finance ($197M, 2023) and H11 Cream Finance V2 ($130M, 2021).

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::Finding;

lazy_static! {
    /// Patterns that indicate a function modifies critical financial state
    static ref STATE_MODIFICATION_PATTERNS: Vec<&'static str> = vec![
        "collateral",
        "debt",
        "borrow",
        "principal",
        "balance",
        "reserve",
        "supply",
        "borrowed",
    ];

    /// Patterns that indicate health check verification
    static ref HEALTH_CHECK_PATTERNS: [&'static str; 12] = [
        "checkHealth",
        "isHealthy",
        "health",
        "checkLiquidity",
        "checkCollateral",
        "liquidity",
        "getHealthFactor",
        "healthFactor",
        "require.*health",
        "require.*liquidity",
        "MIN_HEALTH",
        "healthThreshold",
    ];

    /// Regex for external/public functions
    static ref FUNCTION_REGEX: Regex =
        Regex::new(r"(?i)\bfunction\s+\w+\s*\([^)]*\)\s*(public|external)").unwrap();

    /// Regex for state modifications
    static ref STATE_MOD_REGEX: Regex =
        Regex::new(r"(?i)collateral|debt|borrow|reserve|balance").unwrap();
}

/// Detects missing health checks after state modifications in lending protocols.
pub fn detect_missing_health_check(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Pattern 1: Is this actually a lending market?
    //
    // The gate used to be `contains("collateral") || contains("health") || ...`,
    // any single keyword. "collateral" alone is not lending — a prediction
    // market, an escrow, or an options vault all hold collateral without ever
    // lending against it, and every public function in those contracts was
    // flagged CRITICAL for missing a health check it has no reason to have.
    //
    // A post-state health check only means something where value can be
    // *borrowed* against deposited value, so require evidence of a debt
    // position, plus a second corroborating signal.
    let lower = source.to_lowercase();
    let has_debt_concept = [
        "borrow",
        "debt",
        "liquidat",
        "healthfactor",
        "health_factor",
    ]
    .iter()
    .any(|k| lower.contains(k));
    let corroborating = [
        "collateral",
        "ltv",
        "loan",
        "interest",
        "utilization",
        "solvency",
        "undercollateral",
    ]
    .iter()
    .filter(|k| lower.contains(*k))
    .count();

    if !has_debt_concept || corroborating == 0 {
        return findings;
    }

    // Pattern 2: Find state-modifying functions
    let _source_lower = source.to_lowercase();

    for (func_line_num, func_line) in source.lines().enumerate() {
        let line_lower = func_line.to_lowercase();

        // Look for function declarations
        if !line_lower.contains("function")
            || (!line_lower.contains("public") && !line_lower.contains("external"))
        {
            continue;
        }

        let func_name = extract_function_name(func_line);
        if func_name.is_empty() {
            continue;
        }

        // The actual function, delimited by brace depth — not a fixed window
        // that bleeds into whatever follows.
        let func_body = crate::detectors::textutil::enclosing_function_body(source, func_line_num);

        let func_body_lower = func_body.to_lowercase();

        // Pattern 3: Check if function modifies critical state
        let modifies_state = func_body_lower.contains("collateral")
            || func_body_lower.contains("debt")
            || func_body_lower.contains("borrow")
            || func_body_lower.contains("reserve")
            || func_body_lower.contains("balance");

        if !modifies_state {
            continue;
        }

        // Pattern 4: Check if function has health check before return
        if !has_health_check_before_return(&func_body) {
            let message = format!(
                "Missing health check after state modification in {}(). \
                 Function modifies collateral/debt/balance but does not verify \
                 account health before returning. This pattern was exploited in \
                 H19 Euler Finance ($197M) when users could donate collateral \
                 without triggering a health check, then self-liquidate at profit. \
                 \
                 Required fix: Add health check validation (e.g., require(isHealthy(msg.sender))) \
                 before the function returns.",
                func_name
            );

            findings.push(
                Finding::new(
                    "evm_missing_post_state_health_check".to_string(),
                    truent_core::Severity::Critical,
                    file_path.to_string(),
                    func_line_num + 1,
                    0,
                    message,
                    func_line.trim().to_string(),
                )
                .with_metadata("exploit_id".to_string(), "H19".to_string())
                .with_metadata("exploit_name".to_string(), "Euler Finance".to_string())
                .with_metadata("loss".to_string(), "$197M".to_string())
                .with_metadata("year".to_string(), "2023".to_string())
                .with_metadata(
                    "also_affects".to_string(),
                    "H11 Cream Finance V2 ($130M, 2021)".to_string(),
                )
                .with_metadata("detector".to_string(), "pattern_analysis".to_string())
                .with_source_fragment(func_body),
            );
        }
    }

    findings
}

/// Check if contract contains lending-related functions
#[allow(dead_code)]
fn is_lending_like_contract(source: &str) -> bool {
    let lending_functions = vec![
        "borrow",
        "liquidate",
        "deposit",
        "withdraw",
        "repay",
        "lend",
        "collateral",
        "health",
        "liquidation",
    ];

    let source_lower = source.to_lowercase();
    lending_functions
        .iter()
        .filter(|func| source_lower.contains(**func))
        .count()
        >= 2
}

/// Extract function name from function declaration
fn extract_function_name(line: &str) -> String {
    let line_lower = line.to_lowercase();
    if let Some(start) = line_lower.find("function ") {
        let after_function = &line[start + 9..];
        let line_lower_after = &line_lower[start + 9..];
        if let Some(end) = line_lower_after.find('(') {
            return after_function[..end].trim().to_string();
        }
    }
    String::new()
}

/// Check if function has health check before return statements
fn has_health_check_before_return(func_body: &str) -> bool {
    // Remove comments from analysis
    let mut cleaned = String::new();
    let mut in_comment = false;
    let mut chars = func_body.chars().peekable();

    while let Some(ch) = chars.next() {
        if !in_comment && ch == '/' && chars.peek() == Some(&'/') {
            // Single line comment - skip until newline
            in_comment = true;
            chars.next(); // consume the second /
            continue;
        }
        if in_comment && ch == '\n' {
            in_comment = false;
            cleaned.push('\n');
            continue;
        }
        if !in_comment {
            cleaned.push(ch);
        }
    }

    let func_lower = cleaned.to_lowercase();

    // Check 1: Direct function calls for health checks (e.g., _checkLiquidity, isHealthy)
    if func_lower.contains("_checkliquidity")
        || func_lower.contains("_checkhealth")
        || func_lower.contains("_checkcollateral")
        || func_lower.contains("ishealthy")
        || func_lower.contains("issolvable")
        || func_lower.contains("checkcollateral")
    {
        return true;
    }

    // Check 2: Require/assert statements with health keywords (may be multiline)
    if func_lower.contains("require(") || func_lower.contains("assert(") {
        // Look for patterns like require(...calculateHealthFactor or require(isHealthy
        if func_lower.contains("calculatehealthfactor")
            || func_lower.contains("health_factor")
            || func_lower.contains("healthfactor")
            || func_lower.contains("ishealthy")
            || func_lower.contains("min_health")
            || (func_lower.contains("require(") && func_lower.contains("liquidity"))
            || (func_lower.contains("require(")
                && func_lower.contains("collateral")
                && func_lower.contains("min"))
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_donation_pattern_euler() {
        let code = r#"
            contract Euler {
                mapping(address => uint) collateral;
                mapping(address => uint) debt;

                function donateToReserves(uint amount) external {
                    require(msg.sender == owner, "Not owner");
                    collateral[msg.sender] -= amount;
                    reserves.balance += amount;
                    // MISSING: require(isHealthy(msg.sender))
                }
            }
        "#;

        let findings = detect_missing_health_check(code, "test.sol");
        assert!(!findings.is_empty(), "Should detect missing health check");
        assert_eq!(findings[0].severity, truent_core::Severity::Critical);
        assert!(findings[0].invariant_id.contains("health_check"));
    }

    #[test]
    fn test_safe_with_health_check() {
        let code = r#"
            contract SafeProtocol {
                function deposit(uint amount) external {
                    collateral[msg.sender] += amount;
                    reserves -= amount;
                    require(
                        calculateHealthFactor(msg.sender) >= MIN_HEALTH,
                        "Account would be unhealthy"
                    );
                }
            }
        "#;

        let findings = detect_missing_health_check(code, "test.sol");
        assert!(
            findings.is_empty(),
            "Should not flag when health check present"
        );
    }

    #[test]
    fn test_safe_with_liquidity_check() {
        let code = r#"
            contract SafeProtocol {
                function borrow(uint amount) external {
                    debt[msg.sender] += amount;
                    _checkLiquidity(msg.sender);
                }
            }
        "#;

        let findings = detect_missing_health_check(code, "test.sol");
        assert!(findings.is_empty(), "Should not flag with _checkLiquidity");
    }

    #[test]
    fn test_non_financial_contract() {
        let code = r#"
            contract ERC20 {
                function transfer(address to, uint amount) external {
                    balances[msg.sender] -= amount;
                    balances[to] += amount;
                }
            }
        "#;

        let findings = detect_missing_health_check(code, "test.sol");
        assert!(findings.is_empty(), "Should not flag non-lending contracts");
    }

    #[test]
    fn test_safe_with_implicit_health_check() {
        let code = r#"
            contract SafeProtocol {
                function donateToReserves(uint amount) external {
                    collateral[msg.sender] -= amount;
                    reserves += amount;
                    require(isHealthy(msg.sender), "Health check failed");
                }
            }
        "#;

        let findings = detect_missing_health_check(code, "test.sol");
        assert!(
            findings.is_empty(),
            "Should detect implicit isHealthy check"
        );
    }
}

#[cfg(test)]
mod trust_regression_tests {
    use super::*;

    /// Holding collateral is not lending. A prediction market, escrow or
    /// options vault all use the word without ever lending against it — and
    /// every public function in them was flagged CRITICAL for missing a health
    /// check that does not apply.
    #[test]
    fn collateral_alone_is_not_a_lending_market() {
        let src = r#"
            contract PredictionMarket {
                uint256 public collateral;
                function buy(uint256 amt) external {
                    collateral += amt;
                    _mintShares(msg.sender, amt);
                }
                function redeem(uint256 amt) external {
                    collateral -= amt;
                    _credit(msg.sender, amt);
                }
            }
        "#;
        assert!(
            detect_missing_health_check(src, "m.sol").is_empty(),
            "no borrowing, no debt, no liquidation — not a lending market"
        );
    }

    /// A real lending market must still be checked.
    #[test]
    fn actual_lending_market_is_still_checked() {
        let src = r#"
            contract Lending {
                mapping(address => uint256) public collateral;
                mapping(address => uint256) public debt;
                function borrow(uint256 amt) external {
                    debt[msg.sender] += amt;
                    token.transfer(msg.sender, amt);
                }
                function liquidate(address user) external {
                    debt[user] = 0;
                    collateral[user] = 0;
                }
            }
        "#;
        assert!(
            !detect_missing_health_check(src, "l.sol").is_empty(),
            "borrow + debt + liquidate + collateral is unambiguously lending"
        );
    }
}
