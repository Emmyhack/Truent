//! Detector for oracle self-trade manipulation vulnerabilities.
//!
//! This detector identifies when oracle prices can be manipulated by user trades
//! within the same transaction or block. This pattern was exploited in H17 Mango Markets
//! ($117M, 2023) where users could liquidate themselves at manipulated prices.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::Finding;

lazy_static! {
    /// Regex to match external function definitions
    static ref EXTERNAL_FUNC_REGEX: Regex =
        Regex::new(r"(?i)function\s+\w+\s*\([^)]*\)\s*(external|public)").unwrap();

    /// Regex to match an actual read from an external price source.
    ///
    /// This previously matched the bare words `price|exchange|rate|twap|spot`
    /// anywhere in the function window, so any contract with a `priceOf()`
    /// getter — or merely the word "price" in a comment — was reported as a
    /// CRITICAL oracle manipulation. The vulnerability requires reading a
    /// price from a *manipulable external source*; a price derived from the
    /// contract's own state is a different thing entirely. Matching the call
    /// shapes of the real oracle interfaces keeps that distinction.
    static ref ORACLE_PRICE_REGEX: Regex = Regex::new(concat!(
        // External feeds.
        r"(?i)(latestRoundData|latestAnswer|getRoundData|\bAggregatorV\d|\bIAggregator",
        r"|getPriceUnsafe|getPriceNoOlderThan|getEmaPrice|\bIPyth",
        r"|\bconsult\s*\(|\bobserve\s*\(|getReserves\s*\(\s*\)",
        r"|\boracle\s*\.|\bpriceFeed\s*\.|\bpriceOracle\s*\.|IPriceOracle|IPriceFeed",
        // A price *acquired* in the body: a call to a price getter, or a read
        // from a price mapping. Both are manipulable within a transaction.
        r"|\bget\w*[Pp]rice\w*\s*\(|\b\w*[Pp]rice\w*\s*\[|\b\w*[Rr]ate\w*\s*\[)"
    )).unwrap();

    /// Strips comments so prose about prices cannot trigger the detector.
    /// The original matched the bare word `price`, so a doc comment was
    /// enough to raise a CRITICAL on a contract with no oracle at all.
    static ref COMMENT_REGEX: Regex = Regex::new(r"(?s)//[^\n]*|/\*.*?\*/").unwrap();

    /// Regex to match user trade/swap functions
    static ref TRADE_REGEX: Regex =
        Regex::new(r"(?i)(swap|trade|execute|buy|sell)").unwrap();
}

/// Detects oracle self-trade manipulation vulnerabilities.
pub fn detect_oracle_self_trade(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Pattern 1: Find functions that both trade and use oracle prices
    for (func_line_num, func_line) in source.lines().enumerate() {
        if !EXTERNAL_FUNC_REGEX.is_match(func_line) {
            continue;
        }

        // An interface or abstract declaration has no body; there is nothing
        // to analyse and nothing to exploit.
        if func_line.trim_end().ends_with(';') {
            continue;
        }

        let func_name = extract_function_name(func_line);

        // The body is the *actual* function, delimited by brace depth.
        //
        // This used to be a fixed 50-line window from the declaration, which
        // bled into whatever followed: a `withdraw` function was reported as
        // an unvalidated-oracle trade because an unrelated `getPrice` happened
        // to sit six lines below it.
        let func_body = crate::detectors::textutil::enclosing_function_body(source, func_line_num);

        // Pattern 2: Check if function modifies state (trades) AND uses oracle
        let modifies_state = func_body.to_lowercase().contains("transfer")
            || func_body.to_lowercase().contains("swap")
            || func_body.to_lowercase().contains("mint")
            || func_body.to_lowercase().contains("burn");

        let code_only = COMMENT_REGEX.replace_all(&func_body, " ");
        let uses_oracle = ORACLE_PRICE_REGEX.is_match(&code_only);

        if modifies_state && uses_oracle {
            // Pattern 3: Check if oracle price is validated
            if !has_oracle_safety_checks(&func_body) {
                let message = format!(
                    "Function '{}' modifies state and uses oracle prices without safety checks. \
                     An attacker can manipulate oracle prices via self-trades or liquidate themselves \
                     at manipulated prices within the same transaction. \
                     H17 Mango Markets ($117M) was exploited when users could execute trades that \
                     moved prices against them, then liquidate their own positions at those inflated prices. \
                     \
                     Attack: \
                     1. User initiates trade in {} function \
                     2. Trade moves oracle price adversely (or spreads widen) \
                     3. User liquidates themselves at the new price within same tx \
                     4. User profits from arbitrage between transaction start/end prices \
                     \
                     Required fix: \
                     1. Use time-weighted average price (TWAP) instead of spot price \
                     2. Add max price impact check: require(priceImpact < MAX_IMPACT) \
                     3. Use external oracle (Chainlink, Pyth, Band) with staleness checks \
                     4. Add circuit breaker if price moves > threshold",
                    func_name, func_name
                );

                findings.push(
                    Finding::new(
                        "evm_oracle_self_trade".to_string(),
                        truent_core::Severity::Critical,
                        file_path.to_string(),
                        func_line_num + 1,
                        0,
                        message,
                        func_line.trim().to_string(),
                    )
                    .with_metadata("exploit_id".to_string(), "H17".to_string())
                    .with_metadata("exploit_name".to_string(), "Mango Markets".to_string())
                    .with_metadata("loss".to_string(), "$117M".to_string())
                    .with_metadata("year".to_string(), "2023".to_string())
                    .with_metadata("also_affects".to_string(), "H34 Loopscale".to_string())
                    .with_metadata(
                        "vulnerability_type".to_string(),
                        "oracle_manipulation".to_string(),
                    )
                    .with_metadata(
                        "detector".to_string(),
                        "oracle_state_interaction_check".to_string(),
                    )
                    .with_source_fragment(func_body),
                );
            }
        }
    }

    findings
}

/// Extract function name from function declaration
fn extract_function_name(line: &str) -> String {
    if let Some(start) = line.find("function ") {
        let after_function = &line[start + 9..];
        if let Some(end) = after_function.find('(') {
            return after_function[..end].trim().to_string();
        }
    }
    "execute".to_string()
}

/// Check if function has oracle safety measures
fn has_oracle_safety_checks(func_body: &str) -> bool {
    let func_lower = func_body.to_lowercase();

    let has_twap = func_lower.contains("twap") || func_lower.contains("weighted");
    let has_staleness_check = func_lower.contains("stale")
        || func_lower.contains("block.timestamp")
        || func_lower.contains("timeout")
        || func_lower.contains("updatedAt");
    let has_price_impact = func_lower.contains("impact")
        || func_lower.contains("slippage")
        || func_lower.contains("min_amount")
        || func_lower.contains("max_price");
    let has_circuit_breaker = func_lower.contains("circuit")
        || func_lower.contains("pause")
        || func_lower.contains("max_deviation")
        || func_lower.contains("deviation");

    // Need at least 2 safety measures
    [
        has_twap,
        has_staleness_check,
        has_price_impact,
        has_circuit_breaker,
    ]
    .iter()
    .filter(|&&x| x)
    .count()
        >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_oracle_self_trade() {
        let code = r#"
            function liquidate(address account) external {
                uint price = getPrice(collateral);  // Spot price
                
                // Attacker can manipulate price via swap in same tx
                swapExactTokensForTokens(collateralAmount, 1, path, address(this), block.timestamp);
                
                uint newPrice = getPrice(collateral);  // Price changed!
                
                // Liquidate at new (manipulated) price
                liquidatePosition(account, newPrice);
            }
        "#;

        let findings = detect_oracle_self_trade(code, "protocol.sol");
        assert!(
            !findings.is_empty(),
            "Should detect oracle self-trade vulnerability"
        );
        assert!(findings[0].invariant_id.contains("oracle_self_trade"));
    }

    #[test]
    fn test_vulnerable_mango_pattern() {
        let code = r#"
            contract MangoMarkets {
                function liquidate(address account) external {
                    // Get current spot price
                    uint price = spotPrice[USDC];
                    
                    // Execute large trade (doesn't move price in vulnerable version)
                    swap(1000 USDC for WETH);
                    
                    // Liquidate at potentially different price
                    uint accountHealth = calculateHealth(account, spotPrice[USDC]);
                    require(accountHealth < THRESHOLD, "Not liquidatable");
                    
                    drainCollateral(account);
                }
            }
        "#;

        let findings = detect_oracle_self_trade(code, "mango.sol");
        assert!(
            !findings.is_empty(),
            "Should detect Mango-like vulnerability"
        );
    }

    #[test]
    fn test_safe_with_twap() {
        let code = r#"
            function liquidate(address account) external {
                // Use time-weighted average price (safe)
                uint price = getTWAP(30 minutes);
                
                require(account.health < THRESHOLD, "Not liquidatable");
                drainCollateral(account);
            }
        "#;

        let findings = detect_oracle_self_trade(code, "safe.sol");
        assert!(findings.is_empty(), "Should not flag TWAP usage");
    }

    #[test]
    fn test_safe_with_staleness_and_slippage() {
        let code = r#"
            function liquidate(address account) external {
                (uint price, uint updatedAt) = priceFeed.latestRoundData();
                
                // Check staleness
                require(block.timestamp - updatedAt < MAX_STALENESS, "Stale price");
                
                // Add slippage protection
                uint minPrice = price * 95 / 100;
                uint maxPrice = price * 105 / 100;
                
                require(account.health < THRESHOLD, "Not liquidatable");
                drainCollateral(account);
            }
        "#;

        let findings = detect_oracle_self_trade(code, "safe.sol");
        assert!(findings.is_empty(), "Should detect safety checks");
    }

    #[test]
    fn test_safe_with_circuit_breaker() {
        let code = r#"
            function liquidate(address account) external {
                uint price = getPrice(collateral);
                uint priorPrice = lastPrice;
                
                // Check price deviation (circuit breaker)
                require(
                    (price * 100 / priorPrice) < 120 && (price * 100 / priorPrice) > 80,
                    "Price moved too much"
                );
                
                require(account.health < THRESHOLD);
                drainCollateral(account);
                
                lastPrice = price;
            }
        "#;

        let findings = detect_oracle_self_trade(code, "safe.sol");
        assert!(findings.is_empty(), "Should not flag with circuit breaker");
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;

    /// A contract that prices from its own reserves has no external oracle to
    /// manipulate. The detector used to match the bare word "price" anywhere in
    /// a 50-line window, so a CPMM prediction market with a `priceYes()` view
    /// and the word "price" in its comments raised six CRITICALs.
    #[test]
    fn internal_price_view_is_not_an_oracle() {
        let code = r#"
            /// @notice YES price in 1e6. NO price = 1e6 - this.
            /// A constant-product AMM prices the shares; there is no oracle.
            function priceYes(uint256 marketId) external view returns (uint256) {
                Market storage m = markets[marketId];
                uint256 denom = m.rYes + m.rNo;
                if (denom == 0) return 0;
                return (m.rNo * 1e6) / denom;
            }

            function buy(uint256 marketId, uint8 side, uint256 usdcIn) external returns (uint256) {
                // Complete set mint: the price moves with the reserves.
                _mintShares(marketId, side, msg.sender, sharesOut);
                usdc.transferFrom(msg.sender, address(this), usdcIn);
                return sharesOut;
            }
        "#;
        assert!(
            detect_oracle_self_trade(code, "market.sol").is_empty(),
            "a price derived from internal reserves is not an oracle read"
        );
    }

    /// Comments must never be enough on their own.
    #[test]
    fn prose_about_prices_does_not_trigger() {
        let code = r#"
            // This function does not use any oracle, price feed, spot price,
            // exchange rate or twap. It just moves tokens.
            function send(address to, uint256 amount) external {
                token.transfer(to, amount);
            }
        "#;
        assert!(detect_oracle_self_trade(code, "t.sol").is_empty());
    }

    /// The true positives must survive the tightening.
    #[test]
    fn real_external_feed_still_detected() {
        let code = r#"
            function swapAtOraclePrice(uint256 amt) external {
                (, int256 answer,,,) = priceFeed.latestRoundData();
                uint256 out = amt * uint256(answer);
                token.transfer(msg.sender, out);
            }
        "#;
        assert!(!detect_oracle_self_trade(code, "t.sol").is_empty());
    }
}
