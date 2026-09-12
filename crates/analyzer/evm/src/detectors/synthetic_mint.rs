//! Detector for unbacked synthetic minting vulnerabilities.
//!
//! This detector identifies when synthetic tokens can be minted without sufficient
//! collateral backing. This pattern was exploited in H56 Echo Protocol ($73M, 2026).

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::Finding;

lazy_static! {
    /// Regex to match mint functions
    static ref MINT_FUNCTION_REGEX: Regex =
        Regex::new(r"(?i)function\s+(mint|mints)\s*\(").unwrap();

    /// Regex to match conservation checks
    static ref CONSERVATION_CHECK_REGEX: Regex =
        Regex::new(r"(?i)(totalMinted|totalSupply|totalBacking|totalCollateral|require|assert)").unwrap();

    /// A quantity a backing check constrains.
    static ref BACKING_QUANTITY_REGEX: Regex = Regex::new(
        r"(?i)(total_?minted|total_?collateral|total_?backing|collateral|backing|max_?mint|mint_?ratio|reserves?)"
    ).unwrap();

    /// A dedicated validation helper whose body performs the check.
    static ref BACKING_HELPER_REGEX: Regex = Regex::new(
        r"(?i)(_?check_?backing\w*|_?validate_?mint\w*|_?check_?collateral\w*|_?require_?backing\w*)\s*\("
    ).unwrap();

    /// Regex to match collateral tracking
    static ref COLLATERAL_REGEX: Regex =
        Regex::new(r"(?i)(collateral|backing|reserve|deposit)").unwrap();
}

/// Detects unbacked synthetic minting vulnerabilities.
pub fn detect_unbacked_synthetic_mint(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // A mint is only "unbacked" if there is something it should be backed
    // by. A plain token whose `mint` is role-gated tracks no collateral, and
    // asking it for a conservation check is a category error — it used to be
    // reported as CRITICAL on every AccessControl-style token.
    if !mentions_collateral(source) {
        return findings;
    }

    // Pattern 1: Find mint functions
    for (func_line_num, func_line) in source.lines().enumerate() {
        if !MINT_FUNCTION_REGEX.is_match(func_line) {
            continue;
        }

        let func_name = extract_function_name(func_line);

        // The actual function, delimited by brace depth — not a fixed window
        // that bleeds into whatever follows.
        let func_body = crate::detectors::textutil::enclosing_function_body(source, func_line_num);

        // Pattern 2: Check if there's collateral requirement
        if !checks_backing_requirement(&func_body) {
            let message = format!(
                "Minting function '{}' does not verify collateral backing before minting. \
                 Synthetic tokens must be backed by sufficient collateral. \
                 H56 Echo Protocol ($73M) was exploited when 100M eEGG tokens were minted \
                 without any backing check, allowing attackers to drain collateral. \
                 \
                 Example attack: \
                 1. Deposit 1 ETH as collateral \
                 2. Mint 1,000 synthetic tokens (no backing check) \
                 3. Drain all collateral while keeping synthetic tokens \
                 \
                 Required fix: Verify conservation invariant: \
                 require(totalMinted <= totalCollateral * MAX_MINTING_RATIO, \"Insuffcient backing\");",
                func_name
            );

            findings.push(
                Finding::new(
                    "evm_unbacked_synthetic_mint".to_string(),
                    truent_core::Severity::Critical,
                    file_path.to_string(),
                    func_line_num + 1,
                    0,
                    message,
                    func_line.trim().to_string(),
                )
                .with_metadata("exploit_id".to_string(), "H56".to_string())
                .with_metadata("exploit_name".to_string(), "Echo Protocol".to_string())
                .with_metadata("loss".to_string(), "$73M".to_string())
                .with_metadata("year".to_string(), "2026".to_string())
                .with_metadata(
                    "vulnerability_type".to_string(),
                    "unbacked_mint".to_string(),
                )
                .with_metadata(
                    "detector".to_string(),
                    "conservation_invariant_check".to_string(),
                )
                .with_source_fragment(func_body),
            );
        }
    }

    // Pattern 3: the contract mints a collateral-backed asset but carries no
    // conservation check anywhere.
    //
    // This previously fired on *every* contract without a conservation check —
    // a plain ERC-20, an interface, a library — reporting a HIGH at line 1
    // with a fabricated code snippet. It is now gated on the contract actually
    // being a collateralised minting contract, and anchored to the mint
    // function so the finding points at real source.
    if let Some((mint_line_num, mint_line)) = first_mint_function(source) {
        if mentions_collateral(source) && !has_conservation_check(source) {
            findings.push(
                Finding::new(
                    "evm_unbacked_synthetic_mint".to_string(),
                    truent_core::Severity::High,
                    file_path.to_string(),
                    mint_line_num + 1,
                    0,
                    "Contract mints a collateral-backed asset but has no conservation \
                     invariant anywhere. Without a check that totalMinted stays within \
                     totalCollateral * MAX_RATIO, supply can outrun backing."
                        .to_string(),
                    mint_line.trim().to_string(),
                )
                .with_metadata("exploit_id".to_string(), "H56".to_string())
                .with_metadata(
                    "vulnerability_type".to_string(),
                    "missing_conservation_invariant".to_string(),
                )
                .with_metadata(
                    "detector".to_string(),
                    "architecture_level_check".to_string(),
                ),
            );
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
    "mint".to_string()
}

/// Check if function verifies collateral backing before minting
fn checks_backing_requirement(func_body: &str) -> bool {
    // This used to count how many backing-related *keywords* appeared anywhere
    // in a 40-line window, comments included, and call the function safe at
    // three or more. The result was exactly backwards: a function whose
    // comments read `// No backing check!` and `// drain collateral` scored
    // three and was judged checked, so the detector stayed silent precisely
    // where the code admitted the bug.
    //
    // A backing check is now a *check construct* — require/assert/revert-if —
    // that constrains a backing quantity. Comments and revert strings are
    // stripped first, so prose can neither create nor suppress a finding.
    let code = crate::detectors::textutil::code_lines(func_body).join("\n");
    let lower = code.to_lowercase();

    for (idx, _) in lower
        .match_indices("require(")
        .chain(lower.match_indices("assert("))
    {
        // Look at the condition, not the whole function.
        let tail = &lower[idx..];
        let end = tail.find(';').unwrap_or(tail.len());
        if BACKING_QUANTITY_REGEX.is_match(&tail[..end]) {
            return true;
        }
    }

    // `if (totalMinted > cap) revert ...` is the same check in modern form.
    for (idx, _) in lower
        .match_indices("if (")
        .chain(lower.match_indices("if("))
    {
        let tail = &lower[idx..];
        let end = tail.find('{').unwrap_or(tail.len());
        let condition = &tail[..end];
        if BACKING_QUANTITY_REGEX.is_match(condition)
            && (tail[end..].contains("revert") || tail[end..].contains("require"))
        {
            return true;
        }
    }

    // A dedicated validation helper counts, since its body is the check.
    BACKING_HELPER_REGEX.is_match(&lower)
}

/// Check if contract has any conservation checks
/// The first `function mint(...)` in the source, as `(line index, line)`.
///
/// Matched against code only, so a mint function mentioned in a comment or a
/// revert string does not count.
fn first_mint_function(source: &str) -> Option<(usize, String)> {
    crate::detectors::textutil::code_lines(source)
        .into_iter()
        .enumerate()
        .find(|(_, line)| MINT_FUNCTION_REGEX.is_match(line))
}

/// Whether the contract tracks collateral, backing, reserves or deposits.
///
/// A minting contract that references none of these is not a synthetic-asset
/// contract, and a conservation invariant is not a meaningful expectation.
fn mentions_collateral(source: &str) -> bool {
    let code = crate::detectors::textutil::code_lines(source).join("\n");
    COLLATERAL_REGEX.is_match(&code)
}

fn has_conservation_check(source: &str) -> bool {
    let source_lower = source.to_lowercase();

    // Look for actual conservation check patterns in code, not just keywords in comments
    // NOTE: Removed bare "totalMinted && totalCollateral" check because they appear in
    // comments explaining the LACK of checks (e.g., "No conservation check that totalMinted <= totalCollateral")

    // Check for actual require/assert statements checking conservation
    source_lower.contains("require(totalminted")
        || source_lower.contains("require(total_minted")
        || source_lower.contains("assert(totalminted")
        || source_lower.contains("assert(total_minted")
        || source_lower.contains("require(totalcollateral")
        || source_lower.contains("require(total_collateral")
        || (source_lower.contains("require(")
            && source_lower.contains("minted")
            && source_lower.contains("collateral")
            && !source_lower.contains("no conservation"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_unbacked_mint_echo() {
        let code = r#"
            contract Echo {
                uint public totalMinted;
                uint public totalCollateral;

                function deposit() external payable {
                    totalCollateral += msg.value;
                }

                function mint(uint amount) external {
                    eggToken.mint(msg.sender, amount);  // No backing check!
                    totalMinted += amount;
                }

                function drain(uint amount) external {
                    // User can drain collateral while keeping minted tokens
                    totalCollateral -= amount;
                    payable(msg.sender).transfer(amount);
                }
            }
        "#;

        let findings = detect_unbacked_synthetic_mint(code, "echo.sol");
        assert!(!findings.is_empty(), "Should detect unbacked mint");
        assert!(findings[0].invariant_id.contains("unbacked_synthetic"));
    }

    #[test]
    fn test_vulnerable_no_conservation_check() {
        let code = r#"
            contract BadSynthetic {
                uint public totalCollateral;
                function mint(uint amount) external {
                    _mint(msg.sender, amount);
                    // No verification of totalSupply <= totalCollateral
                }
            }
        "#;

        let findings = detect_unbacked_synthetic_mint(code, "bad.sol");
        assert!(
            !findings.is_empty(),
            "Should detect missing conservation check"
        );
    }

    #[test]
    fn test_safe_with_backing_check() {
        let code = r#"
            contract SafeSynthetic {
                uint public totalMinted;
                uint public totalCollateral;
                uint constant MAX_RATIO = 50;  // 50% backing ratio
                
                function mint(uint amount) external {
                    require(
                        totalMinted + amount <= (totalCollateral * MAX_RATIO) / 100,
                        "Insufficient backing"
                    );
                    _mint(msg.sender, amount);
                    totalMinted += amount;
                }
            }
        "#;

        let findings = detect_unbacked_synthetic_mint(code, "safe.sol");
        assert!(findings.is_empty(), "Should not flag with backing check");
    }

    #[test]
    fn test_safe_with_collateral_verification() {
        let code = r#"
            contract SafeProtocol {
                function mint(uint amount) external {
                    uint availableCollateral = getAvailableCollateral(msg.sender);
                    require(amount <= availableCollateral, "Not enough collateral");
                    require(totalMinted + amount <= maxSupply, "Max supply exceeded");
                    _checkBackingRatio(msg.sender);
                    _mint(msg.sender, amount);
                }
            }
        "#;

        let findings = detect_unbacked_synthetic_mint(code, "safe.sol");
        assert!(findings.is_empty(), "Should detect multiple backing checks");
    }

    #[test]
    fn a_contract_that_does_not_mint_is_not_an_unbacked_mint() {
        // This replaces a test that asserted the opposite. The old contract-
        // level check fired on *every* contract lacking a conservation check —
        // a plain ERC-20, a library, this withdraw-only contract — reporting a
        // HIGH at line 1 with a fabricated snippet. The old test encoded that
        // behaviour, so it had to change with the behaviour.
        let code = r#"
            contract MissingInvariant {
                function withdraw(uint amount) external {
                    balance[msg.sender] -= amount;
                    msg.sender.transfer(amount);
                    // No conservation check that totalMinted <= totalCollateral
                }
            }
        "#;

        let findings = detect_unbacked_synthetic_mint(code, "missing.sol");
        assert!(
            findings.is_empty(),
            "a contract with no mint function cannot have an unbacked mint: {findings:?}"
        );
    }

    #[test]
    fn a_collateralised_minter_without_a_conservation_check_is_flagged() {
        // The case the contract-level check exists for, stated properly.
        let code = r#"
            contract Synth {
                uint public totalMinted;
                uint public totalCollateral;

                function deposit() external payable {
                    totalCollateral += msg.value;
                }

                function mint(uint amount) external {
                    totalMinted += amount;
                    synth.mint(msg.sender, amount);
                }
            }
        "#;

        let findings = detect_unbacked_synthetic_mint(code, "synth.sol");
        assert!(
            !findings.is_empty(),
            "an unbacked collateralised mint must be flagged"
        );
        assert!(
            findings.iter().all(|f| f.line > 1),
            "findings must point at real source, not a hardcoded line 1: {findings:?}"
        );
    }

    #[test]
    fn a_comment_can_neither_create_nor_suppress_a_finding() {
        // The backing check used to count keywords across comments, so
        // `// No backing check!` plus `// drain collateral` scored as *safe*.
        let admits_the_bug = r#"
            contract A {
                uint public totalMinted;
                uint public totalCollateral;
                function mint(uint amount) external {
                    // No backing check! anyone can drain collateral here
                    totalMinted += amount;
                }
            }
        "#;
        assert!(
            !detect_unbacked_synthetic_mint(admits_the_bug, "a.sol").is_empty(),
            "prose admitting the bug must not suppress the finding"
        );

        let actually_checked = r#"
            contract B {
                uint public totalMinted;
                uint public totalCollateral;
                function mint(uint amount) external {
                    require(totalMinted + amount <= totalCollateral * 2, "undercollateralised");
                    totalMinted += amount;
                }
            }
        "#;
        assert!(
            detect_unbacked_synthetic_mint(actually_checked, "b.sol").is_empty(),
            "a real require() on the backing quantity must count as checked"
        );
    }
}
