//! Detector for DVN (Designated Verifier Network) single point of failure vulnerabilities.
//!
//! This detector identifies when DVN configurations allow a single DVN, creating
//! a critical single point of failure. This pattern was exploited in H47 KelpDAO/LayerZero
//! ($292M, 2026) where only 1 DVN was configured.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::Finding;

lazy_static! {
    /// Regex to match DVN array/mapping declarations
    static ref DVN_ARRAY_REGEX: Regex =
        Regex::new(r"(?i)(dvn|verifier|validator)\s*(\[|\(|:)").unwrap();

    /// Regex to match DVN count constraints
    static ref DVN_COUNT_REGEX: Regex =
        Regex::new(r"(?i)(require|assert)\s*\(\s*dvn.*\.length|dvnCount|num.*dvn").unwrap();

    /// Regex to match DVN set/add functions
    static ref DVN_SETTER_REGEX: Regex =
        Regex::new(r"(?i)function\s+(set|add|update|configure)\s*DVN").unwrap();
}

/// Detects DVN single point of failure in LayerZero and similar bridge protocols.
pub fn detect_dvn_single_point_failure(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Pattern 1: Find DVN configuration functions
    for (func_line_num, func_line) in source.lines().enumerate() {
        if !DVN_SETTER_REGEX.is_match(func_line)
            && !func_line.to_lowercase().contains("setdvn")
            && !func_line.to_lowercase().contains("adddvn")
        {
            continue;
        }

        let func_name = extract_function_name(func_line);

        // The actual function, delimited by brace depth — not a fixed window
        // that bleeds into whatever follows.
        let func_body = crate::detectors::textutil::enclosing_function_body(source, func_line_num);

        // Pattern 2: Check if function allows unconstrained DVN count
        if allows_single_dvn(&func_body) {
            let message = format!(
                "DVN configuration function '{}' allows single DVN without minimum count enforcement. \
                 This creates a critical single point of failure. H47 KelpDAO ($292M) was exploited \
                 when only 1 DVN was configured, causing a complete bridge compromise. \
                 \
                 An attacker controlling or compromising the single DVN could forge any cross-chain message. \
                 \
                 Required fix: Enforce minimum DVN count: \
                 require(dvns.length >= 2, \"Minimum 2 DVNs required\"); \
                 Recommended: Require at least 5 independent DVNs for production.",
                func_name
            );

            findings.push(
                Finding::new(
                    "evm_dvn_single_point_failure".to_string(),
                    truent_core::Severity::Critical,
                    file_path.to_string(),
                    func_line_num + 1,
                    0,
                    message,
                    func_line.trim().to_string(),
                )
                .with_metadata("exploit_id".to_string(), "H47".to_string())
                .with_metadata("exploit_name".to_string(), "KelpDAO/LayerZero".to_string())
                .with_metadata("loss".to_string(), "$292M".to_string())
                .with_metadata("year".to_string(), "2026".to_string())
                .with_metadata(
                    "vulnerability_type".to_string(),
                    "single_point_failure".to_string(),
                )
                .with_metadata(
                    "detector".to_string(),
                    "configuration_validation".to_string(),
                )
                .with_source_fragment(func_body),
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
    "setDVN".to_string()
}

/// Check if DVN configuration allows single DVN without validation
fn allows_single_dvn(func_body: &str) -> bool {
    let func_lower = func_body.to_lowercase();

    // Red flag: Has DVN assignment/setting but no minimum length check
    let has_dvn_operation = func_lower.contains("dvn[")
        || func_lower.contains("dvns.push")
        || func_lower.contains("dvns =")
        || func_lower.contains("dvn_list")
        || func_lower.contains("verifiers");

    if !has_dvn_operation {
        return false;
    }

    // Check if there's NO minimum count enforcement
    let has_minimum_check = func_lower.contains("length >=")
        || func_lower.contains("length > 0")
        || func_lower.contains("require(dvn")
        || func_lower.contains("require(verifier")
        || func_lower.contains("dvn_count")
        || func_lower.contains("min_dvn");

    !has_minimum_check
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_single_dvn_kelp_dao() {
        let code = r#"
            contract LayerZeroBridge {
                address[] public dvns;
                
                function setDVN(address newDVN) external onlyAdmin {
                    dvns = new address[](1);
                    dvns[0] = newDVN;  // VULNERABLE: Only 1 DVN allowed!
                }
                
                function verify(bytes calldata proof) external view returns (bool) {
                    return dvns[0].call(proof);  // Single point of failure!
                }
            }
        "#;

        let findings = detect_dvn_single_point_failure(code, "bridge.sol");
        assert!(
            !findings.is_empty(),
            "Should detect single DVN vulnerability"
        );
        assert!(findings[0].invariant_id.contains("dvn_single_point"));
    }

    #[test]
    fn test_vulnerable_unconstrained_dvn() {
        let code = r#"
            contract OFT {
                address[] public dvns;
                
                function addDVN(address dvn) external onlyAdmin {
                    dvns.push(dvn);  // No minimum check!
                }
            }
        "#;

        let findings = detect_dvn_single_point_failure(code, "oft.sol");
        assert!(!findings.is_empty(), "Should detect unconstrained DVN");
    }

    #[test]
    fn test_safe_with_minimum_dvn_check() {
        let code = r#"
            contract SafeBridge {
                address[] public dvns;
                uint constant MIN_DVNS = 3;
                
                function setDVN(address[] calldata newDVNs) external onlyAdmin {
                    require(newDVNs.length >= MIN_DVNS, "Insufficient DVN count");
                    dvns = newDVNs;
                }
            }
        "#;

        let findings = detect_dvn_single_point_failure(code, "bridge.sol");
        assert!(
            findings.is_empty(),
            "Should not flag when minimum DVN check present"
        );
    }

    #[test]
    fn test_safe_with_inline_length_check() {
        let code = r#"
            contract SafeBridge {
                address[] public verifiers;
                
                function setVerifiers(address[] calldata newVerifiers) external {
                    require(newVerifiers.length >= 2, "Need at least 2 verifiers");
                    verifiers = newVerifiers;
                }
            }
        "#;

        let findings = detect_dvn_single_point_failure(code, "bridge.sol");
        assert!(findings.is_empty(), "Should detect length >= 2 check");
    }

    #[test]
    fn test_vulnerable_no_check_pattern() {
        let code = r#"
            contract VulnerableBridge {
                address[] public dvn_list;
                
                function configureDVN(address[] calldata dvns) external {
                    dvn_list = dvns;  // No validation at all!
                }
            }
        "#;

        let findings = detect_dvn_single_point_failure(code, "bridge.sol");
        assert!(
            !findings.is_empty(),
            "Should detect unconstrained configuration"
        );
    }
}
