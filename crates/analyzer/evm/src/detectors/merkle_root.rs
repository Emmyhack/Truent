//! Detector for merkle root zero default vulnerabilities in bridge contracts.
//!
//! This detector identifies merkle root mappings that are initialized to zero
//! or lack explicit initialization. This pattern was exploited in H16 Nomad Bridge
//! ($190M, 2022) where any proof with root == 0 would pass verification.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::Finding;

lazy_static! {
    /// Regex to match merkle root mappings
    static ref MERKLE_ROOT_REGEX: Regex =
        Regex::new(r"(?i)mapping\s*\(\s*bytes32\s*=>\s*bytes32\s*\)\s*\w*\s*(\w+Root|root\w+|confirmedAt)").unwrap();

    /// Regex to match proof verification functions
    static ref VERIFY_FUNCTION_REGEX: Regex =
        Regex::new(r"(?i)function\s+(verify|validate)\w*\s*\(").unwrap();

    /// Regex for zero initialization or lack thereof
    static ref ZERO_INIT_REGEX: Regex =
        Regex::new(r"(?i)=\s*0\s*;|bytes32\s+\w+\s*;").unwrap();
}

/// Detects merkle root zero default vulnerabilities in bridge/proof systems.
pub fn detect_merkle_root_zero_default(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Pattern 1: Find merkle root state variables
    for (var_line_num, var_line) in source.lines().enumerate() {
        if !is_merkle_root_var(var_line) {
            continue;
        }

        // Pattern 2: Check if initialized to zero or not initialized.
        //
        // An `immutable` or `constant` root cannot be left at zero — the
        // language requires assignment — and a root that is assigned under a
        // non-zero check anywhere in the contract is guarded. Both used to be
        // reported because the declaration line alone has no `=`.
        let lower = var_line.to_lowercase();
        if lower.contains("immutable") || lower.contains("constant") {
            continue;
        }
        if (is_zero_initialized(var_line) || is_uninitialized(var_line))
            && !assigned_with_nonzero_check(source, &extract_variable_name(var_line))
        {
            let var_name = extract_variable_name(var_line);

            let message = format!(
                "Merkle root mapping '{}' is initialized to zero or uninitialized. \
                 This allows anyone to submit a proof with root == 0 and have it accepted \
                 as valid. H16 Nomad Bridge ($190M) was completely drained when this \
                 vulnerability was exploited. An attacker could create transactions with \
                 zero merkle proofs and withdraw all bridge funds. \
                 \
                 Required fix: Initialize to a non-zero value or add explicit checks: \
                 require(proposedRoot != 0, \"Cannot set root to zero\");",
                var_name
            );

            findings.push(
                Finding::new(
                    "evm_merkle_root_zero_default".to_string(),
                    truent_core::Severity::Critical,
                    file_path.to_string(),
                    var_line_num + 1,
                    0,
                    message,
                    var_line.trim().to_string(),
                )
                .with_metadata("exploit_id".to_string(), "H16".to_string())
                .with_metadata("exploit_name".to_string(), "Nomad Bridge".to_string())
                .with_metadata("loss".to_string(), "$190M".to_string())
                .with_metadata("year".to_string(), "2022".to_string())
                .with_metadata(
                    "detector".to_string(),
                    "state_variable_analysis".to_string(),
                ),
            );
        }
    }

    // Pattern 3: Check proof verification functions for zero-root acceptance
    for (func_line_num, func_line) in source.lines().enumerate() {
        if !VERIFY_FUNCTION_REGEX.is_match(func_line) {
            continue;
        }

        let func_name = extract_function_name(func_line);

        // The actual function, delimited by brace depth — not a fixed window
        // that bleeds into whatever follows.
        let func_body = crate::detectors::textutil::enclosing_function_body(source, func_line_num);

        // Check if accepts zero root without validation
        if accepts_zero_merkle_root(&func_body) {
            let message = format!(
                "Proof verification function '{}' may accept zero merkle root without validation. \
                 Any proof with root == 0 would pass verification. \
                 H16 Nomad Bridge ($190M) was exploited when this check was missing.",
                func_name
            );

            findings.push(
                Finding::new(
                    "evm_merkle_root_zero_default".to_string(),
                    truent_core::Severity::Critical,
                    file_path.to_string(),
                    func_line_num + 1,
                    0,
                    message,
                    func_line.trim().to_string(),
                )
                .with_metadata("exploit_id".to_string(), "H16".to_string())
                .with_metadata("exploit_name".to_string(), "Nomad Bridge".to_string())
                .with_metadata("loss".to_string(), "$190M".to_string())
                .with_metadata("year".to_string(), "2022".to_string())
                .with_metadata(
                    "vulnerability_type".to_string(),
                    "zero_root_acceptance".to_string(),
                )
                .with_metadata(
                    "detector".to_string(),
                    "proof_verification_analysis".to_string(),
                )
                .with_source_fragment(func_body),
            );
        }
    }

    findings
}

/// Whether `var` is guarded by a non-zero requirement somewhere in the
/// contract (`require(root != 0)`, `require(root != bytes32(0))`,
/// `if (root == bytes32(0)) revert`).
fn assigned_with_nonzero_check(source: &str, var: &str) -> bool {
    if var.is_empty() {
        return false;
    }
    let lower = source.to_lowercase();
    let v = var.to_lowercase();
    lower.contains(&format!("{v} != 0"))
        || lower.contains(&format!("{v} != bytes32(0)"))
        || lower.contains(&format!("{v} == 0"))
        || lower.contains(&format!("{v} == bytes32(0)"))
        || lower.contains(&format!("{v}) != 0"))
        || lower.contains(&format!("{v}) != bytes32(0)"))
}

/// Check if a line is a merkle root variable declaration
fn is_merkle_root_var(line: &str) -> bool {
    let line_lower = line.to_lowercase();
    (line_lower.contains("mapping") && line_lower.contains("root"))
        || (line_lower.contains("mapping") && line_lower.contains("confirmed"))
        || (line_lower.contains("bytes32") && line_lower.contains("root"))
}

/// Check if merkle root is initialized to zero
fn is_zero_initialized(line: &str) -> bool {
    line.contains("= 0") || (line.contains("bytes32") && line.contains(";") && !line.contains("="))
}

/// Check if merkle root has no explicit initialization
fn is_uninitialized(line: &str) -> bool {
    line.contains("bytes32") && line.contains(";") && !line.contains("=")
}

/// Extract variable name from declaration
fn extract_variable_name(line: &str) -> String {
    if let Some(semi_pos) = line.rfind(';') {
        let before_semi = &line[..semi_pos];
        if let Some(space_pos) = before_semi.rfind(' ') {
            return before_semi[space_pos + 1..].trim().to_string();
        }
    }
    "root".to_string()
}

/// Extract function name from function declaration
fn extract_function_name(line: &str) -> String {
    if let Some(start) = line.find("function ") {
        let after_function = &line[start + 9..];
        if let Some(end) = after_function.find('(') {
            return after_function[..end].trim().to_string();
        }
    }
    "verify".to_string()
}

/// Check if proof verification function accepts zero root
fn accepts_zero_merkle_root(func_body: &str) -> bool {
    let func_lower = func_body.to_lowercase();

    // Check for missing zero-root validation
    // Pattern: no "!= 0" or "require" check on the root parameter

    let has_zero_check = func_lower.contains("!= 0")
        || func_lower.contains("!= bytes32(0)")
        || func_lower.contains("require(root")
        || func_lower.contains("require(_root");

    // If there's a root parameter/variable but no zero check, it's vulnerable
    (func_lower.contains("root") || func_lower.contains("merkle")) && !has_zero_check
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_zero_initialized_root() {
        let code = r#"
            contract NomadBridge {
                mapping(bytes32 => bytes32) public confirmedAt = 0;  // VULNERABLE!
                
                function verifyProof(bytes32 root, bytes calldata proof) external {
                    require(roots[root] != 0);  // Missing zero root check!
                }
            }
        "#;

        let findings = detect_merkle_root_zero_default(code, "bridge.sol");
        assert!(!findings.is_empty(), "Should detect zero-initialized root");
        assert!(findings[0].invariant_id.contains("merkle_root_zero"));
    }

    #[test]
    fn test_vulnerable_uninitialized_root() {
        let code = r#"
            contract Bridge {
                mapping(bytes32 => bytes32) public merkleRoot;  // No initialization!
                
                function verify(bytes32 root, bytes calldata proof) external returns (bool) {
                    return merkleRoot[keccak256(proof)] == root;  // Accepts zero root!
                }
            }
        "#;

        let findings = detect_merkle_root_zero_default(code, "bridge.sol");
        assert!(!findings.is_empty(), "Should detect uninitialized root");
    }

    #[test]
    fn test_safe_with_zero_check() {
        let code = r#"
            contract SafeBridge {
                mapping(bytes32 => bytes32) public merkleRoot = keccak256("initial");
                
                function verify(bytes32 root, bytes calldata proof) external returns (bool) {
                    require(root != bytes32(0), "Root cannot be zero");
                    return merkleRoot[keccak256(proof)] == root;
                }
            }
        "#;

        let findings = detect_merkle_root_zero_default(code, "bridge.sol");
        assert!(
            findings.is_empty(),
            "Should not flag when zero check is present"
        );
    }

    #[test]
    fn test_vulnerable_nomad_pattern() {
        let code = r#"
            contract NomadBridge {
                mapping(bytes32 => bool) public committedRoot;
                
                function commitRoot(bytes32 _root) external {
                    committedRoot[_root] = true;  // No zero check!
                }
                
                function verifyProof(bytes calldata proof) external returns (bool) {
                    bytes32 root = keccak256(proof);
                    return committedRoot[root];  // Accepts root = 0x0!
                }
            }
        "#;

        let findings = detect_merkle_root_zero_default(code, "bridge.sol");
        assert!(
            !findings.is_empty(),
            "Should detect Nomad-like vulnerability"
        );
    }
}
