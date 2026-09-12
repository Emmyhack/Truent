/// EVM Upgrade Path Verification Detector
///
/// Detects H47 vulnerability: Unvalidated upgrade paths in proxy contracts
///
/// The vulnerability occurs when:
/// 1. Implementation upgrade doesn't verify new code
/// 2. No storage layout validation after upgrade
/// 3. Malicious implementation can steal funds
/// 4. No time locks or governance checks on upgrades
///
use lazy_static::lazy_static;
use regex::Regex;
use truent_core::Finding;

lazy_static! {
    static ref UPGRADE_FUNCTION: Regex =
        Regex::new(r"(?i)(upgradeTo|setImplementation|updateImplementation|_setImplementation)")
            .unwrap();
    static ref NEW_IMPL_PARAM: Regex =
        Regex::new(r"(?i)newImplementation|newImpl|impl|implementation\s*:").unwrap();
    static ref IMPLEMENTATION_CHECK: Regex =
        Regex::new(r"(?i)(code\.(size|length)|ERC1967)").unwrap();
    static ref TIMELOCK_CHECK: Regex =
        Regex::new(r"(?i)timelock|\bdelay\b|pendingImplementation|schedule|readyAt|eta\b").unwrap();
    static ref HELPER_CALL: Regex = Regex::new(r"\b(_\w+)\s*\(").unwrap();
    static ref INTERFACE_CHECK: Regex =
        Regex::new(r"(?i)supportsInterface|implementsInterface|INTERFACE_ID").unwrap();
}

pub fn detect_upgrade_path_verification(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        if line.trim().starts_with("//") || !UPGRADE_FUNCTION.is_match(line) {
            continue;
        }

        // Only a function *declaration* is an upgrade path; a call to
        // `upgradeTo(...)` elsewhere is not one.
        if !line.contains("function ") {
            continue;
        }

        // The real function body, plus the bodies of any internal helpers it
        // calls with the new implementation. UUPS puts every check in
        // `_authorizeUpgrade`, so looking only at `upgradeTo` — as the old
        // 150-line window did, while also bleeding into unrelated code — saw
        // no check and reported the canonical safe pattern.
        let own_body = crate::detectors::textutil::enclosing_function_body(source, line_num);
        let function_body = with_called_helpers(source, &own_body);

        // Note: an auth modifier is *not* a substitute for validation. An
        // `onlyAdmin` upgrade with no code-size check still lets the admin
        // point the proxy at an EOA or a malicious implementation; the
        // finding is about what the new implementation is checked to be.

        let has_impl_check = IMPLEMENTATION_CHECK.is_match(&function_body);
        let has_timelock = TIMELOCK_CHECK.is_match(&function_body);
        let _has_interface = INTERFACE_CHECK.is_match(&function_body);

        if !has_impl_check && !has_timelock {
            findings.push(
                Finding::new(
                    "evm_upgrade_path_verification".to_string(),
                    truent_core::Severity::Medium,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "Upgrade function lacks implementation validation or timelock. Add code size check and delay mechanism.".to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("exploit_id".to_string(), "H47".to_string())
                .with_metadata("exploit_name".to_string(), "Unvalidated Upgrade".to_string())
                .with_metadata("loss".to_string(), "$1.2M".to_string())
                .with_metadata("year".to_string(), "2023".to_string())
                .with_metadata("vulnerability_type".to_string(), "unsafe_upgrade".to_string())
                .with_metadata("detector".to_string(), "pattern_analysis".to_string())
                .with_metadata("remediation".to_string(), "Add implementation validation and timelock delay".to_string()),
            );
        }
    }

    findings
}

/// `body` plus the source of every internal `_helper(...)` it calls, one level
/// deep — enough for `_authorizeUpgrade`, `_beforeUpgrade` and the like.
fn with_called_helpers(source: &str, body: &str) -> String {
    let mut out = body.to_string();
    let lines: Vec<&str> = source.lines().collect();
    for cap in HELPER_CALL.captures_iter(body) {
        let name = &cap[1];
        if let Some(idx) = lines
            .iter()
            .position(|l| l.contains("function ") && l.contains(&format!("{name}(")))
        {
            out.push('\n');
            out.push_str(&crate::detectors::textutil::enclosing_function_body(
                source, idx,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_upgrade_validation() {
        let vulnerable = r#"
        function upgradeTo(address newImplementation) external onlyAdmin {
            _implementation = newImplementation;
        }
        "#;
        let findings = detect_upgrade_path_verification(vulnerable, "test.sol");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_with_implementation_check() {
        let safe = r#"
        function upgradeTo(address newImplementation) external onlyAdmin {
            require(newImplementation.code.length > 0, "No code");
            _implementation = newImplementation;
        }
        "#;
        let findings = detect_upgrade_path_verification(safe, "test.sol");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_with_timelock() {
        let safe = r#"
        function upgradeTo(address newImplementation) external onlyAdmin {
            require(block.timestamp >= pendingImplementationTime + UPGRADE_DELAY, "Too soon");
            _implementation = newImplementation;
            pendingImplementationTime = 0;
        }
        "#;
        let findings = detect_upgrade_path_verification(safe, "test.sol");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_erc1967_upgrade() {
        let safe = r#"
        function upgradeTo(address newImplementation) external {
            require(ERC1967Utils.getImplementation() != address(0), "No current impl");
            ERC1967Utils.upgradeToAndCall(newImplementation, "");
        }
        "#;
        let findings = detect_upgrade_path_verification(safe, "test.sol");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_pending_implementation() {
        let safe = r#"
        function scheduleUpgrade(address newImplementation) external onlyAdmin {
            pendingImplementation = newImplementation;
            pendingImplementationTime = block.timestamp + TIMELOCK;
        }
        
        function confirmUpgrade() external onlyAdmin {
            require(block.timestamp >= pendingImplementationTime, "Too early");
            _implementation = pendingImplementation;
        }
        "#;
        let findings = detect_upgrade_path_verification(safe, "test.sol");
        assert!(findings.is_empty());
    }
}
