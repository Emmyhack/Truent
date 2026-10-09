/// EVM Constructor Race Condition Detector
///
/// Detects H46 vulnerability: Initialization logic callable after deployment
///
/// The vulnerability occurs when:
/// 1. Constructor logic can be called via public/external functions
/// 2. No initialized flag to prevent re-initialization
/// 3. Attacker can reinitialize contract to reset state
/// 4. Can steal ownership or reset balances
///
use lazy_static::lazy_static;
use regex::Regex;
use truent_core::Finding;

lazy_static! {
    static ref CONSTRUCTOR: Regex = Regex::new(r"(?i)constructor\s*\(").unwrap();
    static ref INITIALIZATION_FUNCTION: Regex =
        Regex::new(r"function\s+(initialize|init|configure|setOwner|setup)\s*\(").unwrap();
    static ref INIT_FLAG: Regex =
        Regex::new(r"(?i)initialized|_initialized|hasInitialized|init_flag").unwrap();
    static ref REQUIRE_NOT_INIT: Regex =
        Regex::new(r"(?i)require\s*\(\s*!.*?initialized|require\s*\(\s*!.*?_initialized").unwrap();
    static ref INITIALIZER_MODIFIER: Regex =
        Regex::new(r"(?i)\binitializer\b|\bonlyInitializing\b").unwrap();
}

pub fn detect_constructor_race_condition(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    for (line_num, line) in lines.iter().enumerate() {
        if line.trim().starts_with("//") || !INITIALIZATION_FUNCTION.is_match(line) {
            continue;
        }
        // `setUp()` is Foundry's test hook; `setup()` only counts as an
        // initializer when it is externally callable.
        if line.contains("setUp")
            || (line.contains("setup") && !line.contains("external") && !line.contains("public"))
        {
            continue;
        }

        // Check if this line or the following context has the initializer modifier
        let has_initializer_modifier = INITIALIZER_MODIFIER.is_match(line);

        let context_end = std::cmp::min(line_num + 150, lines.len());
        let function_body = lines[line_num..context_end].join("\n");

        let has_init_check = REQUIRE_NOT_INIT.is_match(&function_body);

        // Check if this is in a proxy context (has initialize pattern)
        if !has_init_check && !has_initializer_modifier {
            findings.push(
                Finding::new(
                    "evm_constructor_race_condition".to_string(),
                    truent_core::Severity::Medium,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "Initialization function lacks re-entrancy check. Add require(!initialized) to prevent re-initialization attacks.".to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("exploit_id".to_string(), "H46".to_string())
                .with_metadata("exploit_name".to_string(), "Constructor Race".to_string())
                .with_metadata("loss".to_string(), "$0.9M".to_string())
                .with_metadata("year".to_string(), "2023".to_string())
                .with_metadata("vulnerability_type".to_string(), "initialization_race".to_string())
                .with_metadata("detector".to_string(), "pattern_analysis".to_string())
                .with_metadata("remediation".to_string(), "Add require(!initialized) and set initialized = true".to_string()),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_initialization_guard() {
        let vulnerable = r#"
        function initialize(address owner, uint256 supply) external {
            contractOwner = owner;
            totalSupply = supply;
        }
        "#;
        let findings = detect_constructor_race_condition(vulnerable, "test.sol");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_with_initialized_check() {
        let safe = r#"
        function initialize(address owner, uint256 supply) external {
            require(!initialized, "Already initialized");
            contractOwner = owner;
            totalSupply = supply;
            initialized = true;
        }
        "#;
        let findings = detect_constructor_race_condition(safe, "test.sol");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_with_initializer_modifier() {
        let safe = r#"
        function initialize(address owner) external initializer {
            _owner = owner;
        }
        "#;
        let findings = detect_constructor_race_condition(safe, "test.sol");
        assert!(findings.is_empty()); // initializer modifier provides protection
    }

    #[test]
    fn test_init_function_unguarded() {
        let vulnerable = r#"
        function init(uint256 amount) external {
            balance = amount;
            admin = msg.sender;
        }
        "#;
        let findings = detect_constructor_race_condition(vulnerable, "test.sol");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_setup_with_guard() {
        let safe = r#"
        function setup(address newAdmin) external {
            require(!_initialized, "Setup already done");
            admin = newAdmin;
            _initialized = true;
        }
        "#;
        let findings = detect_constructor_race_condition(safe, "test.sol");
        assert!(findings.is_empty());
    }
}
