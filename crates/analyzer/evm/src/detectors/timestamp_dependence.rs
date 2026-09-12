//! Block-value dependence (CWE-829, SWC-116).
//!
//! `block.timestamp` and `block.number` are set by the block producer within
//! a tolerance, and `blockhash`/`prevrandao` are known before a transaction
//! is included. Using any of them as a **source of randomness** or in a
//! **strict equality** gives the producer — or anyone who can see the pending
//! block — control over the outcome.
//!
//! Comparing a timestamp against a deadline (`block.timestamp <= deadline`,
//! `>= readyAt`) is the normal, correct use and is deliberately not reported:
//! permits, timelocks and vesting all depend on it.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

lazy_static! {
    static ref BLOCK_VALUE: Regex =
        Regex::new(r"\b(block\.timestamp|block\.number|block\.prevrandao|block\.difficulty|blockhash\s*\(|\bnow\b)").unwrap();

    /// A block value feeding a hash or a modulo: the randomness shape.
    static ref RANDOMNESS_USE: Regex = Regex::new(
        r"(?x)
          keccak256\s*\([^;]*\b(block\.timestamp|block\.number|block\.prevrandao|block\.difficulty|blockhash|now)\b
        | \b(block\.timestamp|block\.number|block\.prevrandao|block\.difficulty|now)\b[^;]*%\s*\w
        | uint\d*\s*\(\s*(block\.timestamp|block\.number|blockhash\s*\([^)]*\))\s*\)\s*%"
    ).unwrap();

    /// A block value in a strict equality — only satisfiable by a producer
    /// who chooses the block.
    static ref STRICT_EQUALITY: Regex = Regex::new(
        r"\b(block\.timestamp|block\.number|now)\s*(==|!=)\s*[^=]|[^=!<>]\s*(==|!=)\s*(block\.timestamp|block\.number|now)\b"
    ).unwrap();
}

pub fn detect_timestamp_dependence(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in source.lines().enumerate() {
        if !BLOCK_VALUE.is_match(line) {
            continue;
        }

        if RANDOMNESS_USE.is_match(line) {
            findings.push(finding(
                file_path,
                idx,
                line,
                Severity::High,
                "Block value used as a source of randomness: the block producer chooses it, \
                 and anyone can read it from the pending block before acting",
            ));
        } else if STRICT_EQUALITY.is_match(line) {
            findings.push(finding(
                file_path,
                idx,
                line,
                Severity::Medium,
                "Block value compared for strict equality: only a producer who sets the block \
                 to that exact value can satisfy it, so the branch is controllable or dead",
            ));
        }
    }

    findings
}

fn finding(file: &str, idx: usize, line: &str, sev: Severity, msg: &str) -> Finding {
    Finding::new(
        "evm_timestamp_dependence".to_string(),
        sev,
        file.to_string(),
        idx + 1,
        0,
        msg.to_string(),
        line.trim().to_string(),
    )
    .with_metadata("detector".to_string(), "block_value_analysis".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomness_from_block_values_is_flagged() {
        for src in [
            "uint r = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;",
            "uint winner = block.timestamp % players.length;",
            "bytes32 seed = keccak256(abi.encode(blockhash(block.number - 1)));",
            "uint r = uint(blockhash(block.number - 1)) % 10;",
        ] {
            let f = detect_timestamp_dependence(src, "c");
            assert_eq!(f.len(), 1, "{src}");
            assert_eq!(f[0].severity, Severity::High, "{src}");
        }
    }

    #[test]
    fn strict_equality_is_flagged() {
        assert_eq!(
            detect_timestamp_dependence("if (block.timestamp == deadline) {", "c").len(),
            1
        );
        assert_eq!(
            detect_timestamp_dependence("require(block.number != start);", "c").len(),
            1
        );
    }

    #[test]
    fn deadline_comparisons_are_not_flagged() {
        // The ubiquitous, correct uses. Reporting these would fire on every
        // permit, timelock and vesting contract in existence.
        for src in [
            "require(block.timestamp <= deadline, \"expired\");",
            "require(block.timestamp >= p.readyAt, \"timelocked\");",
            "p.readyAt = block.timestamp + DELAY;",
            "require(block.timestamp - updatedAt < 3600, \"stale\");",
            "uint256 elapsed = block.timestamp - start;",
            "if (block.number > lastBlock + 1) {",
        ] {
            assert!(detect_timestamp_dependence(src, "c").is_empty(), "{src}");
        }
    }
}
