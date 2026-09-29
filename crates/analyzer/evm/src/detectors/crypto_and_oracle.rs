//! Signature and oracle validation gaps: an `ecrecover` result never checked
//! against `address(0)`, `abi.encodePacked` over two dynamic values fed to a
//! hash, and Chainlink answers used without checking the price itself.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use super::implementations::split_functions;
use super::textutil::code_lines;

lazy_static! {
    static ref ECRECOVER_ASSIGN: Regex =
        Regex::new(r"(?i)\b(?:address\s+)?(\w+)\s*=\s*ecrecover\s*\(").unwrap();
    static ref ECRECOVER_BARE: Regex = Regex::new(r"(?i)\becrecover\s*\(").unwrap();
    static ref ZERO_ADDRESS: Regex =
        Regex::new(r"(?i)address\s*\(\s*0\s*\)|address\s*\(\s*0x0+\s*\)").unwrap();
    static ref ECDSA_LIB: Regex =
        Regex::new(r"(?i)\bECDSA\s*\.\s*(recover|tryRecover)\b|SignatureChecker").unwrap();
    static ref ENCODE_PACKED_HASH: Regex =
        Regex::new(r"(?i)keccak256\s*\(\s*abi\.encodePacked\s*\(([^;]*)\)\s*\)").unwrap();
    static ref DYNAMIC_DECL: Regex =
        Regex::new(r"(?i)\b(?:string|bytes|\w+\[\])\s+(?:memory|calldata|storage)?\s*(\w+)\b")
            .unwrap();
    static ref LATEST_ROUND_DATA: Regex =
        Regex::new(r"(?i)\(\s*[^)]*\)\s*=\s*\w+(?:\.\w+)*\s*\.latestRoundData\s*\(\s*\)").unwrap();
    static ref LATEST_ANSWER: Regex = Regex::new(r"(?i)\.latestAnswer\s*\(\s*\)").unwrap();
    static ref ANSWER_CHECK: Regex =
        Regex::new(r"(?i)(\w+)\s*(>|<=|<|>=|!=)\s*0\b|\b0\s*(<|>=|>|<=)\s*(\w+)").unwrap();
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
    .with_metadata("detector".to_string(), "crypto_and_oracle".to_string())
}

/// `ecrecover` returns `address(0)` for an invalid signature instead of
/// reverting. A comparison against a caller-supplied or zero-able address
/// then passes with no signature at all.
pub fn detect_ecrecover_unvalidated(source: &str, file_path: &str) -> Vec<Finding> {
    if ECDSA_LIB.is_match(source) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        if !body.iter().any(|l| ECRECOVER_BARE.is_match(l)) {
            continue;
        }
        if body.iter().any(|l| ZERO_ADDRESS.is_match(l)) {
            continue;
        }
        for (idx, line) in &span.lines {
            if ECRECOVER_BARE.is_match(line) {
                out.push(finding(
                    "evm_ecrecover_unvalidated", file_path, *idx, line, Severity::High,
                    "`ecrecover` result never checked against `address(0)`: an invalid signature recovers \
                     to zero rather than reverting, so any check that can be satisfied by zero (an unset \
                     owner, a caller-supplied signer) passes with garbage; require the recovered address \
                     to be non-zero, or use OpenZeppelin ECDSA",
                ));
                break;
            }
        }
    }
    out
}

/// `keccak256(abi.encodePacked(a, b))` with two dynamic-length values:
/// `("ab","c")` and `("a","bc")` pack to the same bytes, so two different
/// inputs share one hash — a forged leaf, key or signature digest.
pub fn detect_encodepacked_hash_collision(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let text: String = span
            .lines
            .iter()
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let dynamic: Vec<String> = DYNAMIC_DECL
            .captures_iter(&text)
            .map(|c| c[1].to_string())
            .collect();
        if dynamic.len() < 2 {
            continue;
        }
        for (idx, line) in &span.lines {
            let Some(c) = ENCODE_PACKED_HASH.captures(line) else {
                continue;
            };
            let args: Vec<String> = c[1]
                .split(',')
                .map(|a| {
                    a.trim()
                        .trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '_')
                        .to_string()
                })
                .collect();
            let dyn_args = args.iter().filter(|a| dynamic.contains(a)).count();
            if dyn_args >= 2 {
                out.push(finding(
                    "evm_encodepacked_hash_collision", file_path, *idx, line, Severity::High,
                    "`abi.encodePacked` over two dynamic values fed to a hash: the boundary between them \
                     is not encoded, so different inputs produce the same digest; use `abi.encode`",
                ));
            }
        }
    }
    out
}

/// A Chainlink answer used without checking the price itself: a feed can
/// return zero or a negative value during an incident, and `latestAnswer`
/// is deprecated because it carries no round data at all.
pub fn detect_oracle_answer_unvalidated(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines = code_lines(source);
    for (idx, line) in lines.iter().enumerate() {
        if LATEST_ANSWER.is_match(line) {
            out.push(finding(
                "evm_oracle_answer_unvalidated", file_path, idx, line, Severity::Medium,
                "`latestAnswer()` is deprecated: it returns 0 for an unknown feed and carries no round \
                 or timestamp data to validate; use `latestRoundData()` and check answer, round and age",
            ));
        }
    }
    for span in split_functions(&lines) {
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        for (idx, line) in &span.lines {
            if !LATEST_ROUND_DATA.is_match(line) {
                continue;
            }
            // The answer is the second element of the destructured tuple.
            let inner = line.split('=').next().unwrap_or("");
            let parts: Vec<&str> = inner
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .split(',')
                .collect();
            let answer = parts
                .get(1)
                .map(|p| p.split_whitespace().last().unwrap_or("").to_string())
                .unwrap_or_default();
            if answer.is_empty() {
                continue;
            }
            let checked = body.iter().any(|l| {
                ANSWER_CHECK.captures_iter(l).any(|c| {
                    c.get(1).map(|m| m.as_str() == answer).unwrap_or(false)
                        || c.get(4).map(|m| m.as_str() == answer).unwrap_or(false)
                })
            });
            if !checked {
                out.push(finding(
                    "evm_oracle_answer_unvalidated", file_path, *idx, line, Severity::High,
                    "Oracle answer used without a sign check: Chainlink feeds can return 0 or a negative \
                     value during an incident, and `uint256(answer)` turns a negative price into an \
                     enormous one; require `answer > 0`",
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
    fn ecrecover() {
        let bad = "contract C { function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s, address owner) external view returns (bool) { address signer = ecrecover(h, v, r, s); return signer == owner; } }";
        assert_eq!(detect_ecrecover_unvalidated(bad, "a.sol").len(), 1);
        let good = "contract C { function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s, address owner) external view returns (bool) { address signer = ecrecover(h, v, r, s); require(signer != address(0)); return signer == owner; } }";
        assert!(detect_ecrecover_unvalidated(good, "a.sol").is_empty());
    }

    #[test]
    fn encode_packed() {
        let bad = "contract C { function key(string memory a, string memory b) public pure returns (bytes32) { return keccak256(abi.encodePacked(a, b)); } }";
        assert_eq!(detect_encodepacked_hash_collision(bad, "a.sol").len(), 1);
        let good = "contract C { function leaf(address who, uint256 amount) public pure returns (bytes32) { return keccak256(abi.encodePacked(who, amount)); } }";
        assert!(detect_encodepacked_hash_collision(good, "a.sol").is_empty());
    }

    #[test]
    fn oracle_answer() {
        let bad = "contract C { function price() public view returns (uint256) { (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData(); require(block.timestamp - updatedAt < 1 hours); return uint256(answer); } }";
        assert_eq!(detect_oracle_answer_unvalidated(bad, "a.sol").len(), 1);
        let good = bad.replace(
            "require(block.timestamp",
            "require(answer > 0); require(block.timestamp",
        );
        assert!(detect_oracle_answer_unvalidated(&good, "a.sol").is_empty());
        assert_eq!(
            detect_oracle_answer_unvalidated("int256 p = feed.latestAnswer();", "a.sol").len(),
            1
        );
    }
}
