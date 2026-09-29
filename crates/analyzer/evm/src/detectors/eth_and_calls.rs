//! Ether movement and call patterns: the 2300-gas stipend, `msg.value`
//! reused across a loop, `tx.origin` as authentication, and `permit` calls
//! that a front-runner can make revert.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use super::implementations::split_functions;
use super::textutil::code_lines;

lazy_static! {
    static ref ETH_TRANSFER_OR_SEND: Regex =
        Regex::new(r"(?i)\.\s*(transfer|send)\s*\(([^()]*(?:\([^()]*\))?[^()]*)\)").unwrap();
    static ref LOOP_START: Regex = Regex::new(r"(?i)\b(for|while)\s*\(").unwrap();
    static ref MSG_VALUE: Regex = Regex::new(r"\bmsg\.value\b").unwrap();
    static ref DELEGATE_MULTICALL: Regex = Regex::new(r"(?i)delegatecall\s*\(").unwrap();
    static ref PAYABLE_DECL: Regex =
        Regex::new(r"(?i)\bfunction\s+\w+\s*\([^)]*\)[^{]*\bpayable\b").unwrap();
    static ref TX_ORIGIN_AUTH: Regex = Regex::new(
        r"(?i)\b(require|if)\s*\([^;]*\btx\.origin\b|\btx\.origin\s*(==|!=)|(==|!=)\s*tx\.origin\b"
    )
    .unwrap();
    static ref TX_ORIGIN_EOA_CHECK: Regex =
        Regex::new(r"(?i)tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin").unwrap();
    static ref PERMIT_CALL: Regex = Regex::new(r"(?i)\b\w+\s*\.\s*permit\s*\(").unwrap();
    /// A permit *implementation* (has a body); an interface declaration ends in `;`.
    static ref PERMIT_IMPL: Regex = Regex::new(r"(?i)\bfunction\s+permit\s*\([^;{]*\)[^;{]*\{").unwrap();
    static ref TRY_PERMIT: Regex =
        Regex::new(r"(?i)\btry\s+\w+(?:\.\w+)*\s*\.\s*permit\s*\(").unwrap();
    static ref ALLOWANCE_GUARD: Regex = Regex::new(r"(?i)\.allowance\s*\(").unwrap();
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
    .with_metadata("detector".to_string(), "eth_and_calls".to_string())
}

/// Top-level argument count of the first call on the line.
fn arg_count(args: &str) -> usize {
    if args.trim().is_empty() {
        return 0;
    }
    let mut depth = 0i32;
    let mut n = 1;
    for ch in args.chars() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => n += 1,
            _ => {}
        }
    }
    n
}

/// `x.transfer(amount)` / `x.send(amount)` forward only 2300 gas: a
/// recipient that is a contract with any logic in `receive` fails, and gas
/// repricings have broken this before (EIP-1884).
pub fn detect_fixed_gas_eth_transfer(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (idx, line) in code_lines(source).iter().enumerate() {
        for c in ETH_TRANSFER_OR_SEND.captures_iter(line) {
            if arg_count(&c[2]) == 1 {
                out.push(finding(
                    "evm_fixed_gas_eth_transfer", file_path, idx, line, Severity::Medium,
                    "Ether sent with `.transfer`/`.send`: only 2300 gas is forwarded, so a contract \
                     recipient (multisig, smart wallet) reverts and, in a loop or a withdraw path, blocks \
                     everyone; use `call{value: ..}(\"\")` and check the result",
                ));
                break;
            }
        }
    }
    out
}

/// `msg.value` read inside a loop, or inside a payable function that
/// delegatecalls (a multicall): one payment is counted once per iteration.
pub fn detect_msg_value_reused_in_loop(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((_, decl)) = span.lines.first() else {
            continue;
        };
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        let payable_multicall =
            PAYABLE_DECL.is_match(decl) && body.iter().any(|l| DELEGATE_MULTICALL.is_match(l));
        let mut depth_at_loop: Option<i32> = None;
        let mut depth = 0i32;
        for (idx, line) in &span.lines {
            if depth_at_loop.is_none() && LOOP_START.is_match(line) {
                depth_at_loop = Some(depth);
            }
            depth += line.matches('{').count() as i32;
            let in_loop = depth_at_loop.map(|d| depth > d).unwrap_or(false);
            if MSG_VALUE.is_match(line)
                && (in_loop || (payable_multicall && DELEGATE_MULTICALL.is_match(line)))
            {
                out.push(finding(
                    "evm_msg_value_reused_in_loop",
                    file_path,
                    *idx,
                    line,
                    Severity::High,
                    "`msg.value` reused across iterations: one payment satisfies every iteration, \
                     so a caller buys N items for the price of one",
                ));
            }
            depth -= line.matches('}').count() as i32;
            if let Some(d) = depth_at_loop {
                if depth <= d && !LOOP_START.is_match(line) {
                    depth_at_loop = None;
                }
            }
        }
    }
    out
}

/// `tx.origin` compared for authorisation. A phishing contract called by the
/// owner passes the check; `tx.origin == msg.sender` (an EOA check) is a
/// different, weaker pattern and is not reported here.
pub fn detect_tx_origin_authentication(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (idx, line) in code_lines(source).iter().enumerate() {
        if TX_ORIGIN_AUTH.is_match(line) && !TX_ORIGIN_EOA_CHECK.is_match(line) {
            out.push(finding(
                "evm_tx_origin_authentication", file_path, idx, line, Severity::High,
                "`tx.origin` used for authorisation: any contract the authorised account interacts \
                 with can call this on their behalf; compare `msg.sender`",
            ));
        }
    }
    out
}

/// A `permit` called directly before use. Anyone who sees the signature can
/// submit the permit first; this call then reverts and the whole action
/// fails. Wrap it in `try` or skip it when the allowance already suffices.
pub fn detect_permit_frontrun_dos(source: &str, file_path: &str) -> Vec<Finding> {
    if PERMIT_IMPL.is_match(source) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        if body.iter().any(|l| ALLOWANCE_GUARD.is_match(l)) {
            continue;
        }
        for (idx, line) in &span.lines {
            if PERMIT_CALL.is_match(line) && !TRY_PERMIT.is_match(line) {
                out.push(finding(
                    "evm_permit_frontrun_dos", file_path, *idx, line, Severity::Medium,
                    "`permit` executed unconditionally: a front-runner can submit the same signature \
                     first, after which this call reverts and the user's transaction fails; use \
                     `try permit(..) {} catch {}` or check the allowance before calling",
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
    fn eth_transfer_one_arg_only() {
        assert_eq!(
            detect_fixed_gas_eth_transfer("payable(msg.sender).transfer(amount);", "a.sol").len(),
            1
        );
        assert!(detect_fixed_gas_eth_transfer("token.transfer(to, amount);", "a.sol").is_empty());
        assert!(detect_fixed_gas_eth_transfer(
            "(bool ok, ) = to.call{value: amount}(\"\");",
            "a.sol"
        )
        .is_empty());
    }

    #[test]
    fn msg_value_in_loop() {
        let bad = "contract C {\n    function buy(uint256[] calldata ids) external payable {\n        for (uint256 i; i < ids.length; i++) {\n            require(msg.value >= price, \"p\");\n            _mint(ids[i]);\n        }\n    }\n}";
        assert_eq!(detect_msg_value_reused_in_loop(bad, "a.sol").len(), 1);
        let good = "contract C {\n    function buy(uint256[] calldata ids) external payable {\n        require(msg.value >= price * ids.length, \"p\");\n        for (uint256 i; i < ids.length; i++) {\n            _mint(ids[i]);\n        }\n    }\n}";
        assert!(detect_msg_value_reused_in_loop(good, "a.sol").is_empty());
    }

    #[test]
    fn tx_origin() {
        assert_eq!(
            detect_tx_origin_authentication("require(tx.origin == owner, \"x\");", "a.sol").len(),
            1
        );
        assert!(detect_tx_origin_authentication(
            "require(tx.origin == msg.sender, \"eoa\");",
            "a.sol"
        )
        .is_empty());
    }

    #[test]
    fn permit() {
        let bad = "contract C {\n    function depositWithPermit(uint256 a, uint256 d, uint8 v, bytes32 r, bytes32 s) external {\n        token.permit(msg.sender, address(this), a, d, v, r, s);\n        token.transferFrom(msg.sender, address(this), a);\n    }\n}";
        assert_eq!(detect_permit_frontrun_dos(bad, "a.sol").len(), 1);
        let good = bad
            .replace("token.permit(", "try token.permit(")
            .replace("v, r, s);", "v, r, s) {} catch {}");
        assert!(detect_permit_frontrun_dos(&good, "a.sol").is_empty());
    }
}
