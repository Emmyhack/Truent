//! Denial-of-service and gas-griefing shapes.
//!
//! - **Unbounded loop over a growable storage array** — anyone who can
//!   `push` makes the loop cost more than the block gas limit, and the
//!   function that contains it can never complete again.
//! - **Push payment inside a loop** — one recipient that reverts (a contract
//!   without a payable fallback, a blocklisted address) blocks payment to
//!   everyone after it. Pull payments (`withdraw`) are the fix.
//! - **No pause mechanism** — a protocol that moves value under an admin
//!   role but has no way to halt it when an exploit is in progress. Plain
//!   tokens are not asked for one.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use super::textutil::{enclosing_function_body, Normalized};

lazy_static! {
    /// `for (…; i < name.length; …)`
    static ref FOR_LENGTH: Regex = Regex::new(r"for\s*\([^;]*;\s*\w+\s*<\s*([A-Za-z_]\w*)\.length\s*;").unwrap();
    /// `T[] public name;` at contract level (storage array).
    static ref STORAGE_ARRAY: Regex = Regex::new(r"(?m)^\s*[A-Za-z_][\w.]*\[\]\s+(?:public|private|internal)?\s*([A-Za-z_]\w*)\s*;").unwrap();
    static ref LOOP_START: Regex = Regex::new(r"\b(for|while)\s*\(").unwrap();
    static ref PUSH_PAYMENT: Regex = Regex::new(r"\.(transfer|send)\s*\(|\.call\s*\{\s*value\s*:").unwrap();
    static ref FUNC_DECL: Regex = Regex::new(r"\bfunction\s+(\w+)\s*\(").unwrap();
    static ref VIEW_FN: Regex = Regex::new(r"\b(view|pure)\b").unwrap();
    static ref VALUE_FN: Regex = Regex::new(r"\bfunction\s+(withdraw|deposit|borrow|repay|redeem|swap|liquidate|stake|unstake|claim|harvest|flashLoan|bridge|release)\w*\s*\(").unwrap();
    static ref ADMIN_MARK: Regex = Regex::new(r"\bonlyOwner\b|\bonlyRole\b|\bAccessControl\b|\bOwnable\b|\bonlyAdmin\b|\bonlyGovernance\b").unwrap();
    static ref PAUSE_MARK: Regex = Regex::new(r"\bPausable\b|\bwhenNotPaused\b|\bpaused\s*\(|\bpaused\b|\bfunction\s+pause\b|\bemergencyStop\b|\bcircuitBreaker\b|\bhalt(ed)?\b").unwrap();
    static ref CONTRACT_DECL: Regex = Regex::new(r"(?m)^\s*(abstract\s+)?contract\s+(\w+)").unwrap();
}

pub fn detect_gas_dos(source: &str, file_path: &str) -> Vec<Finding> {
    let n = Normalized::new(source);
    let code = &n.code;
    let lines: Vec<&str> = code.lines().collect();
    let mut out = Vec::new();

    let storage_arrays: Vec<String> = STORAGE_ARRAY
        .captures_iter(code)
        .map(|c| c[1].to_string())
        .collect();

    for (i, line) in lines.iter().enumerate() {
        // Unbounded loop over a growable storage array in a non-view function.
        if let Some(c) = FOR_LENGTH.captures(line) {
            let arr = &c[1];
            if storage_arrays.iter().any(|a| a == arr) && code.contains(&format!("{arr}.push(")) {
                let decl = (0..=i).rev().find(|&k| FUNC_DECL.is_match(lines[k]));
                let in_mutating = decl.map(|k| !VIEW_FN.is_match(lines[k])).unwrap_or(false);
                if in_mutating {
                    out.push(Finding::new(
                        "evm_unbounded_loop".to_string(),
                        Severity::Medium,
                        file_path.to_string(),
                        i + 1,
                        0,
                        format!(
                            "Loop over storage array `{arr}`, which grows via push(): once it is long enough the loop exceeds the block gas limit and this function can never complete — a permanent denial of service for everyone who depends on it. Bound the iteration or process in pages"
                        ),
                        line.trim().to_string(),
                    )
                    .with_metadata("chain".to_string(), "evm".to_string()));
                }
            }
        }

        // Push payment inside a loop body.
        if LOOP_START.is_match(line) {
            let body = enclosing_function_body(code, i);
            // The loop body only: from the loop line to its matching brace.
            let mut depth = 0i32;
            let mut opened = false;
            let mut loop_body = String::new();
            for l in body.lines() {
                loop_body.push_str(l);
                loop_body.push('\n');
                depth += l.matches('{').count() as i32;
                if depth > 0 {
                    opened = true;
                }
                depth -= l.matches('}').count() as i32;
                if opened && depth <= 0 {
                    break;
                }
            }
            if let Some(m) = PUSH_PAYMENT.find(&loop_body) {
                let rel = loop_body[..m.start()].matches('\n').count();
                out.push(Finding::new(
                    "evm_push_payment_in_loop".to_string(),
                    Severity::Medium,
                    file_path.to_string(),
                    i + 1 + rel,
                    0,
                    "Value is pushed to a list of recipients inside a loop: one recipient that reverts (a contract without a payable fallback, a blocklisted address) blocks payment to every recipient after it, and the loop grows with the list. Record balances and let recipients pull".to_string(),
                    lines.get(i + rel).map(|l| l.trim().to_string()).unwrap_or_default(),
                )
                .with_metadata("chain".to_string(), "evm".to_string()));
            }
        }
    }

    // No pause mechanism on an admin-controlled, value-moving protocol.
    for c in CONTRACT_DECL.captures_iter(code) {
        let start = c.get(0).unwrap().start();
        let contract_line = code[..start].matches('\n').count();
        let body = enclosing_function_body(code, contract_line);
        let value_fns = VALUE_FN.find_iter(&body).count();
        if value_fns >= 2 && ADMIN_MARK.is_match(&body) && !PAUSE_MARK.is_match(code) {
            out.push(Finding::new(
                "evm_missing_pause_mechanism".to_string(),
                Severity::Low,
                file_path.to_string(),
                contract_line + 1,
                0,
                format!(
                    "`{}` moves value through {} entry points under an admin role but has no pause or circuit breaker: when an exploit is in progress there is no way to stop the bleeding while a fix is prepared. Add Pausable with whenNotPaused on value-moving functions, guarded by a multisig",
                    &c[2], value_fns
                ),
                lines.get(contract_line).map(|l| l.trim().to_string()).unwrap_or_default(),
            )
            .with_metadata("chain".to_string(), "evm".to_string()));
        }
    }

    n.restore_snippets(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(src: &str) -> Vec<String> {
        detect_gas_dos(src, "t.sol")
            .into_iter()
            .map(|f| f.invariant_id)
            .collect()
    }

    #[test]
    fn unbounded_loop_over_growable_storage_array() {
        let src = "contract A {\n  address[] public holders;\n  function add(address a) external { holders.push(a); }\n  function distribute() external {\n    for (uint i = 0; i < holders.length; i++) { balances[holders[i]] += 1; }\n  }\n}";
        assert!(ids(src).contains(&"evm_unbounded_loop".into()));
    }

    #[test]
    fn view_loops_and_memory_arrays_are_fine() {
        let view = "contract A {\n  address[] public holders;\n  function add(address a) external { holders.push(a); }\n  function total() external view returns (uint t) {\n    for (uint i = 0; i < holders.length; i++) { t += 1; }\n  }\n}";
        assert!(!ids(view).contains(&"evm_unbounded_loop".into()));
        let mem = "contract A {\n  function sum(uint[] memory xs) external {\n    for (uint i = 0; i < xs.length; i++) { s += xs[i]; }\n  }\n}";
        assert!(ids(mem).is_empty());
    }

    #[test]
    fn push_payment_in_loop() {
        let src = "contract A {\n  function pay(address[] calldata to) external {\n    for (uint i = 0; i < to.length; i++) {\n      payable(to[i]).transfer(1 ether);\n    }\n  }\n}";
        let f = detect_gas_dos(src, "t.sol");
        assert!(
            f.iter()
                .any(|f| f.invariant_id == "evm_push_payment_in_loop" && f.line == 4),
            "{f:?}"
        );
    }

    #[test]
    fn pause_only_asked_of_protocols() {
        let protocol = "contract Vault is Ownable {\n  function deposit() external payable {}\n  function withdraw(uint a) external {}\n  function borrow(uint a) external {}\n  function setFee(uint f) external onlyOwner {}\n}";
        assert!(ids(protocol).contains(&"evm_missing_pause_mechanism".into()));
        let paused = "contract Vault is Ownable, Pausable {\n  function deposit() external payable whenNotPaused {}\n  function withdraw(uint a) external whenNotPaused {}\n  function borrow(uint a) external {}\n}";
        assert!(!ids(paused).contains(&"evm_missing_pause_mechanism".into()));
        let token = "contract Token is ERC20, Ownable {\n  function mint(address to, uint a) external onlyOwner {}\n}";
        assert!(!ids(token).contains(&"evm_missing_pause_mechanism".into()));
    }
}
