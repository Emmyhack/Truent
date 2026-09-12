//! hevm text output (`hevm test`).
//!
//! ```text
//! [PASS] prove_deposit_adds(uint256,uint256)
//! [FAIL] prove_total_never_wraps(uint256)
//!    Counterexample:
//!      result:   Revert
//!      calldata: prove_total_never_wraps(0x8000…)
//! ```
//!
//! A `[FAIL]` followed by a `Counterexample:` block is proven; a `[FAIL]`
//! without one (or a timeout / unknown line) is unresolved.

use truent_core::{Finding, Severity};

use crate::{finding, Stats};

/// Parse hevm's console output.
pub fn parse(text: &str, project: &str) -> (Vec<Finding>, Stats) {
    let mut stats = Stats::default();
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        if let Some(name) = l.strip_prefix("[PASS]") {
            let _ = name;
            stats.checks += 1;
            stats.passed += 1;
        } else if let Some(name) = l.strip_prefix("[FAIL]") {
            stats.checks += 1;
            let name = name.trim().to_string();
            // Collect the indented block that follows.
            let mut block = Vec::new();
            let mut j = i + 1;
            while j < lines.len() && (lines[j].starts_with(' ') || lines[j].starts_with('\t')) {
                block.push(lines[j].trim());
                j += 1;
            }
            let has_cex = block.iter().any(|b| b.starts_with("Counterexample"));
            let calldata = block
                .iter()
                .find_map(|b| b.strip_prefix("calldata:"))
                .map(|c| c.trim().to_string());
            if has_cex {
                stats.failed += 1;
                out.push(finding(
                    "evm_symbolic_counterexample",
                    Severity::High,
                    project,
                    1,
                    format!(
                        "hevm found a concrete input that violates `{name}`: the property does not hold for every input"
                    ),
                    match calldata {
                        Some(c) => format!("{name} — calldata {c}"),
                        None => format!("{name} — counterexample"),
                    },
                    true,
                ));
            } else {
                stats.unresolved += 1;
                out.push(finding(
                    "evm_symbolic_unresolved",
                    Severity::Low,
                    project,
                    1,
                    format!("hevm reported `{name}` as failed without a counterexample (timeout or unknown); undecided is not proven"),
                    format!("{name} — {}", block.first().copied().unwrap_or("no detail")),
                    false,
                ));
            }
            i = j;
            continue;
        } else if l.contains("timeout") || l.contains("Timeout") || l.starts_with("[UNKNOWN]") {
            stats.checks += 1;
            stats.unresolved += 1;
        }
        i += 1;
    }
    (out, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/hevm.txt");

    #[test]
    fn fail_with_counterexample_is_proven() {
        let (f, s) = parse(FIXTURE, "examples/foundry");
        assert_eq!((s.checks, s.passed, s.failed), (2, 1, 1));
        assert_eq!(f.len(), 1);
        assert!(f[0].is_proven());
        assert!(f[0].snippet.contains("0x8000"));
    }

    #[test]
    fn fail_without_counterexample_is_unresolved() {
        let (f, s) = parse("[FAIL] prove_x(uint256)\n   timeout\n", "p");
        assert_eq!(s.unresolved, 1);
        assert_eq!(f[0].invariant_id, "evm_symbolic_unresolved");
    }
}
