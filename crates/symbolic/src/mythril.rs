//! Mythril JSON output (`myth analyze … -o json`).
//!
//! Every Mythril issue carries a `tx_sequence`: the concrete transactions its
//! symbolic engine solved for to reach the state. That sequence is the
//! witness, so an issue with one is proven; an issue without is a lead.

use serde::Deserialize;
use truent_core::{Finding, Severity};

use crate::{finding, Stats};

#[derive(Deserialize)]
struct Output {
    #[serde(default)]
    issues: Vec<Issue>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct Issue {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    function: String,
    #[serde(default)]
    lineno: usize,
    #[serde(default)]
    severity: String,
    #[serde(rename = "swc-id", default)]
    swc_id: String,
    #[serde(default)]
    tx_sequence: Option<serde_json::Value>,
}

/// Parse a Mythril JSON report.
pub fn parse(json: &str, project: &str) -> (Vec<Finding>, Stats) {
    let mut stats = Stats::default();
    let mut out = Vec::new();
    let Ok(o) = serde_json::from_str::<Output>(json) else {
        return (out, stats);
    };
    if let Some(e) = o.error {
        if !e.is_empty() {
            stats.unresolved += 1;
        }
    }
    // Mythril has no per-check notion; each issue is a failed property.
    for i in &o.issues {
        stats.checks += 1;
        stats.failed += 1;
        let sev = match i.severity.to_ascii_lowercase().as_str() {
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Low,
        };
        let steps = i
            .tx_sequence
            .as_ref()
            .and_then(|t| t.get("steps"))
            .and_then(|s| s.as_array())
            .map(|s| s.len())
            .unwrap_or(0);
        let witness = i
            .tx_sequence
            .as_ref()
            .and_then(|t| t.get("steps"))
            .and_then(|s| s.as_array())
            .map(|s| {
                s.iter()
                    .filter_map(|st| st.get("name").and_then(|n| n.as_str()))
                    .collect::<Vec<_>>()
                    .join(" → ")
            })
            .unwrap_or_default();
        let file = if i.filename.is_empty() {
            project.to_string()
        } else if i.filename.starts_with(project) {
            i.filename.clone()
        } else {
            format!("{project}/{}", i.filename.trim_start_matches("./"))
        };
        out.push(finding(
            "evm_symbolic_counterexample",
            sev,
            &file,
            i.lineno,
            format!(
                "Mythril{}: {} in `{}` — {}",
                if i.swc_id.is_empty() {
                    String::new()
                } else {
                    format!(" (SWC-{})", i.swc_id)
                },
                i.title,
                i.function,
                i.description.lines().next().unwrap_or("")
            ),
            if steps > 0 {
                format!(
                    "{} — reached by {steps} transaction(s): {witness}",
                    i.function
                )
            } else {
                format!("{} — no transaction sequence exported", i.function)
            },
            steps > 0,
        ));
    }
    (out, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/mythril.json");

    #[test]
    fn issue_with_tx_sequence_is_proven() {
        let (f, s) = parse(FIXTURE, "examples/foundry");
        assert_eq!(s.failed, 1);
        assert_eq!(f.len(), 1);
        assert!(f[0].is_proven());
        assert_eq!(f[0].line, 10);
        assert_eq!(f[0].file, "examples/foundry/src/Vault.sol");
        assert!(f[0].message.contains("SWC-101"));
        assert!(f[0].snippet.contains("withdraw(uint256)"));
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn issue_without_sequence_is_a_lead() {
        let j = r#"{"issues":[{"title":"x","filename":"a.sol","function":"f()","lineno":3,"severity":"Low"}],"success":true}"#;
        let (f, _) = parse(j, "p");
        assert!(!f[0].is_proven());
    }

    #[test]
    fn empty_and_garbage() {
        assert!(parse(r#"{"issues":[],"success":true}"#, "p").0.is_empty());
        assert!(parse("nope", "p").0.is_empty());
    }
}
