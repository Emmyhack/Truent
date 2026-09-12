//! halmos JSON output (`--json-output`).
//!
//! ```json
//! { "exitcode": 1, "test_results": { "test/Vault.t.sol:VaultTest": [
//!   { "name": "check_total_never_wraps(uint256)", "exitcode": 1, "num_models": 1,
//!     "models": [ { "model": { "p_amount_uint256_…": { "variable_name": "amount",
//!       "solidity_type": "uint256", "value": 5789…968 } }, "is_valid": true } ] } ] } }
//! ```
//!
//! Per-check `exitcode`: 0 pass, 1 counterexample, anything else unresolved
//! (timeout, unknown, every path reverted). Only a counterexample with a
//! valid model is proven.

use serde::Deserialize;
use truent_core::{Finding, Severity};

use crate::{finding, Stats};

#[derive(Deserialize)]
struct Output {
    #[serde(default)]
    test_results: std::collections::BTreeMap<String, Vec<Check>>,
}

#[derive(Deserialize)]
struct Check {
    name: String,
    exitcode: i64,
    #[serde(default)]
    models: Vec<Model>,
}

#[derive(Deserialize)]
struct Model {
    #[serde(default)]
    model: std::collections::BTreeMap<String, Var>,
    #[serde(default = "yes")]
    is_valid: bool,
}
fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct Var {
    #[serde(default)]
    variable_name: String,
    #[serde(default)]
    solidity_type: String,
    #[serde(default)]
    value: serde_json::Value,
}

fn render_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Number(n) => {
            // Large uint256 values read better in hex.
            match n.as_u64() {
                Some(x) => x.to_string(),
                None => {
                    let s = n.to_string();
                    match s.parse::<u128>() {
                        Ok(x) => format!("{x:#x}"),
                        Err(_) => big_to_hex(&s).unwrap_or(s),
                    }
                }
            }
        }
        serde_json::Value::String(s) if s.chars().all(|c| c.is_ascii_digit()) => {
            big_to_hex(s).unwrap_or_else(|| s.clone())
        }
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Wrap integer literals of 16+ digits in quotes.
fn quote_big_numbers(json: &str) -> String {
    let b = json.as_bytes();
    let mut out = String::with_capacity(json.len() + 64);
    let mut i = 0;
    let mut in_str = false;
    let mut esc = false;
    while i < b.len() {
        let c = b[i] as char;
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        // A digit run that is the fractional part of a float, or an exponent,
        // is not an integer literal.
        let prev = if i == 0 { ' ' } else { b[i - 1] as char };
        if c.is_ascii_digit()
            && !(prev.is_ascii_alphanumeric()
                || prev == '.'
                || prev == '+'
                || prev == '-' && i >= 2 && matches!(b[i - 2] as char, 'e' | 'E'))
        {
            let mut j = i;
            while j < b.len() && (b[j] as char).is_ascii_digit() {
                j += 1;
            }
            let is_float = j < b.len() && matches!(b[j] as char, '.' | 'e' | 'E');
            if j - i >= 16 && !is_float {
                out.push('"');
                out.push_str(&json[i..j]);
                out.push('"');
            } else {
                out.push_str(&json[i..j]);
            }
            i = j;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Decimal string → hex, for values wider than u128.
fn big_to_hex(dec: &str) -> Option<String> {
    let mut digits: Vec<u32> = dec
        .bytes()
        .map(|b| (b as char).to_digit(10))
        .collect::<Option<_>>()?;
    let mut hex = Vec::new();
    while !digits.iter().all(|&d| d == 0) {
        let mut rem = 0u32;
        for d in digits.iter_mut() {
            let cur = rem * 10 + *d;
            *d = cur / 16;
            rem = cur % 16;
        }
        hex.push(std::char::from_digit(rem, 16)?);
    }
    if hex.is_empty() {
        return Some("0x0".into());
    }
    hex.reverse();
    Some(format!("0x{}", hex.into_iter().collect::<String>()))
}

/// Parse a halmos JSON report into findings and stats. `file` is what the
/// report names as the location: the `path:Contract` key from halmos.
pub fn parse(json: &str, project: &str) -> (Vec<Finding>, Stats) {
    let mut stats = Stats::default();
    let mut out = Vec::new();
    // A uint256 witness is a bare JSON integer far beyond u64; serde_json
    // would round it through f64. Quote big literals first so the exact
    // digits survive and render as hex.
    let json = quote_big_numbers(json);
    let Ok(o) = serde_json::from_str::<Output>(&json) else {
        return (out, stats);
    };
    for (suite, checks) in &o.test_results {
        let file = suite.split(':').next().unwrap_or(suite);
        let location = format!("{project}/{file}");
        for c in checks {
            stats.checks += 1;
            match c.exitcode {
                0 => stats.passed += 1,
                1 => {
                    stats.failed += 1;
                    let model = c.models.iter().find(|m| m.is_valid);
                    let witness: Vec<String> = model
                        .map(|m| {
                            m.model
                                .values()
                                .map(|v| {
                                    format!(
                                        "{}: {} = {}",
                                        if v.variable_name.is_empty() {
                                            "arg"
                                        } else {
                                            &v.variable_name
                                        },
                                        v.solidity_type,
                                        render_value(&v.value)
                                    )
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    out.push(finding(
                        "evm_symbolic_counterexample",
                        Severity::High,
                        &location,
                        1,
                        format!(
                            "halmos found a concrete input that violates `{}`: the property does not hold for every input, and here is one that breaks it",
                            c.name
                        ),
                        if witness.is_empty() {
                            format!("{} — counterexample (model not exported)", c.name)
                        } else {
                            format!("{} — {}", c.name, witness.join(", "))
                        },
                        model.is_some(),
                    ));
                }
                other => {
                    stats.unresolved += 1;
                    out.push(finding(
                        "evm_symbolic_unresolved",
                        Severity::Low,
                        &location,
                        1,
                        format!(
                            "halmos could not decide `{}` (exit {other}): a timeout, an unknown solver result, or every path reverted. An undecided property is not a proven one — raise the solver timeout, loosen the setup, or split the check",
                            c.name
                        ),
                        format!("{} — exitcode {other}", c.name),
                        false,
                    ));
                }
            }
        }
    }
    (out, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/halmos.json");

    #[test]
    fn real_output_yields_one_proven_counterexample() {
        let (f, s) = parse(FIXTURE, "examples/foundry");
        assert_eq!((s.checks, s.passed, s.failed, s.unresolved), (2, 1, 1, 0));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].invariant_id, "evm_symbolic_counterexample");
        assert!(f[0].is_proven(), "a model is a concrete witness");
        assert!(f[0].message.contains("check_total_never_wraps"));
        assert!(f[0].snippet.contains("amount: uint256 = 0x8000000000000000000000000000000000000000000000000000000000000000"), "{}", f[0].snippet);
        assert_eq!(f[0].file, "examples/foundry/test/Vault.t.sol");
    }

    #[test]
    fn unresolved_is_a_lead_not_a_pass() {
        let j = r#"{"exitcode":4,"test_results":{"t/A.t.sol:A":[{"name":"check_x(uint256)","exitcode":4,"num_models":0,"models":[]}]}}"#;
        let (f, s) = parse(j, "p");
        assert_eq!(s.unresolved, 1);
        assert_eq!(f[0].invariant_id, "evm_symbolic_unresolved");
        assert!(!f[0].is_proven());
    }

    #[test]
    fn counterexample_without_model_is_not_proven() {
        let j = r#"{"exitcode":1,"test_results":{"t/A.t.sol:A":[{"name":"check_x()","exitcode":1,"num_models":0,"models":[]}]}}"#;
        let (f, _) = parse(j, "p");
        assert!(!f[0].is_proven());
    }

    #[test]
    fn garbage_is_empty_not_a_panic() {
        let (f, s) = parse("not json", "p");
        assert!(f.is_empty() && s.checks == 0);
    }

    #[test]
    fn big_literals_are_quoted_but_small_ones_and_floats_are_not() {
        let j = r#"{"a": 12, "b": 57896044618658097711785492504343953926634992332820282019728792003956564819968, "t": [4.10349354200298, 3.8956053750007413, 1e-05, 1.0500021744519472e-05], "s": "1234567890123456789"}"#;
        let q = quote_big_numbers(j);
        assert!(q.contains(r#""b": "57896044618658097711785492504343953926634992332820282019728792003956564819968""#));
        assert!(
            q.contains(r#""a": 12"#)
                && q.contains("3.8956053750007413")
                && q.contains("1.0500021744519472e-05")
        );
        assert!(
            q.contains(r#""s": "1234567890123456789""#),
            "strings untouched"
        );
        assert!(serde_json::from_str::<serde_json::Value>(&q).is_ok());
    }

    #[test]
    fn big_numbers_render_as_hex() {
        assert_eq!(big_to_hex("255").unwrap(), "0xff");
        assert_eq!(big_to_hex("0").unwrap(), "0x0");
        assert_eq!(
            big_to_hex(
                "57896044618658097711785492504343953926634992332820282019728792003956564819968"
            )
            .unwrap(),
            "0x8000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
