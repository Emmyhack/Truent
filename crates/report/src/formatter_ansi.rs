//! Report formatter with ANSI colors, JSON, and SARIF output.
//!
//! Formats findings for terminal (with colors), JSON (NDJSON), and SARIF 2.1.0.

use serde_json::{json, Value};
use std::fmt::Write;
use truent_core::{Finding, Severity};

/// ANSI color codes for terminal output
const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_BOLD_RED: &str = "\x1b[1;31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_BOLD_YELLOW: &str = "\x1b[1;33m";
const ANSI_CYAN: &str = "\x1b[36m";
const ANSI_BLUE: &str = "\x1b[34m";
const ANSI_GREEN: &str = "\x1b[32m";

/// Format findings for terminal output with ANSI colors
pub fn format_terminal(findings: &[Finding], use_color: bool) -> String {
    let mut output = String::new();

    if findings.is_empty() {
        writeln!(
            &mut output,
            "{}✓ No findings - all checks passed{}",
            if use_color { ANSI_GREEN } else { "" },
            if use_color { ANSI_RESET } else { "" }
        )
        .unwrap();
        return output;
    }

    // Header
    writeln!(
        &mut output,
        "\n{}╔════════════════════════════════════════════════════════════════╗{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();
    writeln!(
        &mut output,
        "{}║{}  Truent Security Analysis Results{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_RESET } else { "" },
        if use_color { ANSI_BOLD } else { "" }
    )
    .unwrap();
    writeln!(
        &mut output,
        "{}║{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();
    writeln!(
        &mut output,
        "{}╚════════════════════════════════════════════════════════════════╝{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();

    // Findings grouped by severity
    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    let high: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .collect();
    let medium: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .collect();
    let low: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .collect();
    let info: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .collect();

    // Print findings by severity
    if !critical.is_empty() {
        writeln!(
            &mut output,
            "\n{}",
            format_severity_section("CRITICAL", &critical, use_color)
        )
        .unwrap();
    }
    if !high.is_empty() {
        writeln!(
            &mut output,
            "\n{}",
            format_severity_section("HIGH", &high, use_color)
        )
        .unwrap();
    }
    if !medium.is_empty() {
        writeln!(
            &mut output,
            "\n{}",
            format_severity_section("MEDIUM", &medium, use_color)
        )
        .unwrap();
    }
    if !low.is_empty() {
        writeln!(
            &mut output,
            "\n{}",
            format_severity_section("LOW", &low, use_color)
        )
        .unwrap();
    }
    if !info.is_empty() {
        writeln!(
            &mut output,
            "\n{}",
            format_severity_section("INFO", &info, use_color)
        )
        .unwrap();
    }

    // Summary table
    writeln!(
        &mut output,
        "\n{}",
        format_summary_table(findings, use_color)
    )
    .unwrap();

    output
}

fn format_severity_section(severity: &str, findings: &[&Finding], use_color: bool) -> String {
    let mut output = String::new();

    let color = if use_color {
        match severity {
            "CRITICAL" => ANSI_BOLD_RED,
            "HIGH" => ANSI_BOLD_YELLOW,
            "MEDIUM" => ANSI_YELLOW,
            "LOW" => ANSI_BLUE,
            "INFO" => ANSI_CYAN,
            _ => "",
        }
    } else {
        ""
    };

    writeln!(
        &mut output,
        "{}[{}]{} ({})",
        if use_color { ANSI_BOLD } else { "" },
        severity,
        if use_color { ANSI_RESET } else { "" },
        findings.len()
    )
    .unwrap();

    for (idx, finding) in findings.iter().enumerate() {
        writeln!(
            &mut output,
            "\n  {}{}. {}{}{}:{}",
            if use_color { ANSI_BOLD } else { "" },
            idx + 1,
            if use_color { color } else { "" },
            finding.invariant_id,
            if use_color { ANSI_RESET } else { "" },
            if use_color { ANSI_RESET } else { "" }
        )
        .unwrap();
        writeln!(
            &mut output,
            "     Location: {}:{}:{}",
            finding.file, finding.line, finding.col
        )
        .unwrap();
        writeln!(&mut output, "     Message:  {}", finding.message).unwrap();

        if !finding.snippet.is_empty() {
            writeln!(&mut output, "     Code:     {}", finding.snippet).unwrap();
        }
    }

    output
}

fn format_summary_table(findings: &[Finding], use_color: bool) -> String {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    let mut output = String::new();
    writeln!(
        &mut output,
        "{}┌─────────────┬────────┐{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();
    writeln!(
        &mut output,
        "{}│ Severity    │ Count  │{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();
    writeln!(
        &mut output,
        "{}├─────────────┼────────┤{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();

    writeln!(
        &mut output,
        "{}│ {}CRITICAL{} │   {}   │{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_BOLD_RED } else { "" },
        if use_color {
            format!("{}{}", ANSI_RESET, ANSI_BOLD)
        } else {
            String::new()
        },
        critical,
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();

    writeln!(
        &mut output,
        "{}│ {}HIGH{}     │   {}   │{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_BOLD_YELLOW } else { "" },
        if use_color {
            format!("{}{}", ANSI_RESET, ANSI_BOLD)
        } else {
            String::new()
        },
        high,
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();

    writeln!(
        &mut output,
        "{}│ {}MEDIUM{}   │   {}   │{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_YELLOW } else { "" },
        if use_color {
            format!("{}{}", ANSI_RESET, ANSI_BOLD)
        } else {
            String::new()
        },
        medium,
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();

    writeln!(
        &mut output,
        "{}│ {}LOW{}      │   {}   │{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_BLUE } else { "" },
        if use_color {
            format!("{}{}", ANSI_RESET, ANSI_BOLD)
        } else {
            String::new()
        },
        low,
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();

    writeln!(
        &mut output,
        "{}│ {}INFO{}     │   {}   │{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_CYAN } else { "" },
        if use_color {
            format!("{}{}", ANSI_RESET, ANSI_BOLD)
        } else {
            String::new()
        },
        info,
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();

    writeln!(
        &mut output,
        "{}└─────────────┴────────┘{}",
        if use_color { ANSI_BOLD } else { "" },
        if use_color { ANSI_RESET } else { "" }
    )
    .unwrap();

    output
}

/// Format findings as NDJSON (one Finding per line)
pub fn format_ndjson(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| serde_json::to_string(f).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Format findings as SARIF 2.1.0 (GitHub Code Scanning compatible)
/// Render findings as SARIF 2.1.0 for GitHub code scanning and friends.
///
/// Two things matter here beyond the obvious shape:
///
/// 1. **Rules are deduplicated.** SARIF's `runs[].tool.driver.rules` is a
///    *rule catalogue*, not a per-result list. Emitting one entry per finding
///    (and pointing every result at `ruleIndex: 0`) made ten reentrancy hits
///    look like ten distinct rules, all mis-attributed to the first one.
/// 2. **CWE is emitted as a real taxonomy.** `taxonomies[]` plus per-rule
///    `relationships[]` is what makes GitHub code scanning group and filter
///    findings by CWE. Tags alone do not.
pub fn format_sarif(findings: &[Finding], tool_version: &str) -> Value {
    use std::collections::BTreeMap;
    use truent_core::taxonomy::{taxonomy_for, Cwe};

    // Stable rule catalogue: one entry per distinct invariant, in first-seen
    // order, with an index each result can point at.
    let mut rule_index: BTreeMap<&str, usize> = BTreeMap::new();
    let mut rule_order: Vec<&Finding> = Vec::new();
    for f in findings {
        if !rule_index.contains_key(f.invariant_id.as_str()) {
            rule_index.insert(f.invariant_id.as_str(), rule_order.len());
            rule_order.push(f);
        }
    }

    // Every CWE referenced by any rule, deduplicated, as taxonomy entries.
    let mut cwe_taxa: BTreeMap<u16, Cwe> = BTreeMap::new();
    for f in &rule_order {
        if let Some(t) = taxonomy_for(&f.invariant_id) {
            for cwe in t.cwe {
                cwe_taxa.insert(cwe.id, *cwe);
            }
        }
    }
    let cwe_taxa: Vec<Cwe> = cwe_taxa.into_values().collect();
    let cwe_position: BTreeMap<u16, usize> = cwe_taxa
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id, i))
        .collect();

    let rules: Vec<Value> = rule_order
        .iter()
        .map(|f| {
            let taxonomy = taxonomy_for(&f.invariant_id);
            let tags: Vec<String> = taxonomy.map(|t| t.tags()).unwrap_or_default();

            // `relationships` is the machine-readable CWE link; `tags` is the
            // human-facing one. Code scanning reads the first, people read the
            // second, so both are emitted.
            let relationships: Vec<Value> = taxonomy
                .map(|t| {
                    t.cwe
                        .iter()
                        .filter_map(|cwe| {
                            cwe_position.get(&cwe.id).map(|idx| {
                                json!({
                                    "target": {
                                        "id": cwe.id_str(),
                                        "index": idx,
                                        "toolComponent": { "name": "CWE", "guid": CWE_COMPONENT_GUID }
                                    },
                                    "kinds": ["superset"]
                                })
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            let mut rule = json!({
                "id": f.invariant_id,
                "name": f.invariant_id,
                "shortDescription": {
                    "text": f.message.lines().next().unwrap_or(&f.message)
                },
                "fullDescription": {
                    "text": f.message
                },
                "help": {
                    "text": help_text(&f.invariant_id)
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(f.severity)
                },
                "properties": {
                    "tags": tags,
                    "problem.severity": severity_to_sarif_level(f.severity),
                    "security-severity": security_severity(f.severity)
                }
            });
            if !relationships.is_empty() {
                rule["relationships"] = json!(relationships);
            }
            rule
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.invariant_id,
                "ruleIndex": rule_index.get(f.invariant_id.as_str()).copied().unwrap_or(0),
                "level": severity_to_sarif_level(f.severity),
                "message": {
                    "text": f.message
                },
                "properties": {
                    // Truent's own distinction: proven by execution vs. a
                    // static lead. Survives into the SARIF so a consumer can
                    // treat the two differently.
                    "evidence": f.evidence.label()
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file
                            },
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.col + 1
                            }
                        }
                    }
                ]
            })
        })
        .collect();

    let mut run = json!({
        "tool": {
            "driver": {
                "name": "Truent",
                "version": tool_version,
                "informationUri": "https://github.com/geekstrancend/Truent",
                "rules": rules
            }
        },
        "results": results
    });

    if !cwe_taxa.is_empty() {
        run["taxonomies"] = json!([{
            "name": "CWE",
            "guid": CWE_COMPONENT_GUID,
            "organization": "MITRE",
            "shortDescription": { "text": "The MITRE Common Weakness Enumeration" },
            "informationUri": "https://cwe.mitre.org/data/published/cwe_latest.pdf",
            "isComprehensive": false,
            "taxa": cwe_taxa.iter().map(|c| json!({
                "id": c.id_str(),
                "name": c.name,
                "shortDescription": { "text": c.name },
                "helpUri": c.url()
            })).collect::<Vec<_>>()
        }]);
    }

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run]
    })
}

/// Stable GUID identifying the CWE taxonomy component across runs, so
/// consumers can correlate `relationships[].target.toolComponent` with the
/// entry in `taxonomies[]`.
const CWE_COMPONENT_GUID: &str = "b1a1a6f1-9f6e-4b0a-9a35-4e3b6a4c7f01";

/// Help text for a rule, citing every registry that maps it.
///
/// This is what a reviewer reads in the code-scanning UI, so it carries the
/// links rather than just the internal ID.
fn help_text(invariant_id: &str) -> String {
    use truent_core::taxonomy::taxonomy_for;

    let Some(t) = taxonomy_for(invariant_id) else {
        return format!("Truent invariant: {invariant_id}");
    };

    let mut parts = vec![format!("Truent invariant: {invariant_id}")];
    if let Some(e) = truent_core::exposure::exposure_for(invariant_id) {
        parts.push(format!("Fix: {}", e.fix));
        parts.push(format!("Verify: {}", e.verify));
    }
    if !t.cwe.is_empty() {
        parts.push(format!(
            "CWE: {}",
            t.cwe
                .iter()
                .map(|c| format!("[{}]({})", c.label(), c.url()))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !t.swc.is_empty() {
        parts.push(format!(
            "SWC: {}",
            t.swc
                .iter()
                .map(|s| format!("[{}]({})", s.label(), s.url()))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !t.owasp_sc.is_empty() {
        parts.push(format!(
            "OWASP Smart Contract Top 10: {}",
            t.owasp_sc
                .iter()
                .map(|o| o.label())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !t.dasp.is_empty() {
        parts.push(format!(
            "DASP: {}",
            t.dasp
                .iter()
                .map(|d| d.label())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    parts.join("\n\n")
}

/// GitHub code scanning sorts by `security-severity` (a CVSS-like 0–10 score),
/// not by `level`. Without it every finding lands in the same bucket.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "error",
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_terminal() {
        let findings = vec![Finding::new(
            "test_invariant".to_string(),
            Severity::Critical,
            "contract.sol".to_string(),
            42,
            10,
            "Test vulnerability".to_string(),
            "code line".to_string(),
        )];

        let output = format_terminal(&findings, true);
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("test_invariant"));
    }

    #[test]
    fn test_format_sarif() {
        let findings = vec![Finding::new(
            "test".to_string(),
            Severity::High,
            "file.sol".to_string(),
            1,
            0,
            "msg".to_string(),
            "code".to_string(),
        )];

        let sarif = format_sarif(&findings, "0.3.0");
        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["runs"][0]["results"].is_array());
    }

    fn finding(id: &str, line: usize) -> Finding {
        Finding::new(
            id.to_string(),
            Severity::High,
            "Vault.sol".to_string(),
            line,
            0,
            "msg".to_string(),
            "code".to_string(),
        )
    }

    #[test]
    fn sarif_rules_are_deduplicated_and_indexed() {
        // Three hits, two distinct rules. Previously this produced three rule
        // entries with every result pointing at ruleIndex 0, so consumers
        // attributed all three to whichever rule happened to be first.
        let findings = vec![
            finding("evm_reentrancy_classic", 10),
            finding("evm_reentrancy_classic", 20),
            finding("evm_missing_signer_check", 30),
        ];

        let sarif = format_sarif(&findings, "0.3.0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 2, "rules must be deduplicated by invariant");

        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        for r in results {
            let idx = r["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(
                rules[idx]["id"], r["ruleId"],
                "ruleIndex must point at the rule the result names"
            );
        }
    }

    #[test]
    fn sarif_carries_cwe_taxonomy() {
        let sarif = format_sarif(&[finding("evm_reentrancy_classic", 1)], "0.3.0");

        // The CWE taxonomy component is what lets GitHub code scanning group
        // and filter by weakness class.
        let taxa = sarif["runs"][0]["taxonomies"][0]["taxa"]
            .as_array()
            .unwrap();
        assert!(taxa.iter().any(|t| t["id"] == "CWE-841"));

        let rule = &sarif["runs"][0]["tool"]["driver"]["rules"][0];
        let tags: Vec<&str> = rule["properties"]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        assert!(tags.contains(&"CWE-841"));
        assert!(tags.contains(&"SWC-107"));
        assert!(tags.contains(&"SC05"));
        assert!(tags.contains(&"DASP-1"));

        // security-severity drives ordering in the code-scanning UI.
        assert_eq!(rule["properties"]["security-severity"], "8.0");

        let rel = &rule["relationships"][0]["target"];
        assert_eq!(rel["id"], "CWE-841");
        assert_eq!(rel["toolComponent"]["name"], "CWE");
    }

    #[test]
    fn sarif_omits_taxonomy_for_unmapped_invariants() {
        // A user-authored .sinv rule has no registry mapping. It must still
        // produce valid SARIF — just without invented citations.
        let sarif = format_sarif(&[finding("my_custom_sinv_rule", 1)], "0.3.0");
        let rule = &sarif["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(rule["relationships"].is_null());
        assert_eq!(rule["properties"]["tags"].as_array().unwrap().len(), 0);
        assert!(sarif["runs"][0]["taxonomies"].is_null());
    }
}
