//! Violation panel component for displaying security violations.

use crate::ui::constants::*;
use crate::ui::utils::{box_line, divider, empty_box_line, term_width, wrap_text};
use serde::Serialize;

/// Represents a security violation to be displayed.
#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    /// The index of this violation (1-indexed for display)
    pub index: usize,
    /// Total number of violations
    pub total: usize,
    /// Severitylevel: "critical", "high", "medium", "low"
    pub severity: String,
    /// The type of violation (e.g., "Reentrancy Vulnerability")
    pub title: String,
    /// The invariant ID being violated
    pub invariant_id: String,
    /// File and line location (e.g., "Token.sol:142")
    pub location: String,
    /// CWE ID and description (e.g., "CWE-841 · Improper Enforcement of
    /// Behavioral Workflow"), or `None` for an invariant with no mapping —
    /// a user-authored `.sinv` rule. Rendered as an omitted line rather than
    /// a guessed class.
    pub cwe: Option<String>,
    /// SWC Registry entries. Always empty for non-EVM chains: SWC is a
    /// Solidity registry, and citing it on a Move finding would be fabricated.
    pub swc: Vec<String>,
    /// OWASP Smart Contract Top 10 (2025) categories.
    pub owasp_sc: Vec<String>,
    /// DASP Top 10 categories.
    pub dasp: Vec<String>,
    /// Detailed description of the vulnerability
    pub message: String,
    /// Recommendation for fixing the issue
    pub recommendation: String,
    /// URL to documentation
    pub reference: String,
    /// The actual code snippet where the vulnerability was found
    pub code_snippet: String,
    /// How strongly this result is supported: proven by execution, or a
    /// heuristic lead that has not been demonstrated.
    pub evidence: truent_core::Evidence,
    /// Source file (or URL / `host:port` for runtime findings), separately
    /// from the display `location`, so consumers never have to parse it.
    pub file: String,
    /// 1-based line; runtime findings report 1.
    pub line: usize,
    /// Engine that produced it: `evm`, `solana`, `move`, `soroban`,
    /// `general`, `supply-chain`, `runtime`.
    pub chain: Option<String>,
    /// Exploitability rating: `likely`, `possible`, `unlikely`, `theoretical`.
    pub exploitability: Option<String>,
    /// Why it was rated that way.
    pub exploit_reasons: Vec<String>,
    /// The change that closes the weakness, from the exposure table.
    pub fix: Option<String>,
    /// How to show the fix landed.
    pub verify: Option<String>,
    /// MITRE ATT&CK technique ids.
    pub attack: Vec<String>,
    /// NIST CSF 2.0 subcategory ids.
    pub nist_csf: Vec<String>,
}

/// Render a single violation panel with bordered box.
///
/// Produces a complete violation display with:
/// - Numbered header with severity badge
/// - Title and invariant ID
/// - Location and CWE information
/// - Detailed message with text wrapping
/// - Recommendation with arrow prefix
/// - Reference URL
///
/// # Arguments
/// * `violation` - The violation to display
/// * `width` - The terminal width for text wrapping
///
/// # Returns
/// The formatted violation panel as a string
pub fn render_violation(violation: &Violation, width: usize) -> String {
    let mut output = String::new();

    // Determine colors and icon based on severity
    let (icon, apply_color) = match violation.severity.as_str() {
        "critical" => (ICON_CRITICAL, color_critical as fn(&str) -> String),
        "high" => (ICON_HIGH, color_high as fn(&str) -> String),
        "medium" => (ICON_MEDIUM, color_medium as fn(&str) -> String),
        "low" => (ICON_LOW, color_low as fn(&str) -> String),
        _ => (ICON_LOW, color_low as fn(&str) -> String),
    };

    let content_width = width.saturating_sub(4);

    // Top border with index and severity
    let severity_badge = format!(" {} ", violation.severity.to_uppercase());
    let header_label = format!("{} of {}", violation.index, violation.total);

    // Build the top line with proper spacing and right-alignment
    let top_padding =
        content_width.saturating_sub(header_label.len() + 2 + severity_badge.len() + 10);

    let top_content = format!(
        "─ {}  {}{}─ {} ─",
        header_label,
        "─".repeat(top_padding),
        apply_color(&severity_badge),
        ""
    );

    output.push_str(&format!(
        "{}{}{}        \n",
        apply_color("╭"),
        top_content,
        apply_color("╮")
    ));

    // Empty line
    output.push_str(&format!("{}\n", empty_box_line(width)));

    // Title, evidence tag and invariant ID line.
    //
    // The tag is the first thing a reader sees, because whether the engine
    // reproduced this or merely pattern-matched it changes what they should do
    // about it more than the severity does.
    let evidence_tag = if violation.evidence.is_proven() {
        color_success("[PROVEN]")
    } else {
        color_dim("[LEAD]")
    };
    let title_line = format!(
        "{} {}  {}",
        apply_color(&format!("{} {}", icon, violation.title)),
        evidence_tag,
        color_dim(&violation.invariant_id)
    );
    output.push_str(&format!("{}\n", box_line(&title_line, width)));

    // Empty line
    output.push_str(&format!("{}\n", empty_box_line(width)));

    // Location line
    let location_label = color_dim("Location");
    let location_line = format!("{}  {}", location_label, color_value(&violation.location));
    output.push_str(&format!("{}\n", box_line(&location_line, width)));

    // Taxonomy lines — CWE, SWC, OWASP SC, DASP. Each is omitted entirely
    // when the invariant has no honest mapping for that registry, so a reader
    // never sees a citation the engine cannot stand behind.
    if let Some(cwe) = &violation.cwe {
        let cwe_line = format!("{}  {}", color_dim("CWE"), color_value(cwe));
        output.push_str(&format!("{}\n", box_line(&cwe_line, width)));
    }
    for (label, values) in [
        ("SWC", &violation.swc),
        ("OWASP", &violation.owasp_sc),
        ("DASP", &violation.dasp),
    ] {
        if values.is_empty() {
            continue;
        }
        let line = format!("{}  {}", color_dim(label), color_value(&values.join(", ")));
        output.push_str(&format!("{}\n", box_line(&line, width)));
    }

    // Empty line
    output.push_str(&format!("{}\n", empty_box_line(width)));

    // Message (with wrapping)
    let wrapped_message = wrap_text(&violation.message, content_width);
    for line in wrapped_message {
        output.push_str(&format!("{}\n", box_line(&line, width)));
    }

    // Empty line
    output.push_str(&format!("{}\n", empty_box_line(width)));

    // Recommendation (with arrow prefix and wrapping)
    let wrapped_rec = wrap_text(&violation.recommendation, content_width - 2);
    for (i, line) in wrapped_rec.iter().enumerate() {
        let prefix = if i == 0 {
            format!("{} ", color_recommendation(ICON_ARROW))
        } else {
            "  ".to_string()
        };
        output.push_str(&format!(
            "{}\n",
            box_line(&format!("{}{}", prefix, color_recommendation(line)), width)
        ));
    }

    // Empty line
    output.push_str(&format!("{}\n", empty_box_line(width)));

    // Reference line
    let ref_label = color_dim("Reference");
    let ref_line = format!("{}  {}", ref_label, color_dim(&violation.reference));
    output.push_str(&format!("{}\n", box_line(&ref_line, width)));

    // Empty line
    output.push_str(&empty_box_line(width));
    output.push('\n');

    // Code snippet section (if available)
    if !violation.code_snippet.is_empty() {
        let code_label = color_dim("Vulnerable Code");
        output.push_str(&format!("{}\n", box_line(&code_label, width)));

        // Format code with syntax highlighting
        let code_lines: Vec<&str> = violation.code_snippet.lines().collect();
        for code_line in code_lines {
            let highlighted = format!("  {}", color_value(code_line));
            output.push_str(&format!("{}\n", box_line(&highlighted, width)));
        }
    }

    // Bottom border
    output.push_str(&format!(
        "{}{}{}\n",
        apply_color("╰"),
        divider(content_width + 2),
        apply_color("╯")
    ));

    output
}

/// Render a list of violations.
///
/// Displays all violations separated by blank lines.
///
/// # Arguments
/// * `violations` - List of violations to display
///
/// # Returns
/// The formatted violations as a string
pub fn render_violations(violations: &[Violation]) -> String {
    let width = term_width();
    let mut output = String::new();

    if !violations.is_empty() {
        output.push('\n');
        let header = format!("Violations ({})", violations.len());
        output.push_str(&format!("{}\n\n", color_label(&header)));

        for (idx, violation) in violations.iter().enumerate() {
            let mut v = violation.clone();
            v.index = idx + 1;
            v.total = violations.len();
            output.push_str(&render_violation(&v, width));
            output.push('\n');
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_violation_structure() {
        let violation = Violation {
            index: 1,
            total: 1,
            severity: "critical".to_string(),
            title: "Test Vulnerability".to_string(),
            invariant_id: "test_invariant".to_string(),
            location: "test.sol:42".to_string(),
            cwe: Some("CWE-123 · Test CWE".to_string()),
            swc: vec!["SWC-107 · Reentrancy".to_string()],
            owasp_sc: vec!["SC05 · Reentrancy Attacks".to_string()],
            dasp: vec!["DASP-1 · Reentrancy".to_string()],
            message: "This is a test message".to_string(),
            recommendation: "Fix this issue".to_string(),
            reference: "https://docs.example.com".to_string(),
            code_snippet: "    42 | function transfer() public { }".to_string(),
            evidence: truent_core::Evidence::Lead,
            file: String::new(),
            line: 1,
            chain: None,
            exploitability: None,
            exploit_reasons: Vec::new(),
            fix: None,
            verify: None,
            attack: Vec::new(),
            nist_csf: Vec::new(),
        };

        let rendered = render_violation(&violation, 80);

        // Check that all expected parts are present
        assert!(rendered.contains("CRITICAL"));
        assert!(rendered.contains("Test Vulnerability"));
        assert!(rendered.contains("test_invariant"));
        assert!(rendered.contains("test.sol:42"));
        assert!(rendered.contains("CWE-123"));
        assert!(rendered.contains("This is a test message"));
        assert!(rendered.contains("Fix this issue"));
        assert!(rendered.contains("https://docs.example.com"));

        // Check for box drawing characters
        assert!(rendered.contains("╭"));
        assert!(rendered.contains("╮"));
        assert!(rendered.contains("╰"));
        assert!(rendered.contains("╯"));
    }

    #[test]
    fn test_render_violation_severity_levels() {
        for severity in &["critical", "high", "medium", "low"] {
            let violation = Violation {
                index: 1,
                total: 1,
                severity: severity.to_string(),
                title: "Test".to_string(),
                invariant_id: "test".to_string(),
                location: "test.sol:1".to_string(),
                cwe: Some("CWE-1".to_string()),
                swc: Vec::new(),
                owasp_sc: Vec::new(),
                dasp: Vec::new(),
                message: "msg".to_string(),
                recommendation: "fix".to_string(),
                reference: "ref".to_string(),
                code_snippet: String::new(),
                evidence: truent_core::Evidence::Lead,
                file: String::new(),
                line: 1,
                chain: None,
                exploitability: None,
                exploit_reasons: Vec::new(),
                fix: None,
                verify: None,
                attack: Vec::new(),
                nist_csf: Vec::new(),
            };

            let rendered = render_violation(&violation, 80);
            assert!(rendered.contains(&severity.to_uppercase()));
        }
    }

    #[test]
    fn test_render_violations_list() {
        let violations = vec![
            Violation {
                index: 1,
                total: 2,
                severity: "critical".to_string(),
                title: "Issue 1".to_string(),
                invariant_id: "inv1".to_string(),
                location: "file.sol:1".to_string(),
                cwe: Some("CWE-1".to_string()),
                swc: Vec::new(),
                owasp_sc: Vec::new(),
                dasp: Vec::new(),
                message: "msg1".to_string(),
                recommendation: "fix1".to_string(),
                reference: "ref1".to_string(),
                code_snippet: String::new(),
                evidence: truent_core::Evidence::Lead,
                file: String::new(),
                line: 1,
                chain: None,
                exploitability: None,
                exploit_reasons: Vec::new(),
                fix: None,
                verify: None,
                attack: Vec::new(),
                nist_csf: Vec::new(),
            },
            Violation {
                index: 2,
                total: 2,
                severity: "high".to_string(),
                title: "Issue 2".to_string(),
                invariant_id: "inv2".to_string(),
                location: "file.sol:2".to_string(),
                cwe: Some("CWE-2".to_string()),
                swc: Vec::new(),
                owasp_sc: Vec::new(),
                dasp: Vec::new(),
                message: "msg2".to_string(),
                recommendation: "fix2".to_string(),
                reference: "ref2".to_string(),
                code_snippet: String::new(),
                evidence: truent_core::Evidence::Lead,
                file: String::new(),
                line: 1,
                chain: None,
                exploitability: None,
                exploit_reasons: Vec::new(),
                fix: None,
                verify: None,
                attack: Vec::new(),
                nist_csf: Vec::new(),
            },
        ];

        let rendered = render_violations(&violations);
        assert!(rendered.contains("Violations (2)"));
        assert!(rendered.contains("Issue 1"));
        assert!(rendered.contains("Issue 2"));
    }
}
