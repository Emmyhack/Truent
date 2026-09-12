use std::collections::HashMap;
/// Comprehensive Security Report Generator
///
/// Generates multi-format security analysis reports with severity aggregation,
/// remediation guidance, and industry-standard formatting.
use truent_core::{Finding, Severity};

/// Report format enumeration
#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    /// Markdown format
    Markdown,
    /// JSON format
    Json,
    /// HTML format
    Html,
    /// CSV format
    Csv,
}

/// Severity statistics
#[derive(Debug, Clone)]
pub struct SeverityStats {
    /// Critical severity count
    pub critical: usize,
    /// High severity count
    pub high: usize,
    /// Medium severity count
    pub medium: usize,
    /// Low severity count
    pub low: usize,
    /// Info severity count
    pub info: usize,
}

impl SeverityStats {
    /// Create from findings
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut stats = Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };

        for finding in findings {
            match finding.severity {
                Severity::Critical => stats.critical += 1,
                Severity::High => stats.high += 1,
                Severity::Medium => stats.medium += 1,
                Severity::Low => stats.low += 1,
                Severity::Info => stats.info += 1,
            }
        }

        stats
    }

    /// Total findings count
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Risk score (0.0-100.0)
    pub fn risk_score(&self) -> f64 {
        let total = self.total() as f64;
        if total == 0.0 {
            return 0.0;
        }

        let weighted = (self.critical as f64 * 100.0)
            + (self.high as f64 * 75.0)
            + (self.medium as f64 * 50.0)
            + (self.low as f64 * 25.0)
            + (self.info as f64 * 10.0);

        (weighted / (total * 100.0)).min(100.0)
    }
}

/// Security analysis report
pub struct SecurityReport {
    /// Report title
    pub title: String,
    /// Analysis timestamp
    pub timestamp: String,
    /// Analyzed files/contracts
    pub analyzed_targets: Vec<String>,
    /// All findings
    pub findings: Vec<Finding>,
    /// Severity statistics
    pub severity_stats: SeverityStats,
    /// Detector chain breakdown
    pub chain_breakdown: HashMap<String, usize>,
    /// Executive summary
    pub executive_summary: String,
}

impl SecurityReport {
    /// Create new security report
    pub fn new(
        title: String,
        analyzed_targets: Vec<String>,
        findings: Vec<Finding>,
        executive_summary: String,
    ) -> Self {
        let severity_stats = SeverityStats::from_findings(&findings);

        let mut chain_breakdown = HashMap::new();
        for finding in &findings {
            let count = chain_breakdown
                .entry(finding.invariant_id.clone())
                .or_insert(0);
            *count += 1;
        }

        Self {
            title,
            timestamp: chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            analyzed_targets,
            findings,
            severity_stats,
            chain_breakdown,
            executive_summary,
        }
    }

    /// Generate report in specified format
    pub fn generate(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::Markdown => self.generate_markdown(),
            ReportFormat::Json => self.generate_json(),
            ReportFormat::Html => self.generate_html(),
            ReportFormat::Csv => self.generate_csv(),
        }
    }

    /// Generate Markdown report
    fn generate_markdown(&self) -> String {
        let mut report = format!("# {}\n\n", self.title);
        report.push_str("**Generated:** ");
        report.push_str(&self.timestamp);
        report.push_str("\n\n");

        // Executive Summary
        report.push_str("## Executive Summary\n\n");
        report.push_str(&self.executive_summary);
        report.push_str("\n\n");

        // Statistics
        report.push_str("## Security Statistics\n\n");
        report.push_str(&format!(
            "- **Total Findings:** {}\n",
            self.severity_stats.total()
        ));
        report.push_str(&format!(
            "- **Critical:** {}\n",
            self.severity_stats.critical
        ));
        report.push_str(&format!("- **High:** {}\n", self.severity_stats.high));
        report.push_str(&format!("- **Medium:** {}\n", self.severity_stats.medium));
        report.push_str(&format!("- **Low:** {}\n", self.severity_stats.low));
        report.push_str(&format!("- **Info:** {}\n", self.severity_stats.info));
        report.push_str(&format!(
            "- **Risk Score:** {:.1}/100.0\n\n",
            self.severity_stats.risk_score()
        ));

        // Analyzed Targets
        report.push_str("## Analyzed Targets\n\n");
        for target in &self.analyzed_targets {
            report.push_str(&format!("- {}\n", target));
        }
        report.push('\n');

        // Findings by Severity
        report.push_str("## Detailed Findings\n\n");

        for severity_level in &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let severity_findings: Vec<_> = self
                .findings
                .iter()
                .filter(|f| f.severity == *severity_level)
                .collect();

            if !severity_findings.is_empty() {
                report.push_str(&format!("### {:?} Severity\n\n", severity_level));

                for finding in severity_findings {
                    report.push_str(&format!("#### {}\n", finding.message));
                    report.push_str(&format!("- **File:** {}\n", finding.file));
                    report.push_str(&format!(
                        "- **Location:** Line {}, Column {}\n",
                        finding.line, finding.col
                    ));
                    report.push_str(&format!("- **Detector:** `{}`\n", finding.invariant_id));
                    // Registry citations. A client triaging this report maps it
                    // into their own tracker by CWE/SWC, not by our rule name.
                    for (label, values) in taxonomy_lines(finding) {
                        report.push_str(&format!("- **{}:** {}\n", label, values.join(", ")));
                    }
                    report.push_str(&format!("- **Code:** {}\n", finding.snippet));
                    report.push('\n');
                }
            }
        }

        report
    }

    /// Generate JSON report.
    ///
    /// Built via `serde_json` rather than hand-formatted strings so that any
    /// attacker-influenced content (a crafted contract/file name ending up in
    /// `title`, or a finding `message`/`file` containing quotes or control
    /// characters) is always escaped correctly instead of corrupting the JSON
    /// structure.
    fn generate_json(&self) -> String {
        let report = serde_json::json!({
            "title": self.title,
            "timestamp": self.timestamp,
            "statistics": {
                "total_findings": self.severity_stats.total(),
                "critical": self.severity_stats.critical,
                "high": self.severity_stats.high,
                "medium": self.severity_stats.medium,
                "low": self.severity_stats.low,
                "info": self.severity_stats.info,
                "risk_score": self.severity_stats.risk_score(),
            },
            "target_count": self.analyzed_targets.len(),
            "targets": self.analyzed_targets,
            "summary": self.executive_summary,
            // Findings are serialized with their taxonomy attached rather than
            // bare, so a consumer does not have to carry its own copy of the
            // invariant-to-CWE mapping to make sense of the output.
            "findings": self.findings.iter().map(|f| {
                let mut v = serde_json::to_value(f).unwrap_or(serde_json::Value::Null);
                if let (Some(obj), Some(t)) = (v.as_object_mut(), f.taxonomy()) {
                    obj.insert("taxonomy".to_string(), serde_json::json!({
                        "cwe": t.cwe.iter().map(|c| serde_json::json!({
                            "id": c.id_str(), "name": c.name, "url": c.url()
                        })).collect::<Vec<_>>(),
                        "swc": t.swc.iter().map(|x| serde_json::json!({
                            "id": x.id_str(), "title": x.title, "url": x.url()
                        })).collect::<Vec<_>>(),
                        "owasp_sc": t.owasp_sc.iter().map(|o| serde_json::json!({
                            "id": o.id_str(), "title": o.title()
                        })).collect::<Vec<_>>(),
                        "dasp": t.dasp.iter().map(|d| serde_json::json!({
                            "id": d.id_str(), "title": d.title()
                        })).collect::<Vec<_>>(),
                        "tags": t.tags(),
                    }));
                }
                v
            }).collect::<Vec<_>>(),
        });

        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Generate HTML report.
    ///
    /// Every interpolated value is escaped: the title comes from the scan
    /// target, finding messages can quote contract source, and file paths are
    /// chosen by whoever supplied the repository. A report is a document that
    /// gets opened in a browser and forwarded to a client, so an unescaped
    /// value here is stored XSS in an audit deliverable.
    fn generate_html(&self) -> String {
        let title = html_escape(&self.title);
        let timestamp = html_escape(&self.timestamp);

        let rows = if self.findings.is_empty() {
            "<tr><td colspan=\"5\" class=\"none\">No findings.</td></tr>".to_string()
        } else {
            self.findings
                .iter()
                .map(|f| {
                    format!(
                        "<tr><td><code>{}</code></td><td class=\"{}\">{}</td>\
                         <td>{}:{}</td><td>{}</td><td>{}</td></tr>",
                        html_escape(&f.invariant_id),
                        f.severity.name().to_lowercase(),
                        f.severity.name(),
                        html_escape(&f.file),
                        f.line,
                        taxonomy_badges_html(f),
                        html_escape(&f.message),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               margin: 20px; background: #f6f8fb; color: #24292e; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #fff;
                     padding: 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
        h1 {{ color: #0366d6; border-bottom: 2px solid #e1e4e8; padding-bottom: 10px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
        th, td {{ border: 1px solid #e1e4e8; padding: 8px; text-align: left;
                 vertical-align: top; font-size: 13px; }}
        th {{ background: #f6f8fa; }}
        .critical {{ color: #d73a49; font-weight: 600; }}
        .high     {{ color: #e36209; font-weight: 600; }}
        .medium   {{ color: #b08800; font-weight: 600; }}
        .low      {{ color: #6f42c1; font-weight: 600; }}
        .info     {{ color: #0366d6; font-weight: 600; }}
        .none     {{ color: #22863a; font-weight: 600; text-align: center; }}
        .tax {{ display: inline-block; background: #eef2f7; border: 1px solid #d6dde6;
               border-radius: 4px; padding: 1px 6px; margin: 1px 2px 1px 0; font-size: 11px;
               font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
               color: #3a4652; white-space: nowrap; }}
        .timestamp {{ color: #6a737d; font-size: 12px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p><strong>Generated:</strong> {timestamp}</p>

        <h2>Summary</h2>
        <ul>
            <li><strong>Total Findings:</strong> {total}</li>
            <li><strong>Critical:</strong> {critical}</li>
            <li><strong>High:</strong> {high}</li>
            <li><strong>Medium:</strong> {medium}</li>
            <li><strong>Low:</strong> {low}</li>
            <li><strong>Info:</strong> {info}</li>
            <li><strong>Risk Score:</strong> {risk:.1}/100.0</li>
        </ul>

        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Invariant</th><th>Severity</th><th>Location</th>
                    <th>Classification</th><th>Message</th>
                </tr>
            </thead>
            <tbody>
{rows}
            </tbody>
        </table>

        <div class="timestamp">Generated by Truent</div>
    </div>
</body>
</html>"#,
            title = title,
            timestamp = timestamp,
            total = self.severity_stats.total(),
            critical = self.severity_stats.critical,
            high = self.severity_stats.high,
            medium = self.severity_stats.medium,
            low = self.severity_stats.low,
            info = self.severity_stats.info,
            risk = self.severity_stats.risk_score(),
            rows = rows,
        )
    }

    /// Generate CSV report using RFC 4180 field quoting (every field wrapped
    /// in double quotes, internal quotes doubled) rather than naive comma
    /// stripping, so quotes/commas/newlines in a finding can't corrupt columns.
    fn generate_csv(&self) -> String {
        let mut csv = "Severity,Vulnerability_ID,CWE,SWC,OWASP_SC,File,Line,Message\n".to_string();

        for finding in &self.findings {
            let tax = finding.taxonomy();
            let join = |pick: fn(&truent_core::Taxonomy) -> Vec<String>| -> String {
                tax.map(pick).unwrap_or_default().join("; ")
            };
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                csv_escape(&format!("{:?}", finding.severity)),
                csv_escape(&finding.invariant_id),
                csv_escape(&join(|t| t.cwe.iter().map(|c| c.id_str()).collect())),
                csv_escape(&join(|t| t.swc.iter().map(|x| x.id_str()).collect())),
                csv_escape(&join(|t| t
                    .owasp_sc
                    .iter()
                    .map(|o| o.id_str().to_string())
                    .collect())),
                csv_escape(&finding.file),
                finding.line,
                csv_escape(&finding.message)
            ));
        }

        csv
    }
}

/// Registry citations for a finding, as `(label, values)` pairs.
///
/// Only registries that actually map the finding are returned — an unmapped
/// invariant, or one from a chain a registry does not cover, yields nothing
/// rather than an empty-looking "CWE: —" line.
fn taxonomy_lines(finding: &Finding) -> Vec<(&'static str, Vec<String>)> {
    let Some(t) = finding.taxonomy() else {
        return Vec::new();
    };
    let mut out: Vec<(&'static str, Vec<String>)> = Vec::new();
    if !t.cwe.is_empty() {
        out.push(("CWE", t.cwe.iter().map(|c| c.label()).collect()));
    }
    if !t.swc.is_empty() {
        out.push(("SWC", t.swc.iter().map(|x| x.label()).collect()));
    }
    if !t.owasp_sc.is_empty() {
        out.push((
            "OWASP Smart Contract Top 10",
            t.owasp_sc.iter().map(|o| o.label()).collect(),
        ));
    }
    if !t.dasp.is_empty() {
        out.push(("DASP", t.dasp.iter().map(|d| d.label()).collect()));
    }
    out
}

/// Escape a single CSV field per RFC 4180: always quote, and double any
/// embedded quote characters. Safe regardless of commas/quotes/newlines.
fn csv_escape(field: &str) -> String {
    format!("\"{}\"", field.replace('"', "\"\""))
}

/// Render a finding's registry citations as HTML badges.
///
/// Empty when the invariant has no mapping, so the cell is blank rather than
/// asserting a weakness class Truent cannot stand behind.
fn taxonomy_badges_html(finding: &Finding) -> String {
    taxonomy_lines(finding)
        .into_iter()
        .flat_map(|(_, values)| values)
        .map(|label| {
            // Labels read "CWE-841 · Name"; the badge shows the ID and the
            // tooltip carries the full name.
            let id = label.split(' ').next().unwrap_or(&label).to_string();
            format!(
                "<span class=\"tax\" title=\"{}\">{}</span>",
                html_escape(&label),
                html_escape(&id)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Escape a string for safe interpolation into HTML text content.
///
/// Public because the CLI builds its own HTML report and needs the same
/// escaping. Every value that reaches an HTML report is attacker-influenceable
/// — a scan target is a path the user chose, a finding message can quote
/// contract source, and reports get shared.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a one-finding report for the given invariant.
    fn report_for(invariant_id: &str) -> SecurityReport {
        SecurityReport::new(
            "Test Report".to_string(),
            vec!["Vault.sol".to_string()],
            vec![Finding::new(
                invariant_id.to_string(),
                Severity::Critical,
                "Vault.sol".to_string(),
                42,
                0,
                "Reentrancy in withdraw".to_string(),
                "code".to_string(),
            )],
            "summary".to_string(),
        )
    }

    #[test]
    fn json_report_carries_structured_taxonomy() {
        let json = report_for("evm_reentrancy_classic").generate(ReportFormat::Json);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let tax = &v["findings"][0]["taxonomy"];

        assert_eq!(tax["cwe"][0]["id"], "CWE-841");
        assert_eq!(
            tax["cwe"][0]["url"],
            "https://cwe.mitre.org/data/definitions/841.html"
        );
        assert_eq!(tax["swc"][0]["id"], "SWC-107");
        assert_eq!(tax["owasp_sc"][0]["id"], "SC05");
        assert_eq!(tax["dasp"][0]["id"], "DASP-1");
    }

    #[test]
    fn json_report_omits_taxonomy_when_unmapped() {
        // A user-authored .sinv rule has no mapping. The key must be absent
        // rather than present-and-empty, so a consumer cannot read an empty
        // CWE list as "no weakness class applies".
        let json = report_for("my_custom_sinv_rule").generate(ReportFormat::Json);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["findings"][0]["taxonomy"].is_null());
    }

    #[test]
    fn csv_report_has_taxonomy_columns() {
        let csv = report_for("evm_reentrancy_classic").generate(ReportFormat::Csv);
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().unwrap(),
            "Severity,Vulnerability_ID,CWE,SWC,OWASP_SC,File,Line,Message"
        );
        let row = lines.next().unwrap();
        assert!(row.contains("CWE-841; CWE-663"), "row was: {row}");
        assert!(row.contains("SWC-107"));
        assert!(row.contains("SC05"));
    }

    #[test]
    fn csv_taxonomy_columns_are_empty_not_missing_when_unmapped() {
        // Column count must stay constant or the CSV misaligns downstream.
        let csv = report_for("my_custom_sinv_rule").generate(ReportFormat::Csv);
        let header_cols = csv.lines().next().unwrap().split(',').count();
        let row_cols = csv.lines().nth(1).unwrap().split(',').count();
        assert_eq!(header_cols, row_cols);
    }

    #[test]
    fn markdown_report_cites_registries() {
        let md = report_for("evm_reentrancy_classic").generate(ReportFormat::Markdown);
        assert!(md.contains("**Detector:** `evm_reentrancy_classic`"));
        assert!(md.contains("CWE-841 · Improper Enforcement of Behavioral Workflow"));
        assert!(md.contains("SWC-107 · Reentrancy"));
        assert!(md.contains("**OWASP Smart Contract Top 10:** SC05 · Reentrancy Attacks"));
        assert!(md.contains("DASP-1 · Reentrancy"));
    }

    #[test]
    fn markdown_report_omits_registry_lines_when_unmapped() {
        let md = report_for("my_custom_sinv_rule").generate(ReportFormat::Markdown);
        assert!(md.contains("**Detector:** `my_custom_sinv_rule`"));
        assert!(!md.contains("**CWE:**"), "must not invent a weakness class");
    }

    #[test]
    fn html_report_renders_findings_with_taxonomy() {
        // Before this, generate_html emitted only a summary — a "report" with
        // no findings in it.
        let html = report_for("evm_reentrancy_classic").generate(ReportFormat::Html);
        assert!(html.contains("<th>Classification</th>"));
        assert!(html.contains("evm_reentrancy_classic"));
        assert!(html.contains("Vault.sol:42"));
        assert!(html.contains(r#"class="tax""#));
        assert!(html.contains(">CWE-841<"), "badge should show the bare ID");
        assert!(
            html.contains("Improper Enforcement of Behavioral Workflow"),
            "tooltip should carry the full weakness name"
        );
        assert!(html.contains(">SWC-107<"));
    }

    #[test]
    fn html_report_shows_an_empty_state_rather_than_an_empty_table() {
        let empty = SecurityReport::new(
            "Clean".to_string(),
            vec!["Vault.sol".to_string()],
            vec![],
            "no issues".to_string(),
        );
        let html = empty.generate(ReportFormat::Html);
        assert!(html.contains("No findings."));
    }

    #[test]
    fn html_report_escapes_finding_fields() {
        // File paths and messages both reach the HTML and are both
        // attacker-influenceable. The old generator rendered neither, so
        // nothing covered this.
        let mut report = report_for("evm_reentrancy_classic");
        report.findings[0].file = r#"a"><img src=x onerror=alert(1)>.sol"#.to_string();
        report.findings[0].message = "<script>alert('xss')</script>".to_string();

        let html = report.generate(ReportFormat::Html);
        assert!(
            !html.contains("<img src=x onerror="),
            "file path was not escaped:\n{html}"
        );
        assert!(
            !html.contains("<script>alert('xss')</script>"),
            "message was not escaped:\n{html}"
        );
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_report_omits_badges_for_unmapped_invariants() {
        let html = report_for("my_custom_sinv_rule").generate(ReportFormat::Html);
        assert!(html.contains("my_custom_sinv_rule"));
        assert!(
            !html.contains(r#"class="tax""#),
            "must not invent a classification"
        );
    }

    #[test]
    fn severity_stats_from_findings() {
        let findings = vec![
            Finding::new(
                "test".to_string(),
                Severity::Critical,
                "file.sol".to_string(),
                1,
                0,
                "Test".to_string(),
                "code".to_string(),
            ),
            Finding::new(
                "test".to_string(),
                Severity::High,
                "file.sol".to_string(),
                2,
                0,
                "Test".to_string(),
                "code".to_string(),
            ),
        ];

        let stats = SeverityStats::from_findings(&findings);
        assert_eq!(stats.critical, 1);
        assert_eq!(stats.high, 1);
        assert_eq!(stats.total(), 2);
    }

    #[test]
    fn risk_score_calculation() {
        let stats = SeverityStats {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            info: 0,
        };

        let score = stats.risk_score();
        assert!(score > 0.0);
        assert!(score <= 100.0);
    }

    #[test]
    fn report_generation() {
        let findings = vec![];
        let report = SecurityReport::new(
            "Test Report".to_string(),
            vec!["test.sol".to_string()],
            findings,
            "No issues found".to_string(),
        );

        let md = report.generate(ReportFormat::Markdown);
        assert!(md.contains("Test Report"));
    }

    /// A malicious title (e.g. derived from an attacker-chosen file/contract
    /// name) must never corrupt the JSON structure or let content escape its
    /// string field.
    #[test]
    fn json_report_escapes_untrusted_title() {
        let report = SecurityReport::new(
            r#"Evil" , "injected": true, "x": ""#.to_string(),
            vec!["test.sol".to_string()],
            vec![],
            "summary".to_string(),
        );

        let json = report.generate(ReportFormat::Json);
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("generated JSON must always parse");
        assert!(parsed.get("injected").is_none(), "must not inject new keys");
    }

    /// A finding message containing HTML/script content must be escaped, not
    /// interpolated raw, when embedded in an HTML report.
    #[test]
    fn html_report_escapes_script_content() {
        let report = SecurityReport::new(
            "<script>alert(1)</script>".to_string(),
            vec!["test.sol".to_string()],
            vec![],
            "summary".to_string(),
        );

        let html = report.generate(ReportFormat::Html);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    /// A finding message containing a comma and a quote must not break CSV
    /// column alignment - every field is quoted and internal quotes doubled.
    #[test]
    fn csv_report_escapes_commas_and_quotes() {
        let findings = vec![Finding::new(
            "test_id".to_string(),
            Severity::High,
            "file.sol".to_string(),
            1,
            0,
            r#"message, with "quotes" and, commas"#.to_string(),
            "code".to_string(),
        )];
        let report = SecurityReport::new(
            "Test".to_string(),
            vec!["test.sol".to_string()],
            findings,
            "summary".to_string(),
        );

        let csv = report.generate(ReportFormat::Csv);
        let data_line = csv.lines().nth(1).expect("must have a data row");
        // Exactly 5 quoted fields, not split apart by the embedded commas.
        assert_eq!(data_line.matches('"').count() % 2, 0, "quotes must balance");
        assert!(data_line.contains(r#""message, with ""quotes"" and, commas""#));
    }
}
