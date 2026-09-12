//! Unified finding type for all detectors across all chains.
//!
//! A `Finding` represents a security issue discovered by an invariant detector.
//! All detectors (EVM, Solana, Move) produce findings in this format.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity levels for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Severity {
    /// Informational: Best practices or informational notices.
    Info,
    /// Low severity: Minor issues with low impact.
    Low,
    /// Medium severity: Moderate issues requiring attention.
    Medium,
    /// High severity: Serious issues requiring urgent action.
    High,
    /// Critical severity: Severe vulnerabilities requiring immediate remediation.
    Critical,
}

impl Severity {
    /// Get numeric value for ordering and comparison.
    pub fn value(self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    /// Get human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    /// Get ANSI color code for terminal output.
    pub fn ansi_color(self) -> &'static str {
        match self {
            Self::Info => "\x1b[36m",       // Cyan
            Self::Low => "\x1b[34m",        // Blue
            Self::Medium => "\x1b[33m",     // Yellow
            Self::High => "\x1b[1;33m",     // Bold yellow
            Self::Critical => "\x1b[1;31m", // Bold red
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A security finding discovered by a detector.
///
/// This is the unified output type for all invariant violations, accessible
/// across EVM, Solana, Move, and other analyzers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for the invariant that was violated.
    /// Example: "evm_reentrancy_classic", "sol_missing_signer", "move_access_control_missing"
    pub invariant_id: String,

    /// Severity of this finding.
    pub severity: Severity,

    /// Source file path (relative to project root).
    pub file: String,

    /// Line number in source file (1-indexed).
    pub line: usize,

    /// Column number in source file (0-indexed).
    pub col: usize,

    /// Human-readable description of the finding.
    /// Should explain what was found and why it's a problem.
    pub message: String,

    /// Code snippet showing the problematic code (for context in reports).
    /// Include a few lines of context around the issue.
    pub snippet: String,

    /// Optional source code fragment (full function or smaller unit).
    /// Useful for detailed analysis.
    pub source_fragment: Option<String>,

    /// Optional transaction hash or test case ID (for runtime detections).
    pub transaction_hash: Option<String>,

    /// Additional metadata (chain, detector version, etc).
    /// Can be used by report formatters.
    pub metadata: std::collections::BTreeMap<String, String>,

    /// How strongly this result is supported.
    ///
    /// Defaults to [`Evidence::Lead`]: a result is a *lead* until something
    /// actually executed the code and observed the failure. Static detectors
    /// therefore never claim proof they do not have.
    #[serde(default)]
    pub evidence: Evidence,
}

/// How strongly a result is supported.
///
/// Truent's premise is that a finding is something an engine *made happen*,
/// not something a pattern suggested. Keeping the two apart is what lets a
/// reader trust the report: a `Proven` result comes with a reproduction, and a
/// `Lead` is an honest "worth a look" that has not been demonstrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Evidence {
    /// A pattern matched the source. Nothing was executed; the condition may
    /// be unreachable, intended, or already guarded elsewhere.
    #[default]
    Lead,

    /// The engine executed the contract and observed the property fail. Comes
    /// with the call sequence that reproduces it.
    Proven,
}

impl Evidence {
    /// Short label for reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Proven => "PROVEN",
            Self::Lead => "LEAD",
        }
    }

    /// Whether this result was demonstrated by execution.
    pub fn is_proven(&self) -> bool {
        matches!(self, Self::Proven)
    }
}

impl std::fmt::Display for Evidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl Finding {
    /// Create a new finding.
    pub fn new(
        invariant_id: String,
        severity: Severity,
        file: String,
        line: usize,
        col: usize,
        message: String,
        snippet: String,
    ) -> Self {
        Self {
            invariant_id,
            severity,
            file,
            line,
            col,
            message,
            snippet,
            source_fragment: None,
            transaction_hash: None,
            metadata: Default::default(),
            // A detector must opt in to claiming proof.
            evidence: Evidence::Lead,
        }
    }

    /// Mark this result as demonstrated by execution.
    ///
    /// Only callers that actually ran the contract and observed the failure
    /// may use this — the reproduction is what distinguishes a finding from a
    /// lead.
    pub fn proven(mut self) -> Self {
        self.evidence = Evidence::Proven;
        self
    }

    /// Whether this result was demonstrated by execution.
    pub fn is_proven(&self) -> bool {
        self.evidence.is_proven()
    }

    /// Add metadata to this finding.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set the source fragment for this finding.
    pub fn with_source_fragment(mut self, fragment: String) -> Self {
        self.source_fragment = Some(fragment);
        self
    }

    /// Set the transaction hash for this finding (runtime detections).
    pub fn with_transaction_hash(mut self, tx_hash: String) -> Self {
        self.transaction_hash = Some(tx_hash);
        self
    }

    /// Industry-standard taxonomy for this finding — CWE, SWC, OWASP Smart
    /// Contract Top 10, and DASP.
    ///
    /// Returns `None` for invariants with no mapping (user-authored `.sinv`
    /// rules, test fixtures). Callers must render the absence rather than
    /// substitute a plausible-looking class: a wrong CWE in an audit report is
    /// worse than a missing one.
    pub fn taxonomy(&self) -> Option<&'static crate::taxonomy::Taxonomy> {
        crate::taxonomy::taxonomy_for(&self.invariant_id)
    }

    /// Get a unique key for deduplication (invariant_id + file + line).
    pub fn dedup_key(&self) -> String {
        format!("{}:{}:{}", self.invariant_id, self.file, self.line)
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} at {}:{}:{} - {}",
            self.severity, self.invariant_id, self.file, self.line, self.col, self.message
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Low < Severity::Medium);
    }

    #[test]
    fn test_finding_dedup_key() {
        let f = Finding::new(
            "test_invariant".to_string(),
            Severity::High,
            "contract.sol".to_string(),
            42,
            10,
            "Test message".to_string(),
            "code snippet".to_string(),
        );
        assert_eq!(f.dedup_key(), "test_invariant:contract.sol:42");
    }

    #[test]
    fn test_finding_taxonomy_lookup() {
        let f = Finding::new(
            "evm_reentrancy_classic".to_string(),
            Severity::Critical,
            "Vault.sol".to_string(),
            42,
            0,
            "msg".to_string(),
            "code".to_string(),
        );
        let tax = f.taxonomy().expect("a shipped detector must be mapped");
        assert_eq!(tax.primary_cwe().id, 841);
        assert!(tax.tags().contains(&"SWC-107".to_string()));

        // An unmapped ID yields nothing rather than a guess.
        let unknown = Finding::new(
            "my_custom_sinv_rule".to_string(),
            Severity::Low,
            "x.sol".to_string(),
            1,
            0,
            "m".to_string(),
            "c".to_string(),
        );
        assert!(unknown.taxonomy().is_none());
    }

    #[test]
    fn test_finding_with_metadata() {
        let f = Finding::new(
            "test".to_string(),
            Severity::Medium,
            "file.rs".to_string(),
            1,
            0,
            "msg".to_string(),
            "snippet".to_string(),
        )
        .with_metadata("chain".to_string(), "evm".to_string());

        assert_eq!(f.metadata.get("chain"), Some(&"evm".to_string()));
    }
}
