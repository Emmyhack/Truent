//! Industry-standard vulnerability taxonomy for every invariant Truent reports.
//!
//! A finding is only as useful as the vocabulary it is reported in. A client
//! reading `evm_readonly_reentrancy` learns nothing transferable; the same
//! finding tagged **CWE-841**, **SWC-107**, **OWASP SC05** and **DASP-1** slots
//! straight into their existing triage, their compliance evidence, and GitHub
//! code scanning's CWE facets.
//!
//! This module is the single source of truth for that mapping. Every
//! `Finding::invariant_id` emitted anywhere in the workspace has exactly one
//! entry in [`TAXONOMY`], and [`tests`] fails the build if a detector is added
//! without one — so the mapping cannot silently rot behind the detectors.
//!
//! Four taxonomies are carried, because each answers a different question:
//!
//! | Taxonomy | Answers | Audience |
//! |---|---|---|
//! | [`Cwe`] | *What class of weakness is this?* | SARIF / code scanning / compliance |
//! | [`Swc`] | *Which known Solidity anti-pattern?* | EVM auditors |
//! | [`OwaspSc`] | *Where does it sit in the 2025 Top 10?* | Report executive summaries |
//! | [`Dasp`] | *Which classic DeFi attack category?* | Cross-report comparison |
//!
//! SWC, OWASP SC and DASP are EVM-centric registries. Non-EVM invariants carry
//! CWE (universal) and, where the concept genuinely transfers, an OWASP SC
//! category — but they deliberately leave `swc` empty rather than invent an ID.

use serde::{Deserialize, Serialize};

/// A [CWE](https://cwe.mitre.org) weakness class.
///
/// The universal taxonomy: chain-agnostic, recognised by SARIF consumers,
/// GitHub code scanning, and most compliance frameworks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Cwe {
    /// Numeric CWE identifier (e.g. `841` for `CWE-841`).
    pub id: u16,
    /// Official CWE weakness name.
    pub name: &'static str,
}

impl Cwe {
    /// Canonical identifier, e.g. `"CWE-841"`.
    pub fn id_str(&self) -> String {
        format!("CWE-{}", self.id)
    }

    /// Display label used in reports, e.g. `"CWE-841 · Improper Enforcement of
    /// Behavioral Workflow"`.
    pub fn label(&self) -> String {
        format!("CWE-{} · {}", self.id, self.name)
    }

    /// Canonical MITRE URL for this weakness.
    pub fn url(&self) -> String {
        format!("https://cwe.mitre.org/data/definitions/{}.html", self.id)
    }
}

impl std::fmt::Display for Cwe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// An entry in the [SWC Registry](https://swcregistry.io) — the Smart Contract
/// Weakness Classification.
///
/// SWC is frozen (superseded by EEA EthTrust), but it remains the vocabulary
/// most EVM audit reports and competing tools still speak, so findings that map
/// cleanly to an SWC ID carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Swc {
    /// Numeric SWC identifier (e.g. `107` for `SWC-107`).
    pub id: u16,
    /// Official SWC title.
    pub title: &'static str,
}

impl Swc {
    /// Canonical identifier, e.g. `"SWC-107"`.
    pub fn id_str(&self) -> String {
        format!("SWC-{}", self.id)
    }

    /// Display label, e.g. `"SWC-107 · Reentrancy"`.
    pub fn label(&self) -> String {
        format!("SWC-{} · {}", self.id, self.title)
    }

    /// Canonical SWC Registry URL.
    pub fn url(&self) -> String {
        format!("https://swcregistry.io/docs/SWC-{}", self.id)
    }
}

impl std::fmt::Display for Swc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// A [MITRE ATT&CK](https://attack.mitre.org) technique.
///
/// The vocabulary of adversary behaviour. Contract findings rarely map to
/// it — an exploit of a public contract is `T1190` and little more — but
/// repository findings map precisely: a committed credential is
/// `T1552.001`, a hijacked CI workflow is `T1195.002`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Attack {
    /// Technique ID, e.g. `"T1552.001"`.
    pub id: &'static str,
    /// Technique name.
    pub name: &'static str,
}

impl Attack {
    /// Display label, e.g. `"T1552.001 · Credentials In Files"`.
    pub fn label(&self) -> String {
        format!("{} · {}", self.id, self.name)
    }

    /// Canonical MITRE URL.
    pub fn url(&self) -> String {
        format!(
            "https://attack.mitre.org/techniques/{}/",
            self.id.replace('.', "/")
        )
    }
}

/// A [NIST CSF 2.0](https://www.nist.gov/cyberframework) subcategory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct NistCsf {
    /// Subcategory ID, e.g. `"PR.AA-05"`.
    pub id: &'static str,
    /// Subcategory outcome.
    pub name: &'static str,
}

impl NistCsf {
    /// Display label.
    pub fn label(&self) -> String {
        format!("{} · {}", self.id, self.name)
    }
}

/// [OWASP Smart Contract Top 10 (2025)](https://owasp.org/www-project-smart-contract-top-10/).
///
/// The category an executive summary leads with. Unlike SWC this is actively
/// maintained, and its categories are abstract enough to apply beyond the EVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwaspSc {
    /// SC01 — Access Control Vulnerabilities.
    AccessControl,
    /// SC02 — Price Oracle Manipulation.
    PriceOracleManipulation,
    /// SC03 — Logic Errors.
    LogicErrors,
    /// SC04 — Lack of Input Validation.
    LackOfInputValidation,
    /// SC05 — Reentrancy Attacks.
    Reentrancy,
    /// SC06 — Unchecked External Calls.
    UncheckedExternalCalls,
    /// SC07 — Flash Loan Attacks.
    FlashLoanAttacks,
    /// SC08 — Integer Overflow and Underflow.
    IntegerOverflowUnderflow,
    /// SC09 — Insecure Randomness.
    InsecureRandomness,
    /// SC10 — Denial of Service Attacks.
    DenialOfService,
}

impl OwaspSc {
    /// Canonical identifier, e.g. `"SC05"`.
    pub fn id_str(&self) -> &'static str {
        match self {
            Self::AccessControl => "SC01",
            Self::PriceOracleManipulation => "SC02",
            Self::LogicErrors => "SC03",
            Self::LackOfInputValidation => "SC04",
            Self::Reentrancy => "SC05",
            Self::UncheckedExternalCalls => "SC06",
            Self::FlashLoanAttacks => "SC07",
            Self::IntegerOverflowUnderflow => "SC08",
            Self::InsecureRandomness => "SC09",
            Self::DenialOfService => "SC10",
        }
    }

    /// Official category title.
    pub fn title(&self) -> &'static str {
        match self {
            Self::AccessControl => "Access Control Vulnerabilities",
            Self::PriceOracleManipulation => "Price Oracle Manipulation",
            Self::LogicErrors => "Logic Errors",
            Self::LackOfInputValidation => "Lack of Input Validation",
            Self::Reentrancy => "Reentrancy Attacks",
            Self::UncheckedExternalCalls => "Unchecked External Calls",
            Self::FlashLoanAttacks => "Flash Loan Attacks",
            Self::IntegerOverflowUnderflow => "Integer Overflow and Underflow",
            Self::InsecureRandomness => "Insecure Randomness",
            Self::DenialOfService => "Denial of Service Attacks",
        }
    }

    /// Display label, e.g. `"SC05 · Reentrancy Attacks"`.
    pub fn label(&self) -> String {
        format!("{} · {}", self.id_str(), self.title())
    }

    /// Every category, in Top 10 order.
    pub fn all() -> &'static [OwaspSc] {
        &[
            Self::AccessControl,
            Self::PriceOracleManipulation,
            Self::LogicErrors,
            Self::LackOfInputValidation,
            Self::Reentrancy,
            Self::UncheckedExternalCalls,
            Self::FlashLoanAttacks,
            Self::IntegerOverflowUnderflow,
            Self::InsecureRandomness,
            Self::DenialOfService,
        ]
    }
}

impl std::fmt::Display for OwaspSc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// [DASP Top 10](https://dasp.co) — Decentralized Application Security Project.
///
/// Older than OWASP SC and narrower, but still the shared shorthand auditors
/// use when comparing findings across reports ("that's a classic DASP-1").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dasp {
    /// DASP-1 — Reentrancy.
    Reentrancy,
    /// DASP-2 — Access Control.
    AccessControl,
    /// DASP-3 — Arithmetic.
    Arithmetic,
    /// DASP-4 — Unchecked Low Level Calls.
    UncheckedLowLevelCalls,
    /// DASP-5 — Denial of Service.
    DenialOfService,
    /// DASP-6 — Bad Randomness.
    BadRandomness,
    /// DASP-7 — Front-Running.
    FrontRunning,
    /// DASP-8 — Time Manipulation.
    TimeManipulation,
    /// DASP-9 — Short Address Attack.
    ShortAddressAttack,
    /// DASP-10 — Unknown Unknowns.
    UnknownUnknowns,
}

impl Dasp {
    /// Rank within the Top 10 (1-based).
    pub fn rank(&self) -> u8 {
        match self {
            Self::Reentrancy => 1,
            Self::AccessControl => 2,
            Self::Arithmetic => 3,
            Self::UncheckedLowLevelCalls => 4,
            Self::DenialOfService => 5,
            Self::BadRandomness => 6,
            Self::FrontRunning => 7,
            Self::TimeManipulation => 8,
            Self::ShortAddressAttack => 9,
            Self::UnknownUnknowns => 10,
        }
    }

    /// Official category title.
    pub fn title(&self) -> &'static str {
        match self {
            Self::Reentrancy => "Reentrancy",
            Self::AccessControl => "Access Control",
            Self::Arithmetic => "Arithmetic",
            Self::UncheckedLowLevelCalls => "Unchecked Low Level Calls",
            Self::DenialOfService => "Denial of Service",
            Self::BadRandomness => "Bad Randomness",
            Self::FrontRunning => "Front-Running",
            Self::TimeManipulation => "Time Manipulation",
            Self::ShortAddressAttack => "Short Address Attack",
            Self::UnknownUnknowns => "Unknown Unknowns",
        }
    }

    /// Canonical identifier, e.g. `"DASP-1"`.
    pub fn id_str(&self) -> String {
        format!("DASP-{}", self.rank())
    }

    /// Display label, e.g. `"DASP-1 · Reentrancy"`.
    pub fn label(&self) -> String {
        format!("{} · {}", self.id_str(), self.title())
    }
}

impl std::fmt::Display for Dasp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// The taxonomy mappings for a single invariant.
///
/// Look one up with [`taxonomy_for`]. `cwe` is never empty — every invariant
/// Truent reports has at least one CWE class. The registry-specific fields may
/// legitimately be empty when no honest mapping exists (a Soroban storage-TTL
/// bug has no SWC ID, and inventing one would be worse than omitting it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Taxonomy {
    /// The `Finding::invariant_id` this entry describes.
    pub invariant_id: &'static str,
    /// CWE weakness classes, most specific first. Never empty.
    pub cwe: &'static [Cwe],
    /// SWC Registry entries. Empty for non-EVM or non-Solidity concepts.
    pub swc: &'static [Swc],
    /// OWASP Smart Contract Top 10 (2025) categories.
    pub owasp_sc: &'static [OwaspSc],
    /// DASP Top 10 categories.
    pub dasp: &'static [Dasp],
    /// MITRE ATT&CK techniques. Populated for repository findings; contract
    /// findings leave it empty rather than stretch `T1190` over everything.
    pub attack: &'static [Attack],
    /// NIST CSF 2.0 subcategories.
    pub nist_csf: &'static [NistCsf],
}

impl Taxonomy {
    /// The primary CWE — the one to show when there is room for only one.
    pub fn primary_cwe(&self) -> Cwe {
        // The table invariant (enforced by `every_entry_has_a_cwe`) is that
        // `cwe` is non-empty, so this indexing cannot panic.
        self.cwe[0]
    }

    /// Chain this invariant belongs to, derived from the ID prefix.
    ///
    /// Returns `None` for chain-agnostic rules that run against the shared
    /// semantic model (e.g. `unauthorized_privileged_mutation`). `"general"`
    /// is the repository analyzer, which is not a chain but is a source.
    pub fn chain(&self) -> Option<&'static str> {
        match self.invariant_id.split('_').next() {
            Some("evm") => Some("evm"),
            Some("sol") => Some("solana"),
            Some("move") => Some("move"),
            Some("sor") => Some("soroban"),
            Some("gen") => Some("general"),
            Some("sca") => Some("supply-chain"),
            Some("rt") => Some("runtime"),
            _ => None,
        }
    }

    /// All taxonomy IDs as short strings, for tagging (SARIF `properties.tags`,
    /// HTML badges, NDJSON): `["CWE-841", "SWC-107", "SC05", "DASP-1"]`.
    pub fn tags(&self) -> Vec<String> {
        let mut tags = Vec::new();
        tags.extend(self.cwe.iter().map(Cwe::id_str));
        tags.extend(self.swc.iter().map(Swc::id_str));
        tags.extend(self.owasp_sc.iter().map(|o| o.id_str().to_string()));
        tags.extend(self.dasp.iter().map(Dasp::id_str));
        tags.extend(self.attack.iter().map(|a| a.id.to_string()));
        tags.extend(self.nist_csf.iter().map(|n| n.id.to_string()));
        tags
    }
}

/// Look up the taxonomy for an invariant ID.
///
/// Returns `None` only for IDs that are not real detectors (test fixtures,
/// user-authored `.sinv` invariants). Callers should degrade gracefully rather
/// than guess a class — an absent mapping is more honest than a wrong one,
/// which is exactly the failure mode this module replaced.
pub fn taxonomy_for(invariant_id: &str) -> Option<&'static Taxonomy> {
    TAXONOMY
        .binary_search_by_key(&invariant_id, |t| t.invariant_id)
        .ok()
        .map(|i| &TAXONOMY[i])
}

/// Every taxonomy entry, sorted by invariant ID.
pub fn all() -> &'static [Taxonomy] {
    TAXONOMY
}

/// Named CWE constants used by [`TAXONOMY`].
///
/// Declared once and referenced by name so the table reads as claims about
/// vulnerabilities rather than a wall of magic numbers, and so a correction to
/// a weakness name lands in exactly one place.
pub mod cwes {
    use super::Cwe;

    /// CWE-20 — Improper Input Validation.
    pub const IMPROPER_INPUT_VALIDATION: Cwe = Cwe {
        id: 20,
        name: "Improper Input Validation",
    };
    /// CWE-190 — Integer Overflow or Wraparound.
    pub const INTEGER_OVERFLOW: Cwe = Cwe {
        id: 190,
        name: "Integer Overflow or Wraparound",
    };
    /// CWE-191 — Integer Underflow (Wrap or Wraparound).
    pub const INTEGER_UNDERFLOW: Cwe = Cwe {
        id: 191,
        name: "Integer Underflow (Wrap or Wraparound)",
    };
    /// CWE-252 — Unchecked Return Value.
    pub const UNCHECKED_RETURN_VALUE: Cwe = Cwe {
        id: 252,
        name: "Unchecked Return Value",
    };
    /// CWE-284 — Improper Access Control.
    pub const IMPROPER_ACCESS_CONTROL: Cwe = Cwe {
        id: 284,
        name: "Improper Access Control",
    };
    /// CWE-285 — Improper Authorization.
    pub const IMPROPER_AUTHORIZATION: Cwe = Cwe {
        id: 285,
        name: "Improper Authorization",
    };
    /// CWE-294 — Authentication Bypass by Capture-replay.
    pub const CAPTURE_REPLAY: Cwe = Cwe {
        id: 294,
        name: "Authentication Bypass by Capture-replay",
    };
    /// CWE-330 — Use of Insufficiently Random Values.
    pub const INSUFFICIENTLY_RANDOM: Cwe = Cwe {
        id: 330,
        name: "Use of Insufficiently Random Values",
    };
    /// CWE-345 — Insufficient Verification of Data Authenticity.
    pub const INSUFFICIENT_VERIFICATION: Cwe = Cwe {
        id: 345,
        name: "Insufficient Verification of Data Authenticity",
    };
    /// CWE-347 — Improper Verification of Cryptographic Signature.
    pub const IMPROPER_SIGNATURE_VERIFICATION: Cwe = Cwe {
        id: 347,
        name: "Improper Verification of Cryptographic Signature",
    };
    /// CWE-349 — Acceptance of Extraneous Untrusted Data With Trusted Data.
    pub const EXTRANEOUS_UNTRUSTED_DATA: Cwe = Cwe {
        id: 349,
        name: "Acceptance of Extraneous Untrusted Data With Trusted Data",
    };
    /// CWE-362 — Race Condition (Concurrent Execution using Shared Resource).
    pub const RACE_CONDITION: Cwe = Cwe {
        id: 362,
        name: "Concurrent Execution using Shared Resource with Improper Synchronization",
    };
    /// CWE-367 — Time-of-check Time-of-use (TOCTOU) Race Condition.
    pub const TOCTOU: Cwe = Cwe {
        id: 367,
        name: "Time-of-check Time-of-use (TOCTOU) Race Condition",
    };
    /// CWE-369 — Divide By Zero.
    pub const DIVIDE_BY_ZERO: Cwe = Cwe {
        id: 369,
        name: "Divide By Zero",
    };
    /// CWE-400 — Uncontrolled Resource Consumption.
    pub const UNCONTROLLED_RESOURCE_CONSUMPTION: Cwe = Cwe {
        id: 400,
        name: "Uncontrolled Resource Consumption",
    };
    /// CWE-404 — Improper Resource Shutdown or Release.
    pub const IMPROPER_RESOURCE_SHUTDOWN: Cwe = Cwe {
        id: 404,
        name: "Improper Resource Shutdown or Release",
    };
    /// CWE-494 — Download of Code Without Integrity Check.
    pub const CODE_WITHOUT_INTEGRITY_CHECK: Cwe = Cwe {
        id: 494,
        name: "Download of Code Without Integrity Check",
    };
    /// CWE-610 — Externally Controlled Reference to a Resource in Another Sphere.
    pub const EXTERNALLY_CONTROLLED_REFERENCE: Cwe = Cwe {
        id: 610,
        name: "Externally Controlled Reference to a Resource in Another Sphere",
    };
    /// CWE-654 — Reliance on a Single Factor in a Security Decision.
    pub const SINGLE_FACTOR_RELIANCE: Cwe = Cwe {
        id: 654,
        name: "Reliance on a Single Factor in a Security Decision",
    };
    /// CWE-662 — Improper Synchronization.
    pub const IMPROPER_SYNCHRONIZATION: Cwe = Cwe {
        id: 662,
        name: "Improper Synchronization",
    };
    /// CWE-663 — Use of a Non-reentrant Function in a Concurrent Context.
    pub const NON_REENTRANT_IN_CONCURRENT_CONTEXT: Cwe = Cwe {
        id: 663,
        name: "Use of a Non-reentrant Function in a Concurrent Context",
    };
    /// CWE-665 — Improper Initialization.
    pub const IMPROPER_INITIALIZATION: Cwe = Cwe {
        id: 665,
        name: "Improper Initialization",
    };
    /// CWE-670 — Always-Incorrect Control Flow Implementation.
    pub const ALWAYS_INCORRECT_CONTROL_FLOW: Cwe = Cwe {
        id: 670,
        name: "Always-Incorrect Control Flow Implementation",
    };
    /// CWE-672 — Operation on a Resource after Expiration or Release.
    pub const OPERATION_AFTER_EXPIRATION: Cwe = Cwe {
        id: 672,
        name: "Operation on a Resource after Expiration or Release",
    };
    /// CWE-682 — Incorrect Calculation.
    pub const INCORRECT_CALCULATION: Cwe = Cwe {
        id: 682,
        name: "Incorrect Calculation",
    };
    /// CWE-693 — Protection Mechanism Failure.
    pub const PROTECTION_MECHANISM_FAILURE: Cwe = Cwe {
        id: 693,
        name: "Protection Mechanism Failure",
    };
    /// CWE-703 — Improper Check or Handling of Exceptional Conditions.
    pub const IMPROPER_EXCEPTION_HANDLING: Cwe = Cwe {
        id: 703,
        name: "Improper Check or Handling of Exceptional Conditions",
    };
    /// CWE-732 — Incorrect Permission Assignment for Critical Resource.
    pub const INCORRECT_PERMISSION_ASSIGNMENT: Cwe = Cwe {
        id: 732,
        name: "Incorrect Permission Assignment for Critical Resource",
    };
    /// CWE-754 — Improper Check for Unusual or Exceptional Conditions.
    pub const IMPROPER_CHECK_EXCEPTIONAL: Cwe = Cwe {
        id: 754,
        name: "Improper Check for Unusual or Exceptional Conditions",
    };
    /// CWE-770 — Allocation of Resources Without Limits or Throttling.
    pub const UNBOUNDED_ALLOCATION: Cwe = Cwe {
        id: 770,
        name: "Allocation of Resources Without Limits or Throttling",
    };
    /// CWE-772 — Missing Release of Resource after Effective Lifetime.
    pub const MISSING_RESOURCE_RELEASE: Cwe = Cwe {
        id: 772,
        name: "Missing Release of Resource after Effective Lifetime",
    };
    /// CWE-807 — Reliance on Untrusted Inputs in a Security Decision.
    pub const UNTRUSTED_INPUT_IN_SECURITY_DECISION: Cwe = Cwe {
        id: 807,
        name: "Reliance on Untrusted Inputs in a Security Decision",
    };
    /// CWE-824 — Access of Uninitialized Pointer.
    pub const UNINITIALIZED_POINTER: Cwe = Cwe {
        id: 824,
        name: "Access of Uninitialized Pointer",
    };
    /// CWE-829 — Inclusion of Functionality from Untrusted Control Sphere.
    pub const UNTRUSTED_FUNCTIONALITY_INCLUSION: Cwe = Cwe {
        id: 829,
        name: "Inclusion of Functionality from Untrusted Control Sphere",
    };
    /// CWE-841 — Improper Enforcement of Behavioral Workflow.
    pub const IMPROPER_BEHAVIORAL_WORKFLOW: Cwe = Cwe {
        id: 841,
        name: "Improper Enforcement of Behavioral Workflow",
    };
    /// CWE-843 — Access of Resource Using Incompatible Type (Type Confusion).
    pub const TYPE_CONFUSION: Cwe = Cwe {
        id: 843,
        name: "Access of Resource Using Incompatible Type ('Type Confusion')",
    };
    /// CWE-862 — Missing Authorization.
    pub const MISSING_AUTHORIZATION: Cwe = Cwe {
        id: 862,
        name: "Missing Authorization",
    };
    /// CWE-863 — Incorrect Authorization.
    pub const INCORRECT_AUTHORIZATION: Cwe = Cwe {
        id: 863,
        name: "Incorrect Authorization",
    };
    /// CWE-913 — Improper Control of Dynamically-Managed Code Resources.
    pub const IMPROPER_DYNAMIC_CODE_CONTROL: Cwe = Cwe {
        id: 913,
        name: "Improper Control of Dynamically-Managed Code Resources",
    };
    /// CWE-89.
    pub const IMPROPER_NEUTRALIZATION_SQL: Cwe = Cwe {
        id: 89,
        name:
            "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    };
    /// CWE-78.
    pub const IMPROPER_NEUTRALIZATION_OS: Cwe = Cwe {
        id: 78,
        name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    };
    /// CWE-94.
    pub const CODE_INJECTION: Cwe = Cwe {
        id: 94,
        name: "Improper Control of Generation of Code ('Code Injection')",
    };
    /// CWE-79.
    pub const XSS: Cwe = Cwe {
        id: 79,
        name:
            "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    };
    /// CWE-798.
    pub const HARDCODED_CREDENTIALS: Cwe = Cwe {
        id: 798,
        name: "Use of Hard-coded Credentials",
    };
    /// CWE-502.
    pub const DESERIALIZATION: Cwe = Cwe {
        id: 502,
        name: "Deserialization of Untrusted Data",
    };
    /// CWE-295.
    pub const IMPROPER_CERT_VALIDATION: Cwe = Cwe {
        id: 295,
        name: "Improper Certificate Validation",
    };
    /// CWE-328.
    pub const WEAK_HASH: Cwe = Cwe {
        id: 328,
        name: "Use of Weak Hash",
    };
    /// CWE-532.
    pub const LOG_SENSITIVE: Cwe = Cwe {
        id: 532,
        name: "Insertion of Sensitive Information into Log File",
    };
    /// CWE-250.
    pub const UNNECESSARY_PRIVILEGES: Cwe = Cwe {
        id: 250,
        name: "Execution with Unnecessary Privileges",
    };
    /// CWE-321.
    pub const MISSING_ENCRYPTION_OF_KEY: Cwe = Cwe {
        id: 321,
        name: "Use of Hard-coded Cryptographic Key",
    };
    /// CWE-1395.
    pub const VULNERABLE_THIRD_PARTY: Cwe = Cwe {
        id: 1395,
        name: "Dependency on Vulnerable Third-Party Component",
    };
    /// CWE-942.
    pub const PERMISSIVE_CORS: Cwe = Cwe {
        id: 942,
        name: "Permissive Cross-domain Policy with Untrusted Domains",
    };
    /// CWE-614.
    pub const INSECURE_COOKIE: Cwe = Cwe {
        id: 614,
        name: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    };
    /// CWE-489.
    pub const DEBUG_ACTIVE: Cwe = Cwe {
        id: 489,
        name: "Active Debug Code",
    };
    /// CWE-352.
    pub const CSRF: Cwe = Cwe {
        id: 352,
        name: "Cross-Site Request Forgery (CSRF)",
    };
    /// CWE-918.
    pub const SSRF: Cwe = Cwe {
        id: 918,
        name: "Server-Side Request Forgery (SSRF)",
    };
    /// CWE-22.
    pub const PATH_TRAVERSAL: Cwe = Cwe {
        id: 22,
        name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    };
    /// CWE-668.
    pub const EXPOSED_RESOURCE: Cwe = Cwe {
        id: 668,
        name: "Exposure of Resource to Wrong Sphere",
    };
    /// CWE-311.
    pub const MISSING_ENCRYPTION: Cwe = Cwe {
        id: 311,
        name: "Missing Encryption of Sensitive Data",
    };
    /// CWE-653.
    pub const IMPROPER_ISOLATION: Cwe = Cwe {
        id: 653,
        name: "Improper Isolation or Compartmentalization",
    };
    /// CWE-1104.
    pub const UNCONTROLLED_SEARCH_PATH: Cwe = Cwe {
        id: 1104,
        name: "Use of Unmaintained Third Party Components",
    };
    /// CWE-1284 — Improper Validation of Specified Quantity in Input.
    pub const IMPROPER_QUANTITY_VALIDATION: Cwe = Cwe {
        id: 1284,
        name: "Improper Validation of Specified Quantity in Input",
    };
    /// CWE-1339 — Insufficient Precision or Accuracy of a Real Number.
    pub const INSUFFICIENT_PRECISION: Cwe = Cwe {
        id: 1339,
        name: "Insufficient Precision or Accuracy of a Real Number",
    };
    /// CWE-1021.
    pub const CLICKJACKING: Cwe = Cwe {
        id: 1021,
        name: "Improper Restriction of Rendered UI Layers or Frames",
    };
    /// CWE-200.
    pub const INFORMATION_EXPOSURE: Cwe = Cwe {
        id: 200,
        name: "Exposure of Sensitive Information to an Unauthorized Actor",
    };
    /// CWE-326.
    pub const INADEQUATE_ENCRYPTION_STRENGTH: Cwe = Cwe {
        id: 326,
        name: "Inadequate Encryption Strength",
    };
    /// CWE-915.
    pub const MASS_ASSIGNMENT: Cwe = Cwe {
        id: 915,
        name: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    };
    /// CWE-434.
    pub const UNRESTRICTED_UPLOAD: Cwe = Cwe {
        id: 434,
        name: "Unrestricted Upload of File with Dangerous Type",
    };
    /// CWE-209.
    pub const ERROR_MESSAGE_EXPOSURE: Cwe = Cwe {
        id: 209,
        name: "Generation of Error Message Containing Sensitive Information",
    };
    /// CWE-117.
    pub const LOG_NEUTRALIZATION: Cwe = Cwe {
        id: 117,
        name: "Improper Output Neutralization for Logs",
    };
    /// CWE-377.
    pub const INSECURE_TEMP_FILE: Cwe = Cwe {
        id: 377,
        name: "Insecure Temporary File",
    };
    /// CWE-1333.
    pub const REGEX_COMPLEXITY: Cwe = Cwe {
        id: 1333,
        name: "Inefficient Regular Expression Complexity",
    };
    /// CWE-611.
    pub const XXE: Cwe = Cwe {
        id: 611,
        name: "Improper Restriction of XML External Entity Reference",
    };
    /// CWE-601.
    pub const OPEN_REDIRECT: Cwe = Cwe {
        id: 601,
        name: "URL Redirection to Untrusted Site ('Open Redirect')",
    };
    /// CWE-307.
    pub const EXCESSIVE_AUTH_ATTEMPTS: Cwe = Cwe {
        id: 307,
        name: "Improper Restriction of Excessive Authentication Attempts",
    };
    /// CWE-778.
    pub const INSUFFICIENT_LOGGING: Cwe = Cwe {
        id: 778,
        name: "Insufficient Logging",
    };
    /// CWE-639.
    pub const USER_CONTROLLED_KEY: Cwe = Cwe {
        id: 639,
        name: "Authorization Bypass Through User-Controlled Key",
    };
    /// CWE-346.
    pub const ORIGIN_VALIDATION: Cwe = Cwe {
        id: 346,
        name: "Origin Validation Error",
    };
    /// CWE-427.
    pub const IMPROPER_SEARCH_PATH_PACKAGE: Cwe = Cwe {
        id: 427,
        name: "Uncontrolled Search Path Element",
    };
    /// CWE-834.
    pub const LOOP_WITHOUT_EXIT: Cwe = Cwe {
        id: 834,
        name: "Excessive Iteration",
    };
}

/// Named MITRE ATT&CK constants used by [`TAXONOMY`].
pub mod attacks {
    use super::Attack;
    pub const CREDENTIALS_IN_FILES: Attack = Attack {
        id: "T1552.001",
        name: "Unsecured Credentials: Credentials In Files",
    };
    pub const PRIVATE_KEYS: Attack = Attack {
        id: "T1552.004",
        name: "Unsecured Credentials: Private Keys",
    };
    pub const COMPROMISE_SOFTWARE_SUPPLY_CHAIN: Attack = Attack {
        id: "T1195.002",
        name: "Supply Chain Compromise: Compromise Software Supply Chain",
    };
    pub const COMPROMISE_DEPENDENCIES: Attack = Attack {
        id: "T1195.001",
        name: "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    };
    pub const COMMAND_AND_SCRIPTING: Attack = Attack {
        id: "T1059",
        name: "Command and Scripting Interpreter",
    };
    pub const EXPLOIT_PUBLIC_APPLICATION: Attack = Attack {
        id: "T1190",
        name: "Exploit Public-Facing Application",
    };
    pub const ESCAPE_TO_HOST: Attack = Attack {
        id: "T1611",
        name: "Escape to Host",
    };
    pub const DEPLOY_CONTAINER: Attack = Attack {
        id: "T1610",
        name: "Deploy Container",
    };
    pub const ADVERSARY_IN_THE_MIDDLE: Attack = Attack {
        id: "T1557",
        name: "Adversary-in-the-Middle",
    };
    pub const INGRESS_TOOL_TRANSFER: Attack = Attack {
        id: "T1105",
        name: "Ingress Tool Transfer",
    };
    pub const DATA_FROM_LOGS: Attack = Attack {
        id: "T1552",
        name: "Unsecured Credentials",
    };
    pub const BRUTE_FORCE_CRACKING: Attack = Attack {
        id: "T1110.002",
        name: "Brute Force: Password Cracking",
    };
    pub const DRIVE_BY: Attack = Attack {
        id: "T1189",
        name: "Drive-by Compromise",
    };
    pub const EXPLOIT_REMOTE_SERVICES: Attack = Attack {
        id: "T1210",
        name: "Exploitation of Remote Services",
    };
    pub const DATA_FROM_CLOUD_STORAGE: Attack = Attack {
        id: "T1530",
        name: "Data from Cloud Storage",
    };
    pub const EXTERNAL_REMOTE_SERVICES: Attack = Attack {
        id: "T1133",
        name: "External Remote Services",
    };
    pub const VALID_ACCOUNTS_CLOUD: Attack = Attack {
        id: "T1078.004",
        name: "Valid Accounts: Cloud Accounts",
    };
    pub const FORGE_WEB_CREDENTIALS: Attack = Attack {
        id: "T1606",
        name: "Forge Web Credentials",
    };
    pub const STEAL_WEB_SESSION_COOKIE: Attack = Attack {
        id: "T1539",
        name: "Steal Web Session Cookie",
    };
    pub const EXPLOIT_PUBLIC_APP_SSRF: Attack = Attack {
        id: "T1190",
        name: "Exploit Public-Facing Application",
    };
    pub const ACTIVE_SCANNING: Attack = Attack {
        id: "T1595",
        name: "Active Scanning",
    };
    pub const GATHER_VICTIM_HOST_INFO: Attack = Attack {
        id: "T1592",
        name: "Gather Victim Host Information",
    };
}

/// Named NIST CSF 2.0 constants used by [`TAXONOMY`].
pub mod nist {
    use super::NistCsf;
    pub const PR_AA_05: NistCsf = NistCsf {
        id: "PR.AA-05",
        name: "Access permissions and authorizations are managed, incorporating least privilege",
    };
    pub const PR_DS_01: NistCsf = NistCsf {
        id: "PR.DS-01",
        name: "The confidentiality, integrity, and availability of data-at-rest are protected",
    };
    pub const PR_DS_02: NistCsf = NistCsf {
        id: "PR.DS-02",
        name: "The confidentiality, integrity, and availability of data-in-transit are protected",
    };
    pub const PR_PS_01: NistCsf = NistCsf {
        id: "PR.PS-01",
        name: "Configuration management practices are established and applied",
    };
    pub const PR_PS_02: NistCsf = NistCsf {
        id: "PR.PS-02",
        name: "Software is maintained, replaced, and removed commensurate with risk",
    };
    pub const PR_PS_06: NistCsf = NistCsf {
        id: "PR.PS-06",
        name: "Secure software development practices are integrated",
    };
    pub const GV_SC_07: NistCsf = NistCsf {
        id: "GV.SC-07",
        name: "Supply chain risks are understood, recorded, prioritized, assessed, and monitored",
    };
    pub const DE_CM_09: NistCsf = NistCsf {
        id: "DE.CM-09",
        name: "Computing hardware and software, runtime environments, and their data are monitored",
    };
    pub const PR_IR_01: NistCsf = NistCsf {
        id: "PR.IR-01",
        name: "Networks and environments are protected from unauthorized logical access and usage",
    };
    pub const ID_RA_01: NistCsf = NistCsf {
        id: "ID.RA-01",
        name: "Vulnerabilities in assets are identified, validated, and recorded",
    };
    pub const PR_AA_03: NistCsf = NistCsf {
        id: "PR.AA-03",
        name: "Users, services, and hardware are authenticated",
    };
}

/// Named SWC Registry constants used by [`TAXONOMY`].
pub mod swcs {
    use super::Swc;

    /// SWC-101 — Integer Overflow and Underflow.
    pub const INTEGER_OVERFLOW_UNDERFLOW: Swc = Swc {
        id: 101,
        title: "Integer Overflow and Underflow",
    };
    /// SWC-104 — Unchecked Call Return Value.
    pub const UNCHECKED_CALL_RETURN: Swc = Swc {
        id: 104,
        title: "Unchecked Call Return Value",
    };
    /// SWC-105 — Unprotected Ether Withdrawal.
    pub const UNPROTECTED_ETHER_WITHDRAWAL: Swc = Swc {
        id: 105,
        title: "Unprotected Ether Withdrawal",
    };
    /// SWC-107 — Reentrancy.
    pub const REENTRANCY: Swc = Swc {
        id: 107,
        title: "Reentrancy",
    };
    /// SWC-109 — Uninitialized Storage Pointer.
    pub const UNINITIALIZED_STORAGE_POINTER: Swc = Swc {
        id: 109,
        title: "Uninitialized Storage Pointer",
    };
    /// SWC-112 — Delegatecall to Untrusted Callee.
    pub const DELEGATECALL_UNTRUSTED_CALLEE: Swc = Swc {
        id: 112,
        title: "Delegatecall to Untrusted Callee",
    };
    /// SWC-113 — DoS with Failed Call.
    pub const DOS_WITH_FAILED_CALL: Swc = Swc {
        id: 113,
        title: "DoS with Failed Call",
    };
    pub const DOS_BLOCK_GAS_LIMIT: Swc = Swc {
        id: 128,
        title: "DoS with Failed Call",
    };
    /// SWC-114 — Transaction Order Dependence.
    pub const TRANSACTION_ORDER_DEPENDENCE: Swc = Swc {
        id: 114,
        title: "Transaction Order Dependence",
    };
    /// SWC-115 — Authorization through tx.origin.
    pub const AUTHORIZATION_THROUGH_TX_ORIGIN: Swc = Swc {
        id: 115,
        title: "Authorization through tx.origin",
    };
    /// SWC-116 — Block values as a proxy for time.
    pub const BLOCK_VALUES_AS_TIME_PROXY: Swc = Swc {
        id: 116,
        title: "Block values as a proxy for time",
    };
    /// SWC-118 — Incorrect Constructor Name.
    pub const INCORRECT_CONSTRUCTOR_NAME: Swc = Swc {
        id: 118,
        title: "Incorrect Constructor Name",
    };
    /// SWC-120 — Weak Sources of Randomness from Chain Attributes.
    pub const WEAK_RANDOMNESS: Swc = Swc {
        id: 120,
        title: "Weak Sources of Randomness from Chain Attributes",
    };
    /// SWC-121 — Missing Protection against Signature Replay Attacks.
    pub const SIGNATURE_REPLAY: Swc = Swc {
        id: 121,
        title: "Missing Protection against Signature Replay Attacks",
    };
    /// SWC-122 — Lack of Proper Signature Verification.
    pub const LACK_OF_SIGNATURE_VERIFICATION: Swc = Swc {
        id: 122,
        title: "Lack of Proper Signature Verification",
    };
    /// SWC-123 — Requirement Violation.
    pub const REQUIREMENT_VIOLATION: Swc = Swc {
        id: 123,
        title: "Requirement Violation",
    };
    /// SWC-124 — Write to Arbitrary Storage Location.
    pub const ARBITRARY_STORAGE_WRITE: Swc = Swc {
        id: 124,
        title: "Write to Arbitrary Storage Location",
    };
    /// SWC-127 — Arbitrary Jump with Function Type Variable.
    pub const ARBITRARY_JUMP: Swc = Swc {
        id: 127,
        title: "Arbitrary Jump with Function Type Variable",
    };
    /// SWC-132 — Unexpected Ether balance.
    pub const UNEXPECTED_ETHER_BALANCE: Swc = Swc {
        id: 132,
        title: "Unexpected Ether balance",
    };
}

// Aliases keep the 100-row table readable: full paths would triple its width
// without adding information.
use attacks as A;
use cwes as C;
use nist as N;
use swcs as S;
use Dasp as D;
use OwaspSc as O;

/// The mapping table: one row per `Finding::invariant_id` in the workspace.
///
/// **Sorted by `invariant_id`** — [`taxonomy_for`] binary-searches it, and
/// `table_is_sorted` in this module's tests fails the build if that is ever
/// broken by an insertion in the wrong place.
static TAXONOMY: &[Taxonomy] = &[
    Taxonomy {
        invariant_id: "evm_aa_entropy_weakness",
        cwe: &[C::INSUFFICIENTLY_RANDOM],
        swc: &[S::WEAK_RANDOMNESS],
        owasp_sc: &[O::InsecureRandomness],
        dasp: &[D::BadRandomness],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_access_control",
        cwe: &[C::IMPROPER_ACCESS_CONTROL, C::MISSING_AUTHORIZATION],
        swc: &[S::UNPROTECTED_ETHER_WITHDRAWAL],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_arbitrary_call_msg_value",
        cwe: &[
            C::EXTERNALLY_CONTROLLED_REFERENCE,
            C::UNTRUSTED_FUNCTIONALITY_INCLUSION,
        ],
        swc: &[S::DELEGATECALL_UNTRUSTED_CALLEE],
        owasp_sc: &[O::UncheckedExternalCalls, O::AccessControl],
        dasp: &[D::UncheckedLowLevelCalls],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_arbitrary_function_selector_dispatch",
        cwe: &[
            C::IMPROPER_DYNAMIC_CODE_CONTROL,
            C::IMPROPER_INPUT_VALIDATION,
        ],
        swc: &[S::ARBITRARY_JUMP],
        owasp_sc: &[O::AccessControl, O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_arithmetic_rounding",
        cwe: &[C::INCORRECT_CALCULATION, C::INSUFFICIENT_PRECISION],
        swc: &[S::INTEGER_OVERFLOW_UNDERFLOW],
        owasp_sc: &[O::LogicErrors],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_bridge_address_cryptographic_verify",
        cwe: &[
            C::INSUFFICIENT_VERIFICATION,
            C::IMPROPER_SIGNATURE_VERIFICATION,
        ],
        swc: &[S::LACK_OF_SIGNATURE_VERIFICATION],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_conservation_check_absent",
        cwe: &[C::INCORRECT_CALCULATION],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_constructor_race_condition",
        cwe: &[C::RACE_CONDITION, C::IMPROPER_INITIALIZATION],
        swc: &[S::TRANSACTION_ORDER_DEPENDENCE],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::FrontRunning],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_cross_chain_replay_missing_chainid",
        cwe: &[C::CAPTURE_REPLAY],
        swc: &[S::SIGNATURE_REPLAY],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_delegatecall_injection",
        cwe: &[
            C::UNTRUSTED_FUNCTIONALITY_INCLUSION,
            C::IMPROPER_DYNAMIC_CODE_CONTROL,
        ],
        swc: &[S::DELEGATECALL_UNTRUSTED_CALLEE],
        owasp_sc: &[O::AccessControl, O::UncheckedExternalCalls],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_division_by_zero",
        cwe: &[C::DIVIDE_BY_ZERO, C::IMPROPER_EXCEPTION_HANDLING],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_dvn_single_point_failure",
        cwe: &[C::SINGLE_FACTOR_RELIANCE],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_dvn_threshold",
        cwe: &[C::SINGLE_FACTOR_RELIANCE, C::IMPROPER_AUTHORIZATION],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_eip7702_eoa_assumption",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::PROTECTION_MECHANISM_FAILURE,
        ],
        swc: &[S::AUTHORIZATION_THROUGH_TX_ORIGIN],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_erc4337_validation_side_effects",
        cwe: &[
            C::ALWAYS_INCORRECT_CONTROL_FLOW,
            C::PROTECTION_MECHANISM_FAILURE,
        ],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_erc4626_inflation_protection",
        cwe: &[C::INCORRECT_CALCULATION, C::INSUFFICIENT_PRECISION],
        swc: &[S::UNEXPECTED_ETHER_BALANCE],
        owasp_sc: &[O::LogicErrors, O::PriceOracleManipulation],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_fee_on_transfer_incompatibility",
        cwe: &[C::INCORRECT_CALCULATION, C::IMPROPER_INPUT_VALIDATION],
        swc: &[],
        owasp_sc: &[O::LogicErrors, O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_flash_loan_governance",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::SINGLE_FACTOR_RELIANCE,
        ],
        swc: &[],
        owasp_sc: &[O::FlashLoanAttacks],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_frontrunning",
        cwe: &[C::RACE_CONDITION, C::TOCTOU],
        swc: &[S::TRANSACTION_ORDER_DEPENDENCE],
        owasp_sc: &[O::LogicErrors],
        dasp: &[D::FrontRunning],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_insufficient_multisig_threshold",
        cwe: &[C::SINGLE_FACTOR_RELIANCE, C::IMPROPER_AUTHORIZATION],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_integer_overflow",
        cwe: &[C::INTEGER_OVERFLOW],
        swc: &[S::INTEGER_OVERFLOW_UNDERFLOW],
        owasp_sc: &[O::IntegerOverflowUnderflow],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_integer_underflow",
        cwe: &[C::INTEGER_UNDERFLOW],
        swc: &[S::INTEGER_OVERFLOW_UNDERFLOW],
        owasp_sc: &[O::IntegerOverflowUnderflow],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_legacy_unsafe_math",
        cwe: &[C::INTEGER_OVERFLOW, C::INTEGER_UNDERFLOW],
        swc: &[S::INTEGER_OVERFLOW_UNDERFLOW],
        owasp_sc: &[O::IntegerOverflowUnderflow],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_lst_depeg",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::INCORRECT_CALCULATION,
        ],
        swc: &[],
        owasp_sc: &[O::PriceOracleManipulation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_merkle_root_zero",
        cwe: &[C::INSUFFICIENT_VERIFICATION, C::IMPROPER_INITIALIZATION],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_merkle_root_zero_default",
        cwe: &[C::IMPROPER_INITIALIZATION, C::INSUFFICIENT_VERIFICATION],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_missing_pause_mechanism",
        cwe: &[C::PROTECTION_MECHANISM_FAILURE],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_missing_post_state_health_check",
        cwe: &[C::IMPROPER_CHECK_EXCEPTIONAL],
        swc: &[S::REQUIREMENT_VIOLATION],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_missing_signer_check",
        cwe: &[C::MISSING_AUTHORIZATION, C::IMPROPER_ACCESS_CONTROL],
        swc: &[S::UNPROTECTED_ETHER_WITHDRAWAL],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_oracle_self_trade",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::EXTRANEOUS_UNTRUSTED_DATA,
        ],
        swc: &[],
        owasp_sc: &[O::PriceOracleManipulation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_oracle_spot_price",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::IMPROPER_INPUT_VALIDATION,
        ],
        swc: &[],
        owasp_sc: &[O::PriceOracleManipulation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_precision_loss",
        cwe: &[C::INSUFFICIENT_PRECISION, C::INCORRECT_CALCULATION],
        swc: &[S::INTEGER_OVERFLOW_UNDERFLOW],
        owasp_sc: &[O::LogicErrors],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_proxy_storage_collision",
        cwe: &[C::IMPROPER_INITIALIZATION, C::TYPE_CONFUSION],
        swc: &[S::ARBITRARY_STORAGE_WRITE],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_public_relay",
        cwe: &[
            C::EXTERNALLY_CONTROLLED_REFERENCE,
            C::IMPROPER_ACCESS_CONTROL,
        ],
        swc: &[S::DELEGATECALL_UNTRUSTED_CALLEE],
        owasp_sc: &[O::AccessControl, O::UncheckedExternalCalls],
        dasp: &[D::UncheckedLowLevelCalls],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_push_payment_in_loop",
        cwe: &[
            C::UNCONTROLLED_RESOURCE_CONSUMPTION,
            C::IMPROPER_EXCEPTION_HANDLING,
        ],
        swc: &[S::DOS_WITH_FAILED_CALL],
        owasp_sc: &[O::DenialOfService],
        dasp: &[D::DenialOfService],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_readonly_reentrancy",
        cwe: &[
            C::IMPROPER_BEHAVIORAL_WORKFLOW,
            C::NON_REENTRANT_IN_CONCURRENT_CONTEXT,
        ],
        swc: &[S::REENTRANCY],
        owasp_sc: &[O::Reentrancy],
        dasp: &[D::Reentrancy],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_reentrancy_classic",
        cwe: &[
            C::IMPROPER_BEHAVIORAL_WORKFLOW,
            C::NON_REENTRANT_IN_CONCURRENT_CONTEXT,
        ],
        swc: &[S::REENTRANCY],
        owasp_sc: &[O::Reentrancy],
        dasp: &[D::Reentrancy],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_reentrancy_erc20",
        cwe: &[
            C::IMPROPER_BEHAVIORAL_WORKFLOW,
            C::NON_REENTRANT_IN_CONCURRENT_CONTEXT,
        ],
        swc: &[S::REENTRANCY],
        owasp_sc: &[O::Reentrancy],
        dasp: &[D::Reentrancy],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_reentrancy_protection",
        cwe: &[C::IMPROPER_BEHAVIORAL_WORKFLOW, C::IMPROPER_SYNCHRONIZATION],
        swc: &[S::REENTRANCY],
        owasp_sc: &[O::Reentrancy],
        dasp: &[D::Reentrancy],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_reentrancy_via_whitelisted",
        cwe: &[
            C::IMPROPER_BEHAVIORAL_WORKFLOW,
            C::NON_REENTRANT_IN_CONCURRENT_CONTEXT,
        ],
        swc: &[S::REENTRANCY],
        owasp_sc: &[O::Reentrancy],
        dasp: &[D::Reentrancy],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_router_slippage_validation",
        cwe: &[
            C::IMPROPER_QUANTITY_VALIDATION,
            C::IMPROPER_INPUT_VALIDATION,
        ],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[D::FrontRunning],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_shallow_auth",
        cwe: &[C::INCORRECT_AUTHORIZATION, C::IMPROPER_ACCESS_CONTROL],
        swc: &[S::UNPROTECTED_ETHER_WITHDRAWAL],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_signature_replay_protection",
        cwe: &[C::CAPTURE_REPLAY],
        swc: &[S::SIGNATURE_REPLAY],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_single_eoa_admin",
        cwe: &[C::SINGLE_FACTOR_RELIANCE],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_stale_oracle_price",
        cwe: &[
            C::OPERATION_AFTER_EXPIRATION,
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
        ],
        swc: &[],
        owasp_sc: &[O::PriceOracleManipulation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_state_mutation_ordering",
        cwe: &[
            C::IMPROPER_BEHAVIORAL_WORKFLOW,
            C::NON_REENTRANT_IN_CONCURRENT_CONTEXT,
        ],
        swc: &[S::REENTRANCY],
        owasp_sc: &[O::Reentrancy],
        dasp: &[D::Reentrancy],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_symbolic_counterexample",
        cwe: &[
            C::ALWAYS_INCORRECT_CONTROL_FLOW,
            C::PROTECTION_MECHANISM_FAILURE,
        ],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_symbolic_unresolved",
        cwe: &[C::INSUFFICIENT_VERIFICATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_synthetic_collateral_oracle",
        cwe: &[C::UNTRUSTED_INPUT_IN_SECURITY_DECISION],
        swc: &[],
        owasp_sc: &[O::PriceOracleManipulation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_timestamp_dependence",
        cwe: &[C::UNTRUSTED_FUNCTIONALITY_INCLUSION],
        swc: &[S::BLOCK_VALUES_AS_TIME_PROXY],
        owasp_sc: &[O::LogicErrors],
        dasp: &[D::TimeManipulation],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_token_balance_manipulation",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::EXTRANEOUS_UNTRUSTED_DATA,
        ],
        swc: &[S::UNEXPECTED_ETHER_BALANCE],
        owasp_sc: &[O::PriceOracleManipulation, O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_unbacked_synthetic_mint",
        cwe: &[C::INCORRECT_CALCULATION, C::IMPROPER_CHECK_EXCEPTIONAL],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_unbounded_loop",
        cwe: &[C::UNCONTROLLED_RESOURCE_CONSUMPTION, C::LOOP_WITHOUT_EXIT],
        swc: &[S::DOS_BLOCK_GAS_LIMIT],
        owasp_sc: &[O::DenialOfService],
        dasp: &[D::DenialOfService],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_unbounded_pricing_input",
        cwe: &[
            C::IMPROPER_QUANTITY_VALIDATION,
            C::IMPROPER_INPUT_VALIDATION,
        ],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_unchecked_returns",
        cwe: &[C::UNCHECKED_RETURN_VALUE],
        swc: &[S::UNCHECKED_CALL_RETURN],
        owasp_sc: &[O::UncheckedExternalCalls],
        dasp: &[D::UncheckedLowLevelCalls],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_uninitialized_pointers",
        cwe: &[C::UNINITIALIZED_POINTER, C::IMPROPER_INITIALIZATION],
        swc: &[S::UNINITIALIZED_STORAGE_POINTER],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_unprotected_initializer",
        cwe: &[C::IMPROPER_INITIALIZATION, C::MISSING_AUTHORIZATION],
        swc: &[S::INCORRECT_CONSTRUCTOR_NAME],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_upgrade_path_verification",
        cwe: &[
            C::CODE_WITHOUT_INTEGRITY_CHECK,
            C::IMPROPER_DYNAMIC_CODE_CONTROL,
        ],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "evm_zero_challenge_period",
        cwe: &[C::PROTECTION_MECHANISM_FAILURE, C::IMPROPER_INITIALIZATION],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "gen_ci_pwn_request",
        cwe: &[C::UNTRUSTED_FUNCTIONALITY_INCLUSION, C::CODE_INJECTION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[
            A::COMPROMISE_SOFTWARE_SUPPLY_CHAIN,
            A::COMMAND_AND_SCRIPTING,
        ],
        nist_csf: &[N::GV_SC_07, N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_ci_script_injection",
        cwe: &[C::CODE_INJECTION, C::IMPROPER_NEUTRALIZATION_OS],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[
            A::COMMAND_AND_SCRIPTING,
            A::COMPROMISE_SOFTWARE_SUPPLY_CHAIN,
        ],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_ci_secret_exposed",
        cwe: &[C::LOG_SENSITIVE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::DATA_FROM_LOGS],
        nist_csf: &[N::PR_DS_01],
    },
    Taxonomy {
        invariant_id: "gen_ci_unpinned_action",
        cwe: &[C::UNTRUSTED_FUNCTIONALITY_INCLUSION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07, N::PR_PS_02],
    },
    Taxonomy {
        invariant_id: "gen_ci_unsigned_release",
        cwe: &[
            C::IMPROPER_SIGNATURE_VERIFICATION,
            C::CODE_WITHOUT_INTEGRITY_CHECK,
        ],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_SOFTWARE_SUPPLY_CHAIN],
        nist_csf: &[N::GV_SC_07],
    },
    Taxonomy {
        invariant_id: "gen_code_injection",
        cwe: &[C::CODE_INJECTION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMMAND_AND_SCRIPTING, A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_command_injection",
        cwe: &[C::IMPROPER_NEUTRALIZATION_OS],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMMAND_AND_SCRIPTING, A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_container_privileged",
        cwe: &[
            C::UNNECESSARY_PRIVILEGES,
            C::INCORRECT_PERMISSION_ASSIGNMENT,
        ],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::ESCAPE_TO_HOST, A::DEPLOY_CONTAINER],
        nist_csf: &[N::PR_AA_05, N::PR_PS_01],
    },
    Taxonomy {
        invariant_id: "gen_docker_root_user",
        cwe: &[C::UNNECESSARY_PRIVILEGES],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::ESCAPE_TO_HOST],
        nist_csf: &[N::PR_AA_05, N::PR_PS_01],
    },
    Taxonomy {
        invariant_id: "gen_docker_unpinned_base",
        cwe: &[C::UNTRUSTED_FUNCTIONALITY_INCLUSION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07, N::PR_PS_02],
    },
    Taxonomy {
        invariant_id: "gen_error_detail_exposed",
        cwe: &[C::ERROR_MESSAGE_EXPOSURE, C::INFORMATION_EXPOSURE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::GATHER_VICTIM_HOST_INFO],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_graphql_unrestricted",
        cwe: &[
            C::UNCONTROLLED_RESOURCE_CONSUMPTION,
            C::INFORMATION_EXPOSURE,
        ],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_hardcoded_secret",
        cwe: &[C::HARDCODED_CREDENTIALS],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::CREDENTIALS_IN_FILES],
        nist_csf: &[N::PR_DS_01, N::PR_AA_05],
    },
    Taxonomy {
        invariant_id: "gen_iac_open_ingress",
        cwe: &[C::EXPOSED_RESOURCE, C::IMPROPER_ACCESS_CONTROL],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXTERNAL_REMOTE_SERVICES, A::EXPLOIT_REMOTE_SERVICES],
        nist_csf: &[N::PR_IR_01, N::PR_PS_01],
    },
    Taxonomy {
        invariant_id: "gen_iac_public_database",
        cwe: &[C::EXPOSED_RESOURCE, C::IMPROPER_ACCESS_CONTROL],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXTERNAL_REMOTE_SERVICES],
        nist_csf: &[N::PR_IR_01, N::PR_DS_01],
    },
    Taxonomy {
        invariant_id: "gen_iac_public_storage",
        cwe: &[C::EXPOSED_RESOURCE, C::INCORRECT_PERMISSION_ASSIGNMENT],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::DATA_FROM_CLOUD_STORAGE],
        nist_csf: &[N::PR_DS_01, N::PR_AA_05],
    },
    Taxonomy {
        invariant_id: "gen_iac_unencrypted_storage",
        cwe: &[C::MISSING_ENCRYPTION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::DATA_FROM_CLOUD_STORAGE],
        nist_csf: &[N::PR_DS_01],
    },
    Taxonomy {
        invariant_id: "gen_iac_wildcard_iam",
        cwe: &[
            C::INCORRECT_PERMISSION_ASSIGNMENT,
            C::IMPROPER_ACCESS_CONTROL,
        ],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::VALID_ACCOUNTS_CLOUD],
        nist_csf: &[N::PR_AA_05],
    },
    Taxonomy {
        invariant_id: "gen_insecure_file_permissions",
        cwe: &[C::INCORRECT_PERMISSION_ASSIGNMENT],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_01],
    },
    Taxonomy {
        invariant_id: "gen_insecure_randomness",
        cwe: &[C::INSUFFICIENTLY_RANDOM],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::BRUTE_FORCE_CRACKING],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_insecure_temp_file",
        cwe: &[C::INSECURE_TEMP_FILE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_log_injection",
        cwe: &[C::LOG_NEUTRALIZATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::DE_CM_09],
    },
    Taxonomy {
        invariant_id: "gen_log_sensitive_data",
        cwe: &[C::LOG_SENSITIVE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::DATA_FROM_LOGS],
        nist_csf: &[N::PR_DS_01],
    },
    Taxonomy {
        invariant_id: "gen_mass_assignment",
        cwe: &[C::MASS_ASSIGNMENT, C::IMPROPER_INPUT_VALIDATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_missing_rate_limit",
        cwe: &[C::EXCESSIVE_AUTH_ATTEMPTS],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::BRUTE_FORCE_CRACKING],
        nist_csf: &[N::PR_AA_03],
    },
    Taxonomy {
        invariant_id: "gen_missing_security_logging",
        cwe: &[C::INSUFFICIENT_LOGGING],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::BRUTE_FORCE_CRACKING],
        nist_csf: &[N::DE_CM_09],
    },
    Taxonomy {
        invariant_id: "gen_non_atomic_multi_write",
        cwe: &[C::RACE_CONDITION, C::IMPROPER_SYNCHRONIZATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_object_level_auth_missing",
        cwe: &[C::USER_CONTROLLED_KEY, C::IMPROPER_AUTHORIZATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_AA_05],
    },
    Taxonomy {
        invariant_id: "gen_open_redirect",
        cwe: &[C::OPEN_REDIRECT],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::DRIVE_BY],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_pipe_to_shell",
        cwe: &[C::CODE_WITHOUT_INTEGRITY_CHECK],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::INGRESS_TOOL_TRANSFER, A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07, N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_private_key_committed",
        cwe: &[C::MISSING_ENCRYPTION_OF_KEY, C::HARDCODED_CREDENTIALS],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::PRIVATE_KEYS],
        nist_csf: &[N::PR_DS_01],
    },
    Taxonomy {
        invariant_id: "gen_regex_dos",
        cwe: &[C::REGEX_COMPLEXITY, C::UNCONTROLLED_RESOURCE_CONSUMPTION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_sql_injection",
        cwe: &[C::IMPROPER_NEUTRALIZATION_SQL],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_tls_verification_disabled",
        cwe: &[C::IMPROPER_CERT_VALIDATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::ADVERSARY_IN_THE_MIDDLE],
        nist_csf: &[N::PR_DS_02],
    },
    Taxonomy {
        invariant_id: "gen_toctou_file",
        cwe: &[C::TOCTOU],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_unbounded_query_limit",
        cwe: &[
            C::UNBOUNDED_ALLOCATION,
            C::UNCONTROLLED_RESOURCE_CONSUMPTION,
        ],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_unsafe_deserialization",
        cwe: &[C::DESERIALIZATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMMAND_AND_SCRIPTING, A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_upload_unvalidated",
        cwe: &[C::UNRESTRICTED_UPLOAD],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_weak_hash",
        cwe: &[C::WEAK_HASH],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::BRUTE_FORCE_CRACKING],
        nist_csf: &[N::PR_DS_01],
    },
    Taxonomy {
        invariant_id: "gen_web_cors_wildcard",
        cwe: &[C::PERMISSIVE_CORS],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::STEAL_WEB_SESSION_COOKIE],
        nist_csf: &[N::PR_AA_03, N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_web_csrf_disabled",
        cwe: &[C::CSRF],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_web_debug_enabled",
        cwe: &[C::DEBUG_ACTIVE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_01],
    },
    Taxonomy {
        invariant_id: "gen_web_insecure_cookie",
        cwe: &[C::INSECURE_COOKIE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::STEAL_WEB_SESSION_COOKIE],
        nist_csf: &[N::PR_AA_03, N::PR_DS_02],
    },
    Taxonomy {
        invariant_id: "gen_web_jwt_unverified",
        cwe: &[C::IMPROPER_SIGNATURE_VERIFICATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::FORGE_WEB_CREDENTIALS],
        nist_csf: &[N::PR_AA_03],
    },
    Taxonomy {
        invariant_id: "gen_web_path_traversal",
        cwe: &[C::PATH_TRAVERSAL],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_web_ssrf",
        cwe: &[C::SSRF],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APP_SSRF],
        nist_csf: &[N::PR_PS_06, N::PR_IR_01],
    },
    Taxonomy {
        invariant_id: "gen_websocket_no_origin_check",
        cwe: &[C::ORIGIN_VALIDATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::STEAL_WEB_SESSION_COOKIE],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_xss_sink",
        cwe: &[C::XSS],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::DRIVE_BY, A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "gen_xxe",
        cwe: &[C::XXE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::PR_PS_06],
    },
    Taxonomy {
        invariant_id: "move_access_control",
        cwe: &[C::IMPROPER_ACCESS_CONTROL, C::MISSING_AUTHORIZATION],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_access_control_missing",
        cwe: &[C::MISSING_AUTHORIZATION, C::IMPROPER_ACCESS_CONTROL],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_admin_no_timelock",
        cwe: &[
            C::SINGLE_FACTOR_RELIANCE,
            C::INCORRECT_PERMISSION_ASSIGNMENT,
        ],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_integer_overflow",
        cwe: &[C::INTEGER_OVERFLOW],
        swc: &[],
        owasp_sc: &[O::IntegerOverflowUnderflow],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_liquidity_conservation",
        cwe: &[C::INCORRECT_CALCULATION],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_manual_overflow_check",
        cwe: &[C::INTEGER_OVERFLOW, C::INCORRECT_CALCULATION],
        swc: &[],
        owasp_sc: &[O::IntegerOverflowUnderflow],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_oracle_spot_price",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::IMPROPER_INPUT_VALIDATION,
        ],
        swc: &[],
        owasp_sc: &[O::PriceOracleManipulation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_resource_destruction",
        cwe: &[C::IMPROPER_RESOURCE_SHUTDOWN, C::MISSING_RESOURCE_RELEASE],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_resource_leaks",
        cwe: &[C::MISSING_RESOURCE_RELEASE, C::IMPROPER_RESOURCE_SHUTDOWN],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_signer_requirement",
        cwe: &[C::MISSING_AUTHORIZATION, C::IMPROPER_ACCESS_CONTROL],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_type_safety",
        cwe: &[C::TYPE_CONFUSION],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "move_type_safety_violation",
        cwe: &[C::TYPE_CONFUSION],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "rt_exposed_sensitive_path",
        cwe: &[C::INFORMATION_EXPOSURE, C::EXPOSED_RESOURCE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::EXPLOIT_PUBLIC_APPLICATION, A::GATHER_VICTIM_HOST_INFO],
        nist_csf: &[N::PR_PS_01],
    },
    Taxonomy {
        invariant_id: "rt_insecure_cookie",
        cwe: &[C::INSECURE_COOKIE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::STEAL_WEB_SESSION_COOKIE],
        nist_csf: &[N::PR_DS_02],
    },
    Taxonomy {
        invariant_id: "rt_missing_content_type_options",
        cwe: &[C::XSS],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::DRIVE_BY],
        nist_csf: &[N::PR_PS_01],
    },
    Taxonomy {
        invariant_id: "rt_missing_csp",
        cwe: &[C::XSS],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::DRIVE_BY],
        nist_csf: &[N::PR_PS_01],
    },
    Taxonomy {
        invariant_id: "rt_missing_frame_options",
        cwe: &[C::CLICKJACKING],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::DRIVE_BY],
        nist_csf: &[N::PR_PS_01],
    },
    Taxonomy {
        invariant_id: "rt_missing_hsts",
        cwe: &[C::MISSING_ENCRYPTION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::ADVERSARY_IN_THE_MIDDLE],
        nist_csf: &[N::PR_DS_02],
    },
    Taxonomy {
        invariant_id: "rt_no_https_redirect",
        cwe: &[C::MISSING_ENCRYPTION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::ADVERSARY_IN_THE_MIDDLE],
        nist_csf: &[N::PR_DS_02],
    },
    Taxonomy {
        invariant_id: "rt_open_port",
        cwe: &[C::EXPOSED_RESOURCE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::ACTIVE_SCANNING, A::EXTERNAL_REMOTE_SERVICES],
        nist_csf: &[N::ID_RA_01],
    },
    Taxonomy {
        invariant_id: "rt_server_banner",
        cwe: &[C::INFORMATION_EXPOSURE],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::GATHER_VICTIM_HOST_INFO],
        nist_csf: &[N::ID_RA_01],
    },
    Taxonomy {
        invariant_id: "rt_tls_expired",
        cwe: &[C::IMPROPER_CERT_VALIDATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::ADVERSARY_IN_THE_MIDDLE],
        nist_csf: &[N::PR_DS_02],
    },
    Taxonomy {
        invariant_id: "rt_tls_untrusted_cert",
        cwe: &[C::IMPROPER_CERT_VALIDATION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::ADVERSARY_IN_THE_MIDDLE],
        nist_csf: &[N::PR_DS_02],
    },
    Taxonomy {
        invariant_id: "rt_tls_weak_protocol",
        cwe: &[C::INADEQUATE_ENCRYPTION_STRENGTH],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::ADVERSARY_IN_THE_MIDDLE],
        nist_csf: &[N::PR_DS_02],
    },
    Taxonomy {
        invariant_id: "sca_dependency_confusion",
        cwe: &[
            C::IMPROPER_SEARCH_PATH_PACKAGE,
            C::UNTRUSTED_FUNCTIONALITY_INCLUSION,
        ],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07],
    },
    Taxonomy {
        invariant_id: "sca_install_script_dependency",
        cwe: &[
            C::UNTRUSTED_FUNCTIONALITY_INCLUSION,
            C::CODE_WITHOUT_INTEGRITY_CHECK,
        ],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07],
    },
    Taxonomy {
        invariant_id: "sca_lockfile_missing_integrity",
        cwe: &[C::CODE_WITHOUT_INTEGRITY_CHECK],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07],
    },
    Taxonomy {
        invariant_id: "sca_missing_lockfile",
        cwe: &[C::UNTRUSTED_FUNCTIONALITY_INCLUSION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07, N::PR_PS_02],
    },
    Taxonomy {
        invariant_id: "sca_typosquat_candidate",
        cwe: &[C::UNTRUSTED_FUNCTIONALITY_INCLUSION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07],
    },
    Taxonomy {
        invariant_id: "sca_unmaintained_dependency",
        cwe: &[C::UNCONTROLLED_SEARCH_PATH],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07, N::PR_PS_02],
    },
    Taxonomy {
        invariant_id: "sca_unpinned_dependency",
        cwe: &[C::UNTRUSTED_FUNCTIONALITY_INCLUSION],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES],
        nist_csf: &[N::GV_SC_07, N::PR_PS_02],
    },
    Taxonomy {
        invariant_id: "sca_vulnerable_dependency",
        cwe: &[C::VULNERABLE_THIRD_PARTY],
        swc: &[],
        owasp_sc: &[],
        dasp: &[],
        attack: &[A::COMPROMISE_DEPENDENCIES, A::EXPLOIT_PUBLIC_APPLICATION],
        nist_csf: &[N::ID_RA_01, N::PR_PS_02],
    },
    Taxonomy {
        invariant_id: "sol_account_validation",
        cwe: &[C::IMPROPER_INPUT_VALIDATION, C::INSUFFICIENT_VERIFICATION],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_admin_no_timelock",
        cwe: &[
            C::SINGLE_FACTOR_RELIANCE,
            C::INCORRECT_PERMISSION_ASSIGNMENT,
        ],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_durable_nonce_validation",
        cwe: &[C::CAPTURE_REPLAY, C::INSUFFICIENT_VERIFICATION],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_fake_sysvar_instruction_account",
        cwe: &[
            C::INSUFFICIENT_VERIFICATION,
            C::EXTERNALLY_CONTROLLED_REFERENCE,
        ],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_instruction_parsing",
        cwe: &[C::IMPROPER_INPUT_VALIDATION],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_integer_overflow",
        cwe: &[C::INTEGER_OVERFLOW],
        swc: &[],
        owasp_sc: &[O::IntegerOverflowUnderflow],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_lamport_balance",
        cwe: &[C::INCORRECT_CALCULATION],
        swc: &[],
        owasp_sc: &[O::LogicErrors],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_missing_signer",
        cwe: &[C::MISSING_AUTHORIZATION, C::IMPROPER_ACCESS_CONTROL],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_oracle_rate_account",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::INSUFFICIENT_VERIFICATION,
        ],
        swc: &[],
        owasp_sc: &[O::PriceOracleManipulation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_oracle_self_trade",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::EXTRANEOUS_UNTRUSTED_DATA,
        ],
        swc: &[],
        owasp_sc: &[O::PriceOracleManipulation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_pda_authority_validation",
        cwe: &[C::INCORRECT_AUTHORIZATION, C::INSUFFICIENT_VERIFICATION],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_pda_derivation",
        cwe: &[
            C::INSUFFICIENT_VERIFICATION,
            C::EXTERNALLY_CONTROLLED_REFERENCE,
        ],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_rent_exemption",
        cwe: &[C::IMPROPER_RESOURCE_SHUTDOWN, C::OPERATION_AFTER_EXPIRATION],
        swc: &[],
        owasp_sc: &[O::DenialOfService],
        dasp: &[D::DenialOfService],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_rent_exemption_check",
        cwe: &[C::IMPROPER_RESOURCE_SHUTDOWN, C::OPERATION_AFTER_EXPIRATION],
        swc: &[],
        owasp_sc: &[O::DenialOfService],
        dasp: &[D::DenialOfService],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_signer_checks",
        cwe: &[C::MISSING_AUTHORIZATION, C::IMPROPER_ACCESS_CONTROL],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_sysvar_account_validation",
        cwe: &[
            C::INSUFFICIENT_VERIFICATION,
            C::EXTERNALLY_CONTROLLED_REFERENCE,
        ],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_treasury_single_authority",
        cwe: &[C::SINGLE_FACTOR_RELIANCE],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sol_unchecked_token_account_type",
        cwe: &[C::TYPE_CONFUSION, C::INSUFFICIENT_VERIFICATION],
        swc: &[],
        owasp_sc: &[O::LackOfInputValidation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_checked_arithmetic",
        cwe: &[C::INTEGER_OVERFLOW, C::INTEGER_UNDERFLOW],
        swc: &[],
        owasp_sc: &[O::IntegerOverflowUnderflow],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_init_guard",
        cwe: &[C::IMPROPER_INITIALIZATION, C::MISSING_AUTHORIZATION],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_missing_require_auth",
        cwe: &[C::MISSING_AUTHORIZATION, C::IMPROPER_ACCESS_CONTROL],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_no_reentrancy",
        cwe: &[
            C::IMPROPER_BEHAVIORAL_WORKFLOW,
            C::NON_REENTRANT_IN_CONCURRENT_CONTEXT,
        ],
        swc: &[],
        owasp_sc: &[O::Reentrancy],
        dasp: &[D::Reentrancy],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_no_unprotected_upgrade",
        cwe: &[C::MISSING_AUTHORIZATION, C::CODE_WITHOUT_INTEGRITY_CHECK],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_reentrancy_external_call",
        cwe: &[
            C::IMPROPER_BEHAVIORAL_WORKFLOW,
            C::NON_REENTRANT_IN_CONCURRENT_CONTEXT,
        ],
        swc: &[],
        owasp_sc: &[O::Reentrancy],
        dasp: &[D::Reentrancy],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_reinitialization",
        cwe: &[C::IMPROPER_INITIALIZATION, C::MISSING_AUTHORIZATION],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_require_auth_checks",
        cwe: &[C::MISSING_AUTHORIZATION, C::IMPROPER_ACCESS_CONTROL],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_storage_ttl_extended",
        cwe: &[C::OPERATION_AFTER_EXPIRATION, C::IMPROPER_RESOURCE_SHUTDOWN],
        swc: &[],
        owasp_sc: &[O::DenialOfService],
        dasp: &[D::DenialOfService],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_storage_ttl_not_extended",
        cwe: &[C::OPERATION_AFTER_EXPIRATION, C::IMPROPER_RESOURCE_SHUTDOWN],
        swc: &[],
        owasp_sc: &[O::DenialOfService],
        dasp: &[D::DenialOfService],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_temporary_storage_critical_state",
        cwe: &[C::OPERATION_AFTER_EXPIRATION, C::IMPROPER_RESOURCE_SHUTDOWN],
        swc: &[],
        owasp_sc: &[O::DenialOfService],
        dasp: &[D::DenialOfService],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_thin_liquidity_oracle_price",
        cwe: &[
            C::UNTRUSTED_INPUT_IN_SECURITY_DECISION,
            C::EXTRANEOUS_UNTRUSTED_DATA,
        ],
        swc: &[],
        owasp_sc: &[O::PriceOracleManipulation],
        dasp: &[],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_unchecked_arithmetic",
        cwe: &[C::INTEGER_OVERFLOW, C::INTEGER_UNDERFLOW],
        swc: &[],
        owasp_sc: &[O::IntegerOverflowUnderflow],
        dasp: &[D::Arithmetic],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_unhandled_panic",
        cwe: &[
            C::IMPROPER_EXCEPTION_HANDLING,
            C::IMPROPER_CHECK_EXCEPTIONAL,
        ],
        swc: &[],
        owasp_sc: &[O::DenialOfService],
        dasp: &[D::DenialOfService],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "sor_unprotected_upgrade",
        cwe: &[C::MISSING_AUTHORIZATION, C::CODE_WITHOUT_INTEGRITY_CHECK],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
    Taxonomy {
        invariant_id: "unauthorized_privileged_mutation",
        cwe: &[C::MISSING_AUTHORIZATION, C::IMPROPER_ACCESS_CONTROL],
        swc: &[],
        owasp_sc: &[O::AccessControl],
        dasp: &[D::AccessControl],
        attack: &[],
        nist_csf: &[],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    #[test]
    fn table_is_sorted_and_unique() {
        // `taxonomy_for` binary-searches TAXONOMY. An out-of-order insertion
        // would not fail loudly — it would make some lookups silently miss and
        // findings would quietly lose their CWE again. Catch it here instead.
        let ids: Vec<&str> = TAXONOMY.iter().map(|t| t.invariant_id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "TAXONOMY must be sorted by invariant_id");

        let unique: BTreeSet<&str> = ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "TAXONOMY has duplicate invariant_ids"
        );
    }

    #[test]
    fn every_entry_has_a_cwe() {
        // `primary_cwe` indexes `cwe[0]`; this is the invariant that makes that
        // safe. CWE is also the only taxonomy that applies to every chain, so
        // an entry without one carries no portable meaning at all.
        for t in TAXONOMY {
            assert!(
                !t.cwe.is_empty(),
                "{} has no CWE mapping — every invariant must have at least one",
                t.invariant_id
            );
        }
    }

    #[test]
    fn every_entry_is_findable() {
        for t in TAXONOMY {
            let found = taxonomy_for(t.invariant_id)
                .unwrap_or_else(|| panic!("{} is in the table but not findable", t.invariant_id));
            assert_eq!(found.invariant_id, t.invariant_id);
        }
    }

    #[test]
    fn unknown_ids_return_none_rather_than_guessing() {
        // The bug this module replaced guessed a CWE for anything it did not
        // recognise, so user-authored .sinv invariants were reported as
        // "CWE-676 · Use of Potentially Dangerous Function" regardless of what
        // they actually checked. Absence must stay absence.
        assert!(taxonomy_for("definitely_not_a_real_invariant").is_none());
        assert!(taxonomy_for("").is_none());
    }

    #[test]
    fn tags_are_well_formed() {
        for t in TAXONOMY {
            let tags = t.tags();
            assert!(!tags.is_empty(), "{} produced no tags", t.invariant_id);
            for tag in &tags {
                assert!(
                    tag.starts_with("CWE-")
                        || tag.starts_with("SWC-")
                        || tag.starts_with("SC")
                        || tag.starts_with("DASP-")
                        || tag.starts_with('T')
                        || tag.contains('.'),
                    "{}: unexpected tag shape {tag:?}",
                    t.invariant_id
                );
            }
        }
    }

    #[test]
    fn chain_is_derived_from_the_id_prefix() {
        assert_eq!(
            taxonomy_for("evm_reentrancy_classic").unwrap().chain(),
            Some("evm")
        );
        assert_eq!(
            taxonomy_for("sol_missing_signer").unwrap().chain(),
            Some("solana")
        );
        assert_eq!(
            taxonomy_for("move_type_safety").unwrap().chain(),
            Some("move")
        );
        assert_eq!(
            taxonomy_for("sor_missing_require_auth").unwrap().chain(),
            Some("soroban")
        );
        // The shared IR rule belongs to no single chain, and must not be
        // mis-attributed to one.
        assert_eq!(
            taxonomy_for("unauthorized_privileged_mutation")
                .unwrap()
                .chain(),
            None
        );
    }

    #[test]
    fn contract_registries_are_not_applied_to_repository_findings() {
        // SWC, OWASP SC and DASP are smart-contract vocabularies. A committed
        // AWS key is not a DASP category.
        for t in TAXONOMY.iter().filter(|t| {
            matches!(
                t.chain(),
                Some("general") | Some("supply-chain") | Some("runtime")
            )
        }) {
            assert!(
                t.swc.is_empty() && t.owasp_sc.is_empty() && t.dasp.is_empty(),
                "{}",
                t.invariant_id
            );
            assert!(
                !t.attack.is_empty(),
                "{}: repository findings map to ATT&CK",
                t.invariant_id
            );
            assert!(
                !t.nist_csf.is_empty(),
                "{}: repository findings map to NIST CSF",
                t.invariant_id
            );
        }
    }

    #[test]
    fn swc_is_evm_only() {
        // SWC is a Solidity registry. Carrying an SWC ID on a Move or Solana
        // finding would be a fabricated citation, which is worse than none.
        for t in TAXONOMY {
            if !t.swc.is_empty() {
                assert_eq!(
                    t.chain(),
                    Some("evm"),
                    "{} is not an EVM invariant but claims an SWC ID",
                    t.invariant_id
                );
            }
        }
    }

    // ---------------------------------------------------------------------
    // Completeness ratchet
    // ---------------------------------------------------------------------

    /// Workspace root, from this crate's manifest directory.
    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root should resolve")
    }

    /// Every non-test `.rs` file under `crates/`.
    fn production_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                // `tests/` and `benches/` hold fixtures with invented IDs
                // (e.g. `evm_test`) that are not real detectors.
                if matches!(name.as_ref(), "target" | "tests" | "benches" | ".git") {
                    continue;
                }
                production_sources(&path, out);
            } else if name.ends_with(".rs") {
                out.push(path);
            }
        }
    }

    /// Scrape every invariant ID the workspace can actually emit.
    ///
    /// Three birth sites, and only three: a `Finding::new` call, the static
    /// invariant-library table, and a shared-rule `&str` const.
    fn emitted_invariant_ids() -> BTreeSet<String> {
        use regex::Regex;

        let root = workspace_root();
        let mut files = Vec::new();
        production_sources(&root.join("crates"), &mut files);
        assert!(!files.is_empty(), "found no sources under crates/");

        // `Finding::new("evm_foo", ...)` — the detectors — and the general
        // analyzer's `finding("gen_foo", ...)` helper.
        let finding_new =
            Regex::new(r#"(?s)(?:Finding::new|\bfinding|\bf)\(\s*"([a-z0-9_]+)""#).unwrap();
        // `Sink { call: …, id: "gen_foo", … }` — the taint engine's sink table.
        let sink_id = Regex::new(r#"Sink \{[^}]*?\bid: "([a-z0-9_]+)""#).unwrap();
        // `("evm_foo", "Title", "expr"),` — the invariant library's tuple table.
        let library_tuple =
            Regex::new(r#"(?m)^\s*"((?:evm|sol|move|sor|gen)_[a-z0-9_]+)",\s*$"#).unwrap();
        // `pub const FOO: &str = "bar";` — chain-agnostic rules in ir/rules.rs.
        let rule_const = Regex::new(r#"pub const [A-Z_]+: &str = "([a-z0-9_]+)""#).unwrap();

        let mut ids = BTreeSet::new();
        for path in &files {
            let Ok(src) = std::fs::read_to_string(path) else {
                continue;
            };
            // Inline `#[cfg(test)]` modules construct findings with invented
            // IDs (`evm_foo`, `test_detector`). Cut them off at the attribute;
            // by convention they sit at the bottom of the file.
            //
            // If that convention is ever broken and this hides a real
            // detector, `no_stale_taxonomy_rows` fails instead — its row would
            // suddenly look unreferenced. The two tests pin each other.
            let src = match src.find("#[cfg(test)]") {
                Some(i) => src[..i].to_string(),
                None => src,
            };
            for caps in finding_new.captures_iter(&src) {
                ids.insert(caps[1].to_string());
            }
            for caps in sink_id.captures_iter(&src) {
                ids.insert(caps[1].to_string());
            }
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            if file_name == "library.rs" {
                for caps in library_tuple.captures_iter(&src) {
                    ids.insert(caps[1].to_string());
                }
            }
            if file_name == "rules.rs" {
                for caps in rule_const.captures_iter(&src) {
                    ids.insert(caps[1].to_string());
                }
            }
        }
        ids
    }

    #[test]
    fn every_emitted_invariant_is_mapped() {
        // This is the ratchet: adding a detector without a taxonomy row fails
        // the build here, so the mapping can never drift behind the engine.
        // If this fails, add the row to TAXONOMY — do not weaken the test.
        let emitted = emitted_invariant_ids();
        assert!(
            emitted.len() >= TAXONOMY.len(),
            "scraper found only {} IDs for {} taxonomy rows — its patterns have \
             probably drifted from the source",
            emitted.len(),
            TAXONOMY.len()
        );

        let unmapped: Vec<&String> = emitted
            .iter()
            .filter(|id| taxonomy_for(id).is_none())
            .collect();

        assert!(
            unmapped.is_empty(),
            "{} invariant(s) are emitted by the engine but have no taxonomy mapping: {:#?}\n\
             Add a row to TAXONOMY in crates/core/src/taxonomy.rs.",
            unmapped.len(),
            unmapped
        );
    }

    #[test]
    fn no_stale_taxonomy_rows() {
        // The other direction: a row for a detector that no longer exists is
        // dead weight that makes coverage numbers lie.
        let emitted = emitted_invariant_ids();
        let stale: Vec<&str> = TAXONOMY
            .iter()
            .map(|t| t.invariant_id)
            .filter(|id| !emitted.contains(*id))
            .collect();

        assert!(
            stale.is_empty(),
            "{} taxonomy row(s) map invariants nothing emits any more: {:#?}\n\
             Remove them from TAXONOMY.",
            stale.len(),
            stale
        );
    }
}
