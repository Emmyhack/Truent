#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Invar Core: Base abstractions for multi-chain invariant analysis
//! This module defines the core traits and types that are chain-agnostic
//! and form the foundation for all analyzers and generators.

pub mod account_abstraction;
pub mod analysis_context;
pub mod attack_patterns;
pub mod changelog;
pub mod config;
pub mod dvn_fuzzer;
pub mod error;
pub mod evaluator;
pub mod exposure;
pub mod finding;
pub mod fuzzer;
pub mod generated;
pub mod health_check_fuzzer;
pub mod integration_testing;
pub mod merkle_root_fuzzer;
pub mod model;
pub mod oz_integration;
pub mod registry;
pub mod security_validator;
pub mod synthetic_mint_fuzzer;
pub mod taxonomy;
pub mod test_infrastructure;
pub mod text;
pub mod threat_model;
pub mod traits;
pub mod type_checker;
pub mod types;

pub use account_abstraction::{
    AAContext, AALayer, AccountState, CrossLayerCheckResult, EntryPointState, PaymasterState,
    UserOpData,
};
pub use analysis_context::{AnalysisContext, AnalysisWarning};
pub use attack_patterns::AttackPatternDB;
pub use changelog::{
    generate_v0_3_0_changelog, APIDocGenerator, ChangelogGenerator, ReleaseVersion,
};
pub use config::{AlertConfig, ChainConfig, Config, ConfigError, InvariantConfig};
pub use error::{InvarError, Result};
pub use evaluator::{EvalResult, EvaluationError, Evaluator, ExecutionContext, Value};
pub use finding::{Evidence, Finding, Severity};
pub use fuzzer::{CodeFuzzer, FuzzResult};
pub use generated::{get_invariant, invariant_count, invariants_for_chain, CompiledInvariant};
pub use integration_testing::{ExploitTestCase, IntegrationTestResults, IntegrationTestSuite};
pub use model::{FunctionModel, Invariant, ProgramModel, StateVar};
pub use oz_integration::{EnrichedFinding, OZMappingRegistry, OZVulnerabilityType};
pub use registry::{Exploit, ExploitRegistry, EXPLOIT_REGISTRY};
pub use security_validator::{IssueSeverity, SecurityIssue, SecurityReport, SecurityValidator};
pub use taxonomy::{taxonomy_for, Cwe, Dasp, OwaspSc, Swc, Taxonomy};
pub use test_infrastructure::{DetectorTestCase, DetectorTestResult, DetectorTestSuite};
pub use threat_model::{
    DSLSandbox, InjectionVerifier, SimulationIsolation, StrictModeAnalyzer, TamperDetector,
    ThreatModelConfig, ThreatModelError, ThreatResult,
};
pub use traits::{ChainAnalyzer, CodeGenerator, Simulator};
pub use type_checker::TypeChecker;
pub use types::{Type, TypeError, TypeResult, TypedExpr, TypedValue};
