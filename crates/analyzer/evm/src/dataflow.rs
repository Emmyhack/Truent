#![allow(missing_docs)]
//! Data Flow Analysis for value and taint tracking.
//!
//! Enables tracking of:
//! - Variable definitions and uses (def-use chains)
//! - Tainted values (user input, untrusted sources)
//! - Value propagation through assignments and calls
//! - Dependency detection and analysis

use crate::cfg::ControlFlowGraph;
use crate::errors::AnalysisResult;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};

/// Represents a variable's origin and taint status.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueOrigin {
    /// Variable is a constant.
    Constant { value: String },
    /// Variable comes from a parameter.
    Parameter { index: usize, tainted: bool },
    /// Variable comes from state storage.
    StateVar { name: String, tainted: bool },
    /// Variable comes from function call.
    FunctionCall { function: String, tainted: bool },
    /// Variable comes from external call (always tainted).
    ExternalCall { address: String },
    /// Variable comes from arithmetic operation.
    Arithmetic {
        operands: Vec<String>,
        tainted: bool,
    },
    /// Variable comes from untrusted source.
    Untrusted { source: String },
    /// Unknown origin.
    Unknown,
}

impl ValueOrigin {
    /// Check if value is tainted.
    pub fn is_tainted(&self) -> bool {
        matches!(
            self,
            ValueOrigin::Parameter { tainted: true, .. }
                | ValueOrigin::StateVar { tainted: true, .. }
                | ValueOrigin::FunctionCall { tainted: true, .. }
                | ValueOrigin::ExternalCall { .. }
                | ValueOrigin::Arithmetic { tainted: true, .. }
                | ValueOrigin::Untrusted { .. }
        )
    }
}

/// Definition-Use chain entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefUse {
    /// Variable name.
    pub variable: String,
    /// Where it's defined.
    pub definition: Location,
    /// Where it's used.
    pub uses: Vec<Location>,
}

/// Location of definition/use in code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Block ID.
    pub block: usize,
    /// Statement index in block.
    pub statement_idx: usize,
    /// Line number (if available).
    pub line: Option<usize>,
}

/// DataFlow analysis result for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    /// Variable origins.
    pub origins: HashMap<String, ValueOrigin>,
    /// Definition-use chains.
    pub def_use_chains: Vec<DefUse>,
    /// Tainted variables.
    pub tainted_vars: HashSet<String>,
    /// Data dependencies.
    pub dependencies: HashMap<String, HashSet<String>>,
}

impl DataFlow {
    /// Create empty data flow analysis.
    pub fn new() -> Self {
        Self {
            origins: HashMap::new(),
            def_use_chains: Vec::new(),
            tainted_vars: HashSet::new(),
            dependencies: HashMap::new(),
        }
    }

    /// Check if a variable is tainted.
    pub fn is_tainted(&self, var: &str) -> bool {
        self.tainted_vars.contains(var)
    }

    /// Get all variables that depend on a given variable.
    pub fn transitive_dependents(&self, var: &str) -> HashSet<String> {
        let mut result = HashSet::new();
        let mut queue = vec![var.to_string()];

        while let Some(current) = queue.pop() {
            if !result.insert(current.clone()) {
                continue;
            }

            // Find all variables that depend on current
            for (dependent, depends_on) in &self.dependencies {
                if depends_on.contains(&current) {
                    queue.push(dependent.clone());
                }
            }
        }

        result.remove(var);
        result
    }

    /// Check if variable `a` can affect variable `b`.
    pub fn can_affect(&self, a: &str, b: &str) -> bool {
        self.transitive_dependents(a).contains(b)
    }
}

impl Default for DataFlow {
    fn default() -> Self {
        Self::new()
    }
}

/// Data flow analysis engine.
pub struct DataFlowAnalyzer;

impl DataFlowAnalyzer {
    /// Analyze data flow in a control flow graph.
    pub fn analyze(cfg: &ControlFlowGraph) -> AnalysisResult<DataFlow> {
        info!("Performing data flow analysis");

        let mut analysis = DataFlow::new();

        // Compute reaching definitions
        let reaching_defs = Self::compute_reaching_definitions(cfg)?;
        debug!(
            "Computed reaching definitions for {} blocks",
            reaching_defs.len()
        );

        // Compute live variables
        let _live_vars = Self::compute_live_variables(cfg)?;
        debug!("Computed live variables");

        // Extract definition-use chains
        analysis = Self::extract_def_use_chains(cfg, analysis)?;
        debug!("Extracted {} def-use chains", analysis.def_use_chains.len());

        // Identify tainted variables
        analysis = Self::identify_tainted(cfg, analysis)?;
        debug!(
            "Identified {} tainted variables",
            analysis.tainted_vars.len()
        );

        // Build dependency graph
        analysis = Self::build_dependencies(cfg, analysis)?;

        Ok(analysis)
    }

    /// Compute reaching definitions for each block.
    fn compute_reaching_definitions(
        cfg: &ControlFlowGraph,
    ) -> AnalysisResult<HashMap<usize, HashSet<String>>> {
        let blocks = cfg.block_ids();
        let mut reaching: HashMap<_, HashSet<String>> =
            blocks.iter().map(|id| (*id, HashSet::new())).collect();
        let mut changed = true;
        while changed {
            changed = false;
            for block_id in &blocks {
                let mut next = HashSet::new();
                for predecessor in cfg.predecessors(*block_id)? {
                    next.extend(reaching.get(&predecessor).cloned().unwrap_or_default());
                }
                if let Some(block) = cfg.block(*block_id) {
                    for statement in &block.statements {
                        if let Some(definition) = defined_variable(statement) {
                            next.insert(definition.to_string());
                        }
                    }
                }
                if reaching.get(block_id) != Some(&next) {
                    reaching.insert(*block_id, next);
                    changed = true;
                }
            }
        }
        Ok(reaching)
    }

    /// Compute live variables for each block (backwards analysis).
    fn compute_live_variables(
        cfg: &ControlFlowGraph,
    ) -> AnalysisResult<HashMap<usize, HashSet<String>>> {
        let blocks = cfg.block_ids();
        let mut live: HashMap<_, HashSet<String>> =
            blocks.iter().map(|id| (*id, HashSet::new())).collect();
        let mut changed = true;
        while changed {
            changed = false;
            for block_id in blocks.iter().rev() {
                let mut out = HashSet::new();
                for successor in cfg.successors(*block_id)? {
                    out.extend(live.get(&successor).cloned().unwrap_or_default());
                }
                let mut next = out;
                if let Some(block) = cfg.block(*block_id) {
                    for statement in block.statements.iter().rev() {
                        if let Some(definition) = defined_variable(statement) {
                            next.remove(definition);
                        }
                        next.extend(used_variables(statement));
                    }
                }
                if live.get(block_id) != Some(&next) {
                    live.insert(*block_id, next);
                    changed = true;
                }
            }
        }
        Ok(live)
    }

    /// Extract definition-use chains from control flow graph.
    fn extract_def_use_chains(
        cfg: &ControlFlowGraph,
        mut analysis: DataFlow,
    ) -> AnalysisResult<DataFlow> {
        let mut latest: HashMap<String, usize> = HashMap::new();
        for block_id in cfg.block_ids() {
            let Some(block) = cfg.block(block_id) else {
                continue;
            };
            for (statement_idx, statement) in block.statements.iter().enumerate() {
                for variable in used_variables(statement) {
                    if let Some(chain) = latest
                        .get(&variable)
                        .and_then(|index| analysis.def_use_chains.get_mut(*index))
                    {
                        chain.uses.push(Location {
                            block: block_id,
                            statement_idx,
                            line: None,
                        });
                    }
                }
                if let Some(variable) = defined_variable(statement) {
                    analysis.def_use_chains.push(DefUse {
                        variable: variable.to_string(),
                        definition: Location {
                            block: block_id,
                            statement_idx,
                            line: None,
                        },
                        uses: Vec::new(),
                    });
                    latest.insert(variable.to_string(), analysis.def_use_chains.len() - 1);
                }
            }
        }
        Ok(analysis)
    }

    /// Identify tainted variables through data flow.
    fn identify_tainted(
        cfg: &ControlFlowGraph,
        mut analysis: DataFlow,
    ) -> AnalysisResult<DataFlow> {
        // Sources of taint:
        // - External calls
        // - Function parameters marked as untrusted
        // - User input
        // - Unchecked values

        info!("Identifying tainted variables");

        let sources = ["msg.sender", "tx.origin", "msg.data", "calldata", "input"];
        for block_id in cfg.block_ids() {
            let Some(block) = cfg.block(block_id) else {
                continue;
            };
            for statement in &block.statements {
                let Some(target) = defined_variable(statement) else {
                    continue;
                };
                let value = statement_value(statement).unwrap_or_default();
                let dependencies = identifiers(value);
                let tainted = sources.iter().any(|source| value.contains(source))
                    || dependencies
                        .iter()
                        .any(|dependency| analysis.tainted_vars.contains(dependency));
                let origin = if tainted {
                    ValueOrigin::Untrusted {
                        source: value.to_string(),
                    }
                } else if value.parse::<i128>().is_ok() {
                    ValueOrigin::Constant {
                        value: value.to_string(),
                    }
                } else {
                    ValueOrigin::Unknown
                };
                analysis.origins.insert(target.to_string(), origin);
                if tainted {
                    analysis.tainted_vars.insert(target.to_string());
                } else {
                    analysis.tainted_vars.remove(target);
                }
            }
        }
        Ok(analysis)
    }

    /// Build data dependency graph.
    fn build_dependencies(
        cfg: &ControlFlowGraph,
        mut analysis: DataFlow,
    ) -> AnalysisResult<DataFlow> {
        for block_id in cfg.block_ids() {
            let Some(block) = cfg.block(block_id) else {
                continue;
            };
            for statement in &block.statements {
                if let (Some(target), Some(value)) =
                    (defined_variable(statement), statement_value(statement))
                {
                    let dependencies = identifiers(value)
                        .into_iter()
                        .filter(|identifier| identifier != target)
                        .collect();
                    analysis
                        .dependencies
                        .insert(target.to_string(), dependencies);
                }
            }
        }
        Ok(analysis)
    }
}

/// Taint propagation engine.
pub struct TaintAnalyzer {
    /// Tainted source identifiers.
    tainted_sources: HashSet<String>,
}

impl TaintAnalyzer {
    /// Create new taint analyzer.
    pub fn new() -> Self {
        let mut sources = HashSet::new();
        // Mark common untrusted sources
        sources.insert("msg.sender".to_string());
        sources.insert("tx.origin".to_string());
        sources.insert("calldata".to_string());
        sources.insert("input".to_string());

        Self {
            tainted_sources: sources,
        }
    }

    /// Add custom tainted source.
    pub fn add_tainted_source(&mut self, source: String) {
        self.tainted_sources.insert(source);
    }

    /// Check if a value origin is tainted.
    pub fn is_tainted(&self, origin: &ValueOrigin) -> bool {
        origin.is_tainted()
            || (match origin {
                ValueOrigin::FunctionCall { function, .. } => {
                    self.tainted_sources.contains(function)
                }
                _ => false,
            })
    }

    /// Propagate taint through assignments.
    pub fn propagate(&self, source_tainted: bool, _assignment_op: &str) -> bool {
        // Most operations propagate taint
        // Except: hash operations (keccak256, sha256) are taint sinks
        source_tainted
    }
}

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Use-Def Analysis for variable tracking.
pub struct UseDefAnalyzer;

impl UseDefAnalyzer {
    /// Compute use-def chains for all variables.
    pub fn compute_chains(cfg: &ControlFlowGraph) -> AnalysisResult<HashMap<String, Vec<DefUse>>> {
        let analysis = DataFlowAnalyzer::extract_def_use_chains(cfg, DataFlow::new())?;
        let mut chains: HashMap<String, Vec<DefUse>> = HashMap::new();
        for chain in analysis.def_use_chains {
            chains
                .entry(chain.variable.clone())
                .or_default()
                .push(chain);
        }
        Ok(chains)
    }

    /// Find all uses of a variable definition.
    pub fn find_uses(def_use: &DefUse) -> Vec<Location> {
        def_use.uses.clone()
    }

    /// Find the definition of a variable use.
    pub fn find_definition(def_uses: &[DefUse], var: &str) -> Option<Location> {
        def_uses
            .iter()
            .find(|du| du.variable == var)
            .map(|du| du.definition.clone())
    }
}

fn defined_variable(statement: &crate::cfg::Statement) -> Option<&str> {
    match statement {
        crate::cfg::Statement::Assignment { target, .. }
        | crate::cfg::Statement::StateMutation {
            variable: target, ..
        } => Some(target),
        _ => None,
    }
}

fn statement_value(statement: &crate::cfg::Statement) -> Option<&str> {
    match statement {
        crate::cfg::Statement::Assignment { value, .. }
        | crate::cfg::Statement::StateMutation { value, .. } => Some(value),
        _ => None,
    }
}

fn used_variables(statement: &crate::cfg::Statement) -> HashSet<String> {
    match statement {
        crate::cfg::Statement::Assignment { value, .. }
        | crate::cfg::Statement::StateMutation { value, .. } => identifiers(value),
        crate::cfg::Statement::Branch { condition } => identifiers(condition),
        crate::cfg::Statement::FunctionCall { function, args } => {
            let mut used = identifiers(function);
            for argument in args {
                used.extend(identifiers(argument));
            }
            used
        }
        crate::cfg::Statement::Return { value } => {
            value.as_deref().map(identifiers).unwrap_or_default()
        }
        crate::cfg::Statement::Generic { code } => identifiers(code),
    }
}

fn identifiers(source: &str) -> HashSet<String> {
    source
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '_' || character == '.')
        })
        .filter(|token| {
            token
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        })
        .filter(|token| !matches!(*token, "if" | "return" | "true" | "false"))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_origin_taint() {
        let constant = ValueOrigin::Constant {
            value: "42".to_string(),
        };
        assert!(!constant.is_tainted());

        let untrusted = ValueOrigin::Untrusted {
            source: "user_input".to_string(),
        };
        assert!(untrusted.is_tainted());

        let external = ValueOrigin::ExternalCall {
            address: "0x...".to_string(),
        };
        assert!(external.is_tainted());
    }

    #[test]
    fn test_taint_analyzer_creation() {
        let analyzer = TaintAnalyzer::new();
        assert!(analyzer.tainted_sources.contains("msg.sender"));
        assert!(analyzer.tainted_sources.contains("calldata"));
    }

    #[test]
    fn test_data_flow_taint_tracking() {
        let mut data_flow = DataFlow::new();
        data_flow.tainted_vars.insert("user_input".to_string());

        assert!(data_flow.is_tainted("user_input"));
        assert!(!data_flow.is_tainted("safe_var"));
    }

    #[test]
    fn test_data_flow_dependencies() {
        let mut data_flow = DataFlow::new();
        let mut deps = HashSet::new();
        deps.insert("a".to_string());
        deps.insert("b".to_string());

        data_flow.dependencies.insert("c".to_string(), deps);

        assert!(data_flow.dependencies.contains_key("c"));
        assert_eq!(data_flow.dependencies["c"].len(), 2);
    }

    #[test]
    fn test_transitive_dependents() {
        let mut data_flow = DataFlow::new();

        let mut deps_b = HashSet::new();
        deps_b.insert("a".to_string());
        data_flow.dependencies.insert("b".to_string(), deps_b);

        let mut deps_c = HashSet::new();
        deps_c.insert("b".to_string());
        data_flow.dependencies.insert("c".to_string(), deps_c);

        let dependents = data_flow.transitive_dependents("a");
        assert!(dependents.contains("b"));
        assert!(dependents.contains("c"));
    }

    #[test]
    fn analysis_builds_def_use_dependencies_and_propagates_taint() {
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.entry();
        cfg.add_statement(
            entry,
            crate::cfg::Statement::Assignment {
                target: "sender".to_string(),
                value: "msg.sender".to_string(),
            },
        )
        .expect("sender assignment");
        cfg.add_statement(
            entry,
            crate::cfg::Statement::Assignment {
                target: "recipient".to_string(),
                value: "sender".to_string(),
            },
        )
        .expect("recipient assignment");
        cfg.add_statement(
            entry,
            crate::cfg::Statement::Return {
                value: Some("recipient".to_string()),
            },
        )
        .expect("return");
        cfg.mark_exit(entry).expect("exit");

        let analysis = DataFlowAnalyzer::analyze(&cfg).expect("data flow");
        assert!(analysis.is_tainted("sender"));
        assert!(analysis.is_tainted("recipient"));
        assert!(analysis.dependencies["recipient"].contains("sender"));
        let recipient = analysis
            .def_use_chains
            .iter()
            .find(|chain| chain.variable == "recipient")
            .expect("recipient def-use chain");
        assert_eq!(recipient.uses.len(), 1);
    }

    #[test]
    fn use_def_analyzer_groups_redefinitions() {
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.entry();
        for value in ["1", "2"] {
            cfg.add_statement(
                entry,
                crate::cfg::Statement::Assignment {
                    target: "amount".to_string(),
                    value: value.to_string(),
                },
            )
            .expect("assignment");
        }
        let chains = UseDefAnalyzer::compute_chains(&cfg).expect("chains");
        assert_eq!(chains["amount"].len(), 2);
    }
}
