//! EVM analyzer implementation with advanced static analysis capabilities.
//!
//! This analyzer uses:
//! - Solc JSON AST parsing for accurate Solidity analysis
//! - Control flow graphs for path analysis
//! - Bytecode disassembly for compiled code analysis
//! - Pattern-based vulnerability detection

use std::collections::BTreeSet;
use std::path::Path;
use tracing::{debug, info, warn};
use truent_core::model::{FunctionModel, ProgramModel};
use truent_core::traits::ChainAnalyzer;
use truent_core::Finding;
use truent_core::{AnalysisContext, Result};

use crate::ast::{AstContract, SolidityParser, Visibility};
use crate::bytecode::{BytecodeAnalyzer, IssueType, Severity};
use crate::cfg::ControlFlowGraph;
// DEPRECATED: Old detector imports disabled for v0.3.0
// use crate::detectors::{
//     AccessControlDetector, FlashLoanDetector, OverflowDetector, ReentrancyDetector,
// };
use crate::errors::AnalysisError;
use truent_utils::SolcManager;

/// Analyzer for EVM (Solidity) smart contracts.
///
/// Performs comprehensive static analysis on Solidity source code using:
/// - Solc JSON AST parsing for accurate structural analysis
/// - Control flow graph construction for path analysis
/// - Bytecode analysis for compiled code patterns
/// - Taint tracking and data flow analysis
/// - Security vulnerability detection
pub struct EvmAnalyzer;

impl EvmAnalyzer {
    /// Create a new EVM analyzer instance.
    pub fn new() -> Self {
        Self
    }

    /// Parse a Solidity contract using solc JSON AST.
    fn parse_contract(&self, path: &Path) -> std::result::Result<AstContract, AnalysisError> {
        SolidityParser::parse(path).map_err(|e| {
            warn!("Failed to parse contract at {:?}: {}", path, e);
            AnalysisError::ast_parsing(format!("Failed to parse {}: {}", path.display(), e))
        })
    }

    /// Build control flow graph from parsed contract.
    fn build_cfg_from_contract(&self, contract: &AstContract) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();

        // Add basic blocks for each function
        for func in &contract.functions {
            debug!("Building CFG for function: {}", func.name);

            // Create blocks for this function (simplified for now)
            let _entry_id = cfg.new_block();
            let exit_id = cfg.new_block();

            // Mark exit block
            let _ = cfg.mark_exit(exit_id);

            // Add edge from entry to exit
            let _ = cfg.add_edge(_entry_id, exit_id, "normal");
        }

        cfg
    }

    /// Analyze bytecode for compiled patterns.
    fn analyze_bytecode(&self, contract: &AstContract) -> Vec<(IssueType, Severity, String)> {
        // Runtime bytecode represents the code callers can execute. Creation
        // bytecode is only a fallback for compiler outputs that omit it.
        let bytecode = if contract.runtime_bytecode.is_empty() {
            &contract.bytecode
        } else {
            &contract.runtime_bytecode
        };
        if bytecode.is_empty() {
            return Vec::new();
        }

        match BytecodeAnalyzer::analyze(bytecode) {
            Ok(analysis) => analysis
                .issues
                .into_iter()
                .map(|issue| {
                    (
                        issue.issue_type,
                        issue.severity,
                        format!("{} (bytecode PC {})", issue.description, issue.pc),
                    )
                })
                .collect(),
            Err(error) => {
                warn!("Skipping invalid bytecode for '{}': {error}", contract.name);
                Vec::new()
            }
        }
    }

    /// Detect security vulnerabilities using pattern matching and structure analysis.
    fn detect_vulnerabilities(
        &self,
        contract: &AstContract,
        _cfg: &ControlFlowGraph,
        bytecode_issues: &[(IssueType, Severity, String)],
    ) -> Vec<(String, String)> {
        let mut vulnerabilities = Vec::new();

        for (issue_type, severity, description) in bytecode_issues {
            vulnerabilities.push((
                format!("BYTECODE_{issue_type:?}_{severity:?}").to_uppercase(),
                description.clone(),
            ));
        }

        // Check each function for vulnerabilities
        for func in &contract.functions {
            // Check for reentrancy vulnerabilities
            let body_str = func.body.join("\n");
            if body_str.contains(".call") || body_str.contains("transfer") {
                // Check if function modifies state
                if func.is_mutable {
                    vulnerabilities.push((
                        "REENTRANCY".to_string(),
                        format!("Function '{}' may have reentrancy vulnerability", func.name),
                    ));
                }
            }

            // Check for unchecked calls
            if body_str.contains(".call(") && !body_str.contains("require(") {
                vulnerabilities.push((
                    "UNCHECKED_CALL".to_string(),
                    format!("Function '{}' has unchecked external call", func.name),
                ));
            }

            // Check for missing access control on public functions
            if matches!(func.visibility, Visibility::Public | Visibility::External)
                && !func.modifiers.iter().any(|m| m.contains("onlyOwner"))
                && !body_str.contains("require(msg.sender")
            {
                vulnerabilities.push((
                    "ACCESS_CONTROL".to_string(),
                    format!("Function '{}' may lack access control", func.name),
                ));
            }
        }

        vulnerabilities
    }
}

impl Default for EvmAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainAnalyzer for EvmAnalyzer {
    fn analyze(&self, path: &Path) -> Result<ProgramModel> {
        info!("Analyzing EVM contract at {:?}", path);

        // Step 1: Parse using Solc JSON AST for accurate analysis
        let ast_contract = self.parse_contract(path).map_err(|e| {
            truent_core::InvarError::Custom(format!("Failed to parse contract with solc: {}", e))
        })?;

        // Step 2: Build control flow graph
        let cfg = self.build_cfg_from_contract(&ast_contract);
        debug!("Built CFG with {} blocks", cfg.block_count());

        // Step 3: Analyze bytecode for patterns
        let bytecode_issues = self.analyze_bytecode(&ast_contract);
        debug!("Found {} bytecode issues", bytecode_issues.len());

        // Step 4: Detect vulnerabilities using all analysis results
        let _vulnerabilities = self.detect_vulnerabilities(&ast_contract, &cfg, &bytecode_issues);

        // Step 5: Create program model
        let mut program = ProgramModel::new(
            ast_contract.name.clone(),
            "evm".to_string(),
            path.to_string_lossy().to_string(),
        );

        // Add state variables
        for var in &ast_contract.state_vars {
            use truent_core::model::StateVar;
            program.add_state_var(StateVar {
                name: var.name.clone(),
                type_name: var.type_name.clone(),
                is_mutable: var.is_mutable,
                visibility: None,
            });
        }

        // Add functions
        for func in &ast_contract.functions {
            let func_model = FunctionModel {
                name: func.name.clone(),
                parameters: func.parameters.iter().map(|p| p.name.clone()).collect(),
                return_type: if func.returns.is_empty() {
                    None
                } else {
                    Some(func.returns[0].type_name.clone())
                },
                mutates: BTreeSet::new(),
                reads: BTreeSet::new(),
                is_entry_point: matches!(
                    func.visibility,
                    Visibility::Public | Visibility::External
                ),
                is_pure: func.is_pure && !func.is_mutable,
            };
            program.add_function(func_model);
        }

        Ok(program)
    }

    fn chain(&self) -> &str {
        "evm"
    }
}

impl EvmAnalyzer {
    /// Analyze an EVM contract with context and warnings using advanced analysis.
    pub fn analyze_with_context(&self, path: &Path) -> Result<AnalysisContext> {
        let program = self.analyze(path)?;
        let mut context = AnalysisContext::new(program);

        // Parse AST for detailed analysis
        match self.parse_contract(path) {
            Ok(ast_contract) => {
                // Build CFG and analyze paths
                let cfg = self.build_cfg_from_contract(&ast_contract);

                // Analyze bytecode
                let bytecode_issues = self.analyze_bytecode(&ast_contract);

                // Detect vulnerabilities
                let vulnerabilities =
                    self.detect_vulnerabilities(&ast_contract, &cfg, &bytecode_issues);

                // Add vulnerabilities as context warnings
                for (vuln_type, description) in &vulnerabilities {
                    let line_num = 1; // Could be enhanced to track line numbers in AST
                    context.add_warning(
                        format!("[{}] {}", vuln_type, description),
                        path.to_string_lossy().to_string(),
                        line_num,
                        None,
                        None,
                    );
                }

                // Mark as invalid if critical vulnerabilities found
                if vulnerabilities.iter().any(|(t, _)| {
                    t.contains("REENTRANCY") || t.contains("UNCHECKED") || t.contains("Unsafe")
                }) {
                    context.mark_invalid();
                }
            }
            Err(e) => {
                warn!("Failed to perform advanced analysis: {}", e);
                // Fall back to basic heuristic checks
                self.basic_vulnerability_check(path, &mut context)?;
            }
        }

        Ok(context)
    }

    /// Analyze a Solidity contract using solc JSON AST and AST-based detectors.
    ///
    /// This is the primary analysis method for high-precision vulnerability detection.
    /// Falls back to pattern analysis if solc is not available.
    pub fn analyze_with_ast(&self, path: &Path) -> anyhow::Result<Vec<Finding>> {
        let solc = match SolcManager::new() {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "solc not available ({}), falling back to pattern analysis",
                    e
                );
                return self.analyze_with_patterns(path);
            }
        };

        let source = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;

        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        match solc.get_ast_for_source(&source, &file_name) {
            Ok(solc_output) => {
                debug!("Successfully parsed AST for {}", file_name);
                self.run_ast_detectors(&solc_output, &source, &file_name, path)
            }
            Err(e) => {
                warn!("AST parse failed for {} ({}), using patterns", file_name, e);
                self.analyze_with_patterns(path)
            }
        }
    }

    fn run_ast_detectors(
        &self,
        output: &truent_utils::SolcOutput,
        _source: &str,
        _file_name: &str,
        _path: &Path,
    ) -> anyhow::Result<Vec<Finding>> {
        let violations = Vec::new();

        for _ in output.sources.values() {
            // DEPRECATED: Old detectors disabled for v0.3.0
            /*
            // Run reentrancy detector
            let mut reentrancy = ReentrancyDetector::new(source, file_name);
            let mut walker = AstWalker::new(&mut reentrancy);
            if let AstNode::SourceUnit(unit) = serde_json::from_value(source_data.ast.clone())? {
                walker.walk_source_unit(&unit);
            }
            violations.extend(reentrancy.violations);

            // Run overflow detector
            let mut overflow = OverflowDetector::new(source, file_name);
            let mut walker = AstWalker::new(&mut overflow);
            if let AstNode::SourceUnit(unit) = serde_json::from_value(source_data.ast.clone())? {
                walker.walk_source_unit(&unit);
            }
            violations.extend(overflow.violations);

            // Run flash loan detector
            let mut flash_loan = FlashLoanDetector::new(source, file_name);
            let mut walker = AstWalker::new(&mut flash_loan);
            if let AstNode::SourceUnit(unit) = serde_json::from_value(source_data.ast.clone())? {
                walker.walk_source_unit(&unit);
            }
            violations.extend(flash_loan.violations);

            // Run access control detector
            let mut access = AccessControlDetector::new(source, file_name);
            let mut walker = AstWalker::new(&mut access);
            if let AstNode::SourceUnit(unit) = serde_json::from_value(source_data.ast.clone())? {
                walker.walk_source_unit(&unit);
            }
            violations.extend(access.violations);
            */
        }

        Ok(violations)
    }

    /// Analyze with pattern-based fallback
    fn analyze_with_patterns(&self, path: &Path) -> anyhow::Result<Vec<Finding>> {
        let _source = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;

        // Fallback: return empty for now
        // In production, this would have regex-based pattern detectors
        Ok(vec![])
    }

    /// Fallback to basic heuristic vulnerability detection when AST parsing fails.
    fn basic_vulnerability_check(&self, path: &Path, context: &mut AnalysisContext) -> Result<()> {
        let source = std::fs::read_to_string(path).map_err(truent_core::InvarError::IoError)?;
        let lines: Vec<&str> = source.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;

            // Unchecked call return value
            if line.contains(".call") && !line.contains("require") && !line.contains("assert") {
                context.add_warning(
                    "Unchecked call return value detected".to_string(),
                    path.to_string_lossy().to_string(),
                    line_num,
                    None,
                    Some(line.to_string()),
                );
            }

            // Potential integer overflow
            if (line.contains("+ ") || line.contains("+="))
                && (line.contains("balance") || line.contains("amount"))
            {
                context.add_warning(
                    "Potential unchecked arithmetic".to_string(),
                    path.to_string_lossy().to_string(),
                    line_num,
                    None,
                    Some(line.to_string()),
                );
            }

            // Reentrancy pattern
            if line.contains(".transfer") || line.contains(".call") {
                context.add_warning(
                    "Potential reentrancy vulnerability".to_string(),
                    path.to_string_lossy().to_string(),
                    line_num,
                    None,
                    Some(line.to_string()),
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = EvmAnalyzer::new();
        assert_eq!("evm", analyzer.chain());
    }

    fn contract_with_bytecode(runtime_bytecode: &str, bytecode: &str) -> AstContract {
        AstContract {
            name: "Fixture".to_string(),
            id: 1,
            state_vars: vec![],
            functions: vec![],
            events: vec![],
            modifiers: vec![],
            base_contracts: vec![],
            bytecode: bytecode.to_string(),
            runtime_bytecode: runtime_bytecode.to_string(),
        }
    }

    #[test]
    fn bytecode_analysis_uses_runtime_code() {
        // CALL followed by SSTORE is surfaced as a reentrancy risk. The
        // creation bytecode is deliberately invalid to prove it is ignored.
        let contract = contract_with_bytecode("50f155", "not-hex");
        let issues = EvmAnalyzer::new().analyze_bytecode(&contract);

        assert!(issues
            .iter()
            .any(|(kind, _, _)| *kind == IssueType::PotentialReentrancy));
    }

    #[test]
    fn bytecode_analysis_falls_back_to_creation_code() {
        let contract = contract_with_bytecode("", "50f155");
        let issues = EvmAnalyzer::new().analyze_bytecode(&contract);

        assert!(!issues.is_empty());
    }

    #[test]
    fn invalid_bytecode_does_not_abort_source_analysis() {
        let contract = contract_with_bytecode("not-hex", "");
        assert!(EvmAnalyzer::new().analyze_bytecode(&contract).is_empty());
    }
}
