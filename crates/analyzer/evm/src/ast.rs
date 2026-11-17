#![allow(missing_docs)]
//! Solidity source code and AST parsing using solc compiler.
//!
//! This module provides production-grade AST parsing by leveraging the Solidity compiler's
//! JSON AST output, eliminating regex-based parsing limitations and enabling accurate
//! semantic analysis.

use crate::errors::{AnalysisError, AnalysisResult};
use serde_json::Value;
use std::path::Path;
use tracing::{debug, info};

/// Compilation output including source code and AST.
#[derive(Debug, Clone)]
pub struct CompilationOutput {
    /// Solidity source code.
    pub source: String,
    /// Compiled bytecode (hex string).
    pub bytecode: String,
    /// Runtime bytecode (hex string).
    pub runtime_bytecode: String,
    /// JSON Abstract Syntax Tree.
    pub ast: Value,
    /// Contract name.
    pub contract_name: String,
}

/// Represents a contract in the AST.
#[derive(Debug, Clone)]
pub struct AstContract {
    /// Contract name.
    pub name: String,
    /// AST node ID.
    pub id: u64,
    /// State variables.
    pub state_vars: Vec<AstStateVar>,
    /// Functions.
    pub functions: Vec<AstFunction>,
    /// Events.
    pub events: Vec<AstEvent>,
    /// Modifiers.
    pub modifiers: Vec<AstModifier>,
    /// Inheritance chain.
    pub base_contracts: Vec<String>,
    /// Creation bytecode emitted by solc.
    pub bytecode: String,
    /// Deployed runtime bytecode emitted by solc.
    pub runtime_bytecode: String,
}

/// State variable in contract.
#[derive(Debug, Clone)]
pub struct AstStateVar {
    /// Variable name.
    pub name: String,
    /// Type name (e.g., "uint256", "address", "mapping(...)").
    pub type_name: String,
    /// Is mutable (not constant).
    pub is_mutable: bool,
    /// Visibility level.
    pub visibility: Visibility,
    /// AST node ID.
    pub id: u64,
}

/// Function definition.
#[derive(Debug, Clone)]
pub struct AstFunction {
    /// Function name.
    pub name: String,
    /// Function parameters.
    pub parameters: Vec<AstParam>,
    /// Return types.
    pub returns: Vec<AstParam>,
    /// Function visibility.
    pub visibility: Visibility,
    /// Is function state-mutating.
    pub is_mutable: bool,
    /// Is function pure.
    pub is_pure: bool,
    /// Is function view-only.
    pub is_view: bool,
    /// Modifiers applied.
    pub modifiers: Vec<String>,
    /// Function body statements.
    pub body: Vec<String>,
    /// AST node ID.
    pub id: u64,
}

/// Function parameter.
#[derive(Debug, Clone)]
pub struct AstParam {
    /// Parameter name.
    pub name: String,
    /// Parameter type.
    pub type_name: String,
}

/// Event definition.
#[derive(Debug, Clone)]
pub struct AstEvent {
    /// Event name.
    pub name: String,
    /// Event parameters.
    pub parameters: Vec<AstParam>,
    /// AST node ID.
    pub id: u64,
}

/// Modifier definition.
#[derive(Debug, Clone)]
pub struct AstModifier {
    /// Modifier name.
    pub name: String,
    /// Modifier parameters.
    pub parameters: Vec<AstParam>,
    /// AST node ID.
    pub id: u64,
}

/// Visibility level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Public visibility.
    Public,
    /// Internal visibility.
    Internal,
    /// Private visibility.
    Private,
    /// External visibility.
    External,
}

impl std::str::FromStr for Visibility {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public" => Ok(Visibility::Public),
            "internal" => Ok(Visibility::Internal),
            "private" => Ok(Visibility::Private),
            "external" => Ok(Visibility::External),
            _ => Err(format!("Unknown visibility: {}", s)),
        }
    }
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
            Visibility::Internal => write!(f, "internal"),
            Visibility::Private => write!(f, "private"),
            Visibility::External => write!(f, "external"),
        }
    }
}

/// Solidity compiler and AST parser.
///
/// Uses `solc` to compile Solidity and extract the JSON AST.
pub struct SolidityParser;

impl SolidityParser {
    /// Parse Solidity file to AST.
    ///
    /// # Arguments
    /// * `path` - Path to Solidity source file
    ///
    /// # Returns
    /// Parsed contract with full AST information
    pub fn parse(path: &Path) -> AnalysisResult<AstContract> {
        info!("Parsing Solidity file: {:?}", path);

        let source = std::fs::read_to_string(path).map_err(AnalysisError::IoError)?;

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("contract");
        Self::parse_source(&source, filename)
    }

    /// Parse Solidity source code to AST.
    ///
    /// # Arguments
    /// * `source` - Solidity source code
    /// * `filename` - Logical filename (for error messages)
    ///
    /// # Returns
    /// Parsed contract with full AST information
    pub fn parse_source(source: &str, filename: &str) -> AnalysisResult<AstContract> {
        debug!("Compiling {} with solc", filename);

        // Compile with solc to JSON output
        let compilation = Self::compile_to_ast(source, filename)?;

        // Extract contract information from AST
        Self::extract_contract(&compilation)
    }

    /// Compile Solidity source to JSON AST.
    fn compile_to_ast(source: &str, filename: &str) -> AnalysisResult<CompilationOutput> {
        use std::io::Write;

        // Create temporary file for compilation
        let temp_dir = tempfile::tempdir().map_err(|e| {
            AnalysisError::CompilationError(format!("Failed to create temp dir: {}", e))
        })?;

        // `Path::join` discards its base entirely when the argument is an
        // absolute path (or replaces components on an unrelated prefix for a
        // path with directory separators) - callers routinely pass a real
        // file's absolute/relative path as `filename` (it's only used here
        // for solc's `--combined-json` output keys), so joining it verbatim
        // to `temp_dir` could silently resolve outside the temp directory
        // entirely and overwrite that real file with whatever `source` is
        // being compiled (e.g. a fuzzer's mutated variant). Only the
        // basename is needed inside the sandboxed temp dir.
        let basename = std::path::Path::new(filename)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("contract.sol"));
        let temp_file = temp_dir.path().join(basename);
        let mut file = std::fs::File::create(&temp_file).map_err(AnalysisError::IoError)?;
        file.write_all(source.as_bytes())
            .map_err(AnalysisError::IoError)?;
        drop(file);

        // Invoke solc compiler with JSON output
        let output = std::process::Command::new("solc")
            .arg("--combined-json")
            .arg("bin,bin-runtime,ast")
            .arg("--optimize")
            .arg("--optimize-runs=200")
            .arg(&temp_file)
            .output()
            .map_err(|e| {
                debug!("solc invocation failed: {}", e);
                AnalysisError::CompilationError(
                    "solc compiler not found. Install with: apt-get install solc (or brew install solidity on macOS)".to_string(),
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't fail on warnings, only errors
            if stderr.contains("Error:") {
                return Err(AnalysisError::CompilationError(format!(
                    "solc compilation failed:\n{}",
                    stderr
                )));
            }
        }

        let stdout = String::from_utf8(output.stdout).map_err(|e| {
            AnalysisError::CompilationError(format!("Invalid UTF-8 in solc output: {}", e))
        })?;

        let json: Value = serde_json::from_str(&stdout).map_err(|e| {
            AnalysisError::AstParsingError(format!("Failed to parse solc JSON output: {}", e))
        })?;

        // Extract contract name and bytecode from JSON
        let contract_name = Self::extract_contract_name_from_json(&json);
        let bytecode = Self::extract_bytecode_from_json(&json, false);
        let runtime_bytecode = Self::extract_bytecode_from_json(&json, true);

        // Extract the AST
        let ast = json
            .get("contracts")
            .and_then(|c| c.as_object())
            .and_then(|obj| obj.values().next())
            .and_then(|c| c.get("ast"))
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default()));

        Ok(CompilationOutput {
            source: source.to_string(),
            bytecode,
            runtime_bytecode,
            ast,
            contract_name,
        })
    }

    /// Extract contract name from solc JSON output.
    fn extract_contract_name_from_json(json: &Value) -> String {
        json.get("contracts")
            .and_then(|contracts| contracts.as_object())
            .and_then(|obj| obj.values().next())
            .and_then(|contract| contract.as_object())
            .and_then(|obj| obj.keys().next())
            .map(|name| name.trim_start_matches(':').to_string())
            .unwrap_or_else(|| "Unknown".to_string())
    }

    /// Extract bytecode from solc JSON output.
    fn extract_bytecode_from_json(json: &Value, runtime: bool) -> String {
        let key = if runtime { "bin-runtime" } else { "bin" };

        json.get("contracts")
            .and_then(|contracts| contracts.as_object())
            .and_then(|obj| obj.values().next())
            .and_then(|contract| contract.as_object())
            .and_then(|obj| obj.values().next())
            .and_then(|details| details.get(key))
            .and_then(|bytecode| bytecode.as_str())
            .unwrap_or("")
            .to_string()
    }

    /// Extract contract information from JSON AST.
    fn extract_contract(output: &CompilationOutput) -> AnalysisResult<AstContract> {
        let ast = &output.ast;

        // Navigate solc JSON AST structure
        let contract = AstContract {
            name: output.contract_name.clone(),
            id: ast.get("id").and_then(|id| id.as_u64()).unwrap_or(0),
            state_vars: Self::extract_state_vars(ast)?,
            functions: Self::extract_functions(ast, &output.source)?,
            events: Self::extract_events(ast)?,
            modifiers: Self::extract_modifiers(ast)?,
            base_contracts: Self::extract_base_contracts(ast),
            bytecode: output.bytecode.clone(),
            runtime_bytecode: output.runtime_bytecode.clone(),
        };

        info!(
            "Extracted contract '{}' with {} functions, {} state vars, {} events",
            contract.name,
            contract.functions.len(),
            contract.state_vars.len(),
            contract.events.len()
        );

        Ok(contract)
    }

    /// Extract state variables from AST.
    fn extract_state_vars(ast: &Value) -> AnalysisResult<Vec<AstStateVar>> {
        let mut vars = Vec::new();

        // Traverse AST nodes
        if let Some(nodes) = ast.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                Self::collect_state_vars(node, &mut vars);
            }
        }

        debug!("Found {} state variables", vars.len());
        Ok(vars)
    }

    /// Recursively collect state variables from AST nodes.
    fn collect_state_vars(node: &Value, vars: &mut Vec<AstStateVar>) {
        if let Some(node_type) = node.get("nodeType").and_then(|t| t.as_str()) {
            if node_type == "VariableDeclaration" {
                // Only include state variables (not parameters)
                if !Self::is_parameter(node) {
                    if let Some(name) = node.get("name").and_then(|n| n.as_str()) {
                        let var = AstStateVar {
                            name: name.to_string(),
                            type_name: Self::extract_type_name(node),
                            is_mutable: !node
                                .get("constant")
                                .and_then(|c| c.as_bool())
                                .unwrap_or(false),
                            visibility: node
                                .get("visibility")
                                .and_then(|v| v.as_str())
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(Visibility::Internal),
                            id: node.get("id").and_then(|i| i.as_u64()).unwrap_or(0),
                        };
                        vars.push(var);
                    }
                }
            }
        }

        // Recursively process child nodes
        if let Some(nodes) = node.get("nodes").and_then(|n| n.as_array()) {
            for child in nodes {
                Self::collect_state_vars(child, vars);
            }
        }
    }

    /// Check if a variable is a function parameter (not a state var).
    fn is_parameter(node: &Value) -> bool {
        // Parameters are usually constants or have isStateVar = false
        node.get("constant")
            .and_then(|c| c.as_bool())
            .unwrap_or(false)
            || node
                .get("isStateVar")
                .and_then(|isv| isv.as_bool())
                .map(|isv| !isv)
                .unwrap_or(false)
    }

    /// Extract type name from AST node.
    fn extract_type_name(node: &Value) -> String {
        // Try to extract from typeName field
        if let Some(type_name) = node.get("typeName") {
            if let Some(name) = type_name.get("name").and_then(|n| n.as_str()) {
                return name.to_string();
            }
            if let Some(type_str) = type_name.as_str() {
                return type_str.to_string();
            }
            // Handle complex types with nodeType
            if let Some(node_type) = type_name.get("nodeType").and_then(|nt| nt.as_str()) {
                return node_type.to_string();
            }
        }
        "unknown".to_string()
    }

    /// Extract functions from AST.
    fn extract_functions(ast: &Value, source: &str) -> AnalysisResult<Vec<AstFunction>> {
        let mut functions = Vec::new();

        if let Some(nodes) = ast.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                Self::collect_functions(node, &mut functions, source);
            }
        }

        debug!("Found {} functions", functions.len());
        Ok(functions)
    }

    /// Recursively collect functions from AST nodes.
    fn collect_functions(node: &Value, functions: &mut Vec<AstFunction>, source: &str) {
        if let Some(node_type) = node.get("nodeType").and_then(|t| t.as_str()) {
            if node_type == "FunctionDefinition" {
                if let Some(name) = node.get("name").and_then(|n| n.as_str()) {
                    let func = AstFunction {
                        name: name.to_string(),
                        parameters: Self::extract_params(node, "params"),
                        returns: Self::extract_params(node, "returns"),
                        visibility: node
                            .get("visibility")
                            .and_then(|v| v.as_str())
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(Visibility::Internal),
                        is_mutable: !node
                            .get("stateMutability")
                            .and_then(|s| s.as_str())
                            .map(|s| ["pure", "view"].contains(&s))
                            .unwrap_or(false),
                        is_pure: node
                            .get("stateMutability")
                            .and_then(|s| s.as_str())
                            .map(|s| s == "pure")
                            .unwrap_or(false),
                        is_view: node
                            .get("stateMutability")
                            .and_then(|s| s.as_str())
                            .map(|s| s == "view")
                            .unwrap_or(false),
                        modifiers: Self::extract_modifier_names(node),
                        body: Self::extract_function_body(node, source),
                        id: node.get("id").and_then(|id| id.as_u64()).unwrap_or(0),
                    };
                    functions.push(func);
                }
            }
        }

        if let Some(children) = node.get("nodes").and_then(|n| n.as_array()) {
            for child in children {
                Self::collect_functions(child, functions, source);
            }
        }
    }

    /// Extract function modifier names.
    fn extract_modifier_names(node: &Value) -> Vec<String> {
        let mut names = Vec::new();

        if let Some(modifiers) = node.get("modifiers").and_then(|m| m.as_array()) {
            for modifier in modifiers {
                if let Some(name) = modifier.get("name").and_then(|n| n.as_str()) {
                    names.push(name.to_string());
                }
            }
        }

        names
    }

    /// Extract function body as raw source lines, sliced from the original source
    /// text using the AST body node's "src" byte-range ("start:length:fileIndex").
    fn extract_function_body(node: &Value, source: &str) -> Vec<String> {
        let Some(src) = node
            .get("body")
            .and_then(|b| b.get("src"))
            .and_then(|s| s.as_str())
        else {
            return Vec::new();
        };

        let (start, length, _) = crate::ast_types::parse_src(src);
        let start = start as usize;
        let end = start.saturating_add(length as usize).min(source.len());

        // Defensive: never trust byte offsets to land on char boundaries, even
        // though solc's own offsets should always be self-consistent with `source`.
        if start >= end || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
            return Vec::new();
        }

        source[start..end].lines().map(|l| l.to_string()).collect()
    }

    /// Extract function parameters or return types.
    fn extract_params(node: &Value, field: &str) -> Vec<AstParam> {
        let mut params = Vec::new();

        // Handle both old and new solc JSON formats
        let params_node = node.get(field).or_else(|| node.get("parameters"));

        if let Some(params_obj) = params_node {
            if let Some(arr) = params_obj.get("parameters").and_then(|p| p.as_array()) {
                for param in arr {
                    if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                        let type_name = Self::extract_type_name(param);
                        params.push(AstParam {
                            name: name.to_string(),
                            type_name,
                        });
                    }
                }
            }
        }

        params
    }

    /// Extract events from AST.
    fn extract_events(ast: &Value) -> AnalysisResult<Vec<AstEvent>> {
        let mut events = Vec::new();

        if let Some(nodes) = ast.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                Self::collect_events(node, &mut events);
            }
        }

        debug!("Found {} events", events.len());
        Ok(events)
    }

    /// Recursively collect events from AST nodes.
    fn collect_events(node: &Value, events: &mut Vec<AstEvent>) {
        if let Some(node_type) = node.get("nodeType").and_then(|t| t.as_str()) {
            if node_type == "EventDefinition" {
                if let Some(name) = node.get("name").and_then(|n| n.as_str()) {
                    let event = AstEvent {
                        name: name.to_string(),
                        parameters: Self::extract_event_params(node),
                        id: node.get("id").and_then(|id| id.as_u64()).unwrap_or(0),
                    };
                    events.push(event);
                }
            }
        }

        if let Some(children) = node.get("nodes").and_then(|n| n.as_array()) {
            for child in children {
                Self::collect_events(child, events);
            }
        }
    }

    /// Extract event parameters.
    fn extract_event_params(node: &Value) -> Vec<AstParam> {
        let mut params = Vec::new();

        if let Some(arr) = node.get("parameters").and_then(|p| p.as_array()) {
            for param in arr {
                if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                    let type_name = Self::extract_type_name(param);
                    params.push(AstParam {
                        name: name.to_string(),
                        type_name,
                    });
                }
            }
        }

        params
    }

    /// Extract modifiers from AST.
    fn extract_modifiers(ast: &Value) -> AnalysisResult<Vec<AstModifier>> {
        let mut modifiers = Vec::new();

        if let Some(nodes) = ast.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                Self::collect_modifiers(node, &mut modifiers);
            }
        }

        debug!("Found {} modifiers", modifiers.len());
        Ok(modifiers)
    }

    /// Recursively collect modifiers from AST nodes.
    fn collect_modifiers(node: &Value, modifiers: &mut Vec<AstModifier>) {
        if let Some(node_type) = node.get("nodeType").and_then(|t| t.as_str()) {
            if node_type == "ModifierDefinition" {
                if let Some(name) = node.get("name").and_then(|n| n.as_str()) {
                    let modifier = AstModifier {
                        name: name.to_string(),
                        parameters: Self::extract_params(node, "params"),
                        id: node.get("id").and_then(|id| id.as_u64()).unwrap_or(0),
                    };
                    modifiers.push(modifier);
                }
            }
        }

        if let Some(children) = node.get("nodes").and_then(|n| n.as_array()) {
            for child in children {
                Self::collect_modifiers(child, modifiers);
            }
        }
    }

    /// Extract base contracts (inheritance).
    fn extract_base_contracts(ast: &Value) -> Vec<String> {
        let mut bases = Vec::new();

        if let Some(bases_arr) = ast.get("baseContracts").and_then(|b| b.as_array()) {
            for base in bases_arr {
                if let Some(name) = base.get("baseName").and_then(|n| n.as_str()) {
                    bases.push(name.to_string());
                }
            }
        }

        bases
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visibility_parsing() {
        assert_eq!("public".parse::<Visibility>(), Ok(Visibility::Public));
        assert_eq!("internal".parse::<Visibility>(), Ok(Visibility::Internal));
        assert_eq!("private".parse::<Visibility>(), Ok(Visibility::Private));
        assert_eq!("external".parse::<Visibility>(), Ok(Visibility::External));
    }

    #[test]
    fn test_visibility_display() {
        assert_eq!(Visibility::Public.to_string(), "public");
        assert_eq!(Visibility::Internal.to_string(), "internal");
        assert_eq!(Visibility::Private.to_string(), "private");
        assert_eq!(Visibility::External.to_string(), "external");
    }

    /// `Path::join` silently discards its base when the argument is absolute,
    /// so passing a real file's absolute path as `filename` used to make
    /// `compile_to_ast` write straight over that file with whatever `source`
    /// was being compiled - e.g. a fuzzer's mutated variant of a real
    /// fixture. This must only ever write inside the temp directory,
    /// regardless of what shape of path `filename` is.
    #[test]
    fn compile_to_ast_never_writes_outside_temp_dir_for_absolute_filename() {
        let real_file = std::env::temp_dir().join(format!(
            "truent_ast_rs_test_sentinel_{}.sol",
            std::process::id()
        ));
        let original_content = "// untouched sentinel file\ncontract C {}\n";
        std::fs::write(&real_file, original_content).unwrap();

        let absolute_filename = real_file.to_string_lossy().to_string();
        // solc isn't necessarily installed in the test environment; the
        // point of this test is only that the temp-file write itself never
        // lands on `real_file` - whether compilation subsequently succeeds
        // or fails with "solc not found" is irrelevant here.
        let _ = SolidityParser::parse_source("contract C {}", &absolute_filename);

        let content_after = std::fs::read_to_string(&real_file).unwrap();
        std::fs::remove_file(&real_file).ok();
        assert_eq!(
            content_after, original_content,
            "compile_to_ast must not overwrite a real file just because its \
             absolute path was passed as the `filename` argument"
        );
    }
}
