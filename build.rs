// Build script for Truent: Compiles .sinv invariant DSL files into Rust
//
// This script:
// 1. Discovers all .sinv files in invariants/ directory
// 2. Parses and validates each .sinv file
// 3. Generates a Rust module (src/generated/invariants.rs) with InvariantDef structs
// 4. Fails the build if any .sinv file has syntax errors (with file:line info)

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Locate the workspace root.
    //
    // This script runs as `truent-core`'s build script, so the working
    // directory is `crates/core`, not the workspace root. Everything is
    // therefore resolved from CARGO_MANIFEST_DIR rather than relative paths —
    // which is what made the previous version silently generate an empty
    // registry while nine .sinv files sat unread.
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo"),
    );
    let workspace_root = find_workspace_root(&manifest_dir);
    let out_dir = manifest_dir.join("src").join("generated");

    // Rerun if any .sinv files change.
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("invariants").display()
    );
    println!("cargo:rerun-if-changed=build.rs");

    let invariants_dir = workspace_root.join("invariants");

    if !invariants_dir.exists() {
        eprintln!(
            "Warning: {} not found, skipping DSL compilation",
            invariants_dir.display()
        );
        generate_empty_invariants(&out_dir);
        return;
    }

    let mut all_invariants: BTreeMap<String, InvariantDef> = BTreeMap::new();

    // Scan invariants/evm, invariants/solana, invariants/move
    for chain_dir in &["evm", "solana", "move"] {
        let chain_path = invariants_dir.join(chain_dir);

        if !chain_path.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(&chain_path) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.extension().map(|e| e == "sinv").unwrap_or(false) {
                    match parse_sinv_file(&path) {
                        Ok(inv) => {
                            all_invariants.insert(inv.id.clone(), inv);
                        }
                        Err(e) => {
                            eprintln!("{}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    generate_rust_module(&all_invariants, &out_dir);
}

/// Walk up from `start` until a directory containing `invariants/` is found.
///
/// Falls back to `start` so a missing directory is reported by the caller
/// rather than panicking here.
fn find_workspace_root(start: &std::path::Path) -> PathBuf {
    for dir in start.ancestors() {
        if dir.join("invariants").is_dir() {
            return dir.to_path_buf();
        }
    }
    start.to_path_buf()
}

/// Parse a single .sinv file
fn parse_sinv_file(path: &PathBuf) -> Result<InvariantDef, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("{}:1: Failed to read file: {}", path.display(), e))?;

    let mut inv = InvariantDef::default();

    // Parse key = "value" format
    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value
                .trim()
                .trim_matches('"')
                .trim_matches('[')
                .trim_matches(']');

            match key {
                "invariant" => inv.id = value.to_string(),
                "severity" => inv.severity = value.to_string(),
                "chain" => inv.chain = value.to_string(),
                "description" => inv.description = value.to_string(),
                "message" => inv.message = value.to_string(),
                _ => {} // Ignore unknown fields
            }
        }
    }

    // Validate required fields
    if inv.id.is_empty() {
        return Err(format!(
            "{}:1: Missing required field: invariant",
            path.display()
        ));
    }
    if inv.severity.is_empty() {
        return Err(format!(
            "{}:1: Missing required field: severity",
            path.display()
        ));
    }
    if inv.chain.is_empty() {
        return Err(format!(
            "{}:1: Missing required field: chain",
            path.display()
        ));
    }

    Ok(inv)
}

#[derive(Debug, Clone, Default)]
struct InvariantDef {
    id: String,
    severity: String,
    chain: String,
    description: String,
    message: String,
}

/// Generate the invariants.rs module
fn generate_rust_module(invariants: &BTreeMap<String, InvariantDef>, out_dir: &std::path::Path) {
    let mut rust_code = String::from(
        r#"// This file is auto-generated by build.rs from .sinv files.
// DO NOT EDIT MANUALLY.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Compiled invariant definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledInvariant {
    pub id: &'static str,
    pub severity: &'static str,
    pub chain: &'static str,
    pub description: &'static str,
    pub message: &'static str,
}

/// Global registry of all compiled invariants
pub static INVARIANT_REGISTRY: Lazy<BTreeMap<&'static str, CompiledInvariant>> = 
    Lazy::new(|| {
        let mut map = BTreeMap::new();
"#,
    );

    for inv in invariants.values() {
        let id = &inv.id;
        let severity = &inv.severity;
        let chain = &inv.chain;
        let description = &inv.description;
        let message = &inv.message;

        rust_code.push_str(&format!(
            r#"
        map.insert("{id}", CompiledInvariant {{
            id: "{id}",
            severity: "{severity}",
            chain: "{chain}",
            description: "{description}",
            message: "{message}",
        }});
"#
        ));
    }

    rust_code.push_str(
        r#"
        map
    });

/// Get an invariant by ID
pub fn get_invariant(id: &str) -> Option<&'static CompiledInvariant> {
    INVARIANT_REGISTRY.get(id)
}

/// List all invariants for a chain
pub fn invariants_for_chain(chain: &str) -> Vec<&'static CompiledInvariant> {
    INVARIANT_REGISTRY
        .values()
        .filter(|inv| inv.chain == chain)
        .collect()
}

/// Count total invariants
pub fn invariant_count() -> usize {
    INVARIANT_REGISTRY.len()
}
"#,
    );

    fs::create_dir_all(out_dir).ok();

    let out_path = out_dir.join("invariants.rs");
    fs::write(&out_path, rust_code).expect("Failed to write generated invariants.rs");

    println!("cargo:rustc-env=INVARIANTS_GENERATED=1");
}

fn generate_empty_invariants(out_dir: &std::path::Path) {
    fs::create_dir_all(out_dir).ok();

    let out_path = out_dir.join("invariants.rs");
    let empty_code = r#"// Empty invariant registry (no .sinv files found)
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledInvariant {
    pub id: &'static str,
    pub severity: &'static str,
    pub chain: &'static str,
    pub description: &'static str,
    pub message: &'static str,
}

pub static INVARIANT_REGISTRY: Lazy<BTreeMap<&'static str, CompiledInvariant>> = 
    Lazy::new(|| BTreeMap::new());

pub fn get_invariant(id: &str) -> Option<&'static CompiledInvariant> {
    INVARIANT_REGISTRY.get(id)
}

pub fn invariants_for_chain(chain: &str) -> Vec<&'static CompiledInvariant> {
    vec![]
}

pub fn invariant_count() -> usize {
    0
}
"#;

    fs::write(&out_path, empty_code).ok();
}
