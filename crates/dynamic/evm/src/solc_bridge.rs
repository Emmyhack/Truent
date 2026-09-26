//! Bridges `solc`'s `--combined-json abi,bin` output (already produced by
//! `truent_utils::SolcManager`, previously only used for its AST) into the
//! chain-agnostic [`FunctionSpec`]/[`CompiledContract`] shapes the dynamic
//! fuzzer needs.
//!
//! The parsing logic (JSON -> FunctionSpec, hex -> bytes, signature ->
//! selector) is proven correct by the unit tests below, including a
//! cross-check against WETH9's real selector constants. What's still
//! unverified: those tests use a hand-written ABI JSON fixture, not a live
//! sample from an actual `solc --combined-json abi,bin` run, so the shape
//! assumptions here (`contracts[fqn].abi` sometimes being a JSON-encoded
//! string depending on solc version, the exact `bin` field name) haven't
//! been checked against a real compiler yet — see `backend.rs`'s doc
//! comment for the end-to-end test that would close this out.

use crate::types::CompiledContract;
use sha3::{Digest, Keccak256};
use truent_dynamic_core::{FunctionSpec, ParamKind};

/// Computes the 4-byte Solidity function selector: the first 4 bytes of
/// `keccak256("name(type1,type2,...)")`.
pub fn selector_for(name: &str, solidity_types: &[&str]) -> [u8; 4] {
    let signature = format!("{}({})", name, solidity_types.join(","));
    let mut hasher = Keccak256::new();
    hasher.update(signature.as_bytes());
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

fn param_kind_for(solidity_type: &str) -> Option<ParamKind> {
    match solidity_type {
        "address" => Some(ParamKind::Address),
        "bool" => Some(ParamKind::Bool),
        "bytes32" => Some(ParamKind::Bytes32),
        t if t.starts_with("uint") => Some(ParamKind::Uint256),
        // Signed integers, dynamic bytes/string/arrays, tuples, and
        // fixed-size arrays aren't supported by the static-word encoder in
        // truent-dynamic-core yet; functions using them are skipped rather
        // than mis-encoded.
        _ => None,
    }
}

/// Parses one contract's ABI JSON array (solc's `abi` field, already
/// decoded to a `serde_json::Value`) into [`FunctionSpec`]s. Functions with
/// any unsupported parameter type are silently dropped — the fuzzer will
/// simply never call them, which is strictly safer than mis-encoding their
/// arguments.
pub fn parse_abi(abi: &serde_json::Value) -> Vec<FunctionSpec> {
    let Some(entries) = abi.as_array() else {
        return Vec::new();
    };

    let mut functions = Vec::new();
    for entry in entries {
        if entry.get("type").and_then(|t| t.as_str()) != Some("function") {
            continue;
        }
        let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let inputs_json = entry
            .get("inputs")
            .and_then(|i| i.as_array())
            .cloned()
            .unwrap_or_default();

        let solidity_types: Vec<String> = inputs_json
            .iter()
            .filter_map(|i| i.get("type").and_then(|t| t.as_str()).map(String::from))
            .collect();
        if solidity_types.len() != inputs_json.len() {
            continue; // malformed ABI entry, skip rather than guess
        }

        let mut param_kinds = Vec::with_capacity(solidity_types.len());
        let mut supported = true;
        for t in &solidity_types {
            match param_kind_for(t) {
                Some(k) => param_kinds.push(k),
                None => {
                    supported = false;
                    break;
                }
            }
        }
        if !supported {
            continue;
        }

        let state_mutability = entry
            .get("stateMutability")
            .and_then(|s| s.as_str())
            .unwrap_or("nonpayable");
        let mutates_state = !matches!(state_mutability, "view" | "pure");
        let payable = state_mutability == "payable";

        let type_refs: Vec<&str> = solidity_types.iter().map(String::as_str).collect();
        let selector = selector_for(name, &type_refs);

        functions.push(FunctionSpec {
            name: name.to_string(),
            selector,
            inputs: param_kinds,
            mutates_state,
            payable,
        });
    }
    functions
}

/// Decodes solc's `bin` field (creation bytecode as a hex string, with or
/// without a `0x` prefix) into raw bytes.
pub fn parse_bytecode(bin: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = bin.strip_prefix("0x").unwrap_or(bin);
    if trimmed.is_empty() {
        anyhow::bail!("empty bytecode — is this an interface/abstract contract?");
    }
    hex::decode(trimmed).map_err(|e| anyhow::anyhow!("invalid hex in solc bytecode output: {e}"))
}

/// Extracts a [`CompiledContract`] from one entry of `SolcOutput::contracts`
/// (keyed by `"path.sol:ContractName"`). solc's `--combined-json` output
/// represents `abi` either as a nested JSON array or as a JSON-encoded
/// string depending on version — both are handled here.
pub fn compiled_contract_from_solc_entry(
    entry: &serde_json::Value,
) -> anyhow::Result<CompiledContract> {
    let abi_value = entry
        .get("abi")
        .ok_or_else(|| anyhow::anyhow!("solc output missing 'abi' field"))?;
    let abi = match abi_value {
        serde_json::Value::String(s) => serde_json::from_str(s)
            .map_err(|e| anyhow::anyhow!("failed to parse ABI string: {e}"))?,
        other => other.clone(),
    };

    let bin = entry
        .get("bin")
        .and_then(|b| b.as_str())
        .ok_or_else(|| anyhow::anyhow!("solc output missing 'bin' field"))?;

    let constructor_inputs = abi
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("constructor"))
        })
        .and_then(|c| c.get("inputs").and_then(|i| i.as_array()).map(|i| i.len()))
        .unwrap_or(0);

    Ok(CompiledContract {
        init_code: parse_bytecode(bin)?,
        functions: parse_abi(&abi),
        constructor_inputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-written ABI JSON mirroring solc's `--combined-json abi,bin`
    /// shape for a minimal ERC20-like contract, since no solc binary was
    /// available to generate a real sample.
    const SAMPLE_ABI: &str = r#"[
        {"type":"function","name":"totalSupply","inputs":[],"stateMutability":"view"},
        {"type":"function","name":"balanceOf","inputs":[{"type":"address"}],"stateMutability":"view"},
        {"type":"function","name":"transfer","inputs":[{"type":"address"},{"type":"uint256"}],"stateMutability":"nonpayable"},
        {"type":"function","name":"deposit","inputs":[],"stateMutability":"payable"},
        {"type":"event","name":"Transfer","inputs":[]},
        {"type":"function","name":"unsupported","inputs":[{"type":"bytes"}],"stateMutability":"nonpayable"}
    ]"#;

    #[test]
    fn selector_matches_known_weth9_constants() {
        // deposit() and withdraw(uint256) selectors are well-known,
        // independently verifiable constants (WETH9) — a solid check that
        // the keccak256 signature hashing here is correct without needing
        // a live solc/node to cross-check against.
        assert_eq!(selector_for("deposit", &[]), [0xd0, 0xe3, 0x0d, 0xb0]);
        assert_eq!(
            selector_for("withdraw", &["uint256"]),
            [0x2e, 0x1a, 0x7d, 0x4d]
        );
    }

    #[test]
    fn parses_functions_and_skips_events_and_unsupported_types() {
        let abi: serde_json::Value = serde_json::from_str(SAMPLE_ABI).unwrap();
        let functions = parse_abi(&abi);
        let names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();

        assert!(names.contains(&"totalSupply"));
        assert!(names.contains(&"balanceOf"));
        assert!(names.contains(&"transfer"));
        assert!(names.contains(&"deposit"));
        assert!(
            !names.contains(&"Transfer"),
            "events must not be parsed as callable functions"
        );
        assert!(
            !names.contains(&"unsupported"),
            "functions with unsupported param types must be skipped, not mis-encoded"
        );
    }

    #[test]
    fn view_and_payable_mutability_is_captured_correctly() {
        let abi: serde_json::Value = serde_json::from_str(SAMPLE_ABI).unwrap();
        let functions = parse_abi(&abi);

        let total_supply = functions.iter().find(|f| f.name == "totalSupply").unwrap();
        assert!(
            !total_supply.mutates_state,
            "view functions must not be treated as mutators"
        );

        let transfer = functions.iter().find(|f| f.name == "transfer").unwrap();
        assert!(transfer.mutates_state);
        assert!(!transfer.payable);

        let deposit = functions.iter().find(|f| f.name == "deposit").unwrap();
        assert!(deposit.mutates_state);
        assert!(deposit.payable);
    }

    #[test]
    fn parse_bytecode_handles_0x_prefix_and_rejects_empty() {
        assert_eq!(
            parse_bytecode("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            parse_bytecode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(parse_bytecode("").is_err());
    }

    #[test]
    fn compiled_contract_from_solc_entry_handles_string_encoded_abi() {
        let entry = serde_json::json!({
            "abi": SAMPLE_ABI,
            "bin": "0x600160005260206000f3",
        });
        let contract = compiled_contract_from_solc_entry(&entry).unwrap();
        assert!(!contract.functions.is_empty());
        assert!(!contract.init_code.is_empty());
    }
}
