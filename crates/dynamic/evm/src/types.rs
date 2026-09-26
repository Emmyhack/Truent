//! Plain data types shared between `solc_bridge` (always compiled) and
//! `backend` (compiled only with the `revm-backend` feature). Kept
//! dependency-free on purpose so the solc/ABI parsing logic can be built
//! and tested in environments without `revm` available.

use truent_dynamic_core::FunctionSpec;

/// Everything needed to run the dynamic fuzzer against a single Solidity
/// contract: its creation bytecode and the callable surface derived from
/// its ABI.
pub struct CompiledContract {
    pub init_code: Vec<u8>,
    pub functions: Vec<FunctionSpec>,
    /// Number of constructor parameters in the ABI. The fuzzer deploys with
    /// no arguments, so a non-zero count is the usual reason a deployment
    /// reverts — worth naming in the error instead of guessing.
    pub constructor_inputs: usize,
}
