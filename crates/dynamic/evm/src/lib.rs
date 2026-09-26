#![deny(unsafe_code)]
#![allow(missing_docs)]

//! revm-backed dynamic invariant fuzzing for EVM/Solidity contracts.
//!
//! Ties three things together: `truent_utils::SolcManager` (compiles
//! source, already existed), `solc_bridge` (turns its ABI/bytecode output
//! into the chain-agnostic shapes `truent-dynamic-core` understands), and
//! `backend::RevmBackend` (executes calls against real EVM bytecode via
//! `revm`, gated behind the `revm-backend` feature — see that module's doc
//! comment for why it's split out and what's unverified about it).

#[cfg(feature = "revm-backend")]
pub mod backend;
pub mod dsl_invariant;
#[cfg(feature = "revm-backend")]
pub mod reentrancy_inspector;
pub mod rpc;
pub mod solc_bridge;
pub mod types;
pub mod well_known_selectors;

pub use types::CompiledContract;

#[cfg(feature = "revm-backend")]
use truent_dynamic_core::{fuzz, FuzzConfig, Violation};
use truent_dynamic_core::{FunctionSpec, Invariant};

/// Auto-detects standard invariants from a contract's function surface:
/// currently, ERC20-shaped conservation (`totalSupply()` + `balanceOf(address)`
/// both present) and monotonicity for no-argument view functions that are
/// genuinely one-way (cumulative totals, checkpoints, nonces, counters).
/// Deliberately excludes `totalSupply`/`totalAssets`/`sharePrice`, which
/// decrease in normal operation whenever anyone burns, withdraws or the pool
/// takes a loss.
/// Returns an empty list if nothing recognizable is present — dynamic
/// fuzzing without an oracle can't find anything, so callers should treat
/// an empty result as "nothing to check yet", not "contract is safe".
///
/// Pure data in, data out — doesn't touch `revm`, so unlike the rest of
/// this crate it's built and tested unconditionally (see the tests module
/// below), not gated behind the `revm-backend` feature.
pub fn auto_detect_invariants(
    functions: &[FunctionSpec],
    actors: &[[u8; 20]],
) -> Vec<Box<dyn Invariant>> {
    use truent_dynamic_core::{
        AccessControlInvariant, ConservationInvariant, MonotonicInvariant, ParamKind,
    };

    let mut invariants: Vec<Box<dyn Invariant>> = Vec::new();

    let total_supply = functions
        .iter()
        .find(|f| f.name == "totalSupply" && f.inputs.is_empty());
    let balance_of = functions
        .iter()
        .find(|f| f.name == "balanceOf" && f.inputs.len() == 1);
    if let (Some(ts), Some(bo)) = (total_supply, balance_of) {
        invariants.push(Box::new(ConservationInvariant::new(
            "ERC20 conservation: sum(balanceOf) == totalSupply()",
            ts.clone(),
            bo.clone(),
            actors.to_vec(),
        )));
    }

    // OpenZeppelin-Ownable-shaped: owner() view + a single-address mutating
    // setter conventionally named transferOwnership. Every real-world
    // Ownable clone uses that exact selector, so matching on the name
    // (rather than trying to infer "this is the privileged setter" from
    // shape alone, which would be far too broad) keeps false positives
    // near zero while still catching the single most common real
    // access-control bug: a transferOwnership that forgot onlyOwner.
    let owner_fn = functions
        .iter()
        .find(|f| f.name == "owner" && f.inputs.is_empty());
    let transfer_ownership_fn = functions
        .iter()
        .find(|f| f.name == "transferOwnership" && f.inputs == vec![ParamKind::Address]);
    if let (Some(owner_fn), Some(transfer_fn)) = (owner_fn, transfer_ownership_fn) {
        invariants.push(Box::new(AccessControlInvariant::new(
            "transferOwnership authorization",
            owner_fn.clone(),
            transfer_fn.clone(),
        )));
    }

    // Accumulators that only ever go up.
    //
    // `totalSupply`, `totalAssets`, `exchangeRate`, `sharePrice` and
    // `totalDeposits` used to be on this list, and none of them are monotonic:
    // burning reduces supply, withdrawing reduces assets, and a share price
    // falls whenever the pool takes a loss. Asserting monotonicity there
    // reports the contract working correctly as a violation — observed on an
    // ordinary vault, where a plain `withdraw` "failed" the check.
    //
    // What is left is genuinely one-way: counters, nonces and cumulative
    // totals that record history rather than current holdings.
    const MONOTONIC_NAME_HINTS: &[&str] = &[
        "cumulative",
        "checkpoint",
        "nonce",
        "counter",
        "totalminted",
        "totalclaimed",
        "totaldistributed",
        "lastupdated",
    ];

    // Even a well-named accumulator is not monotonic if the contract exposes a
    // way to wind it back. A `reset`, `slash` or `sweep` makes the assumption
    // unsafe, so the property is not asserted at all rather than asserted
    // wrongly.
    const DECREASING_PATHS: &[&str] = &["reset", "slash", "sweep", "clear", "rollback", "decrease"];
    let has_decreasing_path = functions.iter().any(|f| {
        let lower = f.name.to_lowercase();
        f.mutates_state && DECREASING_PATHS.iter().any(|p| lower.contains(p))
    });

    if !has_decreasing_path {
        for f in functions {
            if f.mutates_state || !f.inputs.is_empty() {
                continue;
            }
            let lower = f.name.to_lowercase();
            if MONOTONIC_NAME_HINTS.iter().any(|hint| lower.contains(hint)) {
                invariants.push(Box::new(MonotonicInvariant::new(
                    format!("{} monotonicity", f.name),
                    f.clone(),
                )));
            }
        }
    }

    invariants
}

/// Compiles `source` with `solc`, auto-detects invariants from its ABI, and
/// runs the dynamic fuzzer against it. Returns `Ok(None)` if no violation
/// was found within the configured search budget, `Ok(Some(violation))`
/// with a minimal reproduction if one was, and `Err` for compilation
/// failures.
#[cfg(feature = "revm-backend")]
pub fn fuzz_solidity_source(source: &str, config: FuzzConfig) -> anyhow::Result<Option<Violation>> {
    fuzz_solidity_source_with(source, config, &[])
}

/// As [`fuzz_solidity_source`], plus user-written DSL properties.
///
/// Auto-detection can only recognise shapes it already knows. The properties
/// that decide whether a specific protocol is correct — is it solvent, can a
/// provider always exit — are particular to that protocol, so they have to be
/// stated rather than inferred. Each spec is bound to the contract's getters
/// before the run; a property that cannot be bound is an error, because
/// quietly dropping it would report "no violations" for a check that never
/// ran.
#[cfg(feature = "revm-backend")]
pub fn fuzz_solidity_source_with(
    source: &str,
    config: FuzzConfig,
    dsl_specs: &[truent_core::model::Invariant],
) -> anyhow::Result<Option<Violation>> {
    let solc = truent_utils::SolcManager::new()?;
    let output = solc.get_ast_for_source(source, "fuzz_target.sol")?;

    let Some((_, contract_json)) = output.contracts.iter().find(|(_, v)| {
        v.get("bin")
            .and_then(|b| b.as_str())
            .map(|b| !b.trim_start_matches("0x").is_empty())
            .unwrap_or(false)
    }) else {
        anyhow::bail!("no deployable contract found in source (no non-empty bytecode — is this an interface/abstract contract?)");
    };

    let contract = solc_bridge::compiled_contract_from_solc_entry(contract_json)?;
    if contract.functions.is_empty() {
        anyhow::bail!("compiled successfully but no callable functions with supported argument types were found");
    }

    let mut invariants = auto_detect_invariants(&contract.functions, &config.actors);

    // User-stated properties. Bind them all before running so a typo surfaces
    // immediately rather than as a silently missing check.
    let mut bind_errors = Vec::new();
    for spec in dsl_specs {
        match dsl_invariant::DslInvariant::bind(spec, &contract.functions) {
            Ok(bound) => invariants.push(Box::new(bound)),
            Err(e) => bind_errors.push(e.to_string()),
        }
    }
    if !bind_errors.is_empty() {
        anyhow::bail!(
            "{} invariant(s) could not be bound to this contract:\n\n{}",
            bind_errors.len(),
            bind_errors.join("\n\n")
        );
    }

    if invariants.is_empty() {
        anyhow::bail!(
            "no auto-detectable invariant on this ABI (looked for ERC20-shaped totalSupply/balanceOf, or monotonic accumulator getters) and no --invariants file supplied — nothing to check"
        );
    }

    // `backend_factory` borrows `actors` for as long as the returned
    // closure lives; `config` is about to be moved into `fuzz` below, so
    // the factory needs its own copy rather than borrowing config.actors
    // directly (a borrow of config.actors can't outlive config itself
    // being consumed in the very same call).
    let actors = config.actors.clone();

    // Prove the contract deploys before handing it to the search loop. The
    // factory redeploys it on every attempt and treats a failure as an
    // engine bug (it panics); a constructor that needs arguments is not an
    // engine bug, it is a contract this fuzzer cannot deploy on its own, and
    // the caller should be told that in words.
    let deployer = actors.first().copied().unwrap_or([0xAAu8; 20]);
    if let Err(e) = backend::RevmBackend::deploy(contract.init_code.clone(), deployer) {
        let hint = if contract.constructor_inputs > 0 {
            format!(
                "\n\nThe constructor takes {} argument(s) and the fuzzer deploys with none. \
                 Wrap the contract in one with a no-argument constructor that calls the real \
                 one with concrete values, and fuzz the wrapper.",
                contract.constructor_inputs
            )
        } else {
            String::new()
        };
        anyhow::bail!("could not deploy the contract in the in-memory EVM: {e}{hint}");
    }

    let factory = backend::backend_factory(&contract, &actors);
    Ok(fuzz(factory, &contract.functions, invariants, config))
}

/// Probes already-deployed runtime bytecode (no ABI available — the common
/// case for an unverified contract, a realistic real-world bug-bounty
/// target) against a fixed list of well-known ERC20/Ownable selectors,
/// keeping only the ones that don't revert. The same "read as proxy"
/// technique block explorers use for unverified contracts. Not a complete
/// function-discovery mechanism — it only knows about the selectors it's
/// told to try — but enough to drive [`auto_detect_invariants`] against a
/// contract with zero source available.
#[cfg(feature = "revm-backend")]
pub fn probe_deployed_contract(bytecode: Vec<u8>, contract_address: [u8; 20]) -> Vec<FunctionSpec> {
    use truent_dynamic_core::EncodedCall;
    use well_known_selectors::{
        erc20_mutator_functions, erc20_probe_functions, ownable_mutator_functions,
        ownable_probe_functions,
    };

    fn all_probes_succeed(
        backend: &mut dyn truent_dynamic_core::ExecutionBackend,
        caller: [u8; 20],
        fns: &[FunctionSpec],
    ) -> bool {
        fns.iter().all(|f| {
            let mut calldata = f.selector.to_vec();
            // Zero-fill one 32-byte word per argument (probing with default
            // args; we only care whether the selector exists, i.e. doesn't
            // revert on an unknown-function dispatch).
            calldata.resize(4 + 32 * f.inputs.len(), 0u8);
            let outcome = backend.call(&EncodedCall {
                function: f.clone(),
                calldata,
                caller,
                value: 0,
            });
            !outcome.reverted
        })
    }

    let mut backend = backend::RevmBackend::from_runtime_bytecode(bytecode, contract_address);
    let probe_caller = [0xEEu8; 20];
    let mut confirmed = Vec::new();

    let erc20_read = erc20_probe_functions();
    if all_probes_succeed(&mut backend, probe_caller, &erc20_read) {
        confirmed.extend(erc20_read);
        confirmed.extend(erc20_mutator_functions());
    }

    let ownable_read = ownable_probe_functions();
    if all_probes_succeed(&mut backend, probe_caller, &ownable_read) {
        confirmed.extend(ownable_read);
        confirmed.extend(ownable_mutator_functions());
    }

    confirmed
}

/// Fetches deployed bytecode from `rpc_url` for `contract_address`, probes
/// it against known selectors (see [`probe_deployed_contract`]),
/// auto-detects invariants from whatever's confirmed present, and runs the
/// dynamic fuzzer against it — the no-source-available counterpart to
/// [`fuzz_solidity_source`].
///
/// This does **not** fork the contract's real on-chain storage — only its
/// code is fetched and deployed into an otherwise-empty account. That's
/// enough to exercise bugs in the contract's own accounting logic (exactly
/// what `ConservationInvariant`/`AccessControlInvariant` check), but any
/// behavior depending on pre-existing on-chain storage (existing balances,
/// addresses of other contracts read from storage, etc.) won't be
/// reproduced faithfully. Full state forking is a larger feature this
/// intentionally doesn't attempt yet.
#[cfg(feature = "revm-backend")]
pub fn fuzz_deployed_contract(
    rpc_url: &str,
    contract_address: [u8; 20],
    config: FuzzConfig,
) -> anyhow::Result<Option<Violation>> {
    let bytecode = crate::rpc::fetch_bytecode(rpc_url, contract_address)?;
    if bytecode.is_empty() {
        anyhow::bail!("no code deployed at this address (per eth_getCode) — nothing to fuzz");
    }

    let functions = probe_deployed_contract(bytecode.clone(), contract_address);
    if functions.is_empty() {
        anyhow::bail!(
            "deployed bytecode didn't respond successfully to any known ERC20/Ownable probe selectors — no auto-detectable surface to fuzz"
        );
    }

    let invariants = auto_detect_invariants(&functions, &config.actors);
    if invariants.is_empty() {
        anyhow::bail!("probed functions present, but no auto-detectable invariant on this surface");
    }

    let actors = config.actors.clone();
    let fresh_backend = move || -> Box<dyn truent_dynamic_core::ExecutionBackend> {
        let mut backend =
            backend::RevmBackend::from_runtime_bytecode(bytecode.clone(), contract_address);
        backend.fund_actors(&actors);
        Box::new(backend)
    };

    Ok(fuzz(fresh_backend, &functions, invariants, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use truent_dynamic_core::ParamKind;

    fn view_fn(name: &str, inputs: Vec<ParamKind>) -> FunctionSpec {
        FunctionSpec::new(name, [0u8; 4], inputs, false)
    }

    #[test]
    fn detects_erc20_conservation_when_both_functions_present() {
        let functions = vec![
            view_fn("totalSupply", vec![]),
            view_fn("balanceOf", vec![ParamKind::Address]),
        ];
        let invariants = auto_detect_invariants(&functions, &[[1u8; 20]]);
        assert!(invariants.iter().any(|i| i.name().contains("conservation")));
    }

    #[test]
    fn skips_conservation_when_only_one_of_the_pair_is_present() {
        let functions = vec![view_fn("totalSupply", vec![])];
        let invariants = auto_detect_invariants(&functions, &[[1u8; 20]]);
        assert!(!invariants.iter().any(|i| i.name().contains("conservation")));
    }

    #[test]
    fn detects_monotonic_hints_case_insensitively() {
        let functions = vec![view_fn("CumulativeRewards", vec![])];
        let invariants = auto_detect_invariants(&functions, &[]);
        assert!(invariants.iter().any(|i| i.name().contains("monotonicity")));
    }

    /// A balance-like total is not monotonic: burning, withdrawing or a loss
    /// all reduce it in correct operation. Asserting otherwise reported an
    /// ordinary vault `withdraw` as a violation.
    #[test]
    fn balance_like_totals_are_not_treated_as_monotonic() {
        for name in [
            "totalSupply",
            "totalAssets",
            "sharePrice",
            "exchangeRate",
            "totalDeposits",
        ] {
            let functions = vec![view_fn(name, vec![])];
            let invariants = auto_detect_invariants(&functions, &[]);
            assert!(
                !invariants.iter().any(|i| i.name().contains("monotonicity")),
                "{name} decreases in normal operation and must not be asserted monotonic"
            );
        }
    }

    /// Even a real accumulator is not monotonic if the contract can wind it
    /// back.
    #[test]
    fn an_accumulator_with_a_reset_path_is_not_asserted_monotonic() {
        let functions = vec![
            view_fn("cumulativeFees", vec![]),
            FunctionSpec::new("resetFees", [0u8; 4], vec![], true),
        ];
        let invariants = auto_detect_invariants(&functions, &[]);
        assert!(
            !invariants.iter().any(|i| i.name().contains("monotonicity")),
            "a reset path makes monotonicity unsafe to assume"
        );
    }

    #[test]
    fn ignores_mutating_functions_and_functions_with_arguments_for_monotonic_hints() {
        let functions = vec![
            FunctionSpec::new("cumulativeFees", [0u8; 4], vec![], true), // mutates -> not a getter
            view_fn("checkpointFor", vec![ParamKind::Address]), // takes args -> not a plain accumulator getter
        ];
        let invariants = auto_detect_invariants(&functions, &[]);
        assert!(invariants.is_empty());
    }

    #[test]
    fn returns_empty_on_unrecognized_abi() {
        let functions = vec![view_fn("frobnicate", vec![])];
        assert!(auto_detect_invariants(&functions, &[]).is_empty());
    }

    #[test]
    fn detects_ownable_access_control_when_both_functions_present() {
        let functions = vec![
            view_fn("owner", vec![]),
            FunctionSpec::new(
                "transferOwnership",
                [0u8; 4],
                vec![ParamKind::Address],
                true,
            ),
        ];
        let invariants = auto_detect_invariants(&functions, &[]);
        assert!(invariants
            .iter()
            .any(|i| i.name().contains("transferOwnership authorization")));
    }

    #[test]
    fn skips_access_control_when_transfer_ownership_takes_the_wrong_args() {
        // A same-named function with a different signature (e.g. a
        // two-step transferOwnership(address,bool) variant) shouldn't be
        // matched — the invariant's caller-comparison logic specifically
        // assumes a single address argument.
        let functions = vec![
            view_fn("owner", vec![]),
            FunctionSpec::new(
                "transferOwnership",
                [0u8; 4],
                vec![ParamKind::Address, ParamKind::Bool],
                true,
            ),
        ];
        assert!(auto_detect_invariants(&functions, &[]).is_empty());
    }

    #[test]
    fn skips_access_control_when_only_owner_is_present() {
        let functions = vec![view_fn("owner", vec![])];
        assert!(auto_detect_invariants(&functions, &[]).is_empty());
    }
}

/// The one thing none of the offline tests elsewhere in this workspace can
/// prove: that the *real* revm/solc pipeline — actual compiled bytecode,
/// actual EVM execution — catches a real bug, not just that it type-checks
/// (see this module's doc comment history for why that was previously the
/// open question). Needs solc, auto-downloaded by `SolcManager` if not
/// already present, and therefore network; skips rather than fails if
/// that's unavailable, matching `truent-analyzer-evm`'s existing
/// solc-unavailable fallback convention rather than introducing a new one.
#[cfg(all(test, feature = "revm-backend"))]
mod revm_integration_tests {
    use super::*;

    /// Deliberately vulnerable: `airdrop` credits a recipient's balance
    /// without minting the corresponding supply, breaking
    /// `sum(balanceOf) == totalSupply()` — the same "value created out of
    /// thin air" bug shape as `truent_dynamic_core`'s MockBackend proof,
    /// but here as real Solidity compiled to real bytecode.
    const VULNERABLE_TOKEN_SOURCE: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function airdrop(address to, uint256 amount) public {
        balanceOf[to] += amount;
    }
}
"#;

    #[test]
    fn revm_backend_catches_a_real_conservation_bug_end_to_end() {
        if truent_utils::SolcManager::new().is_err() {
            eprintln!("skipping revm_backend_catches_a_real_conservation_bug_end_to_end: solc unavailable in this environment");
            return;
        }

        let config = FuzzConfig {
            seed: 1,
            max_runs: 300,
            sequence_depth: 10,
            actors: vec![[1u8; 20], [2u8; 20], [3u8; 20]],
        };

        let violation = match fuzz_solidity_source(VULNERABLE_TOKEN_SOURCE, config) {
            Ok(Some(v)) => v,
            Ok(None) => panic!(
                "fuzzer ran to completion without finding VulnerableToken's known conservation bug"
            ),
            Err(e) => panic!("fuzz_solidity_source failed unexpectedly: {e:#}"),
        };

        assert_eq!(
            violation.invariant_name,
            "ERC20 conservation: sum(balanceOf) == totalSupply()"
        );
        assert!(!violation.sequence.is_empty());
    }

    /// Deliberately vulnerable: `transferOwnership` is missing its
    /// `onlyOwner` check — the single most common real-world access-control
    /// bug shape, and the exact thing a forgotten modifier looks like in
    /// production code.
    const VULNERABLE_OWNABLE_SOURCE: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableOwnable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) public {
        owner = newOwner;
    }
}
"#;

    #[test]
    fn revm_backend_catches_a_real_missing_only_owner_bug_end_to_end() {
        if truent_utils::SolcManager::new().is_err() {
            eprintln!("skipping revm_backend_catches_a_real_missing_only_owner_bug_end_to_end: solc unavailable in this environment");
            return;
        }

        let config = FuzzConfig {
            seed: 2,
            max_runs: 200,
            sequence_depth: 4,
            actors: vec![[1u8; 20], [2u8; 20], [3u8; 20]],
        };

        let violation = match fuzz_solidity_source(VULNERABLE_OWNABLE_SOURCE, config) {
            Ok(Some(v)) => v,
            Ok(None) => panic!(
                "fuzzer ran to completion without finding VulnerableOwnable's known missing-onlyOwner bug"
            ),
            Err(e) => panic!("fuzz_solidity_source failed unexpectedly: {e:#}"),
        };

        assert_eq!(violation.invariant_name, "transferOwnership authorization");
        assert!(!violation.sequence.is_empty());
    }

    /// A classic reentrancy pair: `VulnerableBank.withdraw` sends ETH to the
    /// caller *before* zeroing their balance (a checks-effects-interactions
    /// violation), and `Attacker.receive` re-enters `withdraw` to drain more
    /// than it deposited. Real Solidity, compiled and executed — this is the
    /// proof that the `ReentrancyInspector` produces correct traces from
    /// live EVM execution and that `detect_reentrancy` flags them.
    const REENTRANCY_SOURCE: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balanceOf[msg.sender] = 0; // effect after interaction: the bug
    }
}

contract Attacker {
    VulnerableBank public bank;
    uint256 public reenters;

    constructor(address payable b) {
        bank = VulnerableBank(b);
    }

    function attack() external payable {
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }

    receive() external payable {
        if (reenters < 1) {
            reenters++;
            bank.withdraw();
        }
    }
}
"#;

    /// Pulls one named contract's creation bytecode out of solc's
    /// combined-json output (which keys entries as `"path.sol:Name"`).
    fn init_code_for(output: &truent_utils::SolcOutput, name: &str) -> Vec<u8> {
        let suffix = format!(":{name}");
        let entry = output
            .contracts
            .iter()
            .find(|(k, _)| k.ends_with(&suffix))
            .unwrap_or_else(|| panic!("contract {name} not found in solc output"))
            .1;
        solc_bridge::compiled_contract_from_solc_entry(entry)
            .expect("named contract should have parseable bytecode")
            .init_code
    }

    #[test]
    fn revm_backend_catches_real_reentrancy_end_to_end() {
        use crate::backend::RevmBackend;
        // ExecutionBackend brings the `last_call_trace` trait method into scope.
        use truent_dynamic_core::{detect_reentrancy, ExecutionBackend};

        let Ok(solc) = truent_utils::SolcManager::new() else {
            eprintln!("skipping revm_backend_catches_real_reentrancy_end_to_end: solc unavailable in this environment");
            return;
        };
        let output = solc
            .get_ast_for_source(REENTRANCY_SOURCE, "reentrancy.sol")
            .expect("reentrancy source should compile");

        let bank_init = init_code_for(&output, "VulnerableBank");
        let attacker_init = init_code_for(&output, "Attacker");

        // Deploy the bank as the primary contract.
        let deployer = [0xAAu8; 20];
        let mut backend =
            RevmBackend::deploy(bank_init, deployer).expect("bank deployment should succeed");
        let bank_addr = backend.contract_address();

        // Deploy the attacker into the same state, passing the bank address
        // as its constructor argument (ABI-encoded: left-padded to 32 bytes).
        let mut attacker_init_with_arg = attacker_init;
        let mut arg_word = [0u8; 32];
        arg_word[12..32].copy_from_slice(&bank_addr);
        attacker_init_with_arg.extend_from_slice(&arg_word);
        let attacker_addr = backend
            .deploy_secondary(attacker_init_with_arg, deployer)
            .expect("attacker deployment should succeed");

        // Fund an EOA to originate the attack transaction.
        let eoa = [0x11u8; 20];
        backend.fund_actors(&[eoa]);

        // Seed the bank with other depositors' ETH. A reentrancy drain takes
        // *someone else's* money: with only the attacker's own deposit in the
        // pool, the re-entrant withdraw finds an empty contract, the inner
        // `send failed` require trips, and the whole attack reverts — so there
        // is nothing to detect.
        backend.credit(bank_addr, revm::primitives::U256::from(10_000_000u128));

        // attack() is payable: the value funds the initial deposit that the
        // attacker then re-entrantly over-withdraws.
        let attack_selector = solc_bridge::selector_for("attack", &[]);
        let outcome =
            backend.call_address(attacker_addr, attack_selector.to_vec(), eoa, 1_000_000u128);
        assert!(
            !outcome.reverted,
            "the attack transaction itself should succeed (that's what makes it an exploit)"
        );

        let report = detect_reentrancy(backend.last_call_trace())
            .expect("the inspector trace of a real reentrancy attack must be flagged");
        assert_eq!(
            report.address, bank_addr,
            "the re-entered contract should be identified as the bank"
        );
    }
}
