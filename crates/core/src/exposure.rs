//! Exposure: how exploitable a finding is, and how to close it.
//!
//! Truent will not exploit anything. What it can do honestly is answer two
//! questions about every finding without sending a payload:
//!
//! 1. **How possible is it?** Each detector carries a static attack profile —
//!    where the attacker must stand ([`Vector`]), what they must already have
//!    ([`Prereq`]), whether a victim must act ([`Interaction`]) and what
//!    success buys ([`Impact`]). Combined with the finding's evidence (a
//!    [`Finding::is_proven`] observation from the wire outranks a static
//!    lead) this gives an [`Exploitability`] rating with the reasons spelled
//!    out. It is a *profile*, not a demonstration: a `Likely` rating means
//!    "the shape of this bug is reachable from the network with nothing in
//!    hand", not "we ran it".
//! 2. **How is it prevented?** Every detector has a concrete `fix` and a
//!    `verify` step — the command or test that shows the fix landed.
//!
//! The table covers every row of [`crate::taxonomy`]; a test fails the build
//! if a detector is ever added without an exposure profile.

use crate::finding::Finding;

/// Where the attacker must be to reach the weakness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vector {
    /// Anyone who can reach the service / submit a transaction.
    Network,
    /// Same chain, mempool, network segment or on-path position.
    Adjacent,
    /// Repository, CI, or host access.
    Local,
}

/// What the attacker must already hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Prereq {
    None,
    /// A valid account or token holding.
    Authenticated,
    /// A specific state or configuration (a stale oracle, a fee-on-transfer token).
    Condition,
    /// A privileged role (admin, deployer, CI maintainer).
    Privileged,
}

/// Whether a victim must do something.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Interaction {
    None,
    Required,
}

/// What success buys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    /// Funds, code execution, credentials, or full control.
    Full,
    /// Integrity or availability of part of the system.
    Partial,
    /// Disclosure that aids a further attack.
    Information,
}

/// One detector's attack profile and remediation.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Exposure {
    pub invariant_id: &'static str,
    pub vector: Vector,
    pub prereq: Prereq,
    pub interaction: Interaction,
    pub impact: Impact,
    /// The change that closes the weakness.
    pub fix: &'static str,
    /// How to show the fix landed.
    pub verify: &'static str,
}

/// How possible exploitation is, for one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exploitability {
    /// Requires privileged access or an unusual condition; the finding is a
    /// hardening gap more than an attack path.
    Theoretical,
    /// Reachable, but needs a foothold, a condition, or a victim's action.
    Unlikely,
    /// Reachable from the network with a common precondition.
    Possible,
    /// Reachable from the network by anyone, with nothing in hand — or
    /// observed live.
    Likely,
}

impl Exploitability {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Likely => "LIKELY",
            Self::Possible => "POSSIBLE",
            Self::Unlikely => "UNLIKELY",
            Self::Theoretical => "THEORETICAL",
        }
    }
}

/// A rating with the reasons that produced it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Rating {
    pub exploitability: Exploitability,
    pub reasons: Vec<String>,
}

/// The exposure profile for a detector.
pub fn exposure_for(invariant_id: &str) -> Option<&'static Exposure> {
    EXPOSURE
        .binary_search_by_key(&invariant_id, |e| e.invariant_id)
        .ok()
        .map(|i| &EXPOSURE[i])
}

/// All profiles.
pub fn all() -> &'static [Exposure] {
    EXPOSURE
}

/// Rate a finding. Static profile first, then evidence: a proven observation
/// is by definition reachable from wherever the probe stood.
pub fn rate(f: &Finding) -> Option<Rating> {
    let e = exposure_for(&f.invariant_id)?;
    let mut score: i32 = match e.vector {
        Vector::Network => 3,
        Vector::Adjacent => 2,
        Vector::Local => 1,
    };
    let mut reasons = vec![match e.vector {
        Vector::Network => "reachable by anyone who can reach the service or submit a transaction",
        Vector::Adjacent => "requires an on-path, same-chain or mempool position",
        Vector::Local => "requires repository, CI or host access",
    }
    .to_string()];
    match e.prereq {
        Prereq::None => reasons.push("no account, token or role needed".into()),
        Prereq::Authenticated => {
            score -= 1;
            reasons.push("needs a valid account or token holding".into());
        }
        Prereq::Condition => {
            score -= 1;
            reasons.push("needs a specific state or configuration to be present".into());
        }
        Prereq::Privileged => {
            score -= 2;
            reasons.push("needs a privileged role — an insider or a compromised admin".into());
        }
    }
    if e.interaction == Interaction::Required {
        score -= 1;
        reasons.push("a victim must act (visit a page, click, or be on a hostile network)".into());
    }
    if f.is_proven() {
        score += 1;
        reasons.push("observed live by the probe, not inferred from text".into());
    }
    let exploitability = match score {
        s if s >= 3 => Exploitability::Likely,
        2 => Exploitability::Possible,
        1 => Exploitability::Unlikely,
        _ => Exploitability::Theoretical,
    };
    Some(Rating {
        exploitability,
        reasons,
    })
}

impl Finding {
    /// This finding's exposure profile, if its detector has one.
    pub fn exposure(&self) -> Option<&'static Exposure> {
        exposure_for(&self.invariant_id)
    }

    /// How possible exploitation is, with reasons.
    pub fn exploitability(&self) -> Option<Rating> {
        rate(self)
    }
}

/// **Sorted by `invariant_id`** — `exposure_for` binary-searches it.
static EXPOSURE: &[Exposure] = &[
    Exposure {
        invariant_id: "evm_aa_entropy_weakness",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Follow ERC-4337/EIP-7702 rules: no state side effects in validation, do not assume `msg.sender == tx.origin` means an EOA, derive salts from user-controlled and unique inputs.",
        verify: "Bundler simulation passes; tests cover delegated-EOA callers.",
    },
    Exposure {
        invariant_id: "evm_access_control",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Gate the function with an explicit role check (`onlyOwner`/AccessControl) tied to msg.sender, not tx.origin or a caller-supplied address.",
        verify: "Test: call from a non-privileged account and assert revert.",
    },
    Exposure {
        invariant_id: "evm_arbitrary_call_msg_value",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Do not forward `msg.value` in a call whose target or data the caller controls; separate payable entry points from generic call routers.",
        verify: "Test: router call with attacker-chosen target cannot move the contract's ETH.",
    },
    Exposure {
        invariant_id: "evm_arbitrary_function_selector_dispatch",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Never delegatecall or forward a caller-supplied target/selector; allowlist targets in storage set by an admin.",
        verify: "Test: arbitrary target/selector call from an unprivileged account reverts.",
    },
    Exposure {
        invariant_id: "evm_arithmetic_rounding",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Check divisors are non-zero before dividing; multiply before dividing and use fixed-point (WAD/RAY) math for ratios.",
        verify: "Test with zero and dust inputs; assert no revert path leaks and rounding favours the protocol.",
    },
    Exposure {
        invariant_id: "evm_bridge_address_cryptographic_verify",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Verify the remote sender against a registered trusted-remote mapping and check the message hash/signature before minting or releasing.",
        verify: "Test: message from an unregistered remote is rejected.",
    },
    Exposure {
        invariant_id: "evm_conservation_check_absent",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Assert protocol invariants (solvency, conservation, health factor) at the end of every state-changing function.",
        verify: "Invariant fuzz test with `truent fuzz` holds across random call sequences.",
    },
    Exposure {
        invariant_id: "evm_constructor_race_condition",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Set critical addresses in the constructor or in the deployment transaction; never leave an owner/admin settable by the first caller.",
        verify: "Deployment script asserts owner after deploy in the same transaction.",
    },
    Exposure {
        invariant_id: "evm_cross_chain_replay_missing_chainid",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Include nonce, chainId, contract address and deadline in the signed digest (EIP-712) and mark nonces used.",
        verify: "Test: replaying a used signature or a signature from another chain reverts.",
    },
    Exposure {
        invariant_id: "evm_delegatecall_injection",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Never delegatecall or forward a caller-supplied target/selector; allowlist targets in storage set by an admin.",
        verify: "Test: arbitrary target/selector call from an unprivileged account reverts.",
    },
    Exposure {
        invariant_id: "evm_division_by_zero",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Check divisors are non-zero before dividing; multiply before dividing and use fixed-point (WAD/RAY) math for ratios.",
        verify: "Test with zero and dust inputs; assert no revert path leaks and rounding favours the protocol.",
    },
    Exposure {
        invariant_id: "evm_dvn_single_point_failure",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require multiple independent verifiers/signers (threshold >= 2 of N, N >= 3) and hold admin keys in a multisig with a timelock.",
        verify: "Config review: threshold and signer set match policy; `truent scan` clean.",
    },
    Exposure {
        invariant_id: "evm_dvn_threshold",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require multiple independent verifiers/signers (threshold >= 2 of N, N >= 3) and hold admin keys in a multisig with a timelock.",
        verify: "Config review: threshold and signer set match policy; `truent scan` clean.",
    },
    Exposure {
        invariant_id: "evm_eip7702_eoa_assumption",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Follow ERC-4337/EIP-7702 rules: no state side effects in validation, do not assume `msg.sender == tx.origin` means an EOA, derive salts from user-controlled and unique inputs.",
        verify: "Bundler simulation passes; tests cover delegated-EOA callers.",
    },
    Exposure {
        invariant_id: "evm_erc4337_validation_side_effects",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Follow ERC-4337/EIP-7702 rules: no state side effects in validation, do not assume `msg.sender == tx.origin` means an EOA, derive salts from user-controlled and unique inputs.",
        verify: "Bundler simulation passes; tests cover delegated-EOA callers.",
    },
    Exposure {
        invariant_id: "evm_erc4626_inflation_protection",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Use virtual shares/assets offset (OpenZeppelin ERC4626 >=4.9) or seed the vault with a burned initial deposit.",
        verify: "Test: first-depositor donation attack yields no profit.",
    },
    Exposure {
        invariant_id: "evm_fee_on_transfer_incompatibility",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Credit the balance difference measured before and after `transferFrom`, not the requested amount.",
        verify: "Test with a mock fee-on-transfer token: credited amount equals received amount.",
    },
    Exposure {
        invariant_id: "evm_flash_loan_governance",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Use snapshot-based voting power (ERC20Votes, block-delayed checkpoints) so votes reflect balance at a past block.",
        verify: "Test: tokens acquired in the proposal block carry no voting power.",
    },
    Exposure {
        invariant_id: "evm_frontrunning",
        vector: Vector::Adjacent,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Require a caller-supplied `minAmountOut`/`deadline` and enforce them; consider commit-reveal for sensitive ordering.",
        verify: "Test: swap with minAmountOut above the achievable output reverts.",
    },
    Exposure {
        invariant_id: "evm_insufficient_multisig_threshold",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require multiple independent verifiers/signers (threshold >= 2 of N, N >= 3) and hold admin keys in a multisig with a timelock.",
        verify: "Config review: threshold and signer set match policy; `truent scan` clean.",
    },
    Exposure {
        invariant_id: "evm_integer_overflow",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Compile with Solidity >=0.8 (checked arithmetic) or wrap arithmetic in SafeMath; audit every `unchecked` block.",
        verify: "Fuzz test arithmetic paths with boundary values (0, max) and assert revert on overflow.",
    },
    Exposure {
        invariant_id: "evm_integer_underflow",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Compile with Solidity >=0.8 (checked arithmetic) or wrap arithmetic in SafeMath; audit every `unchecked` block.",
        verify: "Fuzz test arithmetic paths with boundary values (0, max) and assert revert on overflow.",
    },
    Exposure {
        invariant_id: "evm_legacy_unsafe_math",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Compile with Solidity >=0.8 (checked arithmetic) or wrap arithmetic in SafeMath; audit every `unchecked` block.",
        verify: "Fuzz test arithmetic paths with boundary values (0, max) and assert revert on overflow.",
    },
    Exposure {
        invariant_id: "evm_lst_depeg",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Value liquid-staking tokens by their exchange rate from the staking contract with a depeg circuit breaker, not 1:1 with the underlying.",
        verify: "Test: simulated 10% depeg triggers the breaker before undercollateralisation.",
    },
    Exposure {
        invariant_id: "evm_merkle_root_zero",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require a non-zero root at initialization and on every update; verify proofs with a non-empty leaf domain separator.",
        verify: "Test: initialization with root 0 reverts; empty proof against zero root fails.",
    },
    Exposure {
        invariant_id: "evm_merkle_root_zero_default",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require a non-zero root at initialization and on every update; verify proofs with a non-empty leaf domain separator.",
        verify: "Test: initialization with root 0 reverts; empty proof against zero root fails.",
    },
    Exposure {
        invariant_id: "evm_missing_pause_mechanism",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Add Pausable with whenNotPaused on value-moving functions; give pause to a multisig or guardian with a short path and unpause to governance.",
        verify: "Test: after pause(), deposit/withdraw/borrow revert; guardian can pause without a timelock.",
    },
    Exposure {
        invariant_id: "evm_missing_post_state_health_check",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Assert protocol invariants (solvency, conservation, health factor) at the end of every state-changing function.",
        verify: "Invariant fuzz test with `truent fuzz` holds across random call sequences.",
    },
    Exposure {
        invariant_id: "evm_missing_signer_check",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Gate the function with an explicit role check (`onlyOwner`/AccessControl) tied to msg.sender, not tx.origin or a caller-supplied address.",
        verify: "Test: call from a non-privileged account and assert revert.",
    },
    Exposure {
        invariant_id: "evm_oracle_self_trade",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Price from a manipulation-resistant source (Chainlink, TWAP over many blocks); never from `balanceOf`/reserves in the same transaction.",
        verify: "Test: flash-loan-driven swap in the same block does not change the price the contract uses.",
    },
    Exposure {
        invariant_id: "evm_oracle_spot_price",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Price from a manipulation-resistant source (Chainlink, TWAP over many blocks); never from `balanceOf`/reserves in the same transaction.",
        verify: "Test: flash-loan-driven swap in the same block does not change the price the contract uses.",
    },
    Exposure {
        invariant_id: "evm_precision_loss",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Check divisors are non-zero before dividing; multiply before dividing and use fixed-point (WAD/RAY) math for ratios.",
        verify: "Test with zero and dust inputs; assert no revert path leaks and rounding favours the protocol.",
    },
    Exposure {
        invariant_id: "evm_proxy_storage_collision",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Use ERC-1967 / unstructured storage slots for proxy state and OpenZeppelin upgradeable base contracts; run storage-layout diff before each upgrade.",
        verify: "`forge inspect <Contract> storage-layout` diff is empty between versions.",
    },
    Exposure {
        invariant_id: "evm_public_relay",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Restrict relay/execute entry points to authorized relayers or require the payload to be signed by the origin.",
        verify: "Test: unauthorized relayer call reverts.",
    },
    Exposure {
        invariant_id: "evm_push_payment_in_loop",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Record what each recipient is owed and let them withdraw (pull payment); never revert the batch on one failed transfer.",
        verify: "Test: a recipient that reverts does not block the others.",
    },
    Exposure {
        invariant_id: "evm_readonly_reentrancy",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Do not read pool/vault state (getters, price, totalSupply) during an external call; take a snapshot before the call or mark view functions with a reentrancy check.",
        verify: "Test: call the view function from a receiver during withdraw and assert it reverts or returns the pre-call value.",
    },
    Exposure {
        invariant_id: "evm_reentrancy_classic",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Apply checks-effects-interactions: update state before any external call, and guard entry points with a nonReentrant modifier (OpenZeppelin ReentrancyGuard).",
        verify: "Re-run `truent scan`; add a test that re-enters from a malicious receiver and asserts revert.",
    },
    Exposure {
        invariant_id: "evm_reentrancy_erc20",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Apply checks-effects-interactions: update state before any external call, and guard entry points with a nonReentrant modifier (OpenZeppelin ReentrancyGuard).",
        verify: "Re-run `truent scan`; add a test that re-enters from a malicious receiver and asserts revert.",
    },
    Exposure {
        invariant_id: "evm_reentrancy_protection",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Apply checks-effects-interactions: update state before any external call, and guard entry points with a nonReentrant modifier (OpenZeppelin ReentrancyGuard).",
        verify: "Re-run `truent scan`; add a test that re-enters from a malicious receiver and asserts revert.",
    },
    Exposure {
        invariant_id: "evm_reentrancy_via_whitelisted",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Apply checks-effects-interactions: update state before any external call, and guard entry points with a nonReentrant modifier (OpenZeppelin ReentrancyGuard).",
        verify: "Re-run `truent scan`; add a test that re-enters from a malicious receiver and asserts revert.",
    },
    Exposure {
        invariant_id: "evm_router_slippage_validation",
        vector: Vector::Adjacent,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Require a caller-supplied `minAmountOut`/`deadline` and enforce them; consider commit-reveal for sensitive ordering.",
        verify: "Test: swap with minAmountOut above the achievable output reverts.",
    },
    Exposure {
        invariant_id: "evm_shallow_auth",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Gate the function with an explicit role check (`onlyOwner`/AccessControl) tied to msg.sender, not tx.origin or a caller-supplied address.",
        verify: "Test: call from a non-privileged account and assert revert.",
    },
    Exposure {
        invariant_id: "evm_signature_replay_protection",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Include nonce, chainId, contract address and deadline in the signed digest (EIP-712) and mark nonces used.",
        verify: "Test: replaying a used signature or a signature from another chain reverts.",
    },
    Exposure {
        invariant_id: "evm_single_eoa_admin",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require multiple independent verifiers/signers (threshold >= 2 of N, N >= 3) and hold admin keys in a multisig with a timelock.",
        verify: "Config review: threshold and signer set match policy; `truent scan` clean.",
    },
    Exposure {
        invariant_id: "evm_stale_oracle_price",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Check `updatedAt` against a max staleness and `answer > 0` on every oracle read; revert or pause when stale.",
        verify: "Test: mocked stale round reverts.",
    },
    Exposure {
        invariant_id: "evm_state_mutation_ordering",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Assert protocol invariants (solvency, conservation, health factor) at the end of every state-changing function.",
        verify: "Invariant fuzz test with `truent fuzz` holds across random call sequences.",
    },
    Exposure {
        invariant_id: "evm_symbolic_counterexample",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Fix the property violation the counterexample demonstrates (the input is in the finding), add the input as a concrete regression test, and re-run `truent symbolic` until the check passes.",
        verify: "`truent symbolic` reports the check as passed and the regression test is green.",
    },
    Exposure {
        invariant_id: "evm_symbolic_unresolved",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Make the check decidable: raise the solver timeout, bound loops, loosen a setup that reverts every path, or split the property into smaller checks.",
        verify: "`truent symbolic` reports the check as passed or failed — not unresolved.",
    },
    Exposure {
        invariant_id: "evm_synthetic_collateral_oracle",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Price from a manipulation-resistant source (Chainlink, TWAP over many blocks); never from `balanceOf`/reserves in the same transaction.",
        verify: "Test: flash-loan-driven swap in the same block does not change the price the contract uses.",
    },
    Exposure {
        invariant_id: "evm_timestamp_dependence",
        vector: Vector::Adjacent,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Do not use `block.timestamp` as a source of randomness or for fine-grained (<15 min) decisions; use block numbers or a VRF.",
        verify: "Review: timestamp comparisons tolerate miner drift.",
    },
    Exposure {
        invariant_id: "evm_token_balance_manipulation",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Price from a manipulation-resistant source (Chainlink, TWAP over many blocks); never from `balanceOf`/reserves in the same transaction.",
        verify: "Test: flash-loan-driven swap in the same block does not change the price the contract uses.",
    },
    Exposure {
        invariant_id: "evm_unbacked_synthetic_mint",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Mint synthetic tokens only against verified collateral deposits in the same transaction; cap supply to backing.",
        verify: "Invariant: totalSupply <= backing at all times under `truent fuzz`.",
    },
    Exposure {
        invariant_id: "evm_unbounded_loop",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Bound the iteration (process in pages with a cursor) or restructure so per-user state is updated on demand instead of looping over all holders.",
        verify: "Test: the function completes at 10× the expected array length within the block gas limit.",
    },
    Exposure {
        invariant_id: "evm_unbounded_pricing_input",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Price from a manipulation-resistant source (Chainlink, TWAP over many blocks); never from `balanceOf`/reserves in the same transaction.",
        verify: "Test: flash-loan-driven swap in the same block does not change the price the contract uses.",
    },
    Exposure {
        invariant_id: "evm_unchecked_returns",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Check the boolean result of low-level calls and ERC-20 transfers, or use SafeERC20 / revert on failure.",
        verify: "Test with a token that returns false: the operation reverts.",
    },
    Exposure {
        invariant_id: "evm_uninitialized_pointers",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Declare storage structs/arrays explicitly with `storage` and initialize them; avoid uninitialized local storage pointers (pre-0.5 pattern).",
        verify: "Compile with a modern Solidity (>=0.5) where this is a compile error.",
    },
    Exposure {
        invariant_id: "evm_unprotected_initializer",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Add the `initializer` modifier, call `_disableInitializers()` in the implementation constructor, and initialize in the same transaction as deployment.",
        verify: "Test: second `initialize` call reverts; implementation contract cannot be initialized.",
    },
    Exposure {
        invariant_id: "evm_upgrade_path_verification",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Restrict `_authorizeUpgrade`/`upgradeTo` to an admin behind a timelock; validate the new implementation (ERC-1822 UUID / interface check).",
        verify: "Test: non-admin upgrade reverts; upgrade to a non-UUPS implementation reverts.",
    },
    Exposure {
        invariant_id: "evm_zero_challenge_period",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Enforce a non-zero challenge/withdrawal delay before finalizing optimistic messages or withdrawals.",
        verify: "Test: finalize before the delay elapses reverts.",
    },
    Exposure {
        invariant_id: "gen_ci_pwn_request",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Do not check out PR head code in `pull_request_target` workflows; use `pull_request` or split into an unprivileged job.",
        verify: "Workflow review: no `ref: ${{ github.event.pull_request.head.sha }}` under `pull_request_target`.",
    },
    Exposure {
        invariant_id: "gen_ci_script_injection",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Pass untrusted event fields (titles, branch names, bodies) through `env:` and quote them; never interpolate `${{ }}` directly in `run:`.",
        verify: "Workflow lint (actionlint) clean; `truent scan` clean.",
    },
    Exposure {
        invariant_id: "gen_ci_secret_exposed",
        vector: Vector::Local,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Never echo secrets or pass them to untrusted actions; use `::add-mask::` and least-privilege `permissions:`.",
        verify: "Workflow logs contain no secret values; scan clean.",
    },
    Exposure {
        invariant_id: "gen_ci_unpinned_action",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Pin every action to a full commit SHA (`uses: owner/repo@<sha> # vX`) and let Dependabot update it.",
        verify: "`truent harden` dependabot config present; scan clean.",
    },
    Exposure {
        invariant_id: "gen_ci_unsigned_release",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Sign artifacts and publish provenance (cosign, npm --provenance with id-token: write, gh attest, SLSA generator).",
        verify: "`cosign verify` / `npm audit signatures` succeeds on the released artifact.",
    },
    Exposure {
        invariant_id: "gen_code_injection",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Remove `eval`/`exec`/`new Function` on any input-derived string; use a parser or an allowlisted dispatch table.",
        verify: "Taint test: source→eval flow no longer present.",
    },
    Exposure {
        invariant_id: "gen_command_injection",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Invoke programs with an argument array (no shell); if a shell is unavoidable, quote with `shlex.quote` and allowlist inputs. Download-then-verify (checksum/signature) instead of piping to sh.",
        verify: "Taint test: source→shell flow no longer present.",
    },
    Exposure {
        invariant_id: "gen_container_privileged",
        vector: Vector::Local,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Remove `privileged: true`, host namespaces and dangerous capabilities; set `allowPrivilegeEscalation: false`, `runAsNonRoot: true`.",
        verify: "Admission policy (Pod Security Standards: restricted) passes.",
    },
    Exposure {
        invariant_id: "gen_docker_root_user",
        vector: Vector::Local,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Add a non-root `USER` after installing dependencies; use read-only root filesystem where possible.",
        verify: "`docker run --rm image id` shows a non-zero uid.",
    },
    Exposure {
        invariant_id: "gen_docker_unpinned_base",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Pin base images by digest (`FROM image@sha256:…`) and update via Dependabot/Renovate.",
        verify: "Dockerfile references digests; scan clean.",
    },
    Exposure {
        invariant_id: "gen_error_detail_exposed",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Information,
        fix: "Return a generic message and a correlation id to the client; log the exception with the id server-side.",
        verify: "Trigger an error: the response carries no stack, path or query text.",
    },
    Exposure {
        invariant_id: "gen_graphql_unrestricted",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Disable introspection in production; add depth and complexity limits (graphql-depth-limit, graphql-armor); consider persisted queries only.",
        verify: "Test: a 20-level nested query is rejected; introspection returns an error in production.",
    },
    Exposure {
        invariant_id: "gen_hardcoded_secret",
        vector: Vector::Local,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Rotate the credential now (assume it is compromised), move it to a secret manager or environment, and add the file pattern to `.gitignore`. Purge it from git history if pushed.",
        verify: "`truent scan --chain general` is clean; the old credential is revoked at the provider.",
    },
    Exposure {
        invariant_id: "gen_iac_open_ingress",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Restrict ingress CIDRs to known ranges; never expose admin/database ports to 0.0.0.0/0 — use a bastion or VPN.",
        verify: "`truent probe` from the internet shows no rt_open_port on admin/db ports.",
    },
    Exposure {
        invariant_id: "gen_iac_public_database",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Set `publicly_accessible = false`, place the database in private subnets, and allow only the application security group.",
        verify: "Connection from outside the VPC times out.",
    },
    Exposure {
        invariant_id: "gen_iac_public_storage",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Enable Block Public Access, remove public ACLs/policies, and serve public assets through a CDN with a restricted origin.",
        verify: "Anonymous `GET` on the bucket returns 403.",
    },
    Exposure {
        invariant_id: "gen_iac_unencrypted_storage",
        vector: Vector::Local,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Information,
        fix: "Enable encryption at rest (KMS-managed keys) on storage, databases and volumes.",
        verify: "Resource attributes show encryption enabled.",
    },
    Exposure {
        invariant_id: "gen_iac_wildcard_iam",
        vector: Vector::Network,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Replace `Action: *` / `Resource: *` with the specific actions and ARNs the workload uses; use IAM Access Analyzer.",
        verify: "Policy simulation shows no unintended allow.",
    },
    Exposure {
        invariant_id: "gen_insecure_file_permissions",
        vector: Vector::Local,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Set the least permission that works (0644 files, 0755 dirs, 0600 for secrets); never 777/666.",
        verify: "`find -perm -o+w` on the deployed tree returns nothing.",
    },
    Exposure {
        invariant_id: "gen_insecure_randomness",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Generate tokens/keys/nonces with a CSPRNG: `secrets`, `crypto.randomBytes`/`crypto.randomUUID`, `crypto/rand`.",
        verify: "Scan clean; tokens are >=128 bits from a CSPRNG.",
    },
    Exposure {
        invariant_id: "gen_insecure_temp_file",
        vector: Vector::Local,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Use mkstemp / os.CreateTemp / fs.mkdtemp, which create the file atomically with a random name and 0600.",
        verify: "Scan clean; temp files are created with mode 0600.",
    },
    Exposure {
        invariant_id: "gen_log_injection",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Log user input as a structured field, not inside the message string; strip CR/LF or encode before logging.",
        verify: "Test: input containing `\\n` does not create a forged log line.",
    },
    Exposure {
        invariant_id: "gen_log_sensitive_data",
        vector: Vector::Local,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Never log credentials, tokens or card data; log an identifier or a masked form; add a redaction filter to the logger.",
        verify: "Grep logs for the sensitive field names: nothing appears in clear.",
    },
    Exposure {
        invariant_id: "gen_mass_assignment",
        vector: Vector::Network,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Bind only an explicit allowlist of fields from the request (a DTO / serializer with declared fields); never pass the raw body to create/update.",
        verify: "Test: a request setting `role`/`is_admin`/`balance` leaves them unchanged.",
    },
    Exposure {
        invariant_id: "gen_missing_rate_limit",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Rate-limit login, reset, token and OTP routes per IP and per account; lock out or add friction after repeated failures.",
        verify: "Test: the 11th login attempt in a minute is rejected with 429.",
    },
    Exposure {
        invariant_id: "gen_missing_security_logging",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Information,
        fix: "Log every authentication outcome, authorization denial and privileged change with actor, target, result and source IP; ship to a SIEM.",
        verify: "A failed login appears in the log with actor and IP within seconds.",
    },
    Exposure {
        invariant_id: "gen_non_atomic_multi_write",
        vector: Vector::Network,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Wrap the writes in one database transaction; use SELECT … FOR UPDATE or optimistic versioning for the balance rows.",
        verify: "Test: a failure after the first write rolls back; two concurrent transfers cannot double-spend.",
    },
    Exposure {
        invariant_id: "gen_object_level_auth_missing",
        vector: Vector::Network,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Scope the query by the caller (`owner: req.user.id`, `user=request.user`) or check ownership before use; enforce in a shared repository layer, not per handler.",
        verify: "Test: user A requesting user B's object id gets 403/404.",
    },
    Exposure {
        invariant_id: "gen_open_redirect",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Only redirect to relative paths or to hosts on an allowlist; validate with is_safe_url / url_has_allowed_host_and_scheme.",
        verify: "Test: `?next=https://evil.example` redirects to `/`.",
    },
    Exposure {
        invariant_id: "gen_pipe_to_shell",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Invoke programs with an argument array (no shell); if a shell is unavoidable, quote with `shlex.quote` and allowlist inputs. Download-then-verify (checksum/signature) instead of piping to sh.",
        verify: "Taint test: source→shell flow no longer present.",
    },
    Exposure {
        invariant_id: "gen_private_key_committed",
        vector: Vector::Local,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Revoke and regenerate the key; remove the file; store keys in a secret manager; add `*.pem`/`*.key` to `.gitignore`.",
        verify: "Old key rejected by the service; scan clean.",
    },
    Exposure {
        invariant_id: "gen_regex_dos",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Rewrite the pattern without a quantifier on a group that contains a quantifier, bound input length, or use a linear-time engine (RE2, `regex` crate).",
        verify: "Test: a 50 KB adversarial input matches or fails in milliseconds.",
    },
    Exposure {
        invariant_id: "gen_sql_injection",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Use parameterized queries / prepared statements; never concatenate input into SQL. Use an ORM query builder for dynamic filters.",
        verify: "Taint test: source→query flow no longer present.",
    },
    Exposure {
        invariant_id: "gen_tls_verification_disabled",
        vector: Vector::Adjacent,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Remove `verify=False` / `rejectUnauthorized: false` / `InsecureSkipVerify`; trust the proper CA bundle or pin the certificate.",
        verify: "Test against an invalid certificate: the client refuses.",
    },
    Exposure {
        invariant_id: "gen_toctou_file",
        vector: Vector::Local,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Open the file and handle the error instead of checking first; use O_EXCL/O_NOFOLLOW or atomic rename for writes.",
        verify: "Review: no exists()/stat() immediately followed by open() on the same path.",
    },
    Exposure {
        invariant_id: "gen_unbounded_query_limit",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Clamp the page size (`Math.min(limit, MAX)`); reject or default values above the cap.",
        verify: "Test: `?limit=1000000` returns at most MAX rows.",
    },
    Exposure {
        invariant_id: "gen_unsafe_deserialization",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Replace pickle/yaml.load/marshal with JSON or `yaml.safe_load`; if binary formats are required, sign and verify payloads.",
        verify: "Test: crafted payload is rejected.",
    },
    Exposure {
        invariant_id: "gen_upload_unvalidated",
        vector: Vector::Network,
        prereq: Prereq::Authenticated,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Validate uploads: allowlist extensions and MIME by content sniffing, cap size (multer limits / MAX_CONTENT_LENGTH / MaxBytesReader), rename to a generated name, store outside the web root.",
        verify: "Test: an `.html`/`.php` upload and a 1 GB upload are both rejected.",
    },
    Exposure {
        invariant_id: "gen_weak_hash",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Use SHA-256+ for integrity and Argon2id/bcrypt/scrypt for passwords; keep MD5/SHA-1 only for non-security checksums and say so.",
        verify: "Scan clean; password hashes verified with a modern KDF.",
    },
    Exposure {
        invariant_id: "gen_web_cors_wildcard",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Set `Access-Control-Allow-Origin` to an explicit origin allowlist; never combine `*` or reflected origin with credentials.",
        verify: "Test: cross-origin request with credentials from an unlisted origin is refused.",
    },
    Exposure {
        invariant_id: "gen_web_csrf_disabled",
        vector: Vector::Network,
        prereq: Prereq::Authenticated,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Re-enable CSRF protection (framework middleware) and use SameSite=Lax/Strict cookies; exempt only token-authenticated APIs.",
        verify: "Test: state-changing POST without the CSRF token is rejected.",
    },
    Exposure {
        invariant_id: "gen_web_debug_enabled",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Turn debug off in production (`DEBUG=False`, no `debug=True` in `app.run`); drive it from the environment.",
        verify: "`truent probe` shows no stack traces; scan clean.",
    },
    Exposure {
        invariant_id: "gen_web_insecure_cookie",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Set `Secure`, `HttpOnly` and `SameSite=Lax` (or Strict) on session and CSRF cookies.",
        verify: "`truent probe` reports no rt_insecure_cookie.",
    },
    Exposure {
        invariant_id: "gen_web_jwt_unverified",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Verify signature and algorithm on every token (`jwt.verify` with an explicit `algorithms` list); reject `alg: none`.",
        verify: "Test: tampered or unsigned token is rejected.",
    },
    Exposure {
        invariant_id: "gen_web_path_traversal",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Resolve the joined path and verify it stays under the base directory; use `secure_filename`/`path.basename` for user-supplied names.",
        verify: "Test: `../../etc/passwd` is rejected.",
    },
    Exposure {
        invariant_id: "gen_web_ssrf",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Allowlist destination hosts/schemes, resolve and block private/link-local ranges, and disable redirects for server-side fetches.",
        verify: "Test: request to 169.254.169.254 / 127.0.0.1 is refused.",
    },
    Exposure {
        invariant_id: "gen_websocket_no_origin_check",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Full,
        fix: "Verify the Origin header against an allowlist in verifyClient / CheckOrigin / origins=.",
        verify: "Test: a connection with a foreign Origin is refused.",
    },
    Exposure {
        invariant_id: "gen_xss_sink",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Set text with `textContent`, or sanitize HTML with DOMPurify before `innerHTML`; enable a CSP.",
        verify: "Test: `<script>` in input is rendered inert.",
    },
    Exposure {
        invariant_id: "gen_xxe",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Disable external entities and DTD loading (defusedxml, `XMLParser(resolve_entities=False)`, `noent: false`).",
        verify: "Test: a document with an external entity referencing /etc/passwd is rejected.",
    },
    Exposure {
        invariant_id: "move_access_control",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require `&signer` for privileged entry functions and check `signer::address_of` against the stored admin/capability holder.",
        verify: "Test: call from a non-admin signer aborts.",
    },
    Exposure {
        invariant_id: "move_access_control_missing",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require `&signer` for privileged entry functions and check `signer::address_of` against the stored admin/capability holder.",
        verify: "Test: call from a non-admin signer aborts.",
    },
    Exposure {
        invariant_id: "move_admin_no_timelock",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Route admin actions through a timelock resource with a published delay and a multisig account.",
        verify: "Config review: admin is a multisig; delay enforced in code.",
    },
    Exposure {
        invariant_id: "move_integer_overflow",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Rely on Move's abort-on-overflow and remove manual wraparound; use u128/u256 intermediates for products.",
        verify: "Test boundary values; operations abort instead of wrapping.",
    },
    Exposure {
        invariant_id: "move_liquidity_conservation",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Assert reserve conservation (k invariant / total supply == sum of balances) at the end of every swap/mint/burn.",
        verify: "Invariant test over random sequences holds.",
    },
    Exposure {
        invariant_id: "move_manual_overflow_check",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Rely on Move's abort-on-overflow and remove manual wraparound; use u128/u256 intermediates for products.",
        verify: "Test boundary values; operations abort instead of wrapping.",
    },
    Exposure {
        invariant_id: "move_oracle_spot_price",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Use a TWAP or external oracle with staleness checks instead of instantaneous pool reserves.",
        verify: "Test: same-transaction manipulation does not change the price used.",
    },
    Exposure {
        invariant_id: "move_resource_destruction",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Ensure every resource is either stored, returned, or explicitly destroyed by its declaring module; never drop coins by unpacking.",
        verify: "Move Prover / unit tests cover every destroy path.",
    },
    Exposure {
        invariant_id: "move_resource_leaks",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Ensure every resource is either stored, returned, or explicitly destroyed by its declaring module; never drop coins by unpacking.",
        verify: "Move Prover / unit tests cover every destroy path.",
    },
    Exposure {
        invariant_id: "move_signer_requirement",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require `&signer` for privileged entry functions and check `signer::address_of` against the stored admin/capability holder.",
        verify: "Test: call from a non-admin signer aborts.",
    },
    Exposure {
        invariant_id: "move_type_safety",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Restrict struct abilities (`key`, `store`, `copy`, `drop`) to what is needed and validate generic type arguments against an allowlist.",
        verify: "Test: calling with an unexpected type argument aborts.",
    },
    Exposure {
        invariant_id: "move_type_safety_violation",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Restrict struct abilities (`key`, `store`, `copy`, `drop`) to what is needed and validate generic type arguments against an allowlist.",
        verify: "Test: calling with an unexpected type argument aborts.",
    },
    Exposure {
        invariant_id: "rt_exposed_sensitive_path",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Deny access to dotfiles and VCS/config paths at the web server (`location ~ /\\.(git|env|aws) { deny all; }`), stop deploying them, and rotate anything they contained.",
        verify: "`truent probe` shows no rt_exposed_sensitive_path; credentials rotated.",
    },
    Exposure {
        invariant_id: "rt_insecure_cookie",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Set `Secure`, `HttpOnly` and `SameSite=Lax` (or Strict) on session and CSRF cookies.",
        verify: "`truent probe` reports no rt_insecure_cookie.",
    },
    Exposure {
        invariant_id: "rt_missing_content_type_options",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Send `X-Content-Type-Options: nosniff` on every response.",
        verify: "`truent probe` shows no rt_missing_content_type_options.",
    },
    Exposure {
        invariant_id: "rt_missing_csp",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Add a Content-Security-Policy (`default-src 'self'`; nonce-based scripts; `frame-ancestors 'none'`; a `report-to` endpoint). Start in report-only mode.",
        verify: "`truent probe` shows no rt_missing_csp.",
    },
    Exposure {
        invariant_id: "rt_missing_frame_options",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Send `X-Frame-Options: DENY` (or `SAMEORIGIN`) or `frame-ancestors` in the CSP.",
        verify: "`truent probe` shows no rt_missing_frame_options.",
    },
    Exposure {
        invariant_id: "rt_missing_hsts",
        vector: Vector::Adjacent,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Partial,
        fix: "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` on every HTTPS response.",
        verify: "`truent probe` shows no rt_missing_hsts.",
    },
    Exposure {
        invariant_id: "rt_no_https_redirect",
        vector: Vector::Adjacent,
        prereq: Prereq::None,
        interaction: Interaction::Required,
        impact: Impact::Full,
        fix: "Redirect all HTTP to HTTPS with 301 at the edge and enable HSTS.",
        verify: "`truent probe http://host` shows a 301 to https://.",
    },
    Exposure {
        invariant_id: "rt_open_port",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Bind the service to localhost or a private interface, put it behind a firewall/security group, and require authentication.",
        verify: "`truent probe --ports` shows the port closed from outside.",
    },
    Exposure {
        invariant_id: "rt_server_banner",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Information,
        fix: "Suppress version strings (`server_tokens off`, `ServerTokens Prod`, remove `X-Powered-By`).",
        verify: "`truent probe` shows no rt_server_banner.",
    },
    Exposure {
        invariant_id: "rt_tls_expired",
        vector: Vector::Adjacent,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Renew the certificate and automate renewal (ACME / certbot / managed certificates) with expiry monitoring.",
        verify: "`truent probe` shows no rt_tls_expired.",
    },
    Exposure {
        invariant_id: "rt_tls_untrusted_cert",
        vector: Vector::Adjacent,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Serve a certificate from a trusted CA for the exact hostname (or wildcard) with the full intermediate chain.",
        verify: "`truent probe` reports chain verified: true.",
    },
    Exposure {
        invariant_id: "rt_tls_weak_protocol",
        vector: Vector::Adjacent,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Enable TLS 1.2 and 1.3 with AEAD cipher suites only; disable SSLv3/TLS 1.0/1.1 and RC4/3DES.",
        verify: "`truent probe` completes a TLS 1.3 handshake.",
    },
    Exposure {
        invariant_id: "sca_dependency_confusion",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Serve private packages through one proxy registry (`--index-url`, `.npmrc` scope mapping) and register the private names publicly as placeholders; pin with hashes.",
        verify: "`pip download` / `npm view` for the private name resolves only from the private registry.",
    },
    Exposure {
        invariant_id: "sca_install_script_dependency",
        vector: Vector::Local,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Review each install script; install with `--ignore-scripts` and allowlist the few that are required (e.g. native builds).",
        verify: "CI install runs with `--ignore-scripts`; the allowlist is documented.",
    },
    Exposure {
        invariant_id: "sca_lockfile_missing_integrity",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Regenerate the lockfile with a current toolchain so every entry carries an integrity hash / checksum; install with `npm ci` / `--locked`.",
        verify: "Every lockfile entry has integrity; `npm ci` refuses a modified tarball.",
    },
    Exposure {
        invariant_id: "sca_missing_lockfile",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Commit the lockfile (`Cargo.lock`, `package-lock.json`, `poetry.lock`, …) and use `--frozen`/`npm ci` in CI.",
        verify: "Lockfile present; CI install uses it.",
    },
    Exposure {
        invariant_id: "sca_typosquat_candidate",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Confirm the package is the intended one; if it is a typo, replace it and rotate anything the wrong package could have read.",
        verify: "The dependency name matches the upstream project exactly.",
    },
    Exposure {
        invariant_id: "sca_unmaintained_dependency",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Migrate to a maintained alternative; unmaintained crates receive no security fixes.",
        verify: "`truent deps` shows no sca_unmaintained_dependency.",
    },
    Exposure {
        invariant_id: "sca_unpinned_dependency",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Pin versions (exact or with a lockfile committed) so builds are reproducible and a hijacked release cannot enter silently.",
        verify: "Lockfile committed; scan clean.",
    },
    Exposure {
        invariant_id: "sca_vulnerable_dependency",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Upgrade to the fixed version named in the advisory; if none exists, remove or replace the dependency, or document a reachability-based exception.",
        verify: "`truent deps --advisory-db` shows no sca_vulnerable_dependency.",
    },
    Exposure {
        invariant_id: "sol_account_validation",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Validate every account: owner program, discriminator/type, PDA seeds+bump re-derived in program, sysvar by address (`Sysvar<'info, T>`), token account mint/owner.",
        verify: "Test: passing a fake account (wrong owner/seeds/mint) fails.",
    },
    Exposure {
        invariant_id: "sol_admin_no_timelock",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Put the upgrade/treasury authority behind a multisig (Squads) and a timelock; publish the delay.",
        verify: "Config review: authority is a multisig PDA, not a single keypair.",
    },
    Exposure {
        invariant_id: "sol_durable_nonce_validation",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Reject or specially handle durable-nonce transactions where replay timing matters; check `recent_blockhash` expectations.",
        verify: "Test: durable-nonce transaction does not bypass expiry logic.",
    },
    Exposure {
        invariant_id: "sol_fake_sysvar_instruction_account",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Validate every account: owner program, discriminator/type, PDA seeds+bump re-derived in program, sysvar by address (`Sysvar<'info, T>`), token account mint/owner.",
        verify: "Test: passing a fake account (wrong owner/seeds/mint) fails.",
    },
    Exposure {
        invariant_id: "sol_instruction_parsing",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Deserialize instruction data with a schema (Borsh/Anchor) and reject trailing or malformed bytes.",
        verify: "Fuzz instruction data; malformed inputs error rather than misparse.",
    },
    Exposure {
        invariant_id: "sol_integer_overflow",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Use `checked_*` / `saturating_*` arithmetic and enable `overflow-checks = true` in release profile.",
        verify: "Test boundary values; overflow errors rather than wraps.",
    },
    Exposure {
        invariant_id: "sol_lamport_balance",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Check rent exemption after any lamport transfer and never leave an account below the exempt minimum; validate lamport arithmetic.",
        verify: "Test: withdrawal that would drop below rent-exempt minimum fails.",
    },
    Exposure {
        invariant_id: "sol_missing_signer",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Mark the authority account `Signer<'info>` (Anchor) or check `is_signer` explicitly before any privileged action.",
        verify: "Test: instruction without the signer fails with MissingRequiredSignature.",
    },
    Exposure {
        invariant_id: "sol_oracle_rate_account",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Validate every account: owner program, discriminator/type, PDA seeds+bump re-derived in program, sysvar by address (`Sysvar<'info, T>`), token account mint/owner.",
        verify: "Test: passing a fake account (wrong owner/seeds/mint) fails.",
    },
    Exposure {
        invariant_id: "sol_oracle_self_trade",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Read prices from an oracle account (Pyth/Switchboard) with staleness and confidence checks, not from pool reserves in the same transaction.",
        verify: "Test: same-slot swap does not move the price used.",
    },
    Exposure {
        invariant_id: "sol_pda_authority_validation",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Validate every account: owner program, discriminator/type, PDA seeds+bump re-derived in program, sysvar by address (`Sysvar<'info, T>`), token account mint/owner.",
        verify: "Test: passing a fake account (wrong owner/seeds/mint) fails.",
    },
    Exposure {
        invariant_id: "sol_pda_derivation",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Validate every account: owner program, discriminator/type, PDA seeds+bump re-derived in program, sysvar by address (`Sysvar<'info, T>`), token account mint/owner.",
        verify: "Test: passing a fake account (wrong owner/seeds/mint) fails.",
    },
    Exposure {
        invariant_id: "sol_rent_exemption",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Check rent exemption after any lamport transfer and never leave an account below the exempt minimum; validate lamport arithmetic.",
        verify: "Test: withdrawal that would drop below rent-exempt minimum fails.",
    },
    Exposure {
        invariant_id: "sol_rent_exemption_check",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Check rent exemption after any lamport transfer and never leave an account below the exempt minimum; validate lamport arithmetic.",
        verify: "Test: withdrawal that would drop below rent-exempt minimum fails.",
    },
    Exposure {
        invariant_id: "sol_signer_checks",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Mark the authority account `Signer<'info>` (Anchor) or check `is_signer` explicitly before any privileged action.",
        verify: "Test: instruction without the signer fails with MissingRequiredSignature.",
    },
    Exposure {
        invariant_id: "sol_sysvar_account_validation",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Validate every account: owner program, discriminator/type, PDA seeds+bump re-derived in program, sysvar by address (`Sysvar<'info, T>`), token account mint/owner.",
        verify: "Test: passing a fake account (wrong owner/seeds/mint) fails.",
    },
    Exposure {
        invariant_id: "sol_treasury_single_authority",
        vector: Vector::Network,
        prereq: Prereq::Privileged,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Put the upgrade/treasury authority behind a multisig (Squads) and a timelock; publish the delay.",
        verify: "Config review: authority is a multisig PDA, not a single keypair.",
    },
    Exposure {
        invariant_id: "sol_unchecked_token_account_type",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Validate every account: owner program, discriminator/type, PDA seeds+bump re-derived in program, sysvar by address (`Sysvar<'info, T>`), token account mint/owner.",
        verify: "Test: passing a fake account (wrong owner/seeds/mint) fails.",
    },
    Exposure {
        invariant_id: "sor_checked_arithmetic",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Use `checked_add/sub/mul` and handle `None`; enable overflow checks in release.",
        verify: "Test boundary values; overflow errors.",
    },
    Exposure {
        invariant_id: "sor_init_guard",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Guard `initialize` with an instance-storage flag and panic on re-entry.",
        verify: "Test: second initialize panics.",
    },
    Exposure {
        invariant_id: "sor_missing_require_auth",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Call `address.require_auth()` on the acting address before any state change on its behalf.",
        verify: "Test: invocation without authorization fails.",
    },
    Exposure {
        invariant_id: "sor_no_reentrancy",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Update state before cross-contract calls; Soroban forbids reentrancy by default — do not re-enable it and do not rely on post-call state.",
        verify: "Test with a malicious callee: state is consistent.",
    },
    Exposure {
        invariant_id: "sor_no_unprotected_upgrade",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require admin authorization (`admin.require_auth()`) in `upgrade` and consider a timelock.",
        verify: "Test: upgrade from a non-admin fails.",
    },
    Exposure {
        invariant_id: "sor_reentrancy_external_call",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Update state before cross-contract calls; Soroban forbids reentrancy by default — do not re-enable it and do not rely on post-call state.",
        verify: "Test with a malicious callee: state is consistent.",
    },
    Exposure {
        invariant_id: "sor_reinitialization",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Guard `initialize` with an instance-storage flag and panic on re-entry.",
        verify: "Test: second initialize panics.",
    },
    Exposure {
        invariant_id: "sor_require_auth_checks",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Call `address.require_auth()` on the acting address before any state change on its behalf.",
        verify: "Test: invocation without authorization fails.",
    },
    Exposure {
        invariant_id: "sor_storage_ttl_extended",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Keep critical state in persistent/instance storage and extend TTL (`extend_ttl`) on every access; never in temporary storage.",
        verify: "Test: state survives ledger expiry simulation.",
    },
    Exposure {
        invariant_id: "sor_storage_ttl_not_extended",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Keep critical state in persistent/instance storage and extend TTL (`extend_ttl`) on every access; never in temporary storage.",
        verify: "Test: state survives ledger expiry simulation.",
    },
    Exposure {
        invariant_id: "sor_temporary_storage_critical_state",
        vector: Vector::Network,
        prereq: Prereq::Condition,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Keep critical state in persistent/instance storage and extend TTL (`extend_ttl`) on every access; never in temporary storage.",
        verify: "Test: state survives ledger expiry simulation.",
    },
    Exposure {
        invariant_id: "sor_thin_liquidity_oracle_price",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Source prices from an oracle contract with liquidity/staleness thresholds instead of thin pool reserves.",
        verify: "Test: manipulation within one ledger does not change the price used.",
    },
    Exposure {
        invariant_id: "sor_unchecked_arithmetic",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Use `checked_add/sub/mul` and handle `None`; enable overflow checks in release.",
        verify: "Test boundary values; overflow errors.",
    },
    Exposure {
        invariant_id: "sor_unhandled_panic",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Partial,
        fix: "Return typed errors (`Result<_, Error>`) instead of panicking on user input.",
        verify: "Test: bad input returns an error code, not a trap.",
    },
    Exposure {
        invariant_id: "sor_unprotected_upgrade",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Require admin authorization (`admin.require_auth()`) in `upgrade` and consider a timelock.",
        verify: "Test: upgrade from a non-admin fails.",
    },
    Exposure {
        invariant_id: "unauthorized_privileged_mutation",
        vector: Vector::Network,
        prereq: Prereq::None,
        interaction: Interaction::None,
        impact: Impact::Full,
        fix: "Restrict every state-mutating privileged function to an authenticated admin role.",
        verify: "Test: unauthorized caller is rejected.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::taxonomy;

    #[test]
    fn table_is_sorted_and_unique() {
        for w in EXPOSURE.windows(2) {
            assert!(
                w[0].invariant_id < w[1].invariant_id,
                "{} must sort before {}",
                w[0].invariant_id,
                w[1].invariant_id
            );
        }
    }

    #[test]
    fn every_taxonomy_row_has_an_exposure_profile() {
        // The ratchet: a detector without a fix and a verify step is not
        // finished. If this fails, add the row — do not weaken the test.
        for t in taxonomy::all() {
            let e = exposure_for(t.invariant_id)
                .unwrap_or_else(|| panic!("{} has no exposure profile", t.invariant_id));
            assert!(e.fix.len() > 30, "{}: fix is too thin", t.invariant_id);
            assert!(
                e.verify.len() > 10,
                "{}: verify is too thin",
                t.invariant_id
            );
        }
    }

    #[test]
    fn no_stale_exposure_rows() {
        for e in EXPOSURE {
            assert!(
                taxonomy::taxonomy_for(e.invariant_id).is_some(),
                "{} is not a taxonomy row",
                e.invariant_id
            );
        }
    }

    fn f(id: &str) -> Finding {
        Finding::new(
            id.into(),
            Severity::High,
            "x".into(),
            1,
            0,
            "m".into(),
            "s".into(),
        )
    }

    #[test]
    fn network_no_prereq_is_likely() {
        let r = rate(&f("gen_sql_injection")).unwrap();
        assert_eq!(r.exploitability, Exploitability::Likely);
        assert!(r.reasons.iter().any(|s| s.contains("reachable by anyone")));
    }

    #[test]
    fn privileged_prereq_is_theoretical() {
        assert_eq!(
            rate(&f("gen_iac_unencrypted_storage"))
                .unwrap()
                .exploitability,
            Exploitability::Theoretical
        );
    }

    #[test]
    fn victim_interaction_lowers_and_proof_raises() {
        // Static insecure cookie: network, no prereq, victim must be on a
        // hostile network → Possible.
        let s = rate(&f("gen_web_insecure_cookie")).unwrap();
        assert_eq!(s.exploitability, Exploitability::Possible);
        // The same weakness observed live → Likely.
        let p = rate(&f("rt_insecure_cookie").proven()).unwrap();
        assert_eq!(p.exploitability, Exploitability::Likely);
        assert!(p.reasons.iter().any(|s| s.contains("observed live")));
    }

    #[test]
    fn unknown_ids_have_no_rating() {
        assert!(rate(&f("nope")).is_none());
    }
}
