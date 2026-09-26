# Chain primer — EVM (Solidity)

Appended to every agent bundle when `.sol` files are in scope. The specialty files were
written for this chain, so this primer is short: it names what the engine already covers
here, and where each specialty starts.

## Execution model

One contract, one storage, one caller at a time. `msg.sender` is the immediate caller (a
contract or an EOA), `tx.origin` is the EOA that signed. External calls transfer control to
the callee, which may call back **before** the caller's next line runs — that is reentrancy,
and it is the reason checks-effects-interactions exists. `delegatecall` runs the callee's code
in the caller's storage. Value moves as native ETH (`msg.value`, `call{value:}`) or as ERC-20
balances the token contract keeps; the two have different failure modes and the code that
treats them alike is where the boundary agent starts.

Arithmetic reverts on overflow since 0.8; `unchecked` blocks and older pragmas do not.
Division truncates toward zero. Casts to a narrower type revert on overflow in 0.8 only when
written as an explicit conversion the compiler checks — `uint128(x)` truncates silently.

## Trust boundaries

- **Caller:** anything. Every `external`/`public` function is reachable by any address.
- **Tokens:** an arbitrary contract. Fee-on-transfer, rebasing, blacklisting, no return
  value (USDT), `false` return (Tether Gold), 6 decimals, reverting on zero approve.
- **Oracles:** Chainlink `latestRoundData` (`updatedAt`, `answer > 0`), Uniswap `slot0`
  (spot, manipulable in one block), TWAPs.
- **Proxies:** implementation storage layout vs proxy slots; initializers callable on the
  implementation.
- **Cross-chain:** a message is bytes; the sender, the source chain and the nonce are claims
  the receiver must verify.

## Where each specialty hunts here

| Specialty | Start at |
|---|---|
| math-precision | every `/` in a value-moving function; every `1e18`; every `uint128(`; `a * b / c` with attacker-scale operands |
| access-control | every storage variable with two writers of different guard strength; `initialize` on the implementation; `delegatecall` targets |
| economic-security | `transferFrom` amount vs balance delta; `slot0`; `amountOutMin = 0`; ERC-4626 `max*` vs `mint` |
| execution-trace | `msg.value` vs `amount`; `abi.encodePacked` decoded elsewhere; state read before an external call and used after |
| invariant | `totalSupply` vs `sum(balanceOf)`; caps enforced on `deposit` but not on settlement; `view` vs write pairs |
| periphery | libraries, encoders, `mload` widths, `bytes20(` truncation, helpers reading storage under the wrong context |
| first-principles | every implicit ordering (A before B), identity (this address is what we think), freshness (this price is current) |
| asymmetry | deposit/withdraw, mint/burn, native/ERC20 branches, user `x()` vs admin `forceX()` |
| boundary | every external call under: no code at receiver, non-standard token, zero/max input, ignored return |
| numerical-gap | fees that truncate to zero at small amounts; accumulators incremented by truncated values |
| trust-gap | `onlyKeeper` + `amountOutMin = 0`; deposit at spot, withdraw at TWAP; setters that redirect in-flight value |
| flow-gap | balance computed before a fee-on-transfer call and used after; callbacks mid-flow (ERC-721 `onERC721Received`, V3 mint callback) |

## What the engine already covers (do not re-derive)

Detector ids the EVM analyzer runs on every scan. If one of these is the bug you found, it is
in the "Engine findings" section, or the code does not match its shape — in either case your
job is the second path and the wider impact, not the pattern.

`evm_access_control` · `evm_shallow_auth` · `evm_missing_signer_check` · `evm_unprotected_initializer` ·
`evm_constructor_race_condition` · `evm_single_eoa_admin` · `evm_insufficient_multisig_threshold` ·
`evm_dvn_threshold` · `evm_dvn_single_point_failure` · `evm_upgrade_path_verification` ·
`evm_proxy_storage_collision` · `evm_missing_pause_mechanism` · `evm_zero_challenge_period` ·
`evm_reentrancy_classic` · `evm_reentrancy_erc20` · `evm_readonly_reentrancy` ·
`evm_reentrancy_protection` · `evm_reentrancy_via_whitelisted` · `evm_state_mutation_ordering` ·
`evm_integer_overflow` · `evm_integer_underflow` · `evm_legacy_unsafe_math` · `evm_precision_loss` ·
`evm_arithmetic_rounding` · `evm_division_by_zero` · `evm_uninitialized_pointers` ·
`evm_unchecked_returns` · `evm_arbitrary_call_msg_value` · `evm_arbitrary_function_selector_dispatch` ·
`evm_delegatecall_injection` · `evm_public_relay` · `evm_push_payment_in_loop` · `evm_unbounded_loop` ·
`evm_oracle_spot_price` · `evm_oracle_self_trade` · `evm_stale_oracle_price` ·
`evm_token_balance_manipulation` · `evm_synthetic_collateral_oracle` · `evm_unbounded_pricing_input` ·
`evm_lst_depeg` · `evm_flash_loan_governance` · `evm_frontrunning` · `evm_router_slippage_validation` ·
`evm_erc4626_inflation_protection` · `evm_fee_on_transfer_incompatibility` ·
`evm_conservation_check_absent` · `evm_missing_post_state_health_check` · `evm_unbacked_synthetic_mint` ·
`evm_signature_replay_protection` · `evm_cross_chain_replay_missing_chainid` ·
`evm_bridge_address_cryptographic_verify` · `evm_merkle_root_zero` · `evm_merkle_root_zero_default` ·
`evm_timestamp_dependence` · `evm_aa_entropy_weakness` · `evm_eip7702_eoa_assumption` ·
`evm_erc4337_validation_side_effects` · `evm_symbolic_counterexample` · `evm_symbolic_unresolved`

Plus the chain-neutral `unauthorized_privileged_mutation` (an entry point performs a
privileged mutation with no authorization check reaching it).

**Dynamic:** `truent fuzz --dynamic --chain evm` auto-detects conservation
(`totalSupply`/`balanceOf`), monotonicity (accumulator getters), access control
(`owner`/`transferOwnership`) and reentrancy (trace). A property in one of those shapes is
something the orchestrator will hand to the engine — state it.

## Concrete bug shapes (the engine's own corpus)

Each file under `crates/analyzer/evm/tests/corpus/bad/` is a minimal program the engine must
flag. They are the shapes, by name: `reentrancy_classic.sol`, `reentrancy_erc20.sol`,
`readonly_reentrancy.sol`, `unprotected_initializer.sol`, `unverified_upgrade.sol`,
`single_eoa_admin.sol`, `unbacked_mint.sol`, `oracle_spot_price.sol`, `division_by_zero.sol`,
`legacy_unsafe_math.sol`, `unchecked_returns.sol`, `selector_dispatch.sol`, `gas_dos.sol`
(unbounded loop + push payment + no pause), `cross_chain_replay.sol`, `merkle_root_zero.sol`,
`timestamp_randomness.sol`. The `good/` siblings (`erc4626_vault.sol`, `uups_proxy.sol`,
`timelock_multisig.sol`, `eip712_permit.sol`, …) are what the safe version looks like.

## No analogue here

Nothing from the other chains is missing on the EVM; the specialties were written for it.
What the EVM lacks that the others have: no account model (a caller passes values, not
accounts), no capability objects (authority is an address comparison), no storage expiry (a
slot lives as long as the contract).
