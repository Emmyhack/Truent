<!-- Adapted from pashov/skills x-ray/references/threats.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine integration, multi-chain. -->
# Protocol-Type Threat Profiles

> **HOW TO USE THIS FILE**
>
> Treat this file as a threat *identification* library, **not** as a prose template for the final report.
>
> - **In Step 2e (Protocol Classification)** — use the detection-signals table to label the protocol by type.
> - **In Step 3a (Writing Section 2 of recon.md)** — use adversary rankings, attack patterns, and critical invariants listed here to know *what to look for* and *who threatens the protocol*, then TRANSLATE that knowledge into the output format.
> - **Engine coverage lines** name the Truent detector ids (`truent scan`) that already encode a pattern. If a pattern has a detector, its presence or absence in `recon/engine-findings.json` is `VERIFIED-STATIC` ground truth — cite the id. If no detector covers it, anything you write about it is `REASONED`. Detector ids are exactly those in `truent taxonomy --format json`; never invent one.
>
> **DO NOT copy exploit-chain prose verbatim into Key Attack Surfaces.** Phrases like *"Oracle manipulation → inflated collateral → drain the pool"* are intentional here — they teach the threat — but the `templates.md` **DO-NOT-EXPLOIT RULE** forbids them in the report. Convert "→ attacker drains X" into "worth tracing…" / "worth checking…" / "worth confirming…" when writing the bullet. Name the surface and the concern; let the auditor finish the sentence.

This reference provides per-protocol-type threat intelligence. The skill auto-classifies the protocol from code signals in Step 2, then uses the matching profile(s) to weight adversaries, attack patterns, and surfaces in the threat model. The protocol-type profiles are written with EVM vocabulary; the same types exist on Solana, Move and Soroban — map the signals through the **Chain-Specific Threat Dimensions** section at the end of this file.

## Protocol Classification Signals

Detect protocol type from function signatures, state variables, and architectural patterns found during source file reading in Step 2. A protocol may match **multiple types** (hybrid). Rank by signal density — the type with the most matches is primary.

| Type | Detection Signals in Code |
|------|--------------------------|
| **Lending/Borrowing** | `borrow()`, `repay()`, `liquidate()`, `liquidationBonus`, `healthFactor`, `collateralFactor`, `LTV`, `debtToken`, `interestRate`, collateral ratio math, health factor calculations, borrow/supply balance tracking |
| **DEX/AMM** | `swap()`, `addLiquidity()`, `removeLiquidity()`, constant-product math (`x * y = k`), stable-swap invariant, `sqrtPriceX96`, `tick`, LP token mint/burn, fee tier, `getAmountOut()`, reserves tracking |
| **Yield Aggregator** | ERC4626 vault pattern (`deposit`/`withdraw`/`convertToShares`/`convertToAssets`), strategy pattern (deposit into external protocol + `harvest()`), yield routing, `totalAssets()`, `strategyDebt`, auto-compound |
| **Stablecoin** | Peg mechanism (mint/burn against collateral), `collateralRatio`, stability fee, `debtCeiling`, redemption mechanism, PSM (peg stability module), `anchor`/`peg`/`target` price references |
| **Derivatives/Perps** | `openPosition()`, `closePosition()`, `increaseSize()`, `decreaseSize()`, `fundingRate`, `margin`, `leverage`, PnL calculation, `markPrice`, `indexPrice`, position struct with size/collateral/entryPrice |
| **Liquid Staking** | `stake()` + derivative token mint, `unstake()`/`requestWithdrawal()`, exchange rate calculation, validator set management, withdrawal queue, rebasing token or share-based token |
| **Bridge** | Cross-chain message passing, `lock()`/`unlock()` or `burn()`/`mint()` pattern, relayer/validator set, message nonce, chain ID checks, merkle proof verification |
| **Governance** | `propose()`, `vote()`, `execute()`, `queue()`, quorum calculation, voting power snapshots, timelock, delegation, `proposalThreshold` |

Non-EVM equivalents of the same signals: Anchor instructions named `borrow`/`liquidate`/`swap` with `CpiContext` token transfers; Move `public entry fun swap<X, Y>` over `Pool<X, Y>` with `Balance<X>`; Soroban `#[contractimpl]` `pub fn borrow(env: Env, …)` writing `persistent()` positions. Classify by mechanism, not by language.

### Hybrid Classification

Many protocols combine types. When multiple types match:
1. Rank by signal count — more matches = higher weight in threat model
2. The **primary type** determines adversary ranking order
3. **Secondary types** add their unique threats to the model (de-duplicating overlapping ones)
4. In the output, state: "Protocol classified as: **[Primary]** with **[Secondary]** characteristics"

Example: A protocol with `swap()`, `addLiquidity()`, `borrow()`, `liquidate()` → Primary: DEX/AMM, Secondary: Lending/Borrowing.

---

## Threat Profiles by Protocol Type

### Lending / Borrowing

**Primary adversaries** (ranked by historical exploit frequency):
1. **Flash loan attacker** — Borrows unlimited capital in a single transaction to manipulate oracle prices, inflate collateral values, and drain borrow capacity. Flash loans reduce the cost of oracle manipulation to near-zero.
2. **Oracle manipulator** — Manipulates price feeds (spot or TWAP) to make collateral appear more valuable or debt appear less valuable. The oracle is the single source of truth for solvency — if it lies, everything downstream breaks.
3. **Liquidation MEV searcher** — Extracts value from liquidation events through front-running, back-running, or sandwich attacks. If MEV extraction makes liquidation unprofitable for honest liquidators, bad debt accumulates.
4. **Malicious first depositor** — In protocols with share-based accounting (supply tokens, debt tokens), the first depositor can manipulate the share price to steal from subsequent depositors. Classic vault inflation attack applied to lending pools.
5. **Compromised admin** — Can change collateral factors, oracle addresses, interest rate models, or pause liquidations. Any of these can instantly make the protocol insolvent or prevent it from recovering.

**Dominant attack patterns:**
- Oracle manipulation → inflated collateral value → max borrow → drain lending pool
- Flash loan borrow → manipulate spot price → liquidate victim at wrong price → profit from liquidation bonus
- Bad debt accumulation through positions that become unliquidatable (oracle lag, gas price spikes, illiquid collateral)
- Interest rate manipulation via large deposit/withdraw cycles (move utilization to manipulate rates)
- Collateral factor misconfiguration allowing undercollateralized borrowing
- Recursive borrowing: deposit collateral → borrow → deposit borrowed asset as collateral → borrow again → amplified exposure that collapses under price movement

**Critical invariants:**
- `totalBorrows <= totalCollateral * LTV` — always, for every market and every account
- Every position must be liquidatable before it can cause bad debt (health factor trigger > underwater threshold)
- Liquidation must be profitable for liquidators (otherwise bad debt accrues silently)
- Oracle price reflects fair market value within acceptable deviation and freshness bounds
- Interest accrual is monotonic and cannot be manipulated to extract value

**What to look for first:**
1. The complete price calculation path: oracle read → price normalization → collateral value → health factor. Every step is a manipulation point.
2. Can a single transaction borrow, manipulate price, and liquidate? If yes, flash loan attack is viable.
3. Liquidation math: is the bonus sufficient to cover gas + slippage? What happens when collateral is illiquid?
4. Share price calculation for supply/debt tokens: what happens when totalSupply == 0?
5. What can admin change instantly vs. through timelock? Can admin change oracle address?

**Engine coverage (EVM):** `evm_oracle_spot_price`, `evm_stale_oracle_price`, `evm_oracle_self_trade`, `evm_synthetic_collateral_oracle`, `evm_missing_post_state_health_check`, `evm_erc4626_inflation_protection`, `evm_unbounded_pricing_input`, `evm_lst_depeg`, `evm_single_eoa_admin`, `evm_missing_pause_mechanism`. Registry precedents: `truent registry list` → euler-finance-2023 (`evm_conservation_check_absent` + `evm_oracle_spot_price`). Liquidation-profitability and interest-rate-manipulation have **no detector** — REASONED only.

---

### DEX / AMM

**Primary adversaries** (ranked):
1. **MEV searcher / sandwich attacker** — The dominant threat to DEX users. Monitors mempool for pending swaps, inserts transactions before and after to extract value. Every swap without adequate slippage protection is a guaranteed extraction opportunity.
2. **Flash loan price manipulator** — Uses flash-loaned capital to move pool prices within a single transaction.
3. **Malicious first LP / empty pool attacker** — Manipulates pool initialization or empty-state transitions. In concentrated liquidity: can set initial tick to a manipulated price. In constant-product: can inflate LP share price through donation before the first real deposit.
4. **Liquidity manipulation attacker** — Adds and removes liquidity strategically to extract value from other LPs.
5. **Compromised admin** — Can change fee structures, pause trading, modify routing, or whitelist malicious pools.

**Dominant attack patterns:**
- Sandwich attacks: front-run swap to move price → victim swaps at worse price → back-run to capture difference
- LP share inflation on empty/new pools (donate assets to inflate share price before real deposits)
- Reentrancy through token callbacks (ERC-777, ERC-1155 hooks) during swap execution when pool state is inconsistent
- Price oracle exploitation: other protocols read AMM spot price, attacker manipulates pool in same tx, other protocol uses wrong price
- Concentrated liquidity tick manipulation: force price through tick boundaries to trigger stop-loss-like behavior in other positions
- Fee-on-transfer token accounting errors: pool receives fewer tokens than expected, invariant breaks

**Critical invariants:**
- Pool invariant holds before and after every operation (k = x * y, or curve-specific)
- LP share value is monotonically non-decreasing from fees (absent impermanent loss)
- No tokens can be extracted without proportional LP burn or valid swap math
- Swap output amount matches the invariant-derived calculation exactly (no rounding exploitation)
- Reserves tracked in contract state match actual token balances (no donation attack surface)

**What to look for first:**
1. Swap math: is the invariant correctly maintained? Are there rounding errors that consistently favor one direction?
2. LP mint/burn math: what happens at totalSupply == 0? Is there minimum liquidity enforcement?
3. Does the pool expose `getPrice()`, `observe()`, or similar that other contracts call? If yes, it's an oracle and manipulation has external blast radius.
4. Slippage protection: is it enforced at the router level? Can it be bypassed? What's the default?
5. Reentrancy guards: does the swap update state before making external calls (token transfers)?

**Engine coverage (EVM):** `evm_router_slippage_validation`, `evm_frontrunning`, `evm_fee_on_transfer_incompatibility`, `evm_token_balance_manipulation`, `evm_reentrancy_classic`, `evm_reentrancy_erc20`, `evm_readonly_reentrancy`, `evm_arithmetic_rounding`, `evm_precision_loss`, `evm_conservation_check_absent`. Move: `move_liquidity_conservation`, `move_divide_before_multiply`. Dynamic: `truent fuzz --dynamic` auto-detects ERC20-shaped conservation (`sum(balanceOf) == totalSupply()`) — a pool's `x*y=k` is **not** auto-detected; state it in an `.invar` file and pass `--invariants` (see SKILL.md Step 2h).

---

### Yield Aggregator / Vault

**Primary adversaries** (ranked):
1. **Share inflation attacker (first depositor)** — The canonical vault attack. Deposit 1 wei, donate a large amount directly to the vault (inflating `totalAssets` without minting shares), then when the next user deposits, they receive 0 shares due to rounding and the attacker redeems for the donated + deposited amount.
2. **Malicious/compromised strategy** — Strategies hold the actual funds. A malicious strategy can report fake losses, retain approvals after migration, or transfer funds out.
3. **Reentrancy through external protocol callbacks** — Vault deposits into Aave/Compound/Yearn, which may trigger callbacks during deposit/withdraw. If vault state is inconsistent during the callback window, reentrancy can manipulate share prices.
4. **Donation/direct-transfer attacker** — Sends tokens directly to the vault contract (not through deposit()) to manipulate `totalAssets()` and therefore share price. If `totalAssets` reads `balanceOf(address(this))`, any donation changes the share price.
5. **Compromised admin** — Can add malicious strategies, change allocation weights, set harvester address, or migrate funds to attacker-controlled strategy.

**Dominant attack patterns:**
- ERC4626 share inflation: deposit(1) → donate(large amount) → next depositor gets 0 shares → redeem(all)
- Strategy reports fake gain → inflated share price → attacker deposits at inflated price → strategy reports real value → attacker loses nothing, previous depositors diluted
- Strategy retains token approval after migration to new strategy — old strategy can still pull funds
- Harvest sandwich: front-run harvest() with deposit (get shares cheap), harvest increases totalAssets, back-run with withdraw (redeem at higher share price)
- Vault accounting desync: strategy's real balance differs from vault's recorded allocation due to external protocol behavior (rebasing, slashing, reward accrual)

**Critical invariants:**
- `totalAssets()` accurately reflects real underlying value at all times
- `convertToShares(convertToAssets(shares)) <= shares` — round-trip must not create value
- `convertToAssets(convertToShares(assets)) <= assets` — same in reverse
- Strategy cannot extract more than it was allocated
- Share price can only increase from yield, never from manipulation

**What to look for first:**
1. Share price calculation: `convertToAssets` / `convertToShares`. Is there a virtual offset or minimum deposit to prevent inflation attacks?
2. Strategy interface: what can a strategy do? Can it report arbitrary gain/loss? Who can add/remove strategies?
3. Does `totalAssets()` use `balanceOf(this)` or internal accounting? If balanceOf, donation attacks are possible.
4. Deposit/withdraw: is there reentrancy protection? Are state changes before external calls?
5. Strategy migration: does the old strategy lose all approvals? Is there a cooldown?

**Engine coverage (EVM):** `evm_erc4626_inflation_protection`, `evm_token_balance_manipulation`, `evm_reentrancy_classic`, `evm_reentrancy_via_whitelisted`, `evm_state_mutation_ordering`, `evm_arithmetic_rounding`, `evm_unchecked_returns`. Dynamic: `truent fuzz --dynamic` checks monotonic accumulator getters when it finds them on the ABI. Strategy-approval retention and harvest-sandwich have **no detector** — REASONED only.

---

### Stablecoin

**Primary adversaries** (ranked):
1. **Oracle manipulator** — If collateral price is manipulated upward, attacker can mint stablecoins against less real collateral. If manipulated downward, legitimate positions get liquidated at unfair prices. In algorithmic stablecoins, oracle manipulation can trigger or amplify depegs.
2. **Economic/governance attacker** — Acquires governance power to change collateral parameters (lower ratios, add risky collateral, change stability fees) to extract value or destabilize the peg. Can also manipulate stability mechanisms.
3. **Bank run attacker** — Triggers mass redemption by creating panic or exploiting information asymmetry. If the stablecoin's redemption mechanism has capacity limits, a strategic redemption can drain the best collateral, leaving remaining holders with worse backing.
4. **Flash loan minter** — Flash loans capital to mint stablecoins, manipulates collateral price, and profits from the discrepancy. Especially dangerous if minting has no cooldown or rate limit.
5. **Compromised admin** — Can change collateral types, oracle addresses, debt ceilings, stability fees, or pause redemptions. Any of these can break the peg or trap user funds.

**Dominant attack patterns:**
- Collateral price manipulation → mint at inflated collateral value → sell stablecoins → collateral price returns to normal → protocol is undercollateralized
- Algorithmic death spiral: sell pressure → depeg → collateral value drops → more liquidations → more sell pressure → repeat (LUNA/UST)
- Redemption mechanism DOS: spam redemptions to drain liquid collateral, leaving illiquid collateral backing remaining supply
- Governance attack: change collateral ratio to allow undercollateralized minting
- Oracle staleness exploitation: mint when oracle reports stale (higher) price, redeem when oracle updates to real (lower) price

**Critical invariants:**
- Every stablecoin unit is backed by >= 1:1 collateral value (or >= configured ratio)
- Mint and redeem are inverse operations: round-trip preserves value (no profitable loops)
- Peg mechanism is convergent, not divergent, under sell pressure
- Liquidation can always restore individual position collateralization
- Total supply <= total debt ceiling across all collateral types

**What to look for first:**
1. Minting path: what collateral is accepted → how is it valued (oracle) → what's the ratio → can the ratio be changed?
2. Redemption path: can all stablecoins be redeemed simultaneously? Is there a priority queue? What happens under stress?
3. Liquidation mechanism: is it profitable? What happens if collateral price drops faster than liquidations can execute?
4. What can governance change? How quickly? Is there a peg-break emergency mechanism?
5. Death spiral analysis: if the stablecoin depegs 10%, does the mechanism push it back or amplify the depeg?

**Engine coverage (EVM):** `evm_unbacked_synthetic_mint`, `evm_synthetic_collateral_oracle`, `evm_stale_oracle_price`, `evm_oracle_spot_price`, `evm_conservation_check_absent`, `evm_flash_loan_governance`. Peg-convergence and redemption-queue fairness have **no detector** — REASONED only.

---

### Derivatives / Perps

**Primary adversaries** (ranked):
1. **Oracle manipulator** — In derivatives, oracle errors are amplified by leverage. A 1% oracle manipulation on a 50x leveraged position creates a 50% PnL swing.
2. **Liquidation MEV searcher** — Extracts value from liquidation events. In perps, positions can be large and leverage amplifies the liquidation bonus. May also manipulate price to trigger liquidations, then capture the liquidated collateral.
3. **Funding rate manipulator** — Skews open interest to force favorable funding rate payments. With enough capital, can make the funding rate so extreme that opposing positions are forced to close, then reverse to capture the funding.
4. **Position size attacker** — Opens positions larger than the protocol can pay out, or opens positions across multiple accounts to circumvent limits. If the protocol's liquidity pool cannot cover max payout, insolvency results.
5. **Compromised admin** — Can change max leverage, funding rate parameters, liquidation thresholds, or oracle addresses. Can also pause liquidations (creating bad debt) or enable instant position changes that bypass risk checks.

**Dominant attack patterns:**
- Oracle manipulation → cascade liquidation → profit from liquidated positions
- Funding rate manipulation through concentrated one-sided open interest
- Position size exceeding protocol's payout capacity (adversary opens at max leverage, market moves in their favor, protocol can't pay)
- Delayed/stale oracle → risk-free directional bet (see current price off-chain, trade at stale on-chain price)
- Cross-margin exploitation: loss in one position affecting collateral of another, creating liquidation cascades within a single account
- ADL (auto-deleveraging) manipulation: force ADL on profitable opposing positions by creating insolvency conditions

**Critical invariants:**
- Sum of all PnL = 0 (zero-sum between longs and shorts, minus fees)
- Available liquidity >= maximum payout of all open positions under worst-case price movement
- Liquidation triggers before any position can cause bad debt to the system
- Funding rate converges open interest imbalance over time (doesn't diverge)
- Mark price cannot deviate from index price beyond safety bounds

**What to look for first:**
1. PnL calculation: is it correct under all conditions (positive, negative, at leverage limits)?
2. Liquidation threshold vs. actual execution: is there enough margin between liquidation trigger and insolvency?
3. Oracle: mark price vs. index price. How is mark price calculated? Can it be manipulated within a block?
4. Max open interest / position size limits: are they enforced? What happens if total payouts exceed pool?
5. Funding rate: can it be manipulated? What's the maximum rate? Can it drain margin faster than expected?

**Engine coverage (EVM):** `evm_stale_oracle_price`, `evm_oracle_spot_price`, `evm_oracle_self_trade`, `evm_missing_post_state_health_check`, `evm_precision_loss`, `evm_integer_overflow`, `evm_integer_underflow`. Registry precedent: gmx-2024 (`evm_oracle_spot_price`), drift-protocol-2023 (`sol_oracle_rate_account`, `evm_precision_loss`). Funding-rate and ADL logic have **no detector** — REASONED only.

---

### Liquid Staking

**Primary adversaries** (ranked):
1. **Exchange rate manipulator** — The derivative token's value depends on an exchange rate (stETH/ETH, rETH/ETH). If this rate can be manipulated (through rewards reporting, slashing events, or direct donation), attackers can buy/sell the derivative at wrong prices against protocols that use it as collateral.
2. **Validator set attacker** — Compromises or controls validators that the protocol delegates to. Can trigger slashing events, withhold rewards, or censor transactions. The trust model around validator selection is critical.
3. **Withdrawal queue attacker** — Exploits timing or ordering in the unstaking queue. May front-run large unstake requests to exit first, or manipulate queue mechanics to delay others' withdrawals.
4. **Oracle/rate arbitrageur** — Exploits lag between the on-chain exchange rate and real underlying value. When a slashing event occurs, the on-chain rate may not update immediately — attacker sells derivative at stale (higher) rate before the slash is reflected.
5. **Compromised admin** — Can change validator set, fee parameters, oracle addresses, or withdrawal mechanisms. Can also pause withdrawals, trapping user funds.

**Dominant attack patterns:**
- Rewards/slashing reporting manipulation: report fake rewards to inflate exchange rate, or delay slashing report to exit at stale rate
- Withdrawal queue griefing: spam small unstake requests to delay large withdrawals
- Rebasing token integration bugs: protocols that integrate the liquid staking derivative may not handle rebasing correctly
- Validator collusion: validators withhold blocks or MEV to reduce rewards below expected rate
- Share price manipulation through direct ETH/token transfer to the contract

**Critical invariants:**
- Exchange rate reflects true underlying value (staked assets + rewards - slashing)
- Total derivative supply * exchange rate <= total underlying staked
- Withdrawal queue processes in fair order (no priority manipulation)
- Validator performance doesn't systematically disadvantage stakers
- Slashing events are reflected in exchange rate before any user can exit at stale rate

**What to look for first:**
1. Exchange rate calculation: who reports rewards/slashing? How often? Can it be manipulated?
2. Withdrawal mechanism: is there a queue? What's the delay? Can it be griefed?
3. Validator selection: who chooses validators? Can a malicious validator be added?
4. Does the derivative token rebase or use shares? How do integrating protocols handle this?
5. What happens if a massive slashing event occurs? Is the loss socialized fairly?

**Engine coverage (EVM):** `evm_lst_depeg`, `evm_token_balance_manipulation`, `evm_erc4626_inflation_protection`, `evm_push_payment_in_loop`, `evm_unbounded_loop`. Validator-set trust and queue fairness have **no detector** — REASONED only.

---

### Bridge

**Primary adversaries** (ranked):
1. **Validator/relayer set attacker** — Compromises the threshold of validators/relayers needed to approve cross-chain messages. This is the #1 bridge exploit vector by total value lost.
2. **Message replay attacker** — Replays a valid cross-chain message on a different chain or replays the same message multiple times to mint/unlock tokens repeatedly.
3. **Race condition exploiter** — Exploits timing gaps between source and destination chain finality. Initiates action on source chain, front-runs the relay on destination chain, or exploits reorgs to reverse source chain action after destination chain has already processed it.
4. **Fake message crafter** — Crafts a cross-chain message that passes validation but contains malicious data. Exploits weaknesses in message encoding, proof verification, or chain ID validation.
5. **Compromised admin** — Can change validator set, pause bridge (trapping funds), or upgrade contracts to drain locked funds. Bridge admin keys are the highest-value targets in DeFi.

**Dominant attack patterns:**
- Validator key compromise → forge cross-chain messages → mint unbacked tokens on destination
- Message replay: same message processed twice (missing nonce check or nonce overflow)
- Proof verification bypass: merkle proof or signature check has edge case that passes invalid proofs
- Chain ID confusion: message valid on chain A gets processed on chain B
- Reorg exploitation: deposit confirmed on source chain → relayed to destination → source chain reorgs → deposit reversed but destination tokens already minted

**Critical invariants:**
- Locked tokens on source chain = minted tokens on destination chain (1:1 backing)
- Every cross-chain message is processed exactly once (no replay)
- Message cannot be forged without validator threshold consensus
- Bridge accounting is consistent across chains (no cross-chain double-spend)

**What to look for first:**
1. Validator/relayer trust model: how many validators? What's the threshold? Can they be changed?
2. Message replay protection: is there a nonce? Is it checked correctly? Can it overflow?
3. Proof verification: merkle proof, signature scheme. Are there edge cases?
4. Finality assumptions: does the bridge wait for finality on source chain?
5. What can the admin do? Can they drain locked funds? Change validators instantly?

**Engine coverage (EVM):** `evm_cross_chain_replay_missing_chainid`, `evm_signature_replay_protection`, `evm_missing_signer_check`, `evm_public_relay`, `evm_bridge_address_cryptographic_verify`, `evm_dvn_threshold`, `evm_dvn_single_point_failure`, `evm_zero_challenge_period`, `evm_merkle_root_zero`, `evm_merkle_root_zero_default`, `evm_insufficient_multisig_threshold`. Registry precedents: badger-dao-2021, allbridge-2023, celer-bridge-2022. Reorg/finality handling has **no detector** — REASONED only.

---

### Governance

**Primary adversaries** (ranked):
1. **Flash loan governance attacker** — Borrows governance tokens via flash loan, votes on a proposal, and returns tokens in the same transaction. Only possible if voting power is measured at current block rather than a snapshot.
2. **Governance capture attacker** — Gradually accumulates voting power (buying tokens, borrowing from lending protocols, receiving delegations) to pass malicious proposals. Patient, multi-block attack with potentially massive payoff.
3. **Proposal spam / griefing attacker** — Submits many proposals to exhaust voter attention, or submits proposals that appear benign but have hidden malicious effects (e.g., "update parameter to X" where X causes insolvency).
4. **Timelock exploitation attacker** — Monitors queued proposals and positions to exploit parameter changes the instant they execute.
5. **Compromised admin/guardian** — Can cancel proposals, pause governance, or execute emergency actions that bypass normal governance flow.

**Dominant attack patterns:**
- Flash loan → vote → return: instant governance control if no snapshot
- Bribe attacks: pay token holders to delegate or vote for malicious proposals (via platforms like Votium)
- Proposal obfuscation: malicious calldata hidden in a seemingly-benign proposal
- Timelock front-running: position before queued proposal executes to profit from parameter changes
- Guardian abuse: emergency powers used to bypass governance for non-emergency purposes

**Critical invariants:**
- Voting power is snapshotted at proposal creation (not measured at vote time)
- Quorum requirements prevent minority capture
- Timelock provides sufficient delay for users to exit before parameter changes take effect
- No single role can bypass governance unilaterally for non-emergency actions
- Proposal calldata matches its description (can be verified on-chain)

**What to look for first:**
1. Voting power: snapshot or current balance? If current, flash loan attack is trivial.
2. Quorum and threshold: are they high enough to prevent capture? What's the token distribution?
3. Timelock: is the delay nonzero? Is it long enough for users to react?
4. What can governance control? List every parameter/action that goes through governance.
5. Emergency powers: who has them? What can they do? Can they drain funds?

**Engine coverage (EVM):** `evm_flash_loan_governance`, `evm_single_eoa_admin`, `evm_insufficient_multisig_threshold`, `evm_missing_pause_mechanism`, `evm_timestamp_dependence`. Registry precedents: beanstalk-2022, compound-governance-2020. Move: `move_admin_no_timelock`, `move_admin_transfer_single_step`. Solana: `sol_admin_no_timelock`. Quorum adequacy and proposal-calldata obfuscation have **no detector** — REASONED only.

# Temporal Threat Dimension

DeFi protocols have a lifecycle, and different threats dominate at different phases. This reference provides per-phase threat intelligence. The skill auto-detects which phases are relevant from code signals and includes the applicable phases in the threat model.

## Phase Detection

Detect which phases are relevant from code patterns found during Step 2 source reading:

| Phase | Include When |
|-------|-------------|
| **Deployment & Initialization** | Always include — every protocol has this phase |
| **Steady State** | Always include — this is the baseline |
| **Market Stress** | Oracle integration exists, OR liquidation logic exists, OR collateral/debt tracking exists, OR any price-dependent calculation |
| **Governance & Upgrade Windows** | Timelock exists, OR governance contract exists, OR proxy pattern (UUPS/transparent/beacon) exists, OR `propose()`/`vote()`/`execute()` functions exist, OR (Solana) program upgrade authority is not `None`, OR (Soroban) `update_current_contract_wasm` is reachable, OR (Sui) an `UpgradeCap` is held |
| **Deprecation & Wind-down** | V2/migration in contract names or comments, OR `migrate()` function exists, OR deprecated contract references, OR multi-version architecture |

---

## Phase 1: Deployment & Initialization

The most dangerous 24-48 hours. The protocol transitions from code to live system with real money. Attackers actively monitor deployment transactions.

### Threats

**Initialization front-running:**
Attacker watches the mempool for `initialize()` calls and front-runs with malicious parameters. Critical for UUPS proxies where `initialize()` sets the owner. Also applies to pool creation, market listing, and oracle setup. On Solana the analogue is an `initialize` instruction whose config PDA is derived from attacker-controllable seeds; on Soroban, an `initialize` that does not check `instance().has(&Admin)`; on Aptos, a `public entry fun init` instead of a private `init_module`.

What to look for: `initialize()` / `init()` functions without access control or without `initializer` modifier. Proxy deployment where `initialize` is called in a separate transaction from deployment. Pool/market creation that can be called by anyone. Engine: `evm_unprotected_initializer`, `evm_constructor_race_condition`, `sor_init_guard`, `sor_reinitialization`.

**Parameter misconfiguration:**
Protocol deployed with testing parameters still active. DELAY=0 in timelocks, test oracle addresses, overly permissive access control, dev-mode fee settings. The code is correct but the configuration creates the vulnerability.

What to look for: Hardcoded constants that look like test values (0 delays, max uint fees, known test addresses like 0xdead). Constructor/initializer parameters without validation. Default values that are insecure. Engine: `evm_zero_challenge_period`, `move_unbounded_parameter`.

**Ownership not transferred:**
Contract deployed with deployer EOA as owner, intended to transfer to multisig, but transfer hasn't happened yet. Creates a window where a single key controls everything.

What to look for: `Ownable` without `transferOwnership()` in deployment scripts. Two-step ownership transfer that hasn't been accepted. Role-based access where roles haven't been granted to the intended addresses. Solana: upgrade authority still the deployer keypair. Engine: `evm_single_eoa_admin`, `sol_treasury_single_authority`, `move_admin_transfer_single_step`.

**Empty-state exploitation:**
Protocols behave differently when empty. First depositor can manipulate share prices (vault inflation), set initial pool prices, or establish initial state that disadvantages subsequent users.

What to look for: `if (totalSupply == 0)` branches. Pool creation with attacker-chosen initial prices/ratios. Vault deposit when totalAssets == 0. Missing minimum initial deposit requirements. Engine: `evm_erc4626_inflation_protection`.

**Deployment ordering bugs:**
Contracts deployed in wrong order, missing approvals between contracts, circular dependencies not resolved, proxy pointing at wrong implementation.

What to look for: Deployment scripts with multiple transactions. Contracts that reference each other (circular setup). Approval chains (token approvals, role grants) that must happen in specific order.

---

## Phase 2: Steady State

Normal operation. This is where the existing adversary types (flash loan, MEV, external user, compromised admin) operate. The standard threat model covers this phase — no additional temporal-specific content needed. The protocol-type threat profiles provide the detailed guidance for this phase.

---

## Phase 3: Market Stress

Protocols that work perfectly in calm markets can break catastrophically during volatility. This phase accounts for some of the largest DeFi losses (LUNA/UST, cascading liquidations during Black Thursday).

### Threats

**Oracle latency under volatility:**
Oracle heartbeat periods (1h for some Chainlink pairs) mean prices can be stale during rapid market moves. Every calculation using that price is wrong for the duration. Borrowers can be liquidated at unfair prices, or worse, cannot be liquidated at all (stale price shows healthy position while real value is underwater).

What to look for: Chainlink `latestRoundData()` calls — what staleness threshold is used? Is it appropriate for the asset's volatility? Is the heartbeat period documented/configured or hardcoded? Is there a deviation threshold check? What happens if `updatedAt` is 0 or in the future? On Aptos/Sui: `pyth::get_price_unsafe` vs `get_price_no_older_than`. On Solana: is the Pyth/Switchboard account's `publish_time`/slot checked, and is the account key pinned? Engine: `evm_stale_oracle_price`, `move_oracle_stale_price`, `sol_oracle_rate_account`, `sor_thin_liquidity_oracle_price`.

**Liquidation cascade:**
Position A is liquidated → liquidation dumps collateral on market → price drops further → Position B is liquidated → cycle repeats. The protocol's own liquidation mechanism amplifies the crash. Can cause systemic insolvency.

What to look for: Liquidation mechanism — does it sell collateral on-market (creating price impact)? Is there a circuit breaker? Is liquidation throttled? Can the protocol handle 30%+ collateral price drops in a single block?

**Liquidity evaporation:**
During stress, LPs withdraw liquidity. Swaps have worse slippage. Liquidation bots can't efficiently swap collateral. Bad debt accumulates because liquidations become unprofitable at the gas + slippage cost.

What to look for: Liquidation profitability assumptions — are they valid when liquidity is thin? Does the protocol assume swap paths exist with sufficient depth? Is there a minimum liquidity requirement?

**Correlated asset depeg:**
Protocol assumes USDC = $1, stETH = ETH, wBTC = BTC. During stress, these correlations break. A lending protocol that treats stETH as equivalent to ETH suddenly has undercollateralized positions.

What to look for: Hardcoded price equivalences (1:1 assumptions). Missing oracle for derivative assets (using underlying asset's oracle instead). Collateral factors that don't account for depeg risk. Engine: `evm_lst_depeg`, `evm_synthetic_collateral_oracle`.

**Gas price spikes:**
Critical operations (liquidations, rebalancing, oracle updates) become prohibitively expensive. Time-sensitive operations fail to execute. Keepers and bots stop operating because gas cost exceeds profit. Solana analogue: compute-unit limits and priority-fee auctions; Sui: shared-object contention on a hot pool object.

What to look for: Gas-sensitive operations (keeper-dependent flows). Liquidation incentive vs. gas cost assumptions. Operations that must execute within a time window. Are there fallback mechanisms for keeper failure? Engine: `evm_unbounded_loop`, `evm_push_payment_in_loop`, `move_unbounded_vector_growth`.

**Withdrawal stampede:**
Many users try to withdraw simultaneously. If the protocol has limited liquid reserves (funds deployed in strategies, locked in positions), early withdrawers drain liquidity and late withdrawers are stuck.

What to look for: Withdrawal queues, rate limits. What percentage of TVL is liquid vs. deployed? Can strategies be unwound quickly? Is there a withdrawal fee that increases under stress (to discourage runs)?

---

## Phase 4: Governance & Upgrade Windows

Every governance action or upgrade creates a transient vulnerability window. The transition period between "old state" and "new state" is when exploits happen.

### Threats

**Timelock exploitation window:**
A governance proposal is queued with a known timelock delay. Everyone can see what parameters will change. Attackers position before execution to exploit new parameters immediately. Example: if collateral factor increases, max borrow the instant the timelock executes.

What to look for: Timelock durations — are they long enough for users to react? Can users exit positions before parameter changes take effect? Are there parameters that could be exploited if their pending value is publicly known?

**Upgrade storage collision:**
Proxy upgrade changes storage layout, corrupting existing state. Balances become wrong, ownership changes unexpectedly, access control breaks. The new implementation reads old storage through a different layout.

What to look for: UUPS `_authorizeUpgrade`, transparent proxy patterns. Is there storage gap usage? Are upgrades tested with the actual storage layout? Is there an upgrade validation step? Solana: account data layout changes without a version/discriminator migration; Soroban: `update_current_contract_wasm` with changed `DataKey` enum ordering. Engine: `evm_proxy_storage_collision`, `evm_upgrade_path_verification`, `sor_unprotected_upgrade`, `sor_no_unprotected_upgrade`.

**Flash loan governance:**
Attacker borrows governance tokens via flash loan, votes, and returns tokens in same transaction. Trivial if voting power is measured at current block. Some protocols are immune (snapshot-based voting), others are not.

What to look for: Voting power source — `balanceOf(msg.sender)` (vulnerable) vs. snapshot at proposal creation block (immune). Can governance tokens be borrowed from lending protocols? Engine: `evm_flash_loan_governance`.

**Governance capture (slow):**
Attacker accumulates voting power over time — buying tokens, receiving delegations, borrowing from Aave. Once threshold is reached, passes malicious proposals. The timelock is the last defense.

What to look for: Token distribution — is voting power concentrated? What's the quorum? Can a well-funded attacker buy enough tokens to pass proposals? Is there a guardian that can veto?

**Migration window:**
Protocol migrates from V1 to V2. During migration, funds are in transit. Approval chains exist between old and new contracts. Users who don't migrate lose access or face degraded conditions. The V1→V2 bridge is an attack target.

What to look for: Migration functions, V1→V2 transfer mechanisms. Do V1 contracts retain fund access? Is there a deadline? Can migration be front-run?

---

## Phase 5: Deprecation & Wind-down

Protocols don't live forever. When maintenance stops, a new class of threats emerges. Include this phase only when there's evidence of version transitions, deprecation markers, or multi-version architecture.

### Threats

**Residual funds in deprecated contracts:**
Old contracts still hold tokens but monitoring/maintenance has stopped. Keepers no longer run. Oracles go stale permanently. Any exploitable path in the old contract becomes a free-money opportunity with zero monitoring.

What to look for: Multi-version architecture. Are old versions still accessible? Do they still hold funds? Is there a forced migration mechanism?

**Abandoned approval chains:**
Users who interacted with V1 still have active token approvals to V1 contracts. If V1 has any exploitable path, those user approvals are a liability — attacker can drain user wallets through the deprecated contract. Solana analogue: SPL token delegates left approved to a deprecated program's PDA.

What to look for: Does the protocol use `approve()` (unlimited) or `permit()`? Is there a mechanism to revoke approvals during migration? Are users notified?

**Dependent protocol breakage:**
Other protocols that integrate with the deprecated protocol don't know it's deprecated. They continue calling functions that return stale data, empty results, or revert unexpectedly.

What to look for: Does this protocol serve as an oracle or data source for others? Is there a deprecation flag or kill switch that integrators can check?

**Frozen state exploitation:**
When governance stops or admin keys are lost, the protocol is frozen in its last configuration. Market conditions change but parameters can't be updated. Interest rates, collateral factors, oracle parameters all become increasingly stale. Soroban-specific: persistent entries whose TTL is no longer extended get archived, and instance storage expiry can brick the contract. Engine: `sor_storage_ttl_not_extended`, `sor_temporary_storage_critical_state`.

What to look for: What happens if no governance proposal passes for 6 months? Are there parameters that must be periodically updated? Is there an automated fallback?

---

## Writing the Temporal Risk Profile

In the output, include a "Temporal Risk Profile" subsection within Section 2. For each applicable phase:

1. **Name the phase** and state why it's relevant to this protocol
2. **List the specific threats** that apply (not all threats from every phase — only those where the code has the relevant patterns)
3. **Cite the code location** where the temporal risk exists
4. **Assess mitigation**: is the risk mitigated, partially mitigated, or unmitigated? When a detector covers the pattern, the mitigation verdict is `VERIFIED-STATIC` (cite the finding or its absence in `engine-findings.json`); otherwise it is `REASONED`.

Keep it concise — 2-4 bullets per applicable phase. Phase 2 (Steady State) is covered by the main threat model, so skip it in the temporal section to avoid duplication.

# Cross-Protocol Composability Threats

DeFi's unique property is composability — protocols interact with other protocols, creating emergent risks that don't exist in isolated analysis. This reference provides a systematic framework for identifying and documenting composability threats.

## External Call Classification

During Step 2 source reading, every external call is already extracted. This enhancement **classifies** each call into the composability threat taxonomy. For each external call found, determine:

1. **Target type**: Oracle, DEX/AMM, Lending pool, Yield protocol, Token, Governance, Bridge, Other
2. **Assumptions about return value**: What does this protocol assume the external call returns? (correct price, exact token amount, success, specific format)
3. **Validation present**: Does the code validate the return? (bounds check, staleness check, zero check, success check)
4. **Mutability of external behavior**: Can the external contract's behavior change without this protocol's consent? (upgradeable proxy? governed parameters?)
5. **Fallback on failure**: What happens if the external call fails? (revert, silent failure, fallback value, try/catch with fail-open?)

Chain mapping: an EVM external call ≙ a Solana CPI (`invoke`/`invoke_signed`/`CpiContext`) ≙ a Move cross-module call (any `use other_addr::module`) ≙ a Soroban `env.invoke_contract` / generated client call. The same five questions apply.

---

## Layer 1: Direct Dependency Risks

The protocol directly calls external contracts. These are visible in the code — every `interface` import and external call is a direct dependency.

### Oracle Dependency Chain

The protocol reads prices from an oracle. But that oracle aggregates from sources that can be manipulated.

**Threat**: Protocol → Oracle → underlying source(s). If any source in the chain is manipulable within the protocol's trust assumptions, the oracle is effectively manipulable.

**What to look for:**
- What oracle is used? (Chainlink, Uniswap TWAP, Pyth, Switchboard, custom)
- What's the oracle's aggregation method? (median of N sources, TWAP, VWAP)
- Staleness check: is `updatedAt` validated? What threshold? Is the threshold appropriate for the asset?
- Deviation check: is the returned price bounded against a reference? (e.g., within 5% of previous price)
- Zero/negative check: what happens if oracle returns 0?
- Sequencer uptime check: on L2s, is the sequencer uptime feed checked?
- Fallback oracle: if primary fails, is there a fallback? Is the fallback also validated?
- Can admin change the oracle address? Instantly or through timelock?
- Engine: `evm_oracle_spot_price`, `evm_stale_oracle_price`, `evm_oracle_self_trade`, `evm_unbounded_pricing_input`, `sol_oracle_rate_account`, `sol_oracle_self_trade`, `move_oracle_spot_price`, `move_oracle_stale_price`, `sor_thin_liquidity_oracle_price`.

### Yield Strategy Dependency

Protocol deposits funds into external yield protocols (Aave, Compound, Yearn, Convex, etc.).

**Threat**: The external protocol holds the actual funds. If it gets exploited, paused, or changes behavior, this protocol's funds are at risk. The strategy is the bridge between "our code" and "their code."

**What to look for:**
- What protocols do strategies deposit into? List each one.
- Is the external protocol upgradeable? By whom? Through what process?
- Can the external protocol pause withdrawals? Under what conditions?
- Does the strategy have emergency withdrawal capability?
- What happens if the strategy reports a loss? How is it socialized?
- Can new strategies be added? By whom? Instantly or through timelock?
- Does the old strategy retain approvals after migration?
- Are there reentrancy risks through the external protocol's callbacks?

### Token Behavior Assumptions

Every `token.transfer()`, `token.transferFrom()`, `token.balanceOf()` call carries implicit assumptions about token behavior.

**Threat**: The code assumes standard ERC20 behavior. Non-standard tokens break these assumptions silently — no revert, just wrong accounting.

**Assumption matrix** (check each for every token the protocol handles):

| Assumption | Standard Tokens | Violating Tokens | Impact if Violated |
|-----------|----------------|-----------------|-------------------|
| Transfer sends exact amount | ERC20 | Fee-on-transfer (USDT with fee, PAXG); SPL Token-2022 with TransferFee extension | Internal accounting > real balance, protocol becomes insolvent |
| Balance doesn't change without transfer | ERC20 | Rebasing (stETH, AMPL, aTokens); Token-2022 InterestBearing | Accounting drift, share price manipulation |
| Transfer always succeeds (or reverts) | ERC20 | USDT (returns false, no revert) | Silent transfer failure, lost funds |
| No callback on transfer | ERC20 | ERC-777, ERC-1155; Token-2022 TransferHook | Reentrancy through transfer callback |
| 18 decimals | Most tokens | USDC (6), WBTC (8), GUSD (2); Soroban SAC 7 | Math errors, massive over/under-valuation |
| Token can't block specific addresses | Most tokens | USDC, USDT (blacklist), cUSDC; Token-2022 PermanentDelegate / Soroban SAC clawback | Withdrawal blocked, funds trapped or clawed back |
| Token can't be paused | Most tokens | USDC, USDT; Token-2022 with freeze authority | All protocol operations blocked |
| Token is immutable | Most tokens | Upgradeable tokens (USDC proxy); Token-2022 mint with extension authorities | Behavior changes post-deployment without consent |
| No max supply cap affecting mint | Most tokens | Some algorithmic tokens | Deposit credited but tokens never arrive |
| The type is the token (Move) | — | Any `Coin<T>` accepted where `T` is unconstrained | Face value of a worthless coin credited as real (`move_unconstrained_type_argument`) |

**What to look for:**
- Does the code use `balanceOf(before) - balanceOf(after)` pattern? (handles fee-on-transfer)
- Does the code use SafeERC20? (handles non-reverting tokens)
- Are token decimals dynamic or hardcoded?
- Does the code handle rebasing token balance changes?
- Is there a token whitelist, or can arbitrary tokens be used?
- Engine: `evm_fee_on_transfer_incompatibility`, `evm_unchecked_returns`, `evm_token_balance_manipulation`, `sol_unchecked_token_account_type`, `move_unconstrained_type_argument`.

### Callback Reentrancy

External calls can trigger callbacks that re-enter the protocol before state is finalized.

**Threat**: Even with reentrancy guards on direct calls, callbacks through external protocols can bypass them. Token transfer → external protocol callback → re-enter through a different function.

**What to look for:**
- State changes after external calls (violating checks-effects-interactions)
- Reentrancy guards: are they per-function or global? Per-function guards don't protect cross-function reentrancy
- ERC-777 tokens: `tokensReceived` hook fires on transfer
- ERC-1155 tokens: `onERC1155Received` fires on transfer
- Aave/Compound flash loan callbacks
- Uniswap swap callbacks
- Vault deposit/withdraw that triggers strategy interaction which triggers external callback
- Soroban: cross-contract calls can re-enter the caller only if the callee calls back; the host forbids direct re-entry by default but state written before the call is still observable. Solana: CPI re-entry into the same program is blocked by the runtime (depth limit and self-recursion rules); the concern is stale account data read before a CPI and reused after.
- Engine: `evm_reentrancy_classic`, `evm_reentrancy_erc20`, `evm_readonly_reentrancy`, `evm_reentrancy_via_whitelisted`, `evm_reentrancy_protection`, `evm_state_mutation_ordering`, `sor_reentrancy_external_call`, `sor_no_reentrancy`. Dynamic (EVM): `truent fuzz --dynamic` auto-detects reentrancy.

---

## Layer 2: Shared State Risks

Two or more protocols interact with the same underlying state, creating indirect dependencies that are invisible in isolated code review.

### Liquidity Coupling

**Threat**: Protocol A and Protocol B both use the same Uniswap pool for swaps or pricing. A large action in Protocol A moves the pool price, affecting Protocol B's calculations within the same block.

**What to look for:**
- Does the protocol swap through public pools? Which ones?
- Do those pools have significant TVL relative to the protocol's swap sizes?
- Could a large liquidation in this protocol move a pool price enough to affect other protocols?
- Is the protocol itself a significant LP in pools that other protocols use?

**Example**: Protocol uses Uniswap ETH/USDC pool for liquidation swaps. Large liquidation dumps ETH into the pool, cratering the pool price. Another lending protocol uses the same pool's spot price as an oracle. Cascade.

### Oracle Sharing

**Threat**: Multiple protocols use the same oracle feed. A market event triggers liquidations across all of them simultaneously, creating correlated selling pressure and oracle feedback loops.

**What to look for:**
- Which oracle feeds does this protocol use?
- Are these the same feeds used by major lending/derivatives protocols?
- Could liquidations in this protocol create sell pressure that affects the oracle price?
- Could liquidations triggered by the oracle price in *other* protocols create sell pressure that triggers liquidations *here*?

### Approval Chain Exposure

**Threat**: Users grant token approvals to protocol contracts. If any approved contract has an exploitable path, user funds are at risk even if users never interact with the vulnerable function.

**What to look for:**
- Does the protocol request unlimited approvals? (`type(uint256).max`)
- Are approvals scoped to specific functions or broad?
- If the protocol is upgradeable, an upgrade could add a function that drains approved tokens
- Are there deprecated contracts that still hold user approvals?

---

## Layer 3: Temporal Composability Risks

External protocols change over time. This protocol's assumptions about them can silently become invalid.

### Governance-Induced Behavior Change

**Threat**: An external protocol's governance changes a parameter that this protocol's logic depends on. No contract interaction changed, but economic assumptions broke.

**What to look for:**
- Does this protocol assume specific parameter values from external protocols? (interest rates, collateral factors, fee tiers)
- Are external protocol parameters read dynamically or hardcoded?
- Would an external parameter change require this protocol to update its own parameters?

**Example**: Aave governance changes ETH collateral factor from 80% to 75%. A vault strategy that assumes 80% leverage ratio is now over-leveraged and at liquidation risk.

### Upgrade-Induced Interface Change

**Threat**: External protocol upgrades its implementation. Function signatures are the same, but behavior changes (gas cost, revert conditions, return values, side effects).

**What to look for:**
- Are external dependencies behind upgradeable proxies? (Solana: is the dependency program's upgrade authority set? Soroban: does the dependency contract expose an upgrade entrypoint? Sui: who holds its `UpgradeCap`?)
- Does this protocol's error handling account for behavior changes? (try/catch that assumes specific revert reasons)
- Are gas estimates hardcoded that could break if external protocol's gas usage changes?

### Deprecation Without Notification

**Threat**: External protocol deprecates an oracle feed, a pool, or an endpoint. The call doesn't revert — it returns stale/wrong data silently. Or it starts reverting, and this protocol's try/catch falls through to an unsafe default.

**What to look for:**
- Are there freshness checks on all external data sources?
- What's the try/catch fallback behavior? Does it fail-open (use stale data) or fail-closed (revert)?
- Is there monitoring for external dependency health?

### Dependency-of-Dependency Upgrade

**Threat**: This protocol uses Protocol A, which uses Protocol B. Protocol B upgrades. Protocol A's behavior changes. This protocol's behavior changes. No visibility into the root cause.

**What to look for:**
- Map the full dependency chain (2-3 levels deep). For each level:
  - Is it upgradeable?
  - Is it governed?
  - Can its behavior change without this protocol's knowledge?
- The deeper the chain, the less control this protocol has. Flag chains deeper than 2 levels.
- Engine (repository level): `truent deps --format json` reports unpinned / unlocked / advisory-matched packages (`sca_unpinned_dependency`, `sca_missing_lockfile`, `sca_vulnerable_dependency`, `sca_unmaintained_dependency`, `sca_dependency_confusion`, `sca_typosquat_candidate`). That is the *build-time* dependency chain; the on-chain chain above is still traced by hand.

---

# Chain-Specific Threat Dimensions

The protocol-type profiles above describe *what the protocol does*; this section describes *what the platform lets an attacker do*. Apply the section for every chain detected in Step 1 (mixed repos apply several). Each subsection follows the same discipline as the profiles: detection signals → adversaries → attack patterns → critical invariants → what to look for first → engine coverage. Detector ids are those Truent ships (see `web/lib/catalog.json` / `truent taxonomy --chain <chain>`); "no detector" means the concern is REASONED-only and must be labelled so in the report.

## Solana (Anchor and native)

**Detection signals:** `#[program]` module, `Context<T>` handlers, `#[derive(Accounts)]` structs, `Signer<'info>`, `AccountInfo<'info>` with `/// CHECK:` comments, `has_one =`, `seeds = […]`, `bump`, `invoke` / `invoke_signed` / `CpiContext`, `lamports()` arithmetic, `Rent::get()`, `Clock::get()` vs `Clock::from_account_info`, `sysvar::instructions`, `anchor_spl::token`, `Token2022`, `durable nonce` / `advance_nonce_account`, `bpf_loader_upgradeable`.

**Primary adversaries** (ranked):
1. **Account substitution attacker** — Passes a different account than the program expects (wrong owner, wrong type, wrong PDA, a lookalike sysvar) where the program does not validate it. The Solana account model puts the burden of validation on the program; every unchecked `AccountInfo` is a free parameter for the attacker.
2. **Missing-signer exploiter** — Calls an instruction that mutates or moves value on behalf of an authority that is only passed as `AccountInfo`, never as `Signer`. No signature is required, so anyone can act as anyone.
3. **CPI confused-deputy** — Gets the program to `invoke_signed` with its PDA authority against an attacker-chosen target program or with attacker-controlled accounts, turning the program's own signing power against it.
4. **Rent / lamport drainer** — Moves lamports out of program-owned accounts below rent-exemption, so the runtime garbage-collects them, or exploits accounts that are closed without zeroing data and can be revived in the same transaction.
5. **Upgrade-authority holder** — Whoever holds the program's upgrade authority can replace the program bytes atomically. This is the admin key of Solana; a hot-wallet upgrade authority is a single-EOA admin.

**Dominant attack patterns:**
- Instruction with `authority: AccountInfo` instead of `Signer` → anyone withdraws from any vault (corpus: `missing_signer.rs`)
- Unvalidated account owner/type → attacker passes a fake `TokenAccount` or a mint with their own authority; program reads attacker-written data as trusted state
- PDA seeds derived from attacker-controlled inputs, or bump not pinned (`bump` without `= stored_bump`) → canonical-bump bypass, duplicate "unique" accounts
- Sysvar read via `from_account_info` on an unchecked account → fake `Clock`/`Rent`/`Instructions` data (corpus: `raw_sysvar.rs`)
- Lamport transfer without a rent-floor check → account purged, state lost (corpus: `drain_below_rent.rs`)
- Durable-nonce transactions replayed or reordered around a price move, signature verified against a nonce account the program never validates
- Oracle price account (Pyth/Switchboard) key not pinned in the accounts struct → attacker supplies a stale or fabricated price account
- Single-keypair treasury authority signing SPL transfers directly (corpus: `single_authority_treasury.rs`)
- Same instruction, two different account-set orderings (`remaining_accounts` iterated without validation) → duplicate mutable account aliasing

**Critical invariants:**
- Every account that gates a privileged path is a `Signer` or is bound via `has_one` / `constraint` to one
- Every account the program reads is validated for owner and discriminator (`Account<'info, T>` / `Program<'info, T>`) or is a documented `/// CHECK:` with the reason
- Every PDA is derived from fixed seeds with a pinned bump and re-derived on every use
- No program-owned account's lamports fall below `Rent::minimum_balance(data_len)` unless it is being closed and its data zeroed
- Sysvars come from `Sysvar::get()` or a `Sysvar<'info, T>` typed account, never from raw `AccountInfo`
- SPL token accounts used for value are typed (`Account<'info, TokenAccount>`) and their `mint` / `owner` constrained
- The program's upgrade authority is a multisig or `None` (immutable) (per deployment, not per code — state as `could not determine` unless a deploy script or Anchor.toml shows it)

**What to look for first:**
1. Every `#[derive(Accounts)]` struct: list each field, its type (`Signer` / `Account<T>` / `AccountInfo` / `UncheckedAccount` / `Program` / `Sysvar`) and its constraints. Unconstrained `AccountInfo` fields on value-moving instructions are the top surface.
2. Every `invoke_signed` / `CpiContext::new_with_signer`: which PDA signs, which program is the target, is the target program id constrained?
3. Every `lamports()` write: is there a rent floor or a close-and-zero?
4. Every oracle account: is the pubkey constrained (`address = PYTH_FEED`) and is freshness checked?
5. Every `init` / `init_if_needed`: who pays, can it be re-run, is `init_if_needed` reachable with attacker-chosen seeds?

**Engine coverage (Solana):** `sol_missing_signer`, `sol_signer_checks`, `sol_account_validation`, `sol_pda_derivation`, `sol_pda_authority_validation`, `sol_rent_exemption`, `sol_rent_exemption_check`, `sol_lamport_balance`, `sol_sysvar_account_validation`, `sol_fake_sysvar_instruction_account`, `sol_instruction_parsing`, `sol_integer_overflow`, `sol_durable_nonce_validation`, `sol_unchecked_token_account_type`, `sol_oracle_rate_account`, `sol_oracle_self_trade`, `sol_treasury_single_authority`, `sol_admin_no_timelock`. Dynamic: `truent fuzz <idl.json> --dynamic --chain solana --plan plan.json` accepts only `token_conservation` and `account_owner` invariants, and in truent 0.6.0 it **validates the IDL and plan and then stops** ("this release cannot execute them … the dynamic Solana backend is deferred to a later version") — no Solana invariant can be `VERIFIED-PROVEN` by the engine yet; label the outcome `validated plan (execution deferred)`. **No detector** for: CPI target-program pinning, `remaining_accounts` aliasing, Token-2022 extension behaviour, upgrade-authority holder — REASONED only.

---

## Move / Aptos

**Detection signals:** `module addr::name { … }` with `acquires`, `borrow_global` / `borrow_global_mut<T>(@addr)`, `move_to(signer, …)`, `&signer` parameters, `signer::address_of`, `public entry fun` vs `public fun` vs `entry fun` vs `fun`, `friend`, `SignerCapability` / `account::create_signer_with_capability`, `resource_account`, `aptos_framework::randomness` with `#[randomness]`, `timestamp::now_seconds`, `coin::` / `fungible_asset::`, `object::` / `ExtendRef` / `TransferRef`, `pyth::get_price_unsafe`, `managed_coin`, `code::publish_package_txn`.

**Primary adversaries** (ranked):
1. **Global-storage writer** — Any `public entry fun` that does `borrow_global_mut<Config>(@module_addr)` without checking `signer::address_of(account) == stored_admin` lets every account rewrite protocol-wide state (corpus: `aptos_unguarded_set_fee.move`, `aptos_unguarded_withdraw.move`).
2. **Capability collector** — Obtains a privileged resource (`AdminCap`, `MintCapability`, `SignerCapability`) because a public function `move_to`s it to the caller or returns a signer derived from it (corpus: `aptos_cap_move_to_caller.move`, `aptos_signer_leak.move`).
3. **Randomness composer** — Calls a `public` randomness function from another module inside a transaction that aborts on an unfavourable outcome, retrying for free (corpus: `aptos_randomness_public.move`).
4. **Stale-price consumer** — Reads `pyth::get_price_unsafe` (no age bound) and trades at yesterday's price (corpus: `aptos_stale_pyth.move`).
5. **Instant admin** — The admin key is correct but its actions (`set_oracle`, `set_fee`, `set_admin`) take effect immediately and single-step, so a compromised or mistyped admin is unrecoverable (corpus: `aptos_admin_no_timelock.move`, `aptos_single_step_admin.move`).

**Dominant attack patterns:**
- `public entry fun withdraw(amount)` with no `&signer` and no admin check → anyone drains the module-address treasury
- `public fun get_resource_signer(): signer` → the protocol's own resource-account signer handed to every caller
- `public entry fun become_admin(account: &signer) { move_to(account, AdminCap{…}) }` → self-service admin
- `#[randomness] public entry fun roll(...)` composable from an attacker module → test-and-abort
- Math `(a / b) * c` → truncation scaled up; `u64` arithmetic without `checked_*` aborts (DoS) rather than wraps — abort-on-overflow is itself an availability surface in payout loops
- `vector` grown by anyone, walked by everyone → gas-exhaustion DoS
- `init_module` logic exposed as `public entry fun initialize` → re-initialisation or front-run initialisation

**Critical invariants:**
- Every write to a resource stored at `@module_addr` is gated on `signer::address_of(account) == admin` (or a capability the caller must already hold)
- No `public`/`public entry` function returns a `signer` or `move_to`s a capability to an arbitrary caller
- Capability structs lack `store` unless transferability is intended and documented
- Randomness-consuming functions are `entry fun` (private), never `public`
- Every oracle read has a max-age check (`get_price_no_older_than` or explicit `publish_time` compare)
- Admin parameter changes go through a pending value + `timestamp::now_seconds() >= effective_at` gate; admin transfer is two-step (`pending_admin` then `accept`)
- User funds are keyed by the caller's own address (`move_to(user, …)`), not aggregated at `@module_addr` without per-user accounting

**What to look for first:**
1. `grep -n 'public entry fun\|public fun'` — for each, does the body `borrow_global_mut` at `@module_addr`? If yes, where is the signer check?
2. Every `move_to(` and every function returning `signer` or a `*Cap`/`*Ref` — who receives it?
3. Every `struct … has` line for capabilities — `store`? `copy`? `drop`?
4. Every `randomness::` call — function visibility?
5. Every `pyth::` / oracle call — `_unsafe` variant?

**Engine coverage (Move):** `move_access_control`, `move_access_control_missing`, `move_signer_requirement`, `move_privileged_handle_exposed`, `move_capability_transferred_to_caller`, `move_capability_with_store`, `move_randomness_public_function`, `move_weak_randomness`, `move_oracle_stale_price`, `move_oracle_spot_price`, `move_admin_no_timelock`, `move_admin_transfer_single_step`, `move_divide_before_multiply`, `move_integer_overflow`, `move_manual_overflow_check`, `move_unbounded_parameter`, `move_unbounded_vector_growth`, `move_resource_leaks`, `move_type_safety`. Dynamic: `truent fuzz --dynamic` **errors** for `--chain move` ("Move/Soroban need their own execution backends, not yet built") — route executable checking to the Move Prover (`aptos move prove`) and `aptos move test`, and label results `EXTERNAL`. **No detector** for: `init_module` vs public initialiser confusion, `fungible_asset` ref misuse, `object::ExtendRef` leakage — REASONED only.

---

## Move / Sui

**Detection signals:** `module addr::name;` (2024 edition) or `module addr::name { … }`, `public struct … has key`, `UID`, `object::new(ctx)`, `transfer::share_object` / `transfer::transfer` / `transfer::public_transfer` / `transfer::freeze_object`, `&mut TxContext`, `ctx.sender()`, `Coin<T>` / `Balance<T>`, `coin::take` / `balance::join`, `phantom` type parameters, `sui::random`, `UpgradeCap`, `Clock`, PTB-composable `public fun` returning structs without `drop` (hot potatoes), `sui::event`.

**Primary adversaries** (ranked):
1. **Shared-object mutator** — A shared object can be passed `&mut` by any transaction; every `public fun f(p: &mut SharedThing, …)` without a capability parameter is a permissionless admin function (corpus: `sui_unguarded_shared_setter.move`, `sui_unguarded_withdraw.move`).
2. **Capability forger / launderer** — Gets an `AdminCap` because `init` (or a public function) transfers it to `ctx.sender()` of an attacker-called function, or because the cap `has store` and can be wrapped and moved (corpus: `sui_cap_to_caller.move`, `sui_cap_with_store.move`).
3. **Hot-potato dropper** — A receipt struct that should force repayment `has drop` (or `store`), so the borrower simply discards it (corpus: `sui_hot_potato_drop.move`).
4. **Type-argument spoofer** — Calls `deposit<T>` with a worthless `Coin<T>` of their own mint, and the ledger credits face value (corpus: `sui_fake_token_deposit.move`).
5. **PTB composer** — Chains `public fun`s in one programmable transaction block, observing intermediate returns and aborting unless favourable — the Sui form of the randomness/flash test-and-abort (corpus: `sui_randomness_public.move`).

**Dominant attack patterns:**
- `public fun set_paused(p: &mut Pool, paused: bool)` on a shared `Pool` → anyone pauses/unpauses
- `public fun withdraw(v: &mut Vault, amount, ctx)` with no `_: &AdminCap` → anyone withdraws
- `AdminCap has key, store` → wrapped into another object and sold/transferred, or `public_transfer`red by a hostile holder
- Flash-loan `Receipt has drop` → borrow without repaying
- `deposit<T>(ledger, Coin<T>)` with no `T` witness/whitelist → fake-token deposit
- `swap` that moves balances with an externally computed `amount_out` and never checks `x*y` (corpus: `sui_swap_no_invariant.move`)
- `(amount / total) * supply` → truncation scaled (corpus: `sui_divide_before_multiply.move`); manual `& 0xFFFF…` overflow masking instead of abort (corpus: `sui_manual_overflow_mask.move`)
- `vector<address>` appended by anyone, walked in payout → DoS (corpus: `sui_unbounded_vector.move`)
- `sui::random` consumed in a `public fun` → PTB test-and-abort
- `UpgradeCap` held by a hot wallet, or `public fun` that `authorize_upgrade`s

**Critical invariants:**
- Every `&mut SharedObject` mutation on a privileged path takes a capability reference (`_: &AdminCap`) or checks `ctx.sender()` against stored state
- Capability objects have `key` only (no `store`) unless transferability is a documented feature; they are created in `init` and transferred to a known address, never to `ctx.sender()` of a public function
- Hot-potato structs have **no** abilities (`public struct Receipt { … }`)
- Generic value entry points constrain `T` (witness pattern, registered-type table, or `phantom` matched to the pool)
- AMM invariants are asserted after the balance moves, in the same function
- Randomness- and price-consuming functions are `entry fun` (non-composable) or guard against same-PTB observation
- Every arithmetic path multiplies before dividing and relies on abort-on-overflow, never on masking

**What to look for first:**
1. Every `transfer::share_object(` — the shared types. Then every `public fun` taking `&mut ThatType` — what gates it?
2. Every `has key, store` struct with `Cap`/`Auth`/`Admin` in the name.
3. Every struct returned from a `public fun` — list its abilities; a receipt with `drop` is a bug.
4. Every generic `<T>` on a value-moving function — how is `T` constrained?
5. Every `init(` — where do the created capabilities go?

**Engine coverage (Move):** same detector set as Aptos — `move_access_control_missing`, `move_capability_transferred_to_caller`, `move_capability_with_store`, `move_hot_potato_has_abilities`, `move_unconstrained_type_argument`, `move_liquidity_conservation`, `move_divide_before_multiply`, `move_manual_overflow_check`, `move_unbounded_vector_growth`, `move_randomness_public_function`, `move_weak_randomness`, `move_oracle_spot_price`, `move_oracle_stale_price`, `move_resource_leaks`, `move_type_safety`. Dynamic: `--dynamic --chain move` **errors**; route to `sui move test` and the Sui prover as `EXTERNAL`. **No detector** for: `UpgradeCap` custody, PTB-level composition of *non-random* reads, `transfer::freeze_object` misuse, `Clock` staleness — REASONED only.

---

## Soroban (Stellar)

**Detection signals:** `#![no_std]`, `use soroban_sdk::{contract, contractimpl, …}`, `#[contract]` struct, `#[contractimpl] impl`, `pub fn f(env: Env, …)`, `Address::require_auth()` / `require_auth_for_args`, `env.storage().instance()` / `.persistent()` / `.temporary()`, `extend_ttl`, `DataKey` enums with `#[contracttype]`, `env.deployer().update_current_contract_wasm`, `env.invoke_contract` / generated `Client`, `token::Client` / `StellarAssetClient`, `i128` arithmetic with or without `checked_*`, `panic!` / `panic_with_error!`, `env.ledger().timestamp()` / `sequence()`.

**Primary adversaries** (ranked):
1. **Unauthenticated caller** — Soroban has no implicit `msg.sender`; authorization exists only where the code calls `require_auth()` on the `Address` it is acting for. Any `pub fn` that moves value from `from` without `from.require_auth()` is callable by anyone for anyone (corpus: `missing_require_auth.rs`).
2. **Upgrader** — `update_current_contract_wasm` swaps the whole contract atomically. If the function that calls it is not gated on an admin `require_auth`, the contract is anyone's; if it is, the admin is a single point of failure.
3. **Re-initialiser** — `initialize` that does not check `instance().has(&DataKey::Admin)` lets a second caller replace the admin.
4. **TTL exploiter** — Persistent entries whose TTL is never extended get archived; instance storage that expires bricks the contract; temporary storage used for critical state (balances, admin) vanishes at the end of its TTL and can be re-created by anyone at default values.
5. **Arithmetic edge-case seeker** — `i128` math without `checked_*` panics on overflow (DoS) or, in `release` profiles with overflow checks disabled, wraps; negative amounts passed where the code assumes positive.

**Dominant attack patterns:**
- `pub fn transfer(env, from, to, amount)` with no `from.require_auth()` → anyone moves anyone's balance
- `pub fn upgrade(env, new_wasm_hash)` without `admin.require_auth()` → contract replacement
- `pub fn initialize(env, admin)` re-callable → admin takeover
- Balances stored in `temporary()` → state disappears; or `persistent()` without `extend_ttl` on the read/write path → archived entries make withdrawals fail
- `require_auth` called on the wrong `Address` (e.g., `to` instead of `from`), or `require_auth_for_args` with args that omit `amount`
- Cross-contract call to an attacker-supplied `Address` (contract id passed as a parameter) → callback into a contract that lies about balances
- Unchecked `from_bal - amount` with a negative `amount` → credits the sender
- `panic!` in a path that another contract composes → whole-transaction abort used as a griefing vector

**Critical invariants:**
- Every state mutation attributable to an `Address` is preceded by that address's `require_auth()` (or `require_auth_for_args` binding every value parameter)
- The upgrade entrypoint requires the stored admin's auth and the admin is a multisig or a governance contract (deployment fact — state `could not determine` if not visible)
- `initialize` is guarded by an `instance().has(&Admin)` (or equivalent) check
- Critical state lives in `instance()` (config) or `persistent()` (per-user) — never `temporary()`
- Every `persistent()` read/write extends TTL; instance TTL is extended on every call
- All `i128` arithmetic is `checked_*` (or the crate sets `overflow-checks = true` for release and the code accepts panics as the failure mode)
- Amounts are validated non-negative before use
- Contract addresses used for cross-contract calls are stored config, not caller-supplied

**What to look for first:**
1. Every `pub fn` in the `#[contractimpl]`: list which `Address` parameters exist and whether each has `require_auth()` before the first storage write.
2. `grep -n 'update_current_contract_wasm'` — gating?
3. Every `env.storage().temporary()` use — what is stored there?
4. Every `persistent().get`/`set` — is there a matching `extend_ttl`?
5. Every `-`, `+`, `*` on `i128` amounts — checked?

**Engine coverage (Soroban):** `sor_missing_require_auth`, `sor_require_auth_checks`, `sor_init_guard`, `sor_reinitialization`, `sor_unprotected_upgrade`, `sor_no_unprotected_upgrade`, `sor_storage_ttl_extended`, `sor_storage_ttl_not_extended`, `sor_temporary_storage_critical_state`, `sor_checked_arithmetic`, `sor_unchecked_arithmetic`, `sor_unhandled_panic`, `sor_reentrancy_external_call`, `sor_no_reentrancy`, `sor_thin_liquidity_oracle_price`. Dynamic: `--dynamic --chain soroban` **errors**; route executable checking to `cargo test` with `soroban_sdk::testutils` and label `EXTERNAL`. **No detector** for: `require_auth` on the wrong address, `require_auth_for_args` argument omission, caller-supplied contract addresses, negative-amount validation — REASONED only.

---

## Cross-chain mapping cheat-sheet

Use this when a profile above says "admin", "external call", "reentrancy" or "initializer" and the code is not Solidity.

| EVM concept | Solana | Move / Aptos | Move / Sui | Soroban |
|-------------|--------|--------------|------------|---------|
| `msg.sender` | the `Signer` accounts in the `Accounts` struct | `&signer` parameter (`signer::address_of`) | `ctx.sender()` | none — only `Address::require_auth()` |
| `onlyOwner` | `has_one = authority` + `Signer` | `assert!(address_of(s) == cfg.admin)` | `_: &AdminCap` parameter | `admin.require_auth()` |
| external call | CPI (`invoke_signed`, `CpiContext`) | cross-module `use` call | PTB step / cross-module call | `env.invoke_contract` / `Client` |
| upgradeable proxy | program upgrade authority | `code::publish_package_txn` (package upgrade policy) | `UpgradeCap` | `update_current_contract_wasm` |
| `initializer` | `#[account(init)]` instruction | `init_module` (private) | `fun init(ctx)` (private) | `initialize` + `instance().has` guard |
| storage variable | account data (rent-paying) | resource at address / object | owned or shared object | `instance` / `persistent` / `temporary` entry with TTL |
| reentrancy | blocked by runtime; stale-read-after-CPI instead | not possible (no dynamic dispatch) | not possible; PTB composition instead | host-blocked by default; callback-only |
| `block.timestamp` | `Clock::get()?.unix_timestamp` | `timestamp::now_seconds()` | `Clock` object | `env.ledger().timestamp()` |
| first-depositor / empty state | `init_if_needed` races | `init_module` idempotence | `init` runs once per publish | `initialize` re-entry |
