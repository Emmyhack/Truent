<!-- Adapted from pashov/skills solidity-auditor/references/judging.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine ground truth, three evidence tiers, multi-chain. -->
# Finding Validation

## The three evidence tiers

Every finding carries exactly one tier, and the tiers are never blurred:

- **`VERIFIED-PROVEN`** — the engine executed it: a dynamic fuzz violation with a minimal
  reproduction, a symbolic counterexample, or an engine violation with `evidence:"proven"`.
  Anyone who runs the Reproduce command gets it again.
- **`VERIFIED-STATIC`** — a compiled detector matched real code (`evidence:"lead"`).
  Deterministic and reproducible, but nothing executed it. It is a proven *pattern*, not a
  proven *exploit*.
- **`REASONED`** — a model proposed it and the engine could not verify it. It is reported,
  labelled, with what remained unverified.

Rank order everywhere — the run file, the ledger, the report — is severity first, then
`PROVEN > STATIC > REASONED`, then confidence.

**The tier is decided by what happened, never by how sure anyone is.** A model's confidence
never promotes a finding above `REASONED`. Only an engine reproduction does (Turn 4 step 3b,
`verification.md`). An engine block is never demoted, re-worded or dropped by a gate: it was
produced by shell from the engine's JSON, and the report prints it as the engine said it.

## Which gates a tier passes through

- **`VERIFIED-PROVEN` and `VERIFIED-STATIC` skip Gates 1–3.** The engine already
  demonstrated execution (PROVEN) or matched the code (STATIC); re-arguing reachability
  against a detector is a model defending code against a machine. They keep the engine's own
  severity and the confidence `scripts/engine.sh` derived from the engine's `exploitability`.
  Gate 4 is read for the write-up only when a REASONED finding is merged into an engine block,
  and it changes nothing in the block.
- **`REASONED` findings run all four gates**, in order, no skip, no reorder, no revisit after
  verdict. Then, if the finding names a checkable property, the engine gets the last word
  (`verification.md`): a reproduction promotes it to `VERIFIED-PROVEN`; a refutation demotes
  it to a Lead or drops it.

Every finding passes the gates below sequentially. Fail any gate → **rejected** or **demoted**
to lead. Later gates are not evaluated for failed findings.

You are not defending the code. The job of these gates is to verify the attacker's claimed
exploit actually fires end-to-end — anything that interrupts the attack between the attacker's
call and the harm means the agent's claim does not execute, and only then does it fail to
qualify as a finding.

## Gate 1 — Attack execution

Trace the agent's claimed attack path from caller to harm. Read every guard, check, modifier,
constraint and capability that sits on that path. Confirm that none of them interrupts the
attack before the exploit step fires.
- A specific guard / check / modifier / account constraint / capability parameter on the attack
  path interrupts the claimed exploit step before harm occurs (quote the exact line and trace
  it) → **REJECTED** (or **DEMOTE** if a related code smell remains)
- The supposed interruption is speculative ("probably wouldn't happen", "the caller would
  notice", "the deployer would set X", "the client would never pass that account") →
  **clears**, continue

Per chain, the guards that count are different things, and a later editor must not collapse
them to "modifier":
- EVM: `require`, modifiers, `nonReentrant`, access-control roles.
- Solana: `Signer<'info>`, `has_one`, `seeds`/`bump`, `owner =`, `constraint =`, the account
  *type* (`Account<'info, T>` deserialises and checks the owner; `AccountInfo` checks
  nothing), explicit `is_signer` / `owner` checks in a native program.
- Move: a `&signer` whose address is compared, a capability parameter, `public(friend)` /
  `public(package)` visibility, abilities on the struct (no `drop` on a hot potato, no `store`
  on a capability), `assert!` bounds.
- Soroban: `require_auth()` / `require_auth_for_args()` on the acting `Address`, the init
  guard, the storage tier the state lives in.

## Gate 2 — Reachability

Prove the vulnerable state exists in a live deployment.

- Structurally impossible (enforced invariant prevents it; the type system prevents it — a
  Move struct with no `drop` cannot be dropped, Move arithmetic cannot silently wrap) →
  **REJECTED**
- Requires privileged actions outside normal operation → **DEMOTE**
- Achievable through normal usage or common token / account behaviors → **clears**, continue

## Gate 3 — Trigger

Prove an unprivileged actor executes the attack.

- Only trusted roles can trigger → **DEMOTE**
- Unprivileged actor triggers profitably → **clears**, continue

**Admin-action findings — reject unless an unprivileged amplifier is named.** This applies
ONLY to actions performed by admin/owner/upgrade authority, NOT to unprivileged attacker
actions. If the harm requires the admin acting maliciously or against documented intent,
**REJECT** — do not even emit as a LEAD (stricter than the DEMOTE above). The finding clears
only when the body names a concrete unprivileged amplifier:

- **race** — admin sets X mid-flow; an unprivileged user exploits the window before the update
  propagates.
- **retroactive sweep** — an admin update rewrites a pending value already credited.
- **asymmetric formula** — admin output chains into a formula an unprivileged actor profits from.
- **access gap** — missing guard, tautological auth, missing signer, missing init guard, a
  capability that leaked to a caller (the access mechanism itself is the bug).

No amplifier named → **REJECTED**. Amplifier named → judge it on that unprivileged path.

**The engine is exempt from this rule and it stays exempt.** `evm_single_eoa_admin`,
`sol_treasury_single_authority`, `move_admin_no_timelock` and the like are admin-structure
detectors: the engine reports them as `VERIFIED-STATIC` with its own severity and
exploitability, and this gate does not run on them. The gate exists to stop a model from
inventing "admin can rug" prose; a deterministic detector with a fix and a verify step is not
that.

## Gate 4 — Impact

Prove material harm to an identifiable victim.

- Self-harm only → **REJECTED**
- Dust-level, no compounding → **DEMOTE**
- Material loss to identifiable victim → **CONFIRMED**

Gate 4 also fixes the **severity** of a REASONED finding, which the agent proposed and this gate
settles: `critical` — unprivileged theft or permanent loss of most funds; `high` — unprivileged
theft or freeze of a bounded but material amount; `medium` — loss that needs a specific state
or a privileged amplifier; `low` — bounded, non-compounding loss. Severity is the first sort
key, so it is written once here and never re-argued in the run file.

## Confidence

Start at **100**, deduct: partial attack path **-20**, bounded non-compounding impact **-15**,
requires specific (but achievable) state **-10**. Confidence ≥ 75 gets description + fix.
Below 75 gets description only.

**The threshold is 75, and it is set here.** `report-formatting.md` and `scripts/assemble.sh`
read it from this line and state it nowhere else. It is 75 and not 80 because the three
lead-promotion rules below all land a promoted lead at exactly 75: at a threshold of 80 every
cross-contract echo, every multi-agent convergence and every completed partial path would be
promoted to a finding and then printed with no **Fix** block. Moving this number means moving
those three, or the promotions stop being worth making.

Engine blocks carry a confidence derived from engine data, not from this scale:
`VERIFIED-PROVEN` is 100; `VERIFIED-STATIC` is 95 / 90 / 85 / 80 for exploitability
`likely` / `possible` / `unlikely` / `theoretical`. All of them clear 75, so every engine
block carries the engine's Fix and Verify text. A REASONED finding the engine reproduces in
Turn 4 becomes `VERIFIED-PROVEN` at 100.

## Safe patterns (do not flag)

EVM:
- `unchecked` in 0.8+ (but verify the reasoning is correct)
- Explicit narrowing casts in 0.8+ (reverts on overflow)
- MINIMUM_LIQUIDITY burn on first deposit
- SafeERC20 (`safeTransfer`/`safeTransferFrom`)
- `nonReentrant` (only flag cross-contract attacks)
- Two-step admin transfer
- Consistent protocol-favoring rounding unless compounding or zero-rounding

Solana / Anchor:
- `Signer<'info>` on the authority plus `has_one = authority` on the account it governs
- `seeds = [...], bump` on a PDA the program re-derives (and `bump = account.bump` on reuse)
- `Account<'info, T>` / `Program<'info, Token>` / `Sysvar<'info, Rent>` typed accounts (they
  check owner and discriminator; a bare `AccountInfo` is the smell, not these)
- `checked_*` arithmetic, or `overflow-checks = true` in the release profile
- `init` with `payer` and `space` computed from the struct

Move:
- Arithmetic that aborts on overflow — Move never wraps silently; a manual mask or a
  hand-rolled overflow check is the smell, not the plain `+`
- A capability struct declared with `key` only (Sui) and created only in `init` /
  `init_module`
- A hot potato struct with no abilities at all
- `public(friend)` / `public(package)` on internal entry points
- `assert!(signer::address_of(s) == @admin)` or a `&AdminCap` parameter on privileged
  functions
- `#[randomness]` on a private `entry fun` (Aptos)

Soroban:
- `require_auth()` on the acting address before the state change
- An init guard on an instance-storage flag
- `persistent` / `instance` storage with `extend_ttl` on access for state that must survive
- `checked_*` arithmetic on `i128`
- Soroban's default prohibition of reentrancy (only flag when the contract re-enables it or
  reads its own state after a cross-contract call that could call back through a third party)

## Lead promotion

Before finalizing leads, promote where warranted:

- **Cross-contract echo.** Same root cause confirmed as FINDING in one contract / program /
  module → promote in every one where the identical pattern appears.
- **Multi-agent convergence.** 2+ agents flagged same area, lead was demoted (not rejected) →
  promote to FINDING at confidence 75.
- **Partial-path completion.** Only weakness is incomplete trace but path is reachable and
  unguarded → promote to FINDING at confidence 75, **description only — a deliberate exception
  to the threshold**. 75 clears the line, so this finding would otherwise carry a **Fix**
  block; it does not, because the trace it would fix was never completed. The other two
  promotions above take their **Fix** block normally.
- **Engine reproduction.** The lead named a property and the engine broke it → `FINDING`,
  `VERIFIED-PROVEN`, confidence 100, the engine's reproduction pasted as proof. This is the
  only promotion that changes a tier, and it is the machine's, not the model's. In truent
  0.6.0 only the EVM engine can do it (revm fuzzing, symbolic counterexamples); the Solana
  plan path validates and stops, and Move / Soroban have no backend.

All three model promotions land at `REASONED`. A promoted lead is still a claim nobody executed.

## Leads

High-signal trails for manual investigation. No confidence score, no fix — title, code smells,
and what remains unverified. Every lead is `REASONED` by definition; a lead the engine
verifies is not a lead any more. A lead that names a `property` the engine could not run (no
ABI shape, a constructor with arguments, a relative import, a Solana plan the engine validated
but cannot execute in this release, no backend on Move / Soroban) says so in its "what remains
unverified" clause.

## Do Not Report

Linter/compiler issues, gas micro-opts, naming, NatSpec, missing events. Admin privileges by
design. Centralization without exploit path. Implausible preconditions (but fee-on-transfer,
rebasing, blacklisting ARE plausible for EVM contracts accepting arbitrary tokens; an
unconstrained generic `T` IS plausible on Move; a client that passes the wrong account IS
plausible on Solana — the program is the only thing that checks). Anything already in the
engine's block list unless reached by a different mechanism or with a wider impact — the
engine's finding stands and the repeat is merged into it (`dedup-and-assembly.md` step 1).
