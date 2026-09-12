---
name: truent-ir
description: "On-chain incident response for a live or past smart-contract exploit. Scopes the damage from the exploit transaction, reproduces the attack against the deployed bytecode with Truent's revm-backed fuzzer to identify the exact broken invariant, and separates confirmed mechanism from speculation before anyone writes a post-mortem. Covers containment, evidence preservation, and the regression invariant that stops a repeat. Triggers on 'truent ir', 'we are being exploited', 'incident response', 'post-mortem', 'we got hacked', 'analyze this exploit tx', 'what went wrong on-chain'."
license: MIT
metadata:
  version: "0.1.0"
  author: geekstrancend
  homepage: https://github.com/geekstrancend/Truent
  domain: smart-contract-security
  subdomain: incident-response
  chains:
    - evm
    - solana
    - move
    - soroban
  requires:
    - "truent >= 0.6.0"
  taxonomy:
    - CWE
    - SWC
    - OWASP-SC-Top-10-2025
    - DASP
  tags:
    - smart-contract
    - incident-response
    - exploit-analysis
    - post-mortem
    - forensics
    - revm
    - root-cause
    - containment
---

# Truent IR

Work out what actually happened, with the engine rather than with a theory.

Post-mortems get written under time pressure by people who have been awake for
twenty hours, and the failure mode is always the same: a plausible mechanism
gets written down, repeated, and becomes the official story — and the real bug
is still live. Truent can execute the deployed bytecode. So the rule here is
that **the stated root cause must be one the engine reproduced**, and anything
else is labelled as hypothesis until it is.

`$SKILL_DIR` = the directory containing this SKILL.md.

- **`VERIFIED`** — reproduced against real bytecode, with the call sequence.
- **`REASONED`** — a hypothesis. Never written into the root-cause section.

## Before anything else

If the exploit is **ongoing**, containment beats analysis. Say so once, in one
line, and ask which the user wants first — do not silently start a forensic
pipeline while funds are leaving. Containment options to surface, in the order
they are usually available:

1. Pause/guardian function, if one exists and the key is reachable.
2. Withdraw remaining funds to a safe address, if an admin path allows it.
3. Revoke approvals and allowances the protocol granted to the drained contract.
4. Contact the chain's security channels and any bridge/CEX the funds are
   moving toward — this is the only step with a real deadline.

Then continue. Analysis with the bleeding stopped is a better analysis.

## Pipeline

### Phase 1 — Scope from the transaction (one message, parallel)

Inputs needed: at least one exploit transaction hash and an RPC endpoint. If
the user has neither, the earliest anomalous block and the affected contract
address will do.

1. `Bash`: pull the transaction and its trace.
   ```bash
   cast tx <tx-hash> --rpc-url <rpc>
   cast receipt <tx-hash> --rpc-url <rpc>
   cast run --trace-printer <tx-hash> --rpc-url <rpc> 2>&1 | head -200
   ```
   From the trace, record: entry point called, contracts touched in order,
   external calls made back into the protocol, and where value moved.
2. `Bash`: establish the blast radius.
   ```bash
   # Balance of the affected contract before and after
   cast balance <contract> --block <block-1> --rpc-url <rpc>
   cast balance <contract> --block <block>   --rpc-url <rpc>
   # Token balances, per affected token
   cast call <token> "balanceOf(address)(uint256)" <contract> --block <block-1> --rpc-url <rpc>
   cast call <token> "balanceOf(address)(uint256)" <contract> --block <block>   --rpc-url <rpc>
   ```
3. `Bash`: is the transaction the first, or the tenth? Scope the window.
   ```bash
   cast logs --address <contract> --from-block <block-500> --to-block latest --rpc-url <rpc> | head -100
   ```

**Preserve evidence now, before anything is patched or redeployed:** save the
raw trace, the receipts, and the affected block numbers to `incident/`. An RPC
provider can prune, and a fork endpoint can go away.

### Phase 2 — Reproduce against deployed bytecode

This is the step that separates this skill from a careful read of the trace.

```bash
truent fuzz --dynamic --address <contract> --rpc-url <rpc> --iterations 2000 --seed 1
```

Truent deploys the fetched bytecode into an in-memory EVM, drives adversarial
call sequences, and checks auto-detected invariants — conservation,
monotonicity, access control, reentrancy — after every call. When one breaks,
it shrinks the violation to the shortest sequence that triggers it.

- **If a violation reproduces:** that minimal sequence is the mechanism. It is
  `VERIFIED`. Compare it against the Phase 1 trace — if the shapes match, the
  root cause is established, not argued.
- **If nothing reproduces:** do not conclude the contract is fine. Raise
  `--iterations`, vary `--seed` (2, 3), and pin the fork to the exact
  pre-exploit block so the state matches:
  ```bash
  truent fuzz --dynamic --address <contract> --rpc-url <rpc> --iterations 20000 --seed 2
  ```
  If it still does not reproduce, the mechanism likely depends on state or
  actors outside this contract — a manipulated oracle, a flash-loan-sized
  balance, a second protocol. Say that; it is itself a finding about where to
  look next.

Also run the static pass over the deployed source, if verified:

```bash
truent scan <source> --chain <chain> --format json
```

A detector that already flagged this exact invariant before the exploit is the
most important line in the eventual post-mortem, and the most uncomfortable —
report it plainly either way.

### Phase 3 — Name the broken invariant

Every exploit is an invariant that was assumed and never enforced. Write it as
a property, not a narrative:

> `totalSupply` must equal the sum of all `balanceOf` — broken because
> `redeem()` burned shares after transferring the underlying, so a reentrant
> `deposit()` priced against a pool that had already paid out.

Then map it:

```bash
truent taxonomy --id <CWE or SWC from the reproducing detector>
```

so the post-mortem carries CWE, SWC, OWASP SC and DASP identifiers. Insurers,
exchanges and downstream integrators triage by those, not by prose.

### Phase 4 — Regression invariant

Turn the reproduced violation into a check that fails if the bug returns.
Write the invariant into the project's `.sinv` set and confirm it fails against
the vulnerable code and passes against the fix:

```bash
truent check <patched-src> --chain <chain> --fail-on medium
```

A fix that is not accompanied by a failing-then-passing check is a fix nobody
can prove.

### Phase 5 — Post-mortem

Write `incident/post-mortem.md`:

```
INCIDENT — <protocol> — <date>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Status        <contained | ongoing | funds recovered>
Loss          <amount, per asset, with the blocks it was measured between>
First tx      <hash> @ block <n>
Last tx       <hash> @ block <n>

Root cause  [VERIFIED — reproduced by truent fuzz, seed <n>]
  Broken invariant: <the property, stated as a property>
  Minimal reproduction:
    1. <call>
    2. <call>
    3. <call>   ← invariant violated here
  Taxonomy: CWE-xxx · <name> | SWC-xxx | SCxx | DASP-x

Timeline
  <block/time>  <what happened, from the trace — not from memory>

What did not cause it
  <hypotheses considered and ruled out, and how they were ruled out>

Detection gap
  <was this detectable before? did a detector flag it and get dismissed?>

Remediation
  <the fix, and the regression invariant that now guards it>

Open questions  [REASONED]
  <everything not reproduced. Explicitly not part of the root cause.>
```

The **What did not cause it** and **Open questions** sections are mandatory and
must be non-empty in any real incident. A post-mortem with no ruled-out
hypotheses is a post-mortem that stopped at the first plausible story.

## Rules

- Never state a root cause the engine did not reproduce. A hypothesis goes in
  **Open questions**, however confident it feels at 4am.
- Never write a loss figure without saying which blocks it was measured
  between and in which asset. "About $4M" ages into a number nobody can check.
- Never attribute the attack to a named individual, group, or address cluster.
  Report the addresses observed on-chain and stop there; attribution is a
  separate discipline with a much higher evidentiary bar.
- Do not draft public communications, user notices, or exchange disclosures
  unless the user asks — and if they do, keep the confirmed/unconfirmed split
  intact rather than smoothing it for the audience.
- Preserve evidence before remediation. A patched contract and a pruned RPC
  between them can make an incident permanently unanalysable.
