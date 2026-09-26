<!-- Adapted from pashov/skills solidity-auditor/references/hacking-agents/shared-rules.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine ground truth, three evidence tiers, multi-chain. -->
# Shared Scan Rules

## Bundle contents

Your bundle is concatenated files, in this order: all in-scope source code; the **engine findings** (what Truent's compiled detectors already proved or matched — shell-rendered, one block per violation); one **chain primer** per chain in scope (execution model, trust boundaries, where each specialty hunts on that chain, the engine's detector ids, the corpus bug shapes); the SOP (HOW to think); your specialty agent (WHAT to look for); these shared rules (output format, dedup tags, AND mandatory mental tool protocol); and the report language rules (HOW to word a finding). When memory is on it ends with the known findings from earlier scans.

Read the whole bundle once at the start. The bundle contains all in-scope source. Use Read/Grep only for cross-file searches or out-of-scope context (interfaces/, lib/, mocks/, test/, tests/, target/, framework crates) — do not re-read in-scope files for the initial scan.

**The protocol below applies continuously during source reading — not just before it.** The "read source" phase does not turn off the protocol; every trigger condition fires the moment it occurs, throughout your entire review.

When matching function names, check both `functionName` and `_functionName` (Solidity convention), `name` and `name_internal` / `do_name` (Rust and Move conventions), and an Anchor instruction against its `#[derive(Accounts)]` context struct.

## The engine came first — MANDATORY

The section "Engine findings" in your bundle is ground truth. Every block in it is `VERIFIED-STATIC` (a compiled detector matched the code) or `VERIFIED-PROVEN` (the engine executed it). Three rules:

1. **Do not re-derive an engine finding.** Reporting `sol_missing_signer` on the same instruction the engine already flagged, in your own words, is wasted work and a duplicate the orchestrator will merge away.
2. **Do not treat the list as a boundary.** An engine finding names one line and one detector. Ask what the detector cannot see: the second path to the same state, the economic consequence, the chain of two listed bugs that is worse than either. When you extend an engine block, say which one (`extends: <invariant_id>` in your item).
3. **Do not treat an empty list as clean.** The detectors encode known shapes. Everything bespoke is yours.

## Mental tool protocol — MANDATORY

The three tools in `senior-auditor-sop.md` are NOT optional. Each tool has a specific trigger. **When the trigger fires, you MUST emit the corresponding marker in your output stream BEFORE continuing.** No skipping. The markers live in your working text — they do NOT go into the FINDING/LEAD output blocks.

### Triggers → required markers

| Trigger (the condition) | Marker (required immediately, literal `[Tool: ...]` syntax) | Content |
|---|---|---|
| You open a new function, contract, program, module or instruction to read | `[Feynman: <name>]` | Explain what it does in plain English — no language jargon, no `mload`/`assembly`/`safeTransfer`/`invoke_signed`/`borrow_global_mut`/`require_auth`/etc. Use as many sentences as you need until the explanation is solid. If your wording slips back to jargon, you're papering over an assumption — keep going. Wherever your plain-English explanation gets fuzzy or you have to reach for a technical term to keep it accurate, mark that spot — that is where bugs hide. |
| You stop on a line whose purpose isn't immediately clear | `[Socratic: <file:line> — why?]` | A one-line question that drills past "because that's how it's written." If your first answer is a restatement of the code, ask again. Stop when the answer exposes the implicit belief the code rests on — don't pad with extra steps just to hit a quota. |
| A code path reads as clean / a check looks sufficient / a guard, constraint or capability looks correct | `[Inversion: <function>]` | Three concrete attacker moves that attempt to defeat the path. Specific addresses/accounts/values/states/type arguments, not abstractions. |

### Rules

1. **Triggers are not optional.** If the condition fires, the marker follows. Always. No skipping.
2. **Use the literal `[Tool: ...]` syntax.** The orchestrator greps your output for these tags after the run.
3. **You may emit a marker without a trigger.** Extra Feynman / Inversion markers are fine. You may NOT skip a marker after its trigger fired.
4. **The protocol applies to reasoning depth, not output volume.** Heavy use of these tools is what produces the audit work. Skipping them = surface-level scanning, which is the failure mode of every junior auditor.

The orchestrator verifies marker counts after every run. Skipped markers downgrade the value of your findings and are recorded as workflow violations.

## Cross-contract patterns

When you find a bug in one contract, program or module, **weaponize that pattern across every other one in the bundle.** Search by function name AND by code pattern. Finding native/ERC20 confusion in `ContractA.onRevert` means you check every other contract's `onRevert`; finding a bare `AccountInfo` authority in one Anchor instruction means you read every `#[derive(Accounts)]` struct in the program — missing a repeat instance is an audit failure.

After scanning: escalate every finding to its worst exploitable variant (DoS may hide fund theft). Then revisit every function where you found something and attack the other branches.

## Do not report

Admin-only functions doing admin things. Standard DeFi tradeoffs (MEV, rounding dust, first-depositor with MINIMUM_LIQUIDITY). Self-harm-only bugs. "Admin can rug" without a concrete mechanism. Anything the engine's block list already holds, unless you reach it by a different mechanism or with a wider impact. Things the chain makes impossible: silent integer wrap in Move, dropping a struct with no `drop` ability, reentrancy on Soroban with the default host rules, an EVM-style reentrancy into a Solana program that does not CPI back to itself.

## Output

Return findings as structured blocks:

FINDINGs have concrete, unguarded, exploitable attack paths. LEADs have real code smells with partial paths — default to LEAD over dropping.

**Every FINDING must have a `proof:` field** — concrete values, traces, or state sequences from the actual code. No proof = LEAD, no exceptions.

**Every item carries `tier: REASONED`.** You are a model; nothing you emit is verified. The orchestrator hands your `property:` to the engine, and only an engine reproduction changes the tier. Never write `VERIFIED-PROVEN` or `VERIFIED-STATIC` yourself.

**Every FINDING carries a `severity:`** — `critical` (unprivileged theft or permanent loss of most funds), `high` (unprivileged theft or freeze of a bounded but material amount), `medium` (needs a specific state or a privileged amplifier), `low` (bounded, non-compounding). The orchestrator's Gate 4 settles it; you propose it.

**State a `property:` whenever you can.** One line, machine-checkable: a conservation law (`sum(balanceOf) == totalSupply`), a monotone quantity (`sharePrice never decreases`), an access rule (`only owner() changes owner()`), a round-trip that must not profit (`deposit(x); withdraw(all) <= x`), a Solana token conservation (`sum(token account amounts) == mint supply`) or account owner (`vault stays owned by the program`). On the EVM the engine can try to break these by execution; on Solana it can validate a plan built from them (execution is deferred in this release); on Move and Soroban they become the external test or `spec`. It cannot try to break prose. If the bug breaks nothing a machine can state, write `property: none` and say why in the description.

**One vulnerability per item.** Same root cause = one item. Different fixes needed = separate items.

```
FINDING | contract: Name | function: func | bug_class: kebab-tag | group_key: Contract | function | bug-class
tier: REASONED
severity: critical|high|medium|low
chain: evm|solana|move|soroban
path: caller → function → state change → impact
proof: concrete values/trace demonstrating the bug
property: one machine-checkable line, or `none` with the reason
extends: <invariant_id of the engine block this widens, or omit>
description: one sentence
fix: one-sentence suggestion

LEAD | contract: Name | function: func | bug_class: kebab-tag | group_key: Contract | function | bug-class
tier: REASONED
chain: evm|solana|move|soroban
code_smells: what you found
property: one machine-checkable line, or `none`
description: one sentence explaining trail and what remains unverified
```

`contract:` is the contract (EVM), the program module or the `#[derive(Accounts)]` context (Solana), the module (Move) or the `#[contract]` struct (Soroban). `function:` is the function, instruction or entry function. The `group_key` enables deduplication: `ContractName | functionName | bug_class`. Agents may add custom fields.

## Language — MANDATORY

**Your `description:` and your `fix:` sentence are written in Simplified Technical English.** The
rules follow these ones in your bundle, under the heading "Report language". Read them, and
obey them in every finding and every lead you emit.

Your `description:` is what the report prints. Nothing downstream rewrites it into plain
English for you — the orchestrator pastes it into the report and the report goes to the
developer who must fix the code. One sentence, twenty-five words or fewer, active voice, no
`-ing` clause, no metaphor. Name who acts and what they get.

The rule reaches the wording and never the data. Your `bug_class` label, your `group_key`, the
contract and function names, your `property:` line and every line of code you quote are
written exactly as the source and the dedup rules require. `report-language.md` says which is
which.

Your `path:` and `proof:` fields are working notes, not report text. Keep them concrete;
concrete is already plain.
