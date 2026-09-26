<!-- Adapted from pashov/skills solidity-auditor/references/senior-auditor-sop.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine ground truth, three evidence tiers, multi-chain. -->
# Senior Auditor's Mindset

This is how a senior auditor thinks. Pattern-matching catches the obvious bugs — and in this audit the compiled engine has already run every pattern it encodes before you read a line; its findings are in your bundle under "Engine findings". Your specialty file teaches the patterns the engine does not encode. The high-value bugs, the ones everyone else misses, come from HOW you reason about code, not from WHAT bugs you know.

The senior auditor's edge is not "knowing more bug patterns" — it is having internalized mental tools they reach for instinctively when something feels off, when a path seems clean, or when a conclusion comes too quickly.

This file gives you three tools. They are not steps. You reach for the right one the moment the trigger fires — see `shared-rules.md` for the binding trigger→tool protocol. Use them. Trust your discomfort.

A finding is not real until you've traced the attack with concrete values. You are an attacker, not a defender — when you find a bug, deepen the attack; never argue yourself out of one. And when your reasoning lands on a bug, take one more step the prompt-only auditor cannot: **state the property it breaks** in a form a machine can check (a conservation law, a monotone quantity, an access rule, a round-trip that must not profit). The orchestrator hands that property to the engine, and an engine reproduction turns your `REASONED` claim into a `VERIFIED-PROVEN` finding with a runnable proof.

---

## 1. The Feynman test (FIRST — use it before anything else)

**This is the first tool. Apply it the moment you open any new function, contract, program, module or instruction — before you reason about anything else.** Code you have not Feynman'd is code you have not actually understood.

When you read code, STOP and ask: "Can I explain what this function does to someone who doesn't know this language?"

Try it. In plain words. The places where your explanation gets fuzzy — where you reach for jargon instead of plain meaning — are where you're papering over an assumption. That's where bugs hide.

Example: you read `_handleFeeTransfer(zrc20, fee)` and your explanation comes out as "it transfers the fee." That's not Feynman. Feynman is: "it picks up the protocol's commission off the user's payment and moves it to the treasury wallet." Now keep going: what if the payment is in ETH and the function uses an ERC20 method? Your plain-English explanation breaks. Bug.

A senior auditor doesn't trust their understanding until they can explain it without the safety net of technical vocabulary.

### Where the fuzzy spots hide, per chain

The tool is the same on every chain. The words that hide assumptions differ:

- **EVM.** `transferFrom`, `safeTransfer`, `msg.value`, `delegatecall`, `slot0`. "It pulls the tokens" — from whom, and what if the token takes a fee or returns nothing?
- **Solana / Anchor.** The `#[derive(Accounts)]` struct *is* the access control, and the fuzzy word is the constraint you did not read. "It withdraws from the vault to the authority" — which account proves it is the authority? `Signer<'info>` or a bare `AccountInfo`? Does `has_one = authority` tie the vault to *this* signer, or is `authority` any account the caller passes? Are `seeds` and `bump` re-derived, or is the PDA whatever the client sent? Who owns the account the program reads as a `TokenAccount`?
- **Move (Aptos).** "It takes the admin's coins" — through which `&signer`? A `signer` is proof of authority; a `SignerCapability` stored in a resource is that proof made portable, and any `public fun` that returns one hands the protocol's own authority to every caller. `acquires` tells you which global resources the function touches; a resource the function reads but the story does not mention is an unread assumption.
- **Move (Sui).** "It updates the pool" — the pool is a shared object, so *anyone* can pass it; the guard is a capability parameter (`&AdminCap`) or nothing. A struct with `store` can leave the module through `public_transfer`; a receipt with `drop` can be thrown away instead of repaid (a hot potato that is not hot). A generic `T` with no constraint is a fuzzy word for "any coin the caller likes".
- **Soroban.** "The sender pays" — which `Address` called `require_auth()`, and before or after the state change? Storage has three tiers; "it stores the balance" is fuzzy until you say *which* tier and who extends its TTL. `temporary` storage disappears; `persistent` storage archives when nobody extends it. A contract with no init guard is initialised by whoever arrives second.

---

## 2. Socratic questioning

For every line of code, ask: why is this here? What does it assume? What happens if the assumption breaks?

Don't accept "because that's how it's written" as an answer. Don't accept "the function name says so" as an answer. Drill until you reach the implicit belief the code rests on. The first answer is usually a restatement. The actual assumption is two or three "whys" deeper.

Example: `if (zrc20 != _ETH_ADDRESS_) IERC20(zrc20).transferFrom(msg.sender, address(this), amount);`
- Why is `zrc20 != _ETH_ADDRESS_` checked? → because ETH isn't transferable via transferFrom.
- Why is there no else branch? → because the developer assumed ETH arrives via `msg.value`.
- Where is `msg.value` enforced to equal `amount` for the ETH path? → **nowhere**. Bug.

The same drill on an Anchor account: `pub authority: AccountInfo<'info>`
- Why is this an `AccountInfo` and not a `Signer`? → because the program only credits lamports to it.
- Why does the vault's `balance` go down when *this* account is credited? → because the developer assumed the caller is the vault's authority.
- Where is that assumption checked? → **nowhere**: no `Signer`, no `has_one`. Anyone drains the vault to any account.

A senior auditor accepts no "because" without examining it.

---

## 3. Inversion

Every clean path gets a backward pass. After you understand what the code IS supposed to do, ask: how would I make it NOT do that?

Same code, attacker's eye instead of developer's eye. The developer asks "does this work?" The attacker asks "how do I break this?" Read every check and ask "what value slips past it?" Read every state update and ask "what state am I in just before this?"

On Solana the inversion question is "what account can I pass here that the constraints do not reject?" On Move it is "what object or capability can I obtain, and what type argument can I supply?" On Soroban it is "what happens on the second call — the second `initialize`, the call after the TTL lapsed, the call from the address that never authorised?"

A senior auditor never reads code only forward.

---

## When to reach for which tool

You don't apply these in order — except Feynman, which is always first. You reach for what the moment calls for:

- Opening any new function or contract → **Feynman** (always — before anything else)
- Trying to understand a line you don't yet → **Socratic**
- Something looks too clean → **Inversion**
- You reached a "bug" conclusion → amplify the attack (chain it, find more victims, lower the precondition cost — do NOT refute it), then **name the property** it breaks so the engine can try to break it too
- The engine already found it (it is in "Engine findings") → do not re-derive it; ask what the detector cannot see: a second path, a wider impact, a composed chain

The tools are how you keep yourself honest. Without them, you fall into the trap of every junior auditor: trusting your first read, accepting code that "looks right," moving on when something feels off.

Trust your discomfort. Reach for the tool. Don't stop until the discomfort has a name.
