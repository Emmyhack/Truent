---
name: truent-keys
description: "Key custody and deploy-safety review for a smart-contract project. Finds plaintext private keys in source, scripts, history and CI; then runs Truent's engine over the on-chain side of the same question — single-EOA admins, multisig thresholds too low to matter, unprotected initializers and upgrade paths — because a well-guarded key on a contract anyone can re-initialize protects nothing. Multi-chain: EVM, Solana, Move, Soroban. Triggers on 'truent keys', 'key hygiene', 'deploy safety', 'check my private keys', 'is my deploy script safe', 'admin key review', 'who can upgrade this'."
license: MIT
metadata:
  version: "0.1.0"
  author: Emmyhack
  homepage: https://github.com/Emmyhack/Truent
  domain: smart-contract-security
  subdomain: key-management
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
    - key-management
    - deployment
    - access-control
    - multisig
    - upgradeability
    - secrets
    - foundry
    - anchor
---

# Truent Keys

Review who can move the protocol's money, and how hard that authority is to
steal.

Key hygiene is usually treated as an ops checklist ("don't commit your `.env`")
and contract authority as an audit topic ("who owns this proxy"). They are the
same question asked twice, and treating them separately is how protocols end
up with a hardware-wallet-protected owner on a contract that anyone can
re-initialize. This skill asks both halves together, and the second half is
answered by the engine rather than by reading.

`$SKILL_DIR` = the directory containing this SKILL.md.

- **`VERIFIED`** — produced by the Truent engine, with file and line.
- **`REASONED`** — a custody or process judgement nothing executed.
- A committed secret is neither: it is a **fact**, reported as one.

## Pipeline

### Phase 1 — Secrets in the repository (one message, parallel)

1. `Bash`: keys in tracked files.
   ```bash
   # 64-hex private keys, mnemonics, and the usual key-shaped assignments
   grep -rnE '(0x)?[0-9a-fA-F]{64}' --include='*.sol' --include='*.js' --include='*.ts' \
        --include='*.rs' --include='*.json' --include='*.toml' --include='*.sh' \
        --exclude-dir=node_modules --exclude-dir=lib --exclude-dir=target . 2>/dev/null | head -40

   grep -rniE '(private_?key|privkey|mnemonic|seed_?phrase|secret_?key)\s*[=:]' \
        --exclude-dir=node_modules --exclude-dir=lib --exclude-dir=target . 2>/dev/null | head -40
   ```
   Filter the 64-hex hits: most are transaction hashes, bytecode, or salts.
   A hit is a key only if its **name or context** says so. Report the ones
   that are, not the ones that match.

2. `Bash`: keys in git history — the check that matters most, because removal
   from HEAD does nothing.
   ```bash
   git log --all --oneline --diff-filter=A -- '*.env' '*.env.*' '*.key' '*.pem' \
       '*keystore*' 'id_rsa*' 2>/dev/null | head -20
   git log --all -p --no-color -S 'PRIVATE_KEY' -- . 2>/dev/null | head -60
   ```
   **If a real key appears in any reachable commit, the key is compromised.**
   Say exactly that. Rotation is the only remediation; rewriting history is
   not, because clones and forks already have it.

3. `Bash`: keys reachable from CI and tooling config.
   ```bash
   git ls-files | grep -E '(^|/)\.env($|\.)|\.envrc$'
   cat .gitignore 2>/dev/null | grep -E '\.env|\.key|keystore' || echo "NOT IGNORED"
   grep -rniE 'private_?key|secrets\.' .github/workflows/ 2>/dev/null | head -20
   ```

### Phase 2 — Deploy and script safety

`Read` every deploy/ops script (`script/*.s.sol`, `scripts/*.ts`,
`migrations/`, `Anchor.toml` cluster config, Soroban deploy scripts) and check:

- **Key source.** Does it read a raw `PRIVATE_KEY` env var
  (`vm.envUint("PRIVATE_KEY")`), or use an encrypted keystore
  (`cast wallet`, `--account`, a hardware signer)? A raw env var means the key
  is in plaintext in the shell, the process table, and probably the shell
  history.
- **Broadcast scope.** Does any script `--broadcast` to a mainnet RPC by
  default, with no chain-id guard? A deploy script whose default target is
  production is one flag away from an accident.
- **Post-deploy handover.** Does the script transfer ownership away from the
  deployer EOA before it finishes? A deployment that leaves the deployer as
  owner has silently made a hot key the protocol admin.
- **Verification of the deployed artifact.** Does it check the deployed
  bytecode or run `truent scan` before broadcasting?

All `REASONED` — nothing here is executed.

### Phase 3 — Engine pass on the on-chain half

The custody question the engine can actually answer: given the contracts,
**who has privileged authority and how well is it guarded?**

```bash
truent scan <src> --chain <chain> --format json
```

Then pull out the authority-shaped findings specifically:

```bash
truent taxonomy --id SC01           # everything mapped to OWASP Access Control
```

The detectors that answer this question directly, and what each one means for
key custody:

| Detector | The custody question it answers |
|---|---|
| `evm_single_eoa_admin` / `sol_treasury_single_authority` | Is one hot key the whole security model? |
| `evm_insufficient_multisig_threshold` | Is the multisig a multisig, or a 1-of-n with extra steps? |
| `evm_unprotected_initializer` / `sor_reinitialization` | Can anyone take ownership by calling `initialize` first? |
| `evm_upgrade_path_verification` / `sor_unprotected_upgrade` | Can the admin key swap in arbitrary code with no check? |
| `evm_missing_signer_check` / `sol_missing_signer` / `sor_missing_require_auth` | Is the authority check even present? |
| `evm_shallow_auth` | Is the check present but not on the path that mutates? |
| `move_admin_no_timelock` / `sol_admin_no_timelock` | Can a stolen admin key act instantly, with no window to respond? |
| `unauthorized_privileged_mutation` | Chain-agnostic: any privileged mutation with no guard reaching it. |

These findings are `VERIFIED`. Report each with its location and its taxonomy
line, and — this is the part that makes the skill worth running — **pair it
with the Phase 1/2 custody finding for the same authority.** A
`evm_single_eoa_admin` finding is medium on its own. The same finding, where
Phase 1 found that EOA's key in git history, is critical and immediate.

### Phase 4 — Report

Write `keys-report.md`. Lead with the pairing, not the lists:

```
KEY CUSTODY & DEPLOY SAFETY — <project>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] Sole protocol admin is an EOA whose key is in git history
  On-chain  [VERIFIED] evm_single_eoa_admin — Vault.sol:41
            CWE-654 · Reliance on a Single Factor in a Security Decision | SC01 | DASP-2
  Off-chain [FACT]     PRIVATE_KEY committed in 3f2a1bc (2025-11-02), still reachable
  Impact    Anyone who has ever cloned this repo can call every owner-gated
            function, including withdraw() and upgradeTo().
  Action    Rotate now, then move admin to a multisig. Rewriting history does
            not help — assume the key is public.

[HIGH] <next pairing>

Unpaired on-chain findings
  <authority findings with no corresponding custody problem>

Unpaired custody findings
  <secrets/process issues with no corresponding on-chain authority>

Not checked
  <what this review could not reach: hardware signer policy, multisig signer
   identities, off-repo infrastructure>
```

## Rules

- Never print a discovered private key, mnemonic, or keystore password in the
  report or in conversation. Cite the **location** (`file:line`, or the commit
  SHA) and the **fact** that it is a key. The report may be shared; the key
  must not travel with it.
- Never test a discovered key against a live RPC, and never derive and report
  its address if that address is not already public — confirming which funds a
  leaked key controls is the attacker's job, not the auditor's. If the user
  explicitly asks whether a specific key is still live, say what they would
  need to check and let them run it.
- Treat "the key was removed in a later commit" as **not remediated**. Rotation
  is the remediation.
- If no secrets are found, say "no secrets found by these checks" and list the
  checks. Do not say the repository is clean.
