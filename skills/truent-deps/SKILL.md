---
name: truent-deps
description: "Supply-chain security review of a smart-contract project's dependencies and CI. Finds forked/drifted libraries, unpinned submodules and package versions, and CI workflows that leak deploy keys — then runs Truent's engine over the dependency code that is actually compiled into your contracts, because a patched modifier in a vendored OpenZeppelin is your bug, not upstream's. Multi-chain: Foundry/Hardhat (EVM), Anchor (Solana), Move, Soroban. Triggers on 'truent deps', 'dependency audit', 'supply chain review', 'check my dependencies', 'are my libs safe', 'audit CI workflows'."
license: MIT
metadata:
  version: "0.1.0"
  author: Emmyhack
  homepage: https://github.com/Emmyhack/Truent
  domain: smart-contract-security
  subdomain: supply-chain
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
    - supply-chain
    - dependencies
    - foundry
    - hardhat
    - anchor
    - ci-cd
    - submodules
    - openzeppelin
    - vendored-code
---

# Truent Deps

Audit what your contracts actually compile, not what your README says they
depend on.

The premise the rest of this skill follows from: **an audit that excludes
`lib/` and `node_modules/` has excluded most of your bytecode.** A protocol
that forked OpenZeppelin eighteen months ago and hand-patched one modifier has
a bug in its own attack surface — but every scanner configured with the
standard "exclude dependencies" rule will report the project clean. The point
of this skill is to find the dependency code that is *not* upstream any more,
and put the engine on it.

`$SKILL_DIR` = the directory containing this SKILL.md.

Two finding tiers, same as `truent-audit`, and never blurred:

- **`VERIFIED`** — the Truent engine ran over the code and produced this.
  Reproducible, with file and line.
- **`REASONED`** — a supply-chain risk judgement (an unpinned tag, an
  over-permissioned workflow) that no engine executed. Honest about it.

## Inputs & scope

- **Default** (no path): the current project.
- **`<path>`**: treat that directory as the project root.
- Unlike `truent-audit`, `lib/`, `node_modules/`, `vendor/` and
  `.gitmodules` targets are **in scope**. That is the entire point.

## Pipeline

### Phase 1 — Inventory (one message, parallel)

Detect the toolchain and enumerate every dependency that reaches the compiler.

1. `Bash`: identify the project type and manifests.
   ```bash
   ls foundry.toml remappings.txt hardhat.config.* package.json \
      Anchor.toml Cargo.toml Move.toml 2>/dev/null
   ```
2. `Bash`: enumerate dependencies per toolchain.
   ```bash
   # Foundry — submodules and their pinned commits
   git submodule status --recursive 2>/dev/null
   cat remappings.txt 2>/dev/null

   # Hardhat / npm — the resolved tree, not the declared range
   [ -f package-lock.json ] && jq -r '.packages | keys[]' package-lock.json 2>/dev/null | head -100
   [ -f yarn.lock ] && grep -E '^\S+@' yarn.lock | head -100

   # Anchor / Rust
   [ -f Cargo.lock ] && grep -A1 '^name = ' Cargo.lock | head -100

   # Move
   [ -f Move.toml ] && sed -n '/\[dependencies\]/,/^\[/p' Move.toml
   ```
3. `Bash`: the compiled-vs-declared gap — which dependency files the build
   actually pulls in.
   ```bash
   grep -rhoE 'import\s+[^;]*from\s+"[^"]+"|import\s+"[^"]+"' --include='*.sol' src/ contracts/ 2>/dev/null \
     | grep -oE '"[^"]+"' | tr -d '"' | sort -u
   ```

**Record, do not yet judge.** Phase 2 decides which of these are risky.

### Phase 2 — Drift detection (the step that finds real bugs)

For each vendored dependency, determine whether it still matches upstream.
Drift is the signal: unmodified upstream code is upstream's problem, modified
code is yours.

1. `Bash`: for git submodules, compare the pinned commit against the upstream
   ref it claims to track.
   ```bash
   git submodule foreach --recursive '
     echo "=== $name ==="
     git fetch --quiet origin --tags 2>/dev/null || true
     echo "HEAD:        $(git rev-parse HEAD)"
     echo "describes:   $(git describe --tags --always 2>/dev/null)"
     echo "local edits: $(git status --porcelain | wc -l) file(s)"
     git status --porcelain
   '
   ```
   **Any non-empty `local edits` is a finding.** A submodule with a dirty
   working tree means code is being compiled that exists in no upstream
   release and that nobody reviewed as project source.

2. `Bash`: for copied-in (non-submodule) libraries, diff against the real
   upstream release.
   ```bash
   # Example: a vendored OpenZeppelin at the version package.json claims
   VER=$(jq -r '.dependencies["@openzeppelin/contracts"] // empty' package.json 2>/dev/null | tr -d '^~')
   [ -n "$VER" ] && {
     TMP=$(mktemp -d)
     npm pack "@openzeppelin/contracts@$VER" --pack-destination "$TMP" >/dev/null 2>&1 &&
     tar -xzf "$TMP"/*.tgz -C "$TMP" &&
     diff -rq "$TMP/package" lib/openzeppelin-contracts 2>/dev/null | head -40
   }
   ```
   Adapt the registry and paths to the toolchain in play. If no upstream
   artifact can be fetched, say so and mark the dependency **unverifiable**
   rather than assuming it is clean.

3. Classify each dependency:
   - **pristine** — byte-identical to a published upstream release. Out of
     scope; note the version and move on.
   - **drifted** — differs from upstream. **Goes into Phase 3 as first-class
     audit scope.**
   - **unpinned** — tracks a branch, a floating tag, or a semver range that
     resolves differently over time. A `REASONED` finding on its own.
   - **unverifiable** — no upstream to compare against. Treat as drifted.

### Phase 3 — Engine pass over drifted code

This is where the skill stops being a linter and starts being Truent.

```bash
truent scan <drifted-dependency-path> --chain <chain> --format json
```

Run it over every **drifted** and **unverifiable** dependency, plus any
project file that imports from one. Findings here are `VERIFIED` and carry the
same CWE/SWC/OWASP/DASP mapping as any other Truent finding — check with:

```bash
truent taxonomy --id SWC-107      # what maps to a given weakness class
```

A detector hit inside a forked library is usually **higher** severity than the
same hit in project code: it is code the team believes is audited, so nobody
is reading it.

### Phase 4 — CI and release-pipeline review

A contract cannot be exploited through a workflow file, but a deploy key can
be stolen from one, and stolen deploy keys have drained more value than most
Solidity bugs.

1. `Read` every file under `.github/workflows/`, `.gitlab-ci.yml`, or
   equivalent. For each, check:
   - **Secret exposure** — does any step `echo`, `cat`, or pass a
     `secrets.*` value into a command whose output is logged? Does a step run
     on `pull_request_target` with a checkout of the PR head? (That
     combination gives any external contributor your secrets.)
   - **Unpinned actions** — `uses: someone/action@main` or `@v4` rather than a
     full commit SHA. A tag is mutable; a compromised action runs with your
     deploy key.
   - **Over-broad triggers** — does a deploy job run on `push` to any branch,
     or on a fork's PR?
   - **Dependency install without a lockfile** — `npm install` instead of
     `npm ci`, `forge install` without a pinned commit.
2. `Bash`: check the obvious secret leaks in the repo itself.
   ```bash
   git ls-files | grep -E '(^|/)\.env($|\.)' 
   git log --all --oneline --diff-filter=A -- '*.env' '*.key' '*keystore*' | head -20
   ```
   A `.env` that was ever committed is compromised even if later removed — the
   object is still in history. Say that plainly; do not soften it.

Anything found here is `REASONED` unless it is a literal committed secret, in
which case it is a fact and should be reported as such.

### Phase 5 — Report

Write `deps-report.md` at the project root. Structure:

```
DEPENDENCY SUPPLY-CHAIN REVIEW — <project>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scope:     <n> dependencies across <toolchain>
Engine:    truent <version>

Dependency inventory
  pristine       <n>   (identical to upstream — out of scope)
  drifted        <n>   ← audited as project code
  unpinned       <n>
  unverifiable   <n>   ← audited as project code

[VERIFIED] <severity> — <invariant_id> in <drifted-dep>/<file>:<line>
  CWE-xxx · <name>  |  SWC-xxx  |  SCxx  |  DASP-x
  <message>
  Why it matters more here: this file is inside a dependency the team
  believes is upstream-audited. It is not; it diverged at <commit>.

[REASONED] <severity> — <supply-chain risk>
  <what, and what would have to be true for it to be exploited>

CI / release pipeline
  <findings, or "no issues found">

Not checked
  <every dependency marked unverifiable, and why>
```

The **Not checked** section is mandatory. A supply-chain report that silently
omits what it could not verify is worse than no report, because it reads as
coverage.

## Rules

- Never report a pristine dependency's upstream CVE as though it were the
  project's bug — say "upstream advisory, pinned version affected, remediation
  is a version bump" and keep it separate from drifted-code findings.
- Never claim a dependency is clean because a scan produced no findings. Say
  "no detector matched" — absence of a hit is not proof of absence.
- If `git fetch` cannot reach upstream (offline, private mirror), stop and say
  so. Do not substitute a guess about whether a fork drifted.
