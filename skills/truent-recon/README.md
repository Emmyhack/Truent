# truent-recon

Know the protocol before the audit starts — and let the engine prove part of
the map.

A report-only recon hands an auditor a list of things to check. `truent-recon`
produces that list *and* runs the machine-checkable items through Truent's
compiled engine first, so the report arrives with some invariants already
`held`, some already `BROKEN` with a minimal proof-of-concept, and every
detector match already on the page. Nothing is dressed up as proven that a
machine did not prove.

## What you get

One run writes a `recon/` folder at the project root:

| Output | What's inside |
|--------|---------------|
| `recon.md` | Overview, threat & trust model, invariant pointer, **engine findings**, **exposure & attack chains**, docs, tests, git history, readiness verdict |
| `entry-points.md` | Every state-changing entry point classified by access level, with chain-aware account/object notes and call chains |
| `invariants.md` | Enforced guards, single-contract, cross-contract and economic invariants — each with its engine verdict (`held` / `BROKEN` / `not checkable` / `EXTERNAL`) |
| `architecture.svg` | Contracts, actors, trust boundaries |
| `engine-findings.json` | The raw `truent scan --chain auto` output, kept for `truent-audit` |

## Chains

EVM (Foundry / Hardhat), Solana (Anchor and native), Move (Aptos and Sui),
Soroban. Mixed repositories are handled per chain; the general analyzer
(secrets, CI, containers) always runs.

Dynamic verification is EVM-native (`truent fuzz --dynamic`). On Solana the
engine validates a fuzz plan against the IDL but does not execute it in this
release (`validated plan (execution deferred)`). Move and Soroban invariants
are routed to the Move Prover / `aptos move test` / `sui move test` /
`cargo test` and labelled `EXTERNAL`.

## Evidence tiers

`VERIFIED-PROVEN` (engine executed it) · `VERIFIED-STATIC` (detector match) ·
`REASONED` (LLM inference) · `EXTERNAL` (another tool) · `(per spec)`
(stated in docs). They never blur.

## Usage

```
Run truent-recon on this codebase
```

Requires the `truent` binary (`cargo install --path crates/cli` or
`cargo build --release --bin truent`). If it is missing the skill still
produces the report — with every engine section marked as not run.

## Tips

- **Start with the verdict.** The last section carries the tier and an
  "Engine ground truth" line with counts by evidence tier.
- **Read `recon.md` §4 before §2.** A `BROKEN` invariant is a confirmed bug with
  a PoC; the surfaces in §2 are pointers.
- **Hand the priority list to `truent-audit`.** `engine-findings.json` and the
  git hotspots are exactly what it seeds from.

## Attribution

The pipeline structure, threat profiles, templates and scripts are adapted from
pashov/skills `x-ray` (MIT) and extended with Truent's engine integration and
multi-chain coverage. See `../THIRD_PARTY_NOTICES.md`; every adapted file
carries an attribution line naming its source.
