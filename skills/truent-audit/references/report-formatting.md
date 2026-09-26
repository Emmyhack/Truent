<!-- Adapted from pashov/skills solidity-auditor/references/report-formatting.md (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine ground truth, three evidence tiers, multi-chain. -->
# Report Formatting

## The one rule

**A report must not overstate its own coverage.** Every other rule in this file serves that
one. The report may print **less** than the scan found — a mistyped marker, a dead agent, a
pass that never ran — and when it does it says so in words. It may never claim to print
**more**. A report that shows 14 findings and reads as if it showed all of them is the defect
this whole design exists to kill.

Its twin, for this skill: **a report must not overstate its own evidence.** Every finding
carries one of three tiers — `VERIFIED-PROVEN`, `VERIFIED-STATIC`, `REASONED` — and the tier
says what happened, not how sure anyone is. A REASONED finding printed without its badge, or
a static match printed as if it were executed, is the same lie in a different column.

## Who reads this file

Nothing composes a report from this template any more. There are three writers and one
reader:

- **`scripts/engine.sh --render`** — writes every engine finding into `engine.md` in the
  finding-block shape below, from the engine's JSON, with no model in the loop.
- **SKILL.md Turn 4 step 5a** — the pass writing its findings into `run-K.md`. It uses the
  **finding block** shape below: title line, location line, `**Description**`, diff `**Fix**`
  block. Those bytes are pasted straight through into the report, so they are written in the
  report's own shape while the pass still has context to spare.
- **SKILL.md Turn 2-engine** — the orchestrator transcribing a dynamic fuzz violation into an
  `engine.md` block: the reproduction is the engine's text, pasted; the block around it is
  this shape.
- **`scripts/assemble.sh`** — the assembler. Everything below the finding block — the banner,
  the Scope table, the ordering, the tier summary, the Findings List, the Leads section,
  "Known from earlier scans", the Reproduce footer, the disclaimer — is what the assembler
  emits.

**This file settles the shape. `report-language.md` settles the words.** Every sentence a
human reads in the report — the finding title, the Description, the Lead description, the
Lead's code smells — is written in Simplified Technical English, and that file holds the rules.
It is read by the same Turn 4 step 5a that writes the block, and it is in all twelve agent
bundles. It never reaches the diff in a **Fix** block, the bug-class label inside a key, an
identifier on a location line, or anything inside an engine block: those are data, and it says
so.

**The template is the contract the assembler emits, not a shape a model imitates.** A later
editor must not re-teach the orchestrator to write it. The orchestrator under context pressure
is the thing that failed; the step that must not lose a finding holds no model judgment.

## Report Path

**Every scan assembles `.truent-audit/runs/{stamp}/full-report.md`** — the whole report,
banner line down to the disclaimer — at any pass count, with or without flags. That file is
the report. There is exactly one producer of it, and it is the assembler.

`--file-output` makes a **copy** of that file into the current working directory as
`{project-name}-truent-audit-report-{stamp}.md`, where `{project-name}` is the repo root
basename and `{stamp}` is `YYYYMMDD-HHMMSS` at scan time. A copy, not a second build —
nothing regenerates, so the flag cannot collapse the report the way the terminal once did. The
flag never causes a report to be produced; it only decides whether a copy lands where the
runner can see it.

The `run-K.md` files and `engine.md` stay in `.truent-audit/runs/{stamp}/` under the same
stamp, so a report and the runs that produced it are tied together by eye. They are never
copied into the working directory — they are memory, not reports.

## Output Format

This is what the assembler emits.

````
# 🔐 Truent Audit — <ContractName or repo name>

---

## Scope

|  |  |
| --- | --- |
| **Mode** | ALL / default / filename                                          |
| **Files reviewed** | `File1.sol` · `File2.sol`<br>`File3.sol` · `programs/x/lib.rs` | <!-- every file, 3 per line -->
| **Engine** | truent 0.6.0 · evm: static ✓, dynamic ✓ · solana: static ✓, dynamic skipped (no IDL) | <!-- always; one static + one dynamic cell per chain in scope -->
| **Confidence threshold (1-100)** | N                                                |
| **Passes** | 3                                                                  | <!-- only when passes > 1 -->
| **Memory** | 12 records before this scan · 14 after · `a1b2c3d`                 | <!-- only when memory is on -->
| **Run files** | ⚠️ 2 findings marked, 1 readable. 1 could not be read.          | <!-- only when the structure check disagrees -->

---

## Findings

_7 finding(s): 1 VERIFIED-PROVEN · 4 VERIFIED-STATIC · 2 REASONED. VERIFIED-PROVEN: the engine executed it. VERIFIED-STATIC: a compiled detector matched real code, nothing executed it. REASONED: a model proposed it and the engine could not verify it._

[100] **1. <Title>**

`ContractName.functionName` · CRITICAL · VERIFIED-PROVEN · Confidence: 100 · seen in 3/3 runs · NEW <!-- runs segment only when passes > 1; memory segment only when memory is on -->

**Description**
<The vulnerable code pattern and why it is exploitable, in 1 short sentence>

**Proof (engine)**
```
Invariant violated: <the engine's line>
Reproduction (N calls):
  1. …
```

**Fix**

```diff
- vulnerable line(s)
+ fixed line(s)
```

---

[95] **2. <Engine title>**

`path/File.sol:42` · HIGH · VERIFIED-STATIC · Confidence: 95 · seen in 3/3 runs · KNOWN (4 scans)

**Engine** `evm_reentrancy_classic` · chain: evm · evidence: lead · exploitability: likely · CWE-841 · Improper Enforcement of Behavioral Workflow · SWC-107 · OWASP SC05 · Reentrancy Attacks · DASP-1 · Reentrancy
- reachable by anyone who can reach the service or submit a transaction

**Description**
<the engine's message>

```solidity
<the engine's code_snippet>
```

**Fix**
<the engine's fix>

**Verify**
<the engine's verify step>

---

[82] **3. <Title>**

`ContractName.functionName` · HIGH · REASONED · Confidence: 82

**Description**
<The vulnerable code pattern and why it is exploitable, in 1 short sentence>

**Fix**

```diff
- vulnerable line(s)
+ fixed line(s)
```

---

< ... all above-threshold findings >

---

[60] **7. <Title>**

`ContractName.functionName` · MEDIUM · REASONED · Confidence: 60

**Description**
<The vulnerable code pattern and why it is exploitable, in 1 short sentence>

---

< ... all below-threshold findings (description only, no Fix block) >

---

Findings List

| # | Severity | Tier | Confidence | Title |
|---|---|---|---|---|
| 1 | CRITICAL | VERIFIED-PROVEN | [100] | <title> |
| 2 | HIGH | VERIFIED-STATIC | [95] | <title> |
| 3 | HIGH | REASONED | [82] | <title> |
| | | | | **Below Confidence Threshold** |
| 7 | MEDIUM | REASONED | [60] | <title> |

---

## Leads

_Vulnerability trails with concrete code smells where the full exploit path could not be completed in one analysis pass, and the engine could not verify them. These are not false positives — they are high-signal leads for manual review. All leads are REASONED. Not scored._

- **<Title>** — `Contract.function` · NEW — Code smells: <missing guard, unsafe arithmetic, etc.> — <1-2 sentence description of the trail and what remains unverified> <!-- memory segment only when memory is on -->
- **<Title>** — `Contract.function` · seen in 2/3 runs · KNOWN (2 scans) — Code smells: <...> — <1-2 sentence description> <!-- runs segment only when passes > 1 -->

---

## Known from earlier scans

<!-- only when memory is on AND the ledger held at least one record — see Memory in the report -->

_Recorded by earlier scans of this repo, not raised again by this one. Not re-checked — a record here may be fixed, or may still be live and missed. An engine record that is absent here means the engine no longer matches that line. `.truent-audit/memory.tsv`._

| Scans | Kind | Location | Title |
|---|---|---|---|
| 4 | FINDING | `Router.swap` | Swap trusts a spot price as an oracle |
| 2 | LEAD | `Vault.sweep` | Sweep lets the owner take user deposits |

---

## Reproduce

_Run these to get every VERIFIED finding above again. The engine is deterministic: same input, same seed, same result._

```bash
truent scan src --chain evm --output json
truent fuzz src/Token.sol --dynamic --chain evm --iterations 500 --seed 1
```

---

> ⚠️ This review was performed by the Truent engine and an AI assistant. VERIFIED-PROVEN findings were executed by the engine. VERIFIED-STATIC findings matched a compiled detector and were not executed. REASONED findings and every Lead are AI analysis that nothing executed. AI analysis can never verify the complete absence of vulnerabilities and no guarantee of security is given. Team security reviews, bug bounty programs, and on-chain monitoring are strongly recommended.

````

**Rules describing the output**, all of them held by the assembler and none of them addressed
to a model:

- Findings are sorted by **severity** (critical, high, medium, low, info), then **tier**
  (`VERIFIED-PROVEN` > `VERIFIED-STATIC` > `REASONED`), then confidence, highest first. A
  finding with no severity sorts last; a finding with no tier prints `**tier missing**` on its
  meta line rather than nothing — an unlabelled finding is the defect this file's second rule
  forbids.
- The **meta line** is one dot-separated chain in a fixed order: location · SEVERITY · TIER ·
  confidence · runs · memory. The location is `Contract.function` for a model finding and
  `path:line` for an engine finding, each as its writer spelled it.
- A finding at or above the threshold carries a **Description** and a **Fix** block. One
  below carries the **Description** only. Nothing in the run file marks which side of the line
  a finding sits on — it is re-derived from the confidence, so there is one source of truth.
- **Engine blocks** carry, after the meta line, an **Engine** line — `invariant_id`, chain,
  evidence, exploitability, then CWE / SWC / OWASP SC / DASP as the engine listed them — the
  engine's exploit reasons as a list, the engine's message as the Description, its
  `code_snippet` fenced, its **Fix** as prose (the engine's text, not a diff) and its
  **Verify** step. `scripts/engine.sh` wrote all of it from the JSON; the assembler pastes it.
- A **`VERIFIED-PROVEN`** block carries a **Proof (engine)** section holding the engine's own
  reproduction, pasted verbatim from the fuzzer's or the symbolic executor's output. A
  PROVEN block with no reproduction is malformed: the tier claims execution and shows none.
- The **Below Confidence Threshold** separator row is printed whenever at least one finding
  falls below the threshold, and left out when none does. Without it the table runs 1, 2, 3
  with nothing to mark the boundary, so a reader of the table alone cannot tell which findings
  carry no **Fix** block.
- **Empty cases say so in words, never with an empty table**: `_None — this scan raised no
  findings._` in place of the Findings List, `_None._` under Leads, `**Body missing** — pass K
  raised this finding and wrote no description.` in place of a body.
- **A `Run files` row appears only when the structure check disagrees.** The model types the
  markers that bound each finding in a run file, so it can mistype one. The assembler counts
  open markers against close markers against readable blocks (in `engine.md` and every run
  file), and prints the disagreement as a Scope row naming how many findings could not be
  read. Everything readable is still printed and the assembler never stops. That row is the
  one rule at the top made mechanical.
- **The `Engine` row is always printed.** The engine runs on every scan, so the row has
  something to say on every scan: the engine version, then one `static` and one `dynamic` cell
  per chain in scope. `static ✓` means `scripts/engine.sh` ran and its JSON was rendered;
  `static ✗ (reason)` means it did not. `dynamic ✓` means the fuzzer ran to completion at
  least once on that chain; `dynamic skipped (reason)` means it could not on this target (no
  ERC20-shaped ABI, a `solc` failure, a reverting constructor, no IDL or plan on Solana);
  `dynamic n/a` means the chain has no execution backend (Move, Soroban). A skip is not a
  pass and the cell never says ✓ for it.
- **The Scope table's column padding is not part of the shape.** Markdown renders
  `| **Mode** | default |` and a space-padded form identically, and the padding above is for
  reading this file. Content and order are the contract; character widths are not.

**The threshold is 75**, set in `judging.md` and printed in the Scope row above. It is named
in `judging.md` and nowhere else; this file reads it from there. A finding at 75 or above gets
a description and a **Fix** block, one below 75 gets the description only. A promoted lead
lands at exactly 75, so it clears — that is why the number is 75. Engine blocks carry 100
(PROVEN) or 95 / 90 / 85 / 80 (STATIC, by exploitability), so every engine block clears it and
carries the engine's Fix.

## The size trigger

**More than 20 findings.** At 20 the terminal prints the assembled file word for word; at 21
it stops printing findings. Findings only — every tier, above and below the threshold
together. **Leads are excluded from the trigger count**, so a scan with 18 findings and 40
leads prints in full.

The trigger is on **size, not on flags**. A plain scan of a small contract is unchanged; a
plain scan of a big one gets the new shape. A large repository whose engine pass alone raises
30 static findings crosses the trigger on the engine's work — that is correct, the full report
holds every one of them.

**Above the trigger the terminal prints four things:** the banner, the Scope table unchanged,
a **Findings List holding the top 3 findings**, and the path to the full report — then the
disclaimer. About fifteen lines.

The full report is unaffected. Above the trigger, as below it, `full-report.md` holds every
finding in the shape above — only the terminal changes.

**The slice is honest because it is counted.** The table's header reads
`Findings List — top 3 of {F}`, and that `{F}` is the whole rule:

- **A report may print less than the scan found. It may never look like it printed more.**
  A bare list of three findings breaks that — a reader cannot tell a truncated list from a
  complete one. `top 3 of 52` cannot be misread.
- **The total goes in the header, not a footnote.** A reader who sees the table sees the
  total in the same glance. This is not a style choice; a footnote can be scrolled past.
- **Three rows, and nothing else is enumerated.** No Leads, no "Known from earlier scans",
  no findings past the third. The tier summary line is printed, because three rows of a
  fifty-finding report must still say how many of the fifty were executed.

> **This replaces the older "nothing is enumerated above the trigger" rule**, which forbade
> every top-N slice. That rule was right that bare truncation lies and wrong to conclude no
> slice can be honest; a counted one is. A later editor must not restore the blanket ban by
> citing the half of the argument that survived.

**The rows are extracted by shell, never typed.** One `awk` over the assembled file — which is
already sorted, so no sort happens in the terminal step. The orchestrator has read dozens of
findings by then and is the least reliable thing in the room; the extractor cannot mis-rank,
mis-quote a function name, invent a confidence or promote a tier. The command is in
`dedup-and-assembly.md` Turn 5 step 3b.

**The `Seen` column appears only when the `Passes` row does** — that is, when the pass count is
above 1. A plain scan's meta line carries no `seen in k/N runs`, so the column is dropped
from the header, the separator and the rows together. A seven-column header over six-column
rows draws as a broken table.

**There is no counts summary beyond the tier line.** The `{F} findings, {L} leads` line and
the `100-90 / 89-75 / below 75` split are not printed. `top 3 of {F}` carries the only total
the moment needs, and the bucket split stood between the reader and the path. The buckets are
still **computed** as a self-check — `A + B + C` must equal `F`, in every mode, or the
assembled file is malformed and the scan says so instead of printing a slice of it.

The path line names `.truent-audit/runs/{stamp}/full-report.md`, or — when `--file-output`
was passed — the **copy** and only the copy. Never both: two paths to identical bytes answer a
question the runner did not ask at the moment they want one filename. That line is the only
part of the block a flag changes.

The exact wording, spacing and order of the block are in `dedup-and-assembly.md` Turn 5 step
3b, which is where the terminal is printed.

## The freeze

**A small scan with no flags prints what it printed before any of this existed.** Below the
trigger the terminal prints `full-report.md` word for word — every byte, nothing added,
nothing cut, no preface — so the freeze is a property of the assembled file.

The freeze covers the report's **content and order, not its column padding** and not what
lands on disk. What it does **not** cover: writing files. Every scan writes a runs directory
and assembles a report there, at any pass count. Writing a file is not printing, and the
freeze is on printed output.

The plain scan's Scope table has exactly **four** rows: `Mode`, `Files reviewed`, `Engine`,
`Confidence threshold (1-100)`. The `Engine` row is the one row this skill adds to the
upstream's three, and it is there on every scan because the engine runs on every scan. A
later editor must not make it conditional on a flag: a report that does not say whether the
engine ran cannot say what its tiers mean.

## Memory in the report

Everything in this section is printed **only when memory is on** (`--memory`, or a pass count
above 1). With memory off the assembled file carries no extra rows, no extra segments, no
extra sections and no dangling `·`.

**Segment order on the meta line.** One dot-separated chain, in a fixed order:

```
`ContractName.functionName` · HIGH · REASONED · Confidence: 95 · seen in 2/3 runs · KNOWN (4 scans)
```

location · severity · tier · confidence · runs · memory. **A segment appears only when it
carries information** — `seen in k/N runs` needs more than one run, `KNOWN (n scans)` / `NEW`
needs memory on. Severity and tier always appear. So:

| Scan | Meta line |
|---|---|
| 1 pass, no flags | `` `Vault.withdraw` · HIGH · REASONED · Confidence: 95 `` |
| 1 pass, `--memory` | `` … · Confidence: 95 · KNOWN (4 scans) `` |
| 3 passes | `` … · Confidence: 95 · seen in 2/3 runs · KNOWN (4 scans) `` |

`KNOWN (4 scans)` and `NEW` are the ledger's own two words, so the report and the file say the
same thing. **`n` counts this scan.** The tag is derived by the assembler from
`memory-before.tsv` — the pre-scan photocopy — and `n` is that row's `scans` **plus one**: the
scan that is printing has just found it again, and the ledger already holds that same number.
Printing the stored count instead would show a report one behind its own ledger. `NEW` carries
no count. The tag is **not** carried in the run-file marker: one source, so the report and the
ledger cannot disagree.

Engine findings are ledger records too: their key is `<file-stem>|engine-L<line>|<invariant_id>`,
and a deterministic detector re-matching the same line on the next scan is `KNOWN (2 scans)`
like any other record. The line number is part of the key, so an unrelated edit above the bug
moves it and the record reads `NEW` again while the old one lands under "Known from earlier
scans". That is a known limitation, stated here so a reader does not take the pair as two bugs.

The `Scans` column of "Known from earlier scans" is the opposite case and is printed **as
stored**: this scan did not raise those records, so nothing about them counts up. The
**Findings List** table is unchanged — it stays `# | Severity | Tier | Confidence | Title`.

Leads carry the same segments as findings, on their own line, because a Lead is a full ledger
record.

**The `Memory` row in Scope.** `<records in the ledger before this scan> records before this
scan · <records after the merge> after · `<sha>``. The SHA is the one every row of this scan
wrote; `none` when the repo has no commits. The row states the whole ledger state in one line,
so the two counts show at a glance what the scan added.

**The "before" count is the count after the prune** — the row count of `memory-before.tsv` as
the merge reads it, not the row count of the file the scan opened. On a scan where the prune
drops records the two differ, and using the pre-prune number makes the row's own arithmetic
wrong: a scan that opened 4 records, pruned 1 and added 12 would read `4 records before this
scan · 15 after`, and a reader counting 4 + 12 gets 16. The prune is already reported on its
own line (`Pruned N records …`), so the Scope row does not restate it and must not contradict
it.

**Building "Known from earlier scans".** These are the records the ledger already held that
this scan did **not** raise again. It is **not** a filter on the `status` column — `status`
stays `KNOWN` once set and never marks the not-found-again case.

**The `comm` block lives in `scripts/assemble.sh`**, under `# Known from earlier scans`. It
reads two inputs Turn 5 copies into the runs directory: `memory-before.tsv`, the pruned
photocopy, and `source-names.tsv`. The keys this scan raised come from the assembler's own
index of `engine.md` and the run files, so no `run-keys.tsv` or `scan-rows.tsv` is carried
in — the run files are the record. It is computed once per scan, scoped to the whole scan and
not to the last run, so a bug found in run 1 but not in run 3 does not appear here.

Each key `comm` returns is one row: `Scans`, `Kind` and `Title` come straight from its row in
`memory-before.tsv`. `Location` is rebuilt from the key's first two segments, which are stored
normalised (lower case, hyphenated) and cannot be printed as they are — each segment is looked
up in `source-names.tsv` and printed as the source spells it, or printed as stored when it is
not in the map, which happens on a named-file scan where the contract was never assembled into
`source.md`, and for the `engine-L42` segment of an engine key, which is not a source name.

Three states, and no fourth:

- The ledger held records this scan did not raise → the table above.
- The ledger held records and this scan raised **every one** → `_None — every record in the
  ledger was raised again by this scan._`
- Memory is off, or the ledger is empty (first-ever scan) → **no section at all.** A plain
  scan grows no empty headings.

The italic line under the heading is load-bearing and is printed verbatim: these records are
**not re-checked**. A reader must not take the section as "still open", and must not take it
as "fixed".

## Loop mode in the report

Everything in this section is printed **only when the pass count is above 1**. One pass prints
none of it.

**One report per scan.** However many passes ran, the runner sees one combined list. The
per-pass output is one summary line each (SKILL.md Turn 4 step 5b) and one `run-K.md` in
`.truent-audit/runs/{stamp}/` — neither is a report.

**`seen in k/N runs`.** `k` is how many of this scan's runs raised that group key; `N` is how
many passes produced a run file. A pass that collapsed produced none, so it is not in `N` — a
report must not claim a run that never happened. The segment sits between confidence and the
memory tag, and it is printed on Leads exactly as it is on findings, because a Lead is a full
ledger record. **An engine finding is seen in `N/N` runs**: the engine ran once,
deterministically, for the whole scan, and its findings do not get a smaller number because
they were not re-derived by agents.

**`seen in k/N runs` and `KNOWN (n scans)` count different things and must never be mixed.**
`k/N` counts runs inside **this** scan and is never written to the ledger. `n` counts scans and
comes from the ledger. A finding first raised by pass 1 of this scan is `NEW` in pass 3 — it is
this scan's work, however many of its runs saw it.

**Which write-up survives the merge.** One winner per key: strongest kind, then strongest
tier, then highest confidence, then the later pass — a later pass read the ledger every
earlier pass wrote, so it is the better-informed write-up. A REASONED finding from pass 1 that
pass 2's verification step promoted to VERIFIED-PROVEN is the same key with a stronger tier,
and the stronger tier wins. **Confidence is untouched by the merge.** A finding three runs saw
keeps the number the runs gave it; repetition is reported on the line, never scored, and
`seen in 3/3 runs` is there for the reader to weigh.

**The `Passes` row in Scope** is composed by the assembler from recorded facts, never written
as prose. It carries degradation text whenever the scan did not run whole — a report claiming
3 passes when one of them ran three-quarters of its agents overstates its own coverage:

```
| **Passes** | 3                                                    |
| **Passes** | 3 (pass 2 ran 11/12 agents)                          |
| **Passes** | 2 of 3 (pass 3 failed)                               |
| **Passes** | 2 of 3 (pass 1 ran 11/12 agents, pass 3 failed)      |
```

The `R of P` prefix comes from counting run files. The dead agent's **name** never appears
here — it stays in the run file, in the sentence under the `<!--RUN-->` marker.

On a 1-pass scan this row is suppressed, so a pass 1 that produced nothing is reported by the
`Run files` row instead: `⚠️ No pass produced a run file. The agents reviewed nothing; only
the engine's findings are below.` — and the engine's findings **are** below, because the
engine ran before any agent was spawned.
