#!/usr/bin/env bash
# Adapted from pashov/skills solidity-auditor/references/assemble.sh (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine ground truth, three evidence tiers, multi-chain.
#
# THE ASSEMBLER. It writes the whole truent-audit report. SKILL.md Turn 5 runs it.
#
# This is the only producer of a report in this skill. The orchestrator does not compose one,
# and must not be re-taught to: an orchestrator under context pressure is the thing that
# failed. Every finding this scan gated is in a run file, every finding the engine produced is
# in engine.md; this script prints all of them or says out loud that it could not.
#
#   assemble.sh --dir .truent-audit/runs/{stamp}
#
# Reads ONE directory and writes {dir}/full-report.md — the complete report, banner line down
# to the disclaimer, ready to print word for word. No model judgment runs in here.
#
# reads   dir/engine.md          the engine's blocks (scripts/engine.sh --render, plus the
#                                dynamic blocks Turn 2-engine transcribed) — shell-written,
#                                never model-written, present on every scan the engine ran
#         dir/run-K.md           the run files, one per pass, model-written
#         dir/scope.tsv          key <TAB> value, append-only, LAST LINE PER KEY WINS
#         dir/memory-before.tsv  the pruned photocopy — its PRESENCE is not the memory flag,
#                                scope.tsv's `mem_before` key is
#         dir/source-names.tsv   normalised <TAB> as spelled in the source
# writes  dir/full-report.md
#
# Every block carries a tier in its marker: VERIFIED-PROVEN (the engine executed it),
# VERIFIED-STATIC (a compiled detector matched real code) or REASONED (a model proposed it and
# nothing executed it). Findings are ordered by severity, then tier (PROVEN > STATIC >
# REASONED), then confidence. The tier is printed on every finding; it is never blurred.
#
# The model types the markers in run files, so it can mistype one. The assembler CHECKS them
# and prints the disagreement into the Scope table. A broken run file becomes a visible line in
# the report, never a silent loss.
#
# Written to .part and moved into place on exit 0, so a half-report never exists. It never
# exits non-zero in place of a report: a scan that reviewed nothing still gets a report that
# says so.
set -euo pipefail

dir=
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir=$2; shift 2 ;;
    *) echo "assemble.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -d "$dir" ] || { echo "assemble.sh: no such directory $dir" >&2; exit 2; }

out="$dir/full-report.md"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

THRESHOLD=75   # judging.md sets it. Named there and read here; never a second opinion.

# ---------------------------------------------------------------- scope.tsv, last wins
# An absent key gives an absent row. That is what keeps a plain scan's table at four rows.
# A missing scope.tsv is every key missing at once — the same path, no special case. It must
# not be a non-zero exit either: `set -e` would turn one absent label into no report at all.
scope() {
  [ -f "$dir/scope.tsv" ] || return 0
  awk -F'\t' -v k="$1" '$1==k { v=$2 } END { print v }' "$dir/scope.tsv"
}

name=$(scope name);            [ -n "$name" ] || name='**name missing**'
mode=$(scope mode);            [ -n "$mode" ] || mode='**Mode missing**'
passes_planned=$(scope passes_planned)
mem_before=$(scope mem_before)
mem_after=$(scope mem_after)
mem_sha=$(scope mem_sha)
chains=$(scope chains)
engine_version=$(scope engine_version)

memory_on=0; [ -n "$mem_before" ] && memory_on=1
if [ "$memory_on" = 1 ] && [ ! -f "$dir/memory-before.tsv" ]; then
  echo "assemble.sh: memory is on but $dir/memory-before.tsv is missing — Turn 5 did not copy it" >&2
  memory_on=0
fi

# run files in PASS order. A plain glob puts run-10 before run-2, which is a real 10-pass bug.
runs=()
while IFS= read -r f; do runs+=("$f"); done < <(
  ls "$dir"/run-*.md 2>/dev/null | sed 's/.*run-\([0-9]*\)\.md/\1 &/' | sort -n | cut -d' ' -f2)
N=${#runs[@]}

# engine.md is read like a run file but is not a pass: it is not in N, and its findings count
# as seen in every run because the engine is deterministic and ran once for the whole scan.
engine_file=""
[ -f "$dir/engine.md" ] && engine_file="$dir/engine.md"
sources=()
[ -n "$engine_file" ] && sources+=("$engine_file")
for f in ${runs[@]+"${runs[@]}"}; do sources+=("$f"); done

# ---------------------------------------------------------------- index every block
# key conf kind agents file pass start end bodystart bodyend title loc leadbody tier sev id evidence
#
# A FINDING and a LEAD are NOT the same shape on disk, and one geometry read over both is what
# produced `- **- **Title**` rows and a "Body missing" line under leads that had a body:
#
#   FINDING            LEAD
#   +0  <!--F ...-->   +0  <!--F ...-->
#   +1                 +1
#   +2  [95] **1. T**  +2  - **T** — `loc` · TAG — smells — why not verified
#   +3                 +3
#   +4  `loc` · Conf   +4  <!--/F-->
#   +5
#   +6  body …
#
# Read with the finding geometry, a lead put its WHOLE formatted line in `title` (which the
# emitter then wrapped in `- **…**` a second time), found no backticks at +4 so `loc` came out
# empty, and had no body region at all. Each kind now gets its own reader.
#
# **No field is ever emitted empty** — `-` stands in. `read` below splits on IFS=$'\t', and a
# tab is IFS *whitespace*, so bash collapses `\t\t` into one delimiter and every later field
# shifts left by one. That is how a lead's memory tag ended up printed as its location.
: > "$work/index.tsv"
for f in ${sources[@]+"${sources[@]}"}; do
  awk -v F="$f" '
    BEGIN { pass = 0 }
    /^<!--RUN / { line=$0; sub(/[[:space:]]*-->[[:space:]]*$/, "", line)
                  n=split(line, a, /[[:space:]]+/)
                  for (i=2; i<=n; i++) { eq=index(a[i],"="); if (substr(a[i],1,eq-1)=="pass") pass=substr(a[i],eq+1) } }
    /^<!--F / {
      key=""; conf=""; kind=""; agents=""; tier=""; sev=""; id=""; evidence=""
      line = $0
      sub(/[[:space:]]*-->[[:space:]]*$/, "", line)   # terminator off BEFORE splitting
      n = split(line, a, /[[:space:]]+/)
      for (i = 2; i <= n; i++) {
        eq = index(a[i], "="); nm = substr(a[i], 1, eq-1); v = substr(a[i], eq+1)
        if (nm == "key") key = v; else if (nm == "conf") conf = v
        else if (nm == "kind") kind = v; else if (nm == "agents") agents = v
        else if (nm == "tier") tier = v; else if (nm == "sev") sev = v
        else if (nm == "id") id = v; else if (nm == "evidence") evidence = v
      }
      if (conf == "") conf = "-"        # a LEAD is not scored
      if (kind == "LEAD") tier = "REASONED"   # a lead is by definition unverified
      if (tier == "") tier = "-"
      if (sev == "") sev = "-"
      if (id == "") id = "-"
      if (evidence == "") evidence = "-"
      if (agents == "") agents = "-"
      start = NR; title = ""; loc = ""; lbody = ""
      next
    }
    kind != "LEAD" && start && NR == start + 2 { t = $0; sub(/^\[[0-9]+\] /, "", t); sub(/^\*\*/, "", t); sub(/\*\*$/, "", t); title = t }
    kind != "LEAD" && start && NR == start + 4 { l = $0; if (match(l, /`[^`]*`/)) loc = substr(l, RSTART+1, RLENGTH-2) }

    # A lead is one line. Split it here, once, so the emitter formats leads and findings with
    # the same fields instead of re-printing a line that is already formatted.
    # `match` + RSTART/RLENGTH, never index()+a literal width: the separator is an em dash,
    # 3 bytes and 1 character, and the two disagree across awks and locales.
    kind == "LEAD" && start && NR == start + 2 && /^- \*\*/ {
      l = $0
      sub(/^- \*\*/, "", l)
      if (match(l, /\*\* — /)) { title = substr(l, 1, RSTART-1); l = substr(l, RSTART+RLENGTH) }
      else                     { title = l; l = "" }
      if (match(l, /^`[^`]*`/)) { loc = substr(l, RSTART+1, RLENGTH-2); l = substr(l, RSTART+RLENGTH) }
      # What is left is " · NEW — body" or " — body". Either way the body starts after the
      # first " — ". The inline tag is DROPPED: the assembler derives the memory tag itself
      # from memory-before.tsv, and two sources for one fact is how they come to disagree.
      if (match(l, / — /)) l = substr(l, RSTART+RLENGTH); else l = ""
      lbody = l
    }
    /^<!--\/F-->/ && start {
      if (title == "") title = "-"
      if (loc   == "") loc   = "-"
      if (lbody == "") lbody = "-"
      print key "\t" conf "\t" kind "\t" agents "\t" F "\t" pass "\t" start "\t" NR "\t" (start+6) "\t" (NR-1) "\t" title "\t" loc "\t" lbody "\t" tier "\t" sev "\t" id "\t" evidence
      start = 0; kind = ""
    }
  ' "$f" >> "$work/index.tsv"
done

# ---------------------------------------------------------------- the structure check
# The model typed these markers. When the counts disagree, a finding was raised and cannot be
# read — say so IN the report. The report may print less than the scan found; it may never
# claim to print more.
#
# No run file at all is the same rule at its limit: pass 1 produced nothing, so the agents
# reviewed nothing. That is a REPORT, not an exit — SKILL.md Turn 3b routes a real scan down
# here, and a shell error in place of a report is the one outcome this skill must never have.
# The engine's blocks are still printed: the engine ran even when every agent died.
broken=
if [ "$N" = 0 ]; then
  if [ -n "$engine_file" ]; then
    broken="⚠️ No pass produced a run file. The agents reviewed nothing; only the engine's findings are below."
  else
    broken="⚠️ No pass produced a run file and no engine file exists. This scan reviewed nothing."
  fi
  echo "assemble.sh: NO RUN FILES — $broken" >&2
fi
if [ "${#sources[@]}" -gt 0 ]; then
  opens=$(cat "${sources[@]}" | grep -c '^<!--F ' || :)
  closes=$(cat "${sources[@]}" | grep -c '^<!--/F-->' || :)
  indexed=$(wc -l < "$work/index.tsv" | tr -d ' ')
  if [ "$opens" != "$closes" ] || [ "$opens" != "$indexed" ]; then
    b2="⚠️ $opens findings marked, $indexed readable. $(( opens - indexed )) could not be read and are missing below. See the run files."
    broken="${broken:+$broken }$b2"
    echo "assemble.sh: STRUCTURE BROKEN — $b2" >&2
  fi
fi

# ---------------------------------------------------------------- dedup across runs
# One winner per key: strongest kind, then strongest tier, then highest confidence, then the
# LATER pass — a later pass read the ledger every earlier pass wrote, so it is the better-
# informed write-up. k counts every run that raised the key, in either section. A key that
# came from engine.md is seen in every run: the engine ran once, deterministically, for the
# whole scan, and it does not get a smaller number for that.
sort -t $'\t' -k1,1 "$work/index.tsv" | awk -F'\t' -v N="$N" -v ENG="$engine_file" '
  function rank(k) { return (k == "FINDING") ? 1 : 0 }
  function trank(t) { return (t == "VERIFIED-PROVEN") ? 3 : (t == "VERIFIED-STATIC") ? 2 : (t == "REASONED") ? 1 : 0 }
  {
    if (ENG != "" && $5 == ENG) eng[$1] = 1
    else if (!(($5 SUBSEP $1) in seenrun)) { seenrun[$5 SUBSEP $1]=1; k[$1]++ }
    c = ($2 == "-") ? -1 : $2 + 0
    t = trank($14)
    if (!($1 in best) || rank($3) > br[$1] \
        || (rank($3) == br[$1] && t > bt[$1]) \
        || (rank($3) == br[$1] && t == bt[$1] && c > bc[$1]) \
        || (rank($3) == br[$1] && t == bt[$1] && c == bc[$1] && $6 + 0 >= bp[$1])) {
      best[$1] = $0; br[$1] = rank($3); bt[$1] = t; bc[$1] = c; bp[$1] = $6 + 0
    }
  }
  END { for (key in best) { kk = (key in eng) ? (N > 0 ? N : 1) : k[key]; print kk "\t" best[key] } }
' > "$work/merged.tsv"

# ---------------------------------------------------------------- the memory tag
# Derived here from memory-before.tsv, not carried in the marker. One source: the report and
# the ledger cannot disagree because both read the same photocopy.
#   KNOWN (n scans) — the STORED count plus one; this scan has just found it again.
# Two rank columns are appended at the same time so `sort` can order by severity and tier.
if [ "$memory_on" = 1 ]; then
  awk -F'\t' -v OFS='\t' '
    function srank(s) { return (s == "critical") ? 5 : (s == "high") ? 4 : (s == "medium") ? 3 : (s == "low") ? 2 : (s == "info") ? 1 : 0 }
    function trank(t) { return (t == "VERIFIED-PROVEN") ? 3 : (t == "VERIFIED-STATIC") ? 2 : (t == "REASONED") ? 1 : 0 }
    FILENAME==ARGV[1] { if (FNR>1) sc[$1]=$3; next }
    { print $0, ($2 in sc) ? "KNOWN (" sc[$2]+1 " scans)" : "NEW", srank($16), trank($15) }
  ' "$dir/memory-before.tsv" "$work/merged.tsv" > "$work/merged.tagged.tsv"
else
  awk -F'\t' -v OFS='\t' '
    function srank(s) { return (s == "critical") ? 5 : (s == "high") ? 4 : (s == "medium") ? 3 : (s == "low") ? 2 : (s == "info") ? 1 : 0 }
    function trank(t) { return (t == "VERIFIED-PROVEN") ? 3 : (t == "VERIFIED-STATIC") ? 2 : (t == "REASONED") ? 1 : 0 }
    { print $0, "-", srank($16), trank($15) }
  ' "$work/merged.tsv" > "$work/merged.tagged.tsv"
fi

# columns now: 1 k · 2 key · 3 conf · 4 kind · 5 agents · 6 file · 7 pass · 8 start · 9 end
#              10 bodystart · 11 bodyend · 12 title · 13 loc · 14 leadbody · 15 tier · 16 sev
#              17 id · 18 evidence · 19 memtag · 20 sevrank · 21 tierrank
# 12, 13, 14, 15, 16, 17 and 18 are never empty — `-` stands in, because IFS=$'\t' collapses
# adjacent tabs. Only 19 may be empty, and it is the last field read, so nothing shifts.
sort -t $'\t' -k4,4 -k20,20nr -k21,21nr -k3,3nr -k2,2 "$work/merged.tagged.tsv" > "$work/sorted.tsv"
awk -F'\t' '$4=="FINDING"' "$work/sorted.tsv" > "$work/findings.tsv"
awk -F'\t' '$4=="LEAD"'    "$work/sorted.tsv" > "$work/leads.tsv"

nfind=$(wc -l < "$work/findings.tsv" | tr -d ' ')
nlead=$(wc -l < "$work/leads.tsv" | tr -d ' ')
nproven=$(awk -F'\t' '$15=="VERIFIED-PROVEN"' "$work/findings.tsv" | wc -l | tr -d ' ')
nstatic=$(awk -F'\t' '$15=="VERIFIED-STATIC"' "$work/findings.tsv" | wc -l | tr -d ' ')
nreasoned=$(awk -F'\t' '$15=="REASONED"' "$work/findings.tsv" | wc -l | tr -d ' ')

# ---------------------------------------------------------------- emit
R="$work/report.md"
: > "$R"
say() { printf '%s\n' "$1" >> "$R"; }
rule() { say ""; say "---"; say ""; }
row() { printf '| %s | %s |\n' "$1" "$2" >> "$R"; }

say "# 🔐 Truent Audit — $name"
rule
say "## Scope"
say ""
row "" ""
row "---" "---"
row "**Mode**" "$mode"

# Files reviewed — 3 per line, in source.md order, joined with `<br>`. One `files` key holds
# them space separated; shell does the wrapping.
files=$(scope files | tr ' ' '\n' | awk 'NF { printf "`%s`", $0; if (++n % 3 == 0) printf "<br>"; else printf " · " }' \
        | sed -e 's/ · $//' -e 's/<br>$//')
row "**Files reviewed**" "$files"

# The Engine cell is COMPOSED from the keys Turn 2-engine wrote, one static and one dynamic
# key per chain in scope. `n/a` is what a chain with no execution backend prints; `skipped`
# is an EVM or Solana run that could not happen and says why. Never a silent blank.
if [ -n "$chains" ]; then
  cell="truent ${engine_version:-?}"
  for c in $chains; do
    st=$(scope "engine_static_$c");  [ -n "$st" ] || st="not run"
    dy=$(scope "engine_dynamic_$c"); [ -n "$dy" ] || dy="not run"
    cell="$cell · $c: static $st, dynamic $dy"
  done
  row "**Engine**" "$cell"
else
  row "**Engine**" "**Engine missing** — Turn 2-engine wrote no \`chains\` key, so nothing here says whether the engine ran."
fi
row "**Confidence threshold (1-100)**" "$THRESHOLD"

# The Passes cell is COMPOSED from facts, never written as prose by a model.
if [ -n "$passes_planned" ] && [ "$passes_planned" -gt 1 ] 2>/dev/null; then
  short=""
  for k in $(seq 1 "$passes_planned"); do
    a=$(scope "pass_${k}_agents"); fail=$(scope "pass_${k}_failed")
    if [ -n "$fail" ]; then short="${short:+$short, }pass $k failed"
    elif [ -n "$a" ] && [ "$a" != "12/12" ]; then short="${short:+$short, }pass $k ran $a agents"; fi
  done
  if [ "$N" -lt "$passes_planned" ]; then cell="$N of $passes_planned"; else cell="$passes_planned"; fi
  [ -n "$short" ] && cell="$cell ($short)"
  row "**Passes**" "$cell"
fi
[ "$memory_on" = 1 ] && row "**Memory**" "$mem_before records before this scan · $mem_after after · \`$mem_sha\`"
[ -n "$broken" ] && row "**Run files**" "$broken"
rule

say "## Findings"
say ""
say "_$nfind finding(s): $nproven VERIFIED-PROVEN · $nstatic VERIFIED-STATIC · $nreasoned REASONED. VERIFIED-PROVEN: the engine executed it. VERIFIED-STATIC: a compiled detector matched real code, nothing executed it. REASONED: a model proposed it and the engine could not verify it._"
say ""

emit_body() {  # file bodystart bodyend  — copied through, never re-worded
  awk -v s="$2" -v e="$3" 'NR>=s && NR<=e' "$1" \
    | awk '{ lines[++n] = $0 } END {
        b=1; while (b<=n && lines[b]=="") b++
        while (n>=b && lines[n]=="") n--
        for (i=b; i<=n; i++) print lines[i] }'
}

i=0
while IFS=$'\t' read -r k key conf kind agents file pass start end bstart bend title loc lbody tier sev id evidence memtag sevrank tierrank; do
  i=$((i+1))
  [ "$title" = "-" ] && title="**Title missing** — the block's title line could not be read"
  if [ "$loc" = "-" ]; then meta="**location missing**"; else meta="\`$loc\`"; fi
  say "[$conf] **$i. $title**"
  say ""
  if [ "$sev" != "-" ]; then meta="$meta · $(printf '%s' "$sev" | tr '[:lower:]' '[:upper:]')"; fi
  if [ "$tier" = "-" ]; then meta="$meta · **tier missing**"; else meta="$meta · $tier"; fi
  meta="$meta · Confidence: $conf"
  [ "$N" -gt 1 ] && meta="$meta · seen in $k/$N runs"
  [ "$memtag" != "-" ] && meta="$meta · $memtag"
  say "$meta"
  say ""
  body=$(emit_body "$file" "$bstart" "$bend")
  if [ -z "$body" ]; then
    if [ "$pass" = 0 ]; then say "**Body missing** — the engine block has no body."
    else say "**Body missing** — pass $pass raised this finding and wrote no description."; fi
  else
    printf '%s\n' "$body" >> "$R"
  fi
  rule
done < "$work/findings.tsv"

if [ "$nfind" = 0 ]; then
  # An empty table with a header row and no rows under it is not a report of nothing, it is a
  # report that looks broken. Say it in words instead.
  say "_None — this scan raised no findings._"
  rule
else
say "Findings List"
say ""
say "| # | Severity | Tier | Confidence | Title |"
say "|---|---|---|---|---|"
i=0; sep=0
while IFS=$'\t' read -r k key conf kind agents file pass start end bstart bend title loc lbody tier sev id evidence memtag sevrank tierrank; do
  i=$((i+1))
  if [ "$sep" = 0 ] && [ "$conf" -lt "$THRESHOLD" ] 2>/dev/null; then
    say "| | | | | **Below Confidence Threshold** |"; sep=1
  fi
  sevu=$(printf '%s' "$sev" | tr '[:lower:]' '[:upper:]')
  say "| $i | $sevu | $tier | [$conf] | $title |"
done < "$work/findings.tsv"
rule
fi

say "## Leads"
say ""
say "_Vulnerability trails with concrete code smells where the full exploit path could not be completed in one analysis pass, and the engine could not verify them. These are not false positives — they are high-signal leads for manual review. All leads are REASONED. Not scored._"
say ""
[ "$nlead" = 0 ] && say "_None._"
while IFS=$'\t' read -r k key conf kind agents file pass start end bstart bend title loc lbody tier sev id evidence memtag sevrank tierrank; do
  seg=""
  [ "$N" -gt 1 ] && seg="$seg · seen in $k/$N runs"
  [ "$memtag" != "-" ] && seg="$seg · $memtag"
  # The body was parsed out of the lead's own line by the indexer. Do NOT read it back out of
  # the run file here: a lead has no body region, so emit_body returned nothing and every lead
  # got the "Body missing" line whether or not it had one.
  [ "$title" = "-" ] && title="**Title missing** — the lead's line could not be read"
  if [ "$loc" = "-" ]; then locmd="**location missing**"; else locmd="\`$loc\`"; fi
  [ "$lbody" = "-" ] && lbody="**Body missing** — pass $pass raised this lead and wrote no description."
  say "- **$title** — $locmd$seg — $lbody"
done < "$work/leads.tsv"

# ---------------------------------------------------------------- Known from earlier scans
# The keys this scan raised come from the index — the run files are the record, so no separate
# run-keys.tsv or scan-rows.tsv has to be carried in.
if [ "$memory_on" = 1 ]; then
  held=$(( $(wc -l < "$dir/memory-before.tsv") - 1 ))
  if [ "$held" -gt 0 ]; then
    tail -n +2 "$dir/memory-before.tsv" | cut -f1 | sort -u > "$work/keys-before.txt"
    cut -f1 "$work/index.tsv" | sort -u > "$work/keys-scan.txt"
    comm -23 "$work/keys-before.txt" "$work/keys-scan.txt" > "$work/keys-left.txt"
    rule
    say "## Known from earlier scans"
    say ""
    say "_Recorded by earlier scans of this repo, not raised again by this one. Not re-checked — a record here may be fixed, or may still be live and missed. An engine record that is absent here means the engine no longer matches that line. \`.truent-audit/memory.tsv\`._"
    say ""
    if [ -s "$work/keys-left.txt" ]; then
      say "| Scans | Kind | Location | Title |"
      say "|---|---|---|---|"
      awk -F'\t' '
        FILENAME==ARGV[1] { nm[$1]=$2; next }
        FILENAME==ARGV[2] { if (FNR>1) { sc[$1]=$3; ti[$1]=$5; ki[$1]=$6 } ; next }
        {
          split($1, p, "|")
          c = (p[1] in nm) ? nm[p[1]] : p[1]      # print-as-stored when the segment is not in the map
          f = (p[2] in nm) ? nm[p[2]] : p[2]
          print "| " sc[$1] " | " ki[$1] " | `" c "." f "` | " ti[$1] " |"
        }
      ' "$dir/source-names.tsv" "$dir/memory-before.tsv" "$work/keys-left.txt" >> "$R"
    else
      say "_None — every record in the ledger was raised again by this scan._"
    fi
  fi
fi

# ---------------------------------------------------------------- Reproduce
# The commands Turn 2-engine ran, one `repro_N` key each, in order. A reader who runs them
# gets the VERIFIED-PROVEN and VERIFIED-STATIC findings above, identically. REASONED findings
# are not reproducible by command, and this section does not pretend they are.
repro=$(awk -F'\t' '$1 ~ /^repro_[0-9]+$/ { n=$1; sub(/^repro_/, "", n); v[n+0]=$2; if (n+0 > m) m=n+0 }
                    END { for (i=1; i<=m; i++) if (i in v) print v[i] }' "$dir/scope.tsv" 2>/dev/null || :)
if [ -n "$repro" ]; then
  rule
  say "## Reproduce"
  say ""
  say "_Run these to get every VERIFIED finding above again. The engine is deterministic: same input, same seed, same result._"
  say ""
  say '```bash'
  printf '%s\n' "$repro" >> "$R"
  say '```'
fi

rule
say "> ⚠️ This review was performed by the Truent engine and an AI assistant. VERIFIED-PROVEN findings were executed by the engine. VERIFIED-STATIC findings matched a compiled detector and were not executed. REASONED findings and every Lead are AI analysis that nothing executed. AI analysis can never verify the complete absence of vulnerabilities and no guarantee of security is given. Team security reviews, bug bounty programs, and on-chain monitoring are strongly recommended."

cp "$R" "$out.part"
mv "$out.part" "$out"
echo "assembled $out — $nfind findings ($nproven proven, $nstatic static, $nreasoned reasoned), $nlead leads, $N run files$( [ -n "$engine_file" ] && printf ', engine.md' )"
