'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { MarketingNav } from '@/components/layout/MarketingNav'
import { PageShell } from '@/components/layout/PageShell'
import { SlimFooter } from '@/components/layout/SlimFooter'
import { AsciiLogo } from '@/components/ui/AsciiLogo'
import { CHAIN_LABEL, CHAIN_ORDER, COMMANDS, ENGINE, EXPLOITABILITY, type Chain } from '@/lib/engine'

const PAGES = [
  { id: 'overview', label: 'Overview' },
  { id: 'getting-started', label: 'Getting Started' },
  { id: 'cli', label: 'CLI Reference' },
  { id: 'honesty', label: 'Evidence & Exploitability' },
  { id: 'api', label: 'Dashboard API' },
  { id: 'ci-cd', label: 'CI/CD Integration' },
  { id: 'reports', label: 'Reports & Release Check' },
] as const

type PageId = (typeof PAGES)[number]['id']

// Old deep links (#ai) map onto the section that replaced them.
const ALIASES: Record<string, PageId> = { ai: 'honesty' }

const severityRows = [
  { level: 'Critical', color: '#ef4444', desc: 'Code execution, funds, or full control reachable by anyone. Deploy-blocking.' },
  { level: 'High', color: '#fbbf24', desc: 'Serious weakness requiring urgent remediation before deployment.' },
  { level: 'Medium', color: '#818cf8', desc: 'Notable issue that should be addressed before deployment.' },
  { level: 'Low', color: '#4ade80', desc: 'Hardening gap or minor issue with limited impact.' },
  { level: 'Info', color: '#96a19a', desc: 'Describes the repository (an install script to review); never fails a gate.' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Primitives
// ─────────────────────────────────────────────────────────────────────────────

const H1 = ({ children }: { children: React.ReactNode }) => (
  <h1 className="m-0 text-[clamp(32px,4vw,46px)] font-normal tracking-[-0.03em] text-[#f2f6f2]">{children}</h1>
)
const Lede = ({ children }: { children: React.ReactNode }) => <p className="m-0 mt-4 max-w-[560px] text-[15px] leading-[1.75] text-sec">{children}</p>
const H2 = ({ children, mono }: { children: React.ReactNode; mono?: boolean }) => (
  <h2 className={`mb-3.5 mt-[52px] text-[22px] font-normal tracking-[-0.02em] text-[#f2f6f2] ${mono ? 'font-mono' : ''}`}>{children}</h2>
)
const H3 = ({ children }: { children: React.ReactNode }) => <h3 className="mb-3 mt-[26px] text-[15.5px] font-medium text-[#d7e2da]">{children}</h3>
const P = ({ children }: { children: React.ReactNode }) => <p className="m-0 mb-5 text-[13.5px] leading-[1.75] text-sec">{children}</p>
const Code = ({ children }: { children: React.ReactNode }) => (
  <code className="rounded border border-white/[0.08] bg-white/[0.04] px-1.5 py-0.5 font-mono text-[11.5px] text-acc-text">{children}</code>
)
const Cmd = ({ children }: { children: React.ReactNode }) => (
  <div className="mb-3 overflow-x-auto rounded-xl border border-white/[0.08] bg-[#080c0a] px-[18px] py-4 font-mono text-[12.5px] text-acc-text">
    <span className="text-[#5c665f]">$ </span>
    {children}
  </div>
)
const Block = ({ children }: { children: React.ReactNode }) => (
  <pre className="overflow-x-auto rounded-xl border border-white/[0.08] bg-[#080c0a] p-[18px] font-mono text-[12.5px] leading-[1.9] text-sec">{children}</pre>
)
const K = ({ children }: { children: React.ReactNode }) => <span className="text-[#8fdcb2]">{children}</span>
const V = ({ children }: { children: React.ReactNode }) => <span className="text-acc-text">{children}</span>

function Table({ cols, head, rows }: { cols: string; head?: string[]; rows: React.ReactNode[][] }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-hair">
      <div className="min-w-[420px]">
        {head && (
          <div className="grid border-b border-white/[0.06] bg-white/[0.03] font-mono text-[10px] uppercase tracking-[0.14em] text-[#8fdcb2]" style={{ gridTemplateColumns: cols }}>
            {head.map((h) => (
              <div key={h} className="px-4 py-[11px]">{h}</div>
            ))}
          </div>
        )}
        {rows.map((r, i) => (
          <div key={i} className="grid border-b border-white/[0.04] last:border-b-0" style={{ gridTemplateColumns: cols }}>
            {r.map((c, j) => (
              <div key={j} className="px-4 py-3 text-[12.5px] text-sec">{c}</div>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}

const SeverityTable = () => (
  <Table cols="1fr 2.6fr" rows={severityRows.map((r) => [<span key="l" className="font-semibold" style={{ color: r.color }}>{r.level}</span>, r.desc])} />
)

const Mono = ({ children }: { children: React.ReactNode }) => <span className="font-mono text-[12px] text-[#d7e2da]">{children}</span>

// ─────────────────────────────────────────────────────────────────────────────
// Sections
// ─────────────────────────────────────────────────────────────────────────────

function Overview({ go }: { go: (p: PageId) => void }) {
  const cards = [
    { icon: '▸', title: 'Quick start', desc: 'Install the CLI and scan a repository in under five minutes.', cta: 'Get started', to: 'getting-started' as const },
    { icon: '⌘', title: 'CLI reference', desc: `${COMMANDS.length} commands: scan, deps, probe, symbolic, exposure, harden, release-check and more.`, cta: 'View commands', to: 'cli' as const },
    { icon: '◈', title: 'Coverage matrix', desc: `${ENGINE.totalDetectors} detectors mapped to CWE / ATT&CK / NIST, as the engine reports them.`, cta: 'Open COVERAGE.md', href: 'https://github.com/Emmyhack/Truent/blob/main/docs/COVERAGE.md' },
    { icon: '◆', title: 'Evidence & exploitability', desc: 'Lead vs proven, LIKELY → THEORETICAL, attack chains: how to read a finding.', cta: 'Read the contract', to: 'honesty' as const, badge: true },
    { icon: '⎇', title: 'CI/CD integration', desc: 'Gate pull requests with SARIF upload; run the probe and the release check.', cta: 'Set up pipeline', to: 'ci-cd' as const },
    { icon: '⟐', title: 'Dashboard API', desc: 'Queue scans and read reports from the hosted dashboard.', cta: 'API reference', to: 'api' as const },
  ]
  const inner = (c: (typeof cards)[number]) => (
    <>
      <div className="flex items-center justify-between">
        <span className="flex h-[38px] w-[38px] items-center justify-center rounded-[11px] border border-acc-text/20 bg-acc-text/[0.08] text-[16px]">{c.icon}</span>
        {c.badge && <span className="rounded-[5px] border border-acc-text/25 bg-acc-text/10 px-2 py-[3px] font-mono text-[9.5px] tracking-[0.12em] text-acc-text">CORE</span>}
      </div>
      <div>
        <div className="mb-1.5 text-[15.5px] font-medium text-text">{c.title}</div>
        <p className="m-0 text-[12.5px] leading-[1.6] text-sec">{c.desc}</p>
      </div>
      <span className="mt-auto text-[12px] font-semibold text-acc-text">{c.cta} →</span>
    </>
  )
  const cardClass = 'flex flex-col gap-3 rounded-2xl border border-hair bg-white/[0.02] p-6 text-left transition-all duration-200 hover:-translate-y-[3px] hover:border-acc-text/[0.35]'

  return (
    <article>
      <h1 className="m-0 text-[clamp(34px,4.5vw,52px)] font-normal tracking-[-0.03em] text-[#f2f6f2]">
        Truent <span className="bg-clip-text text-transparent" style={{ backgroundImage: 'linear-gradient(100deg,#d7ffe9,#34d399)' }}>documentation</span>
      </h1>
      <Lede>
        One engine for smart contracts, application code, dependencies, infrastructure and live targets. Every finding is a lead or proven, rated for exploitability, with the
        fix and how to verify it.
      </Lede>

      <div className="mt-10 grid gap-px overflow-hidden rounded-[14px] border border-hair bg-white/[0.07] sm:grid-cols-3">
        {[
          { label: 'Install', cmd: 'cargo install truent-cli' },
          { label: 'Scan', cmd: 'truent scan . --chain auto' },
          { label: 'Gate', cmd: 'truent release-check . --strict' },
        ].map((s) => (
          <div key={s.label} className="bg-[#080c0a] px-[18px] py-4">
            <div className="mb-2 font-mono text-[9.5px] uppercase tracking-[0.16em] text-[#5c665f]">{s.label}</div>
            <code className="break-all font-mono text-[12px] text-acc-text">{s.cmd}</code>
          </div>
        ))}
      </div>

      <H2>What the engine covers</H2>
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-[14px] border border-hair bg-white/[0.07] sm:grid-cols-4">
        {CHAIN_ORDER.filter((c) => c !== 'chain-agnostic').map((c) => (
          <div key={c} className="bg-[#080c0a] px-4 py-4">
            <div className="text-[22px] font-medium tracking-[-0.02em] text-text">{ENGINE.byChain[c] ?? 0}</div>
            <div className="mt-1 text-[11.5px] text-[#748078]">{CHAIN_LABEL[c as Chain]}</div>
          </div>
        ))}
      </div>

      <h2 className="mb-[22px] mt-14 text-[23px] font-normal tracking-[-0.02em] text-[#f2f6f2]">Explore the docs</h2>
      <div className="grid gap-3 sm:grid-cols-2">
        {cards.map((c) =>
          c.href ? (
            <Link key={c.title} href={c.href} className={cardClass}>{inner(c)}</Link>
          ) : (
            <button key={c.title} onClick={() => c.to && go(c.to)} className={cardClass}>{inner(c)}</button>
          ),
        )}
      </div>

      <div className="mt-11 rounded-2xl border border-acc-text/20 bg-acc-text/[0.04] p-[26px]">
        <h3 className="m-0 mb-[18px] text-[16px] font-medium text-text">What Truent will not do</h3>
        <div className="flex flex-col gap-3">
          {[
            <>Fire exploits or run automated penetration tests. <Code>exposure</Code> rates how possible exploitation is from the attack profile and evidence; <Code>probe</Code> sends only GETs and TCP connects, and only with <Code>--authorized</Code>.</>,
            <>Pretend to be an SMT solver. <Code>symbolic</Code> drives halmos, hevm or Mythril and reports their counterexamples as proven; without an executor it reports an error, never a pass.</>,
            <>Call a static inference proven. Only the probe and symbolic execution produce proven findings; everything else is a lead.</>,
          ].map((tip, i) => (
            <div key={i} className="flex gap-3 text-[13px] leading-[1.6] text-sec">
              <span className="flex-shrink-0 font-mono text-acc-text">0{i + 1}</span>
              <span>{tip}</span>
            </div>
          ))}
        </div>
      </div>
    </article>
  )
}

function GettingStarted() {
  return (
    <article>
      <H1>Getting started</H1>
      <Lede>Install the CLI, scan a repository, and read the first report.</Lede>

      <H2>Installation</H2>
      <H3>Rust CLI (recommended)</H3>
      <Cmd>cargo install truent-cli --locked</Cmd>
      <p className="m-0 mt-2.5 text-[12px] text-[#748078]">
        Requires Rust 1.75 or later — install it at{' '}
        <a href="https://rustup.rs" target="_blank" rel="noopener noreferrer" className="text-acc-text">rustup.rs</a>.
      </p>
      <H3>npm wrapper</H3>
      <Cmd>npm install -g @dextonicx/cli</Cmd>
      <p className="m-0 mt-2.5 text-[12px] text-[#748078]">Downloads the prebuilt binary for your platform and exposes it as <Code>truent</Code>. Same engine, same commands.</p>
      <H3>Check the installation</H3>
      <Cmd>truent doctor</Cmd>
      <P>Runs a real self-test of every component (detectors, taxonomy, SCA, probe evaluators, symbolic parsers, release checklist) and exits non-zero if any fails.</P>

      <H2>First scan</H2>
      <Cmd>truent scan . --chain auto</Cmd>
      <P>
        <Code>auto</Code> picks the engine per file: Solidity → EVM, Anchor/Soroban → Solana/Soroban, Move → Move, and everything else (Python, JS/TS, Go, shell,
        Dockerfile, Kubernetes, Terraform, CI workflows) → the general analyzer. Test corpora are not skipped, so scan the tree you ship.
      </P>
      <H3>Then</H3>
      <Cmd>truent deps . --advisory-db ./advisory-db --sbom sbom.cdx.json</Cmd>
      <Cmd>truent exposure .</Cmd>
      <Cmd>truent harden . --write</Cmd>
      <P>
        <Code>deps</Code> needs an advisory database (clone <Code>rustsec/advisory-db</Code> or a directory of OSV JSON) — without one it makes no vulnerability claims.{' '}
        <Code>exposure</Code> rates every finding and names the attack chains they complete. <Code>harden</Code> generates the preventive files; nothing existing is overwritten.
      </P>

      <H2>Reading the output</H2>
      <P>Every finding has a severity, an evidence class (<Code>lead</Code> or <Code>proven</Code>), an exploitability rating, and a fix with a verify step.</P>
      <SeverityTable />

      <H2>Next steps</H2>
      <div className="flex flex-col gap-3">
        {[
          ['CLI reference', 'Every command with its flags'],
          ['Evidence & exploitability', 'How to read lead vs proven and LIKELY → THEORETICAL'],
          ['CI/CD integration', 'Gate pull requests and upload SARIF'],
          ['Reports & release check', 'The 33-section checklist and the JSON contract'],
        ].map(([title, desc]) => (
          <div key={title} className="flex gap-3 text-[13.5px] leading-[1.65] text-sec">
            <span className="text-acc-text">→</span>
            <span><strong className="font-medium text-text">{title}</strong> — {desc}</span>
          </div>
        ))}
      </div>
    </article>
  )
}

function CliReference() {
  return (
    <article>
      <H1>CLI reference</H1>
      <Lede>Every command the binary ships. Run any of them with <Code>--help</Code> for the full flag list.</Lede>

      <H2>Commands</H2>
      <Table
        cols="1.1fr 1.6fr 2.4fr"
        head={['Command', 'Arguments', 'What it does']}
        rows={COMMANDS.map((c) => [<Mono key="c">truent {c.cmd}</Mono>, <span key="a" className="font-mono text-[11.5px] text-[#748078]">{c.args}</span>, c.what])}
      />

      <H2 mono>truent scan</H2>
      <Cmd>truent scan [PATH] --chain auto --output json --sarif report.sarif --fail-on high</Cmd>
      <Table
        cols="1fr 2.2fr 0.8fr"
        head={['Flag', 'Description', 'Default']}
        rows={[
          [<Mono key="f">--chain</Mono>, 'evm, solana, move, soroban, general, or auto (per file)', <Mono key="d">auto</Mono>],
          [<Mono key="f">--output</Mono>, 'text, json, html', <Mono key="d">text</Mono>],
          [<Mono key="f">--sarif FILE</Mono>, 'Also write SARIF 2.1.0 with CWE / ATT&CK / NIST tags and the fix in rule help', <Mono key="d">—</Mono>],
          [<Mono key="f">--fail-on</Mono>, 'Exit 1 when a finding at or above this severity exists (low, medium, high, critical)', <Mono key="d">critical</Mono>],
          [<Mono key="f">--fail-on-leads</Mono>, 'Also fail on leads, not only proven findings — the strict CI posture', <Mono key="d">off</Mono>],
          [<Mono key="f">--severity</Mono>, 'Show only findings at or above a severity', <Mono key="d">all</Mono>],
          [<Mono key="f">--invariant ID</Mono>, 'Run one detector (e.g. gen_sql_injection)', <Mono key="d">all</Mono>],
          [<Mono key="f">--file FILE</Mono>, 'Write the report to a file instead of stdout', <Mono key="d">—</Mono>],
          [<Mono key="f">--parallel</Mono>, 'Scan files in parallel', <Mono key="d">off</Mono>],
          [<Mono key="f">--no-color</Mono>, 'Plain output for logs and CI', <Mono key="d">auto</Mono>],
        ]}
      />
      <H3>Inline suppression</H3>
      <P>
        A synthetic key in a test fixture is indistinguishable from a real one by inspection, so the author says so where it lives: <Code>truent:allow</Code> on a line (or the line above)
        suppresses every finding there; <Code>truent:allow gen_xss_sink</Code> suppresses one detector. Suppressed counts are reported, never hidden.
      </P>

      <H2 mono>truent deps</H2>
      <Cmd>truent deps . --advisory-db ./advisory-db --sbom sbom.cdx.json --fail-on high</Cmd>
      <P>
        Parses Cargo, npm (v1–v3), yarn, pip, Poetry, Pipfile and Go lockfiles; matches every pinned version against RustSec and OSV advisories with correct semver range semantics;
        checks pinning, lockfile integrity hashes, install scripts, dependency confusion (<Code>--extra-index-url</Code>, unmapped private npm scopes) and typosquat candidates; writes a
        CycloneDX 1.5 SBOM. Without <Code>--advisory-db</Code> it makes no vulnerability claims — clone <Code>rustsec/advisory-db</Code> or point it at a directory of OSV JSON.
      </P>

      <H2 mono>truent harden</H2>
      <Cmd>truent harden . --write</Cmd>
      <P>
        Profiles the repository (GitHub Actions, Dockerfile, Cargo / npm / pip / Go, Express, Next.js, Django, Flask, Solidity) and generates the preventive controls: a secrets{' '}
        <Code>.gitignore</Code> (merged, missing lines only), Dependabot for every ecosystem present, a pre-commit hook, a least-privilege CI gate with SARIF upload, framework
        security-header configuration, a hardened Dockerfile shape, contract invariants, load / chaos / DR / mutation harnesses, a Sigma detection rule and CODEOWNERS. Dry run by
        default; <Code>--write</Code> never overwrites an existing file.
      </P>

      <H2 mono>truent doctor</H2>
      <Cmd>truent doctor</Cmd>
      <P>Self-tests every component against real fixtures — detectors, taxonomy, dependency analysis, probe evaluators, symbolic parsers, exposure table, release checklist — and exits non-zero if any fails. Run it after installing or upgrading.</P>

      <H2>Exit codes</H2>
      <Table
        cols="0.4fr 3fr"
        rows={[
          [<span key="c" className="font-mono text-[13px] font-semibold text-acc-text">0</span>, 'Completed; nothing at or above --fail-on'],
          [<span key="c" className="font-mono text-[13px] font-semibold text-[#ef4444]">1</span>, 'Completed; a finding at or above --fail-on exists (or release-check --strict is NOT READY)'],
          [<span key="c" className="font-mono text-[13px] font-semibold text-[#fbbf24]">2</span>, 'symbolic: no executor ran — the result is an error, not a pass'],
        ]}
      />

      <H2 mono>truent probe</H2>
      <Cmd>truent probe https://example.com --authorized --format json --out probe.json</Cmd>
      <P>
        TLS (expiry, untrusted / self-signed / wrong-name certificate, no modern protocol), security headers, cookie flags, HTTP→HTTPS redirect, version banners, files that must
        never be served (confirmed by content signature), and a TCP sweep of 20 common ports. Sends only GETs and connects; cookie values and bodies are never recorded. Refuses to run
        without <Code>--authorized</Code>. Findings are <strong className="text-text">proven</strong>.
      </P>

      <H2 mono>truent symbolic</H2>
      <Cmd>truent symbolic ./foundry-project --format json --out symbolic.json</Cmd>
      <P>
        Drives the first installed executor (halmos, then hevm, then Mythril; <Code>--tool</Code> to choose). A counterexample is recorded as a proven{' '}
        <Code>evm_symbolic_counterexample</Code> with the concrete input; a timeout or all-paths-reverted check is <Code>evm_symbolic_unresolved</Code>, a lead, never a pass.
      </P>

      <H2 mono>truent exposure</H2>
      <Cmd>truent exposure . --probe-report probe.json</Cmd>
      <P>Rates every finding {Object.values(EXPLOITABILITY).map((e) => e.label).join(' / ')}, lists completed attack chains with the step where the cheapest fix breaks them, and prints the fix and verify step for each finding. Honours <Code>[[accept]]</Code> entries in <Code>.truent.toml</Code>.</P>

      <H2 mono>truent release-check</H2>
      <Cmd>truent release-check . --probe-report probe.json --symbolic-report symbolic.json --strict</Cmd>
      <P>
        Walks the 33-section codebase safety &amp; security checklist ({'>'}400 items). Statuses: PASS, ACCEPTED (under a dated, owned risk acceptance), FAIL, PARTIAL (the test exists but CI never
        runs it), MISSING, NEEDS-TOOL (pass a probe / symbolic report), ASSESS (a person must verify), N/A. <Code>--strict</Code> exits 1 unless READY.
      </P>

      <H2>Risk acceptance</H2>
      <Block>
        <K>[[accept]]</K>{'\n'}
        <K>id</K>     = <V>&quot;sca_unmaintained_dependency&quot;</V>{'\n'}
        <K>path</K>   = <V>&quot;Cargo.lock&quot;</V>{'\n'}
        <K>match</K>  = <V>&quot;paste&quot;</V>{'\n'}
        <K>reason</K> = <V>&quot;transitive via alloy-primitives; no maintained replacement resolvable&quot;</V>{'\n'}
        <K>owner</K>  = <V>&quot;@maintainer&quot;</V>{'\n'}
        <K>until</K>  = <V>&quot;2027-03-31&quot;</V>
      </Block>
      <P>Accepted findings are listed in every report, never hidden; an expired entry stops applying; a malformed file fails loudly.</P>
    </article>
  )
}

function Honesty() {
  return (
    <article>
      <H1>Evidence &amp; exploitability</H1>
      <Lede>How to read a Truent finding: what the engine actually knows, and how possible exploitation is.</Lede>

      <H2>The honesty contract</H2>
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-[14px] border border-hair bg-white/[0.02] p-6">
          <div className="mb-2 font-mono text-[10px] tracking-[0.16em] text-[#8fa398]">LEAD</div>
          <p className="m-0 text-[13px] leading-[1.7] text-sec">
            A pattern or dataflow the engine traced in source — including taint flows across lines, contract invariants, dependency advisories and misconfiguration. Strong evidence,
            but a static inference: it has not been demonstrated by execution.
          </p>
        </div>
        <div className="rounded-[14px] border border-acc-text/25 bg-acc-text/[0.05] p-6">
          <div className="mb-2 font-mono text-[10px] tracking-[0.16em] text-acc-text">PROVEN</div>
          <p className="m-0 text-[13px] leading-[1.7] text-sec">
            A concrete witness exists: the probe observed it on the wire (an expired certificate, a served <Code>/.env</Code>), or a symbolic executor produced an input that violates the
            property. Nothing else is ever marked proven.
          </p>
        </div>
      </div>

      <H2>Exploitability</H2>
      <P>
        Every detector carries an attack profile — where the attacker must stand (network / adjacent / local), what they must already hold (nothing / an account / a condition / a privileged
        role), whether a victim must act, and what success buys. Combined with the evidence class it yields a rating; a proven observation raises it. It is a profile, not a demonstration.
      </P>
      <Table
        cols="1fr 3fr"
        rows={Object.values(EXPLOITABILITY).map((e) => [<span key="l" className="font-mono text-[12px] font-semibold" style={{ color: e.color }}>{e.label}</span>, e.title])}
      />

      <H2>Attack chains</H2>
      <P>
        Findings compose. <Code>exposure</Code> knows {ENGINE.attackChains.length} shapes in which two or three findings form a real attack path, and reports each completed one with its
        narrative, the ATT&amp;CK tactic sequence, and the step where the cheapest fix breaks it.
      </P>
      <div className="grid gap-2.5 sm:grid-cols-2">
        {ENGINE.attackChains.map((c) => (
          <div key={c.id} className="rounded-[10px] border border-white/[0.06] bg-white/[0.02] px-4 py-3">
            <div className="text-[13px] font-medium text-text">{c.name}</div>
            <div className="mt-1 font-mono text-[10px] text-[#748078]">{c.steps.map((s) => s.role).join(' → ')}</div>
          </div>
        ))}
      </div>

      <H2>Fix and verify</H2>
      <P>
        Every one of the {ENGINE.totalDetectors} detectors ships with the change that closes the weakness and the command or test that shows the fix landed. They appear in the dashboard,
        in <Code>exposure</Code>, and in SARIF rule help so GitHub code scanning shows them inline.
      </P>
    </article>
  )
}

function DashboardApi() {
  const Verb = ({ method, path }: { method: 'POST' | 'GET' | 'PATCH'; path: string }) => (
    <h2 className="mb-3.5 mt-[52px] text-[22px] font-normal tracking-[-0.02em] text-[#f2f6f2]">
      <span className={`align-middle rounded-[5px] border px-[9px] py-1 font-mono text-[12px] ${method === 'GET' ? 'border-[#8fdcb2]/25 bg-[#8fdcb2]/10 text-[#8fdcb2]' : 'border-acc-text/25 bg-acc-text/10 text-acc-text'}`}>{method}</span>
      <span className="ml-3 font-mono text-[19px]">{path}</span>
    </h2>
  )
  return (
    <article>
      <H1>Dashboard API</H1>
      <Lede>The hosted dashboard queues scans and stores reports. Requests are authenticated by your dashboard session.</Lede>

      <Verb method="POST" path="/api/analyze" />
      <P>Queue a scan of one file. The worker writes the source under the name its language expects and runs the matching engine.</P>
      <Block>
        {'{\n  '}<K>&quot;projectName&quot;</K>: <V>&quot;vault-v2&quot;</V>,{'\n  '}
        <K>&quot;language&quot;</K>: <V>&quot;solidity&quot;</V>,  <span className="text-[#5c665f]">{'// solidity rust soroban move python javascript typescript go shell dockerfile terraform yaml'}</span>{'\n  '}
        <K>&quot;code&quot;</K>: <V>&quot;pragma solidity ^0.8.20;…&quot;</V>
        {'\n}'}
      </Block>
      <H3>Response — 202 Accepted</H3>
      <Block>
        {'{ '}<K>&quot;success&quot;</K>: <V>true</V>, <K>&quot;scanId&quot;</K>: <V>&quot;clx…&quot;</V>, <K>&quot;status&quot;</K>: <V>&quot;queued&quot;</V>{' }'}
      </Block>
      <P>Limits: 5 submissions per minute; 5 scans per month on Starter, 10,000 on Professional. Submitted source is deleted from the database as soon as the scan finishes.</P>

      <Verb method="GET" path="/api/scans/:id" />
      <P>The scan and its findings. Poll every two seconds while <Code>status</Code> is <Code>queued</Code> or <Code>processing</Code>.</P>
      <Block>
        {'{ '}<K>&quot;scan&quot;</K>: {'{\n    '}
        <K>&quot;status&quot;</K>: <V>&quot;complete&quot;</V>, <K>&quot;durationMs&quot;</K>: <V>412</V>,{'\n    '}
        <K>&quot;findings&quot;</K>: [{'{\n      '}
        <K>&quot;invariantId&quot;</K>: <V>&quot;gen_sql_injection&quot;</V>, <K>&quot;severity&quot;</K>: <span className="text-[#fbbf24]">&quot;high&quot;</span>,{'\n      '}
        <K>&quot;evidence&quot;</K>: <V>&quot;lead&quot;</V>, <K>&quot;exploitability&quot;</K>: <span className="text-[#ef4444]">&quot;likely&quot;</span>,{'\n      '}
        <K>&quot;location&quot;</K>: <V>&quot;app.py · Line 9&quot;</V>, <K>&quot;cwe&quot;</K>: <V>&quot;CWE-89 · …&quot;</V>,{'\n      '}
        <K>&quot;fix&quot;</K>: <V>&quot;Use parameterized queries…&quot;</V>, <K>&quot;verify&quot;</K>: <V>&quot;Taint test: …&quot;</V>,{'\n      '}
        <K>&quot;status&quot;</K>: <V>&quot;open&quot;</V>
        {'\n    }]\n  }\n}'}
      </Block>

      <Verb method="PATCH" path="/api/scans/:id" />
      <P>Update a finding&apos;s workflow status.</P>
      <Block>
        {'{ '}<K>&quot;findingId&quot;</K>: <V>&quot;clx…&quot;</V>, <K>&quot;status&quot;</K>: <V>&quot;acknowledged&quot;</V>{' }'}  <span className="text-[#5c665f]">{'// open | acknowledged | resolved'}</span>
      </Block>

      <Verb method="GET" path="/api/scans" />
      <P>Your scan history, newest first (<Code>?limit=</Code> up to 100), with severity and evidence counts.</P>

      <H2>The CLI JSON contract</H2>
      <P>
        <Code>truent scan --output json</Code> emits <Code>violations[]</Code> with <Code>invariant_id</Code>, <Code>severity</Code>, <Code>file</Code>, <Code>line</Code>,{' '}
        <Code>chain</Code>, <Code>evidence</Code>, <Code>exploitability</Code>, <Code>exploit_reasons</Code>, <Code>fix</Code>, <Code>verify</Code>, <Code>cwe</Code>,{' '}
        <Code>attack</Code>, <Code>nist_csf</Code> and <Code>code_snippet</Code>. The dashboard stores exactly these.
      </P>
    </article>
  )
}

function CiCd() {
  return (
    <article>
      <H1>CI/CD integration</H1>
      <Lede>Gate pull requests, upload SARIF to code scanning, and run the release check on the default branch.</Lede>

      <H2>GitHub Actions</H2>
      <Block>
        <K>name</K>: truent gate{'\n'}
        <K>on</K>: [pull_request, push]{'\n'}
        <K>permissions</K>:{'\n  '}<K>contents</K>: read{'\n  '}<K>security-events</K>: write{'\n'}
        <K>jobs</K>:{'\n  '}<K>scan</K>:{'\n    '}<K>runs-on</K>: ubuntu-latest{'\n    '}<K>steps</K>:{'\n      - '}
        <K>uses</K>: actions/checkout@<span className="text-[#748078]">{'<sha>'}</span> <span className="text-[#5c665f]">{'# pin to a commit'}</span>{'\n      - '}
        <K>run</K>: <V>cargo install truent-cli --locked</V>{'\n      - '}
        <K>run</K>: <V>truent scan . --chain auto --sarif truent.sarif --fail-on high</V>{'\n      - '}
        <K>run</K>: <V>truent deps . --fail-on high</V>{'\n      - '}
        <K>uses</K>: github/codeql-action/upload-sarif@<span className="text-[#748078]">{'<sha>'}</span>{'\n        '}
        <K>with</K>:{'\n          '}<K>sarif_file</K>: <V>truent.sarif</V>
      </Block>
      <P>
        <Code>truent harden . --write</Code> generates this workflow with actions pinned, plus Dependabot, a pre-commit hook and CODEOWNERS.
      </P>

      <H2>Probe the deployed service</H2>
      <Block>
        <K>- run</K>: <V>truent probe https://staging.example.com --authorized --format json --out probe.json</V>
      </Block>

      <H2>Release check on main</H2>
      <Block>
        <K>- run</K>: <V>truent release-check . --probe-report probe.json --symbolic-report symbolic.json --strict</V>
      </Block>
      <P>READY requires no FAIL, MISSING or PARTIAL item; ASSESS items are listed for sign-off. Findings under a dated <Code>[[accept]]</Code> are reported as ACCEPTED.</P>

      <H2>Failing the build</H2>
      <Table
        cols="0.4fr 3fr"
        rows={[
          [<span key="a" className="font-mono text-[13px] font-semibold text-acc-text">0</span>, 'Nothing at or above --fail-on — pipeline proceeds'],
          [<span key="b" className="font-mono text-[13px] font-semibold text-[#ef4444]">1</span>, 'A finding at or above --fail-on, or release-check --strict is NOT READY — fail the job'],
        ]}
      />
    </article>
  )
}

function Reports() {
  const fields = [
    ['Detector', 'invariant_id — `truent taxonomy` lists its CWE / ATT&CK / NIST rows'],
    ['Severity', 'Critical → Info'],
    ['Evidence', 'lead (static inference) or proven (concrete witness)'],
    ['Exploitability', 'LIKELY / POSSIBLE / UNLIKELY / THEORETICAL, with reasons'],
    ['Location', 'File and line, or URL / host:port for live findings'],
    ['Fix', 'The change that closes the weakness'],
    ['Verify', 'The command or test that shows the fix landed'],
    ['Mappings', 'CWE, MITRE ATT&CK, NIST CSF 2.0; SWC / OWASP / DASP for contracts'],
  ]
  return (
    <article>
      <H1>Reports &amp; release check</H1>
      <Lede>What a finding contains, which formats exist, and how the release checklist decides READY.</Lede>

      <H2>Reading a finding</H2>
      <div className="grid gap-2.5 sm:grid-cols-2">
        {fields.map(([k, v]) => (
          <div key={k} className="flex gap-3 rounded-[10px] border border-white/[0.06] bg-white/[0.02] px-4 py-3 text-[13px] leading-[1.65] text-sec">
            <strong className="min-w-[110px] font-medium text-text">{k}</strong>
            {v}
          </div>
        ))}
      </div>

      <H2>Severity definitions</H2>
      <SeverityTable />

      <H2>Formats</H2>
      <div className="grid gap-3 md:grid-cols-4">
        {[
          { t: 'JSON', d: 'The full contract above; what the dashboard stores and what CI parses.' },
          { t: 'SARIF', d: 'GitHub / GitLab code scanning: deduplicated rules with CWE taxonomy, security-severity, and the fix in rule help.' },
          { t: 'HTML', d: 'A self-contained, XSS-safe report for auditors and stakeholders.' },
          { t: 'Markdown', d: 'exposure, assess, threat-model and release-check write Markdown for pull-request summaries.' },
        ].map((f) => (
          <div key={f.t} className="rounded-2xl border border-hair bg-white/[0.02] p-6">
            <h3 className="m-0 mb-2 text-[15px] font-medium text-text">{f.t}</h3>
            <p className="m-0 text-[12.5px] leading-[1.65] text-sec">{f.d}</p>
          </div>
        ))}
      </div>

      <H2>The release checklist</H2>
      <P>
        <Code>release-check</Code> walks 33 sections — functional, regression, SAST, DAST, supply chain, fuzzing, property tests, business logic, state, authorization, authentication,
        concurrency, data integrity, financial, contracts, API, browser, load, chaos, migration, performance, differential, mutation, secrets, logging, files, DoS, build, boundaries,
        recovery, code quality, critical path, final validation. What an engine can decide is decided; what only your own system can run is checked for existence and CI wiring; what only a
        person can verify is listed for sign-off.
      </P>
      <Table
        cols="1fr 3fr"
        rows={[
          [<Mono key="s">PASS</Mono>, 'An engine ran over applicable files and found nothing'],
          [<Mono key="s">ACCEPTED</Mono>, 'Findings exist but every one is under a dated, owned risk acceptance — listed, never hidden'],
          [<Mono key="s">FAIL</Mono>, 'Findings, with counts'],
          [<Mono key="s">PARTIAL</Mono>, 'The test suite / harness exists but no CI workflow runs it; or a symbolic check is undecided'],
          [<Mono key="s">MISSING</Mono>, 'Nothing found — truent harden generates a starting point'],
          [<Mono key="s">NEEDS-TOOL</Mono>, 'Pass a truent probe / truent symbolic report'],
          [<Mono key="s">ASSESS</Mono>, 'Only a person with the system can verify'],
          [<Mono key="s">N/A</Mono>, 'Nothing in the repository to apply to'],
        ]}
      />
    </article>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function DocsPage() {
  const [page, setPage] = useState<PageId>('overview')

  useEffect(() => {
    const apply = () => {
      const h = window.location.hash.replace('#', '')
      const target = ALIASES[h] || h
      if (PAGES.some((p) => p.id === target)) setPage(target as PageId)
    }
    apply()
    window.addEventListener('hashchange', apply)
    return () => window.removeEventListener('hashchange', apply)
  }, [])

  const go = (id: PageId) => {
    setPage(id)
    window.history.replaceState(null, '', `#${id}`)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return (
    <PageShell glow="radial-gradient(1100px 500px at 50% -120px, rgba(52,211,153,0.12), rgba(6,9,8,0) 60%)">
      <MarketingNav />

      <div className="mx-auto grid max-w-[1200px] items-start gap-12 px-6 pt-14 md:grid-cols-[210px_1fr]">
        <aside className="md:sticky md:top-24">
          <div className="mb-[18px] hidden overflow-hidden opacity-30 md:block">
            <AsciiLogo className="text-[3.2px] !leading-[1.08]" />
          </div>
          <div className="mb-3.5 font-mono text-[10px] uppercase tracking-[0.18em] text-[#5c665f]">Documentation</div>
          <nav className="flex flex-row flex-wrap gap-0.5 md:flex-col">
            {PAGES.map((p) => (
              <button
                key={p.id}
                onClick={() => go(p.id)}
                aria-current={page === p.id ? 'page' : undefined}
                className={`rounded-[9px] border-l-2 px-3 py-[9px] text-left text-[13px] transition-colors ${page === p.id ? 'border-acc-text bg-acc-text/[0.09] font-medium text-text' : 'border-transparent text-[#8a948d] hover:text-text'}`}
              >
                {p.label}
              </button>
            ))}
          </nav>
          <div className="mt-7 flex flex-col gap-2.5 border-t border-white/[0.06] pt-5">
            <a href="https://github.com/Emmyhack/Truent" target="_blank" rel="noopener noreferrer" className="text-[12.5px] text-sec transition-colors hover:text-text">GitHub repo ↗</a>
          </div>
        </aside>

        <main className="min-h-[70vh] pb-[90px]">
          {page === 'overview' && <Overview go={go} />}
          {page === 'getting-started' && <GettingStarted />}
          {page === 'cli' && <CliReference />}
          {page === 'honesty' && <Honesty />}
          {page === 'api' && <DashboardApi />}
          {page === 'ci-cd' && <CiCd />}
          {page === 'reports' && <Reports />}

          <div className="mt-[70px] flex flex-wrap items-center justify-between gap-3.5 border-t border-white/[0.06] pt-7">
            <Link href="/pricing" className="text-[13px] text-sec transition-colors hover:text-text">← Plans</Link>
            <Link href="/contact" className="text-[13px] text-acc-text">Need help? Talk to us →</Link>
          </div>
        </main>
      </div>

      <SlimFooter omit={['Docs']} />
    </PageShell>
  )
}
