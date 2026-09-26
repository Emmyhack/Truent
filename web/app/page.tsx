'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { AnimatedCounter } from '@/components/ui/AnimatedCounter'
import { TRUENT_ASCII } from '@/components/ui/AsciiLogo'
import { ParticleHero } from '@/components/ui/ParticleHero'
import { MarketingNav } from '@/components/layout/MarketingNav'
import { MarketingFooter } from '@/components/layout/MarketingFooter'
import { AuthModal } from '@/components/ui/AuthModal'
import { SampleReportModal } from '@/components/ui/SampleReportModal'
import { ChainLogo } from '@/components/ui/ChainLogo'
import { CHAIN_LABEL, CHAIN_ORDER, ENGINE, EVM_COMPATIBLE, NETWORKS, networksForChain, type Chain } from '@/lib/engine'

// ─────────────────────────────────────────────────────────────────────────────
// Copy. Every number is read from lib/catalog.json, which is regenerated from
// the binary — the page can never promise a detector the engine lacks.
// ─────────────────────────────────────────────────────────────────────────────

const steps = [
  {
    num: '01',
    title: 'Point it at what you ship',
    desc: 'A contract, a service, an infrastructure file, a whole repository. One command chooses the right engine for every file; the dashboard takes a single file in seconds.',
  },
  {
    num: '02',
    title: 'Let the engine do the whole job',
    desc: `${ENGINE.totalDetectors} detectors follow untrusted input to the sink, check protocol invariants, match dependencies against advisories, and — when you ask — probe the live edge or hand a Foundry project to a solver.`,
  },
  {
    num: '03',
    title: 'Fix what matters first',
    desc: 'Every finding says whether it is a traced lead or a proven fact, how likely it is to be exploited, the change that closes it, and the command that proves the change worked.',
  },
]

const exploits = [
  { protocol: 'Euler Finance', amount: '$197M', year: '2023', type: 'A flash loan met a vault that never re-checked its own health after the trade.', invariant: 'evm_missing_post_state_health_check' },
  { protocol: 'Nomad Bridge', amount: '$190M', year: '2022', type: 'A Merkle root left at zero made every forged proof valid.', invariant: 'evm_merkle_root_zero_default' },
  { protocol: 'KelpDAO', amount: '$292M', year: '2024', type: 'A cross-chain message needed only one verifier, and that verifier was the weak point.', invariant: 'evm_dvn_single_point_failure' },
]

const reportPerks = [
  'Lead or proven — the evidence class is on every finding',
  'Exploitability, from LIKELY to THEORETICAL, with the reasons',
  'The attack chains your findings complete, and where to cut them',
  'A fix and a verify step for all of them',
  'JSON here; SARIF, HTML and Markdown from the CLI',
]

const plans = [
  { name: 'Starter', price: '$0', per: ' / month', accent: 'text-sec', href: '/pricing', caption: 'The whole engine, five dashboard scans a month' },
  { name: 'Professional', price: '$499', per: ' / month', accent: 'text-acc-text', href: '/pricing', caption: 'Ten thousand scans, custom invariants, priority support', featured: true },
  { name: 'Enterprise', price: 'Custom', per: '', accent: 'text-sec', href: '/contact', caption: 'Managed probes, SSO, on-premises, an engineer on call' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Primitives
// ─────────────────────────────────────────────────────────────────────────────

function useInView<T extends HTMLElement>(threshold = 0.2) {
  const ref = useRef<T | null>(null)
  const [seen, setSeen] = useState(false)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (el.getBoundingClientRect().bottom < 0) {
      setSeen(true)
      return
    }
    const io = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting) {
          setSeen(true)
          io.disconnect()
        }
      },
      { threshold },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [threshold])
  return { ref, seen }
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return <h2 className="m-0 text-[clamp(30px,4vw,44px)] font-normal leading-[1.15] tracking-[-0.02em] text-text">{children}</h2>
}

function Lede({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <p className={`m-0 mt-4 text-[14.5px] leading-[1.75] text-sec ${className}`}>{children}</p>
}

function PrimaryCta({ onClick, href, children, className = '' }: { onClick?: () => void; href?: string; children: React.ReactNode; className?: string }) {
  const cls = `inline-flex items-center gap-3 rounded-full bg-text py-[7px] pl-[22px] pr-[7px] text-[14px] font-semibold text-bg transition-all hover:-translate-y-0.5 hover:bg-acc-text ${className}`
  const inner = (
    <>
      {children}
      <span className="flex h-8 w-8 items-center justify-center rounded-full bg-acc-text text-[15px] text-on-acc">→</span>
    </>
  )
  return href ? <Link href={href} className={cls}>{inner}</Link> : <button onClick={onClick} className={cls}>{inner}</button>
}

function GhostCta({ onClick, href, children }: { onClick?: () => void; href?: string; children: React.ReactNode }) {
  const cls = 'inline-flex items-center rounded-full border border-hair-strong px-6 py-3.5 text-[14px] font-medium text-text transition-colors hover:border-acc-text/50 hover:text-text'
  return href ? <Link href={href} className={cls}>{children}</Link> : <button onClick={onClick} className={cls}>{children}</button>
}

function Reveal({ children, className = '', id }: { children: React.ReactNode; className?: string; id?: string }) {
  const { ref, seen } = useInView<HTMLDivElement>(0.02)
  return (
    <div ref={ref} id={id} className={className} style={{ opacity: seen ? 1 : 0.06, transition: 'opacity 0.9s cubic-bezier(0.16,0.84,0.28,1)' }}>
      {children}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Sections
// ─────────────────────────────────────────────────────────────────────────────

/** Detectors per engine — the catalogue itself, one bar per analyzer. */
function CoverageChart() {
  const { ref, seen } = useInView<HTMLDivElement>(0.25)
  const bars = CHAIN_ORDER.filter((c) => c !== 'chain-agnostic').map((c) => ({ id: c, label: CHAIN_LABEL[c as Chain], count: ENGINE.byChain[c] ?? 0 }))
  const max = Math.max(...bars.map((b) => b.count), 1)
  const ticks = [max, Math.round(max * 0.75), Math.round(max * 0.5), Math.round(max * 0.25), 0]

  return (
    <div ref={ref} className="relative mt-12 overflow-hidden rounded-[20px] border border-hair bg-surface-2 px-[30px] pb-[22px] pt-[26px]">
      <div className="pointer-events-none absolute left-[12%] top-[16%] h-[260px] w-[420px] rounded-full blur-3xl" style={{ background: 'var(--acc-soft)', animation: 'glowpulse 6s ease-in-out infinite' }} />
      <div className="relative mb-[26px] flex flex-wrap items-baseline justify-between gap-2">
        <span className="font-mono text-[10.5px] uppercase tracking-[0.16em] text-acc-text">Detectors by engine</span>
        <span className="font-mono text-[11px] text-sec">truent taxonomy --format json · {ENGINE.version}</span>
      </div>
      <div className="relative grid grid-cols-[34px_1fr] gap-3.5">
        <div className="relative h-[250px] font-mono text-[11px] text-sec">
          {ticks.map((v, i) => (
            <span key={i} className="absolute right-0" style={{ top: `calc(${i * 25}% - 5px)` }}>{v}</span>
          ))}
        </div>
        <div>
          <div className="relative h-[250px]">
            <div className="pointer-events-none absolute inset-0">
              {[0, 25, 50, 75].map((t) => (
                <div key={t} className="absolute left-0 right-0 h-px bg-hair" style={{ top: `${t}%` }} />
              ))}
              <div className="absolute bottom-0 left-0 right-0 h-px bg-hair-strong" />
            </div>
            <div className="absolute bottom-px left-0 right-0 top-0 grid items-end gap-[14px]" style={{ gridTemplateColumns: `repeat(${bars.length}, minmax(0, 1fr))` }}>
              {bars.map((bar, i) => {
                const hot = bar.id === 'evm' || bar.id === 'general'
                return (
                  <div key={bar.id} className="relative flex h-full flex-col justify-end">
                    <div className={`mb-[9px] text-center font-mono text-[12px] font-semibold ${hot ? 'text-acc-text' : 'text-sec'}`} style={{ opacity: seen ? 1 : 0, transition: `opacity 0.5s ease ${180 + i * 110}ms` }}>
                      {bar.count}
                    </div>
                    <div
                      style={{
                        height: seen ? `${(bar.count / max) * 100}%` : '0%',
                        borderRadius: '6px 6px 0 0',
                        transition: `height 1.05s cubic-bezier(0.16,0.84,0.28,1) ${180 + i * 110}ms`,
                        background: hot ? 'var(--acc-text)' : 'var(--hair-strong)',
                        borderTop: `2px solid ${hot ? 'var(--acc-text)' : 'var(--acc)'}`,
                        boxShadow: hot ? '0 -8px 40px var(--acc-soft)' : undefined,
                      }}
                    />
                  </div>
                )
              })}
            </div>
          </div>
          <div className="grid gap-[14px] pt-3" style={{ gridTemplateColumns: `repeat(${bars.length}, minmax(0, 1fr))` }}>
            {bars.map((bar) => (
              <div key={bar.id} className="text-center">
                <div className="mb-1.5 flex h-[15px] items-center justify-center gap-1">
                  {networksForChain(bar.id as Chain).map((n) => (
                    <ChainLogo key={n} network={n} size={14} className="text-sec" />
                  ))}
                </div>
                <div className="font-mono text-[10.5px] tracking-[0.04em] text-text">{bar.label}</div>
                <div className="mt-[5px] font-mono text-[10px] text-sec">{bar.id}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

/** The networks the chain analyzers target, each with its own mark. */
function NetworkBand() {
  return (
    <div className="mt-12">
      <div className="mb-5 flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="m-0 text-[15px] font-medium text-text">Chains Truent reads natively</h3>
        <span className="font-mono text-[11px] text-sec">truent scan . --chain auto</span>
      </div>

      <div className="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-5">
        {NETWORKS.map((n) => (
          <div key={n.id} className="flex flex-col rounded-[16px] border border-hair bg-surface-2 p-5 transition-colors duration-200 hover:border-acc-text/[0.35]">
            <ChainLogo network={n.id} size={26} />
            <div className="mt-3.5 text-[15px] font-medium text-text">{n.name}</div>
            <div className="mt-0.5 font-mono text-[11px] text-sec">{n.language}</div>
            <p className="m-0 mt-3 flex-1 text-[12px] leading-[1.6] text-sec">{n.note}</p>
            <div className="mt-4 border-t border-hair pt-3 font-mono text-[10.5px] tracking-[0.04em] text-sec">
              {CHAIN_LABEL[n.chain]} engine · {ENGINE.byChain[n.chain] ?? 0} detectors
            </div>
          </div>
        ))}
      </div>

      <div className="mt-3.5 flex flex-wrap items-center gap-x-5 gap-y-3 rounded-[14px] border border-hair bg-surface-2 px-5 py-4">
        <span className="text-[12.5px] leading-[1.5] text-sec">
          The Solidity engine runs unchanged on every EVM-compatible chain
        </span>
        <span className="flex flex-wrap items-center gap-3.5">
          {EVM_COMPATIBLE.map((id) => (
            <ChainLogo key={id} network={id} size={19} className="text-sec transition-colors duration-200 hover:text-text" />
          ))}
        </span>
      </div>
    </div>
  )
}

/** Real engine output, revealed one line at a time. */
function TerminalPanel() {
  const { ref, seen } = useInView<HTMLDivElement>(0.4)
  const lines: Array<{ id: string; el: React.ReactNode }> = [
    { id: 'scan', el: <><span className="text-acc-text">SCAN</span><span className="text-sec">{'  '}chain=auto · 3 engines selected · {ENGINE.totalDetectors} detectors loaded</span></> },
    { id: 'gap-0', el: <>&nbsp;</> },
    { id: 'high', el: <><span className="text-high">HIGH</span><span className="text-text">{'  '}gen_sql_injection  api/orders.py:41  <span className="text-sec">LEAD · LIKELY</span></span></> },
    { id: 'h1', el: <span className="text-sec">{'      '}tainted value `uid` reaches a SQL query (request.args → line 39 → execute)</span> },
    { id: 'h2', el: <span className="text-sec">{'      '}fix: parameterized query · verify: taint test source→query no longer present</span> },
    { id: 'gap-1', el: <>&nbsp;</> },
    { id: 'crit', el: <><span className="text-critical">CRITICAL</span><span className="text-text">{'  '}evm_reentrancy_classic  contracts/Vault.sol:88  <span className="text-sec">LEAD · LIKELY</span></span></> },
    { id: 'c1', el: <span className="text-sec">{'      '}external call before state update; no nonReentrant guard</span> },
    { id: 'gap-2', el: <>&nbsp;</> },
    { id: 'chain', el: <><span className="text-critical">CHAIN</span><span className="text-text">{'  '}injection-to-data-exfiltration · break at step 1</span></> },
    { id: 'done', el: <><span className="text-acc-text">GATE</span><span className="text-sec">{'  '}2 findings ≥ high. exit 1 — merge blocked.</span><span className="text-acc-text" style={{ animation: 'blink 1s infinite' }}>▊</span></> },
  ]
  return (
    <div className="rounded-[18px] border border-hair bg-panel/90 p-1.5 shadow-[0_30px_80px_var(--overlay)]">
      <div className="flex items-center gap-1.5 border-b border-hair px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-critical opacity-80" />
        <span className="h-2.5 w-2.5 rounded-full bg-high opacity-80" />
        <span className="h-2.5 w-2.5 rounded-full bg-acc-text opacity-80" />
        <span className="ml-2.5 font-mono text-[11px] text-sec">truent scan . --chain auto --fail-on high</span>
      </div>
      <div ref={ref} className="overflow-x-auto px-5 pb-[22px] pt-[18px] text-left font-mono text-[12.5px] leading-[1.85]">
        <pre aria-hidden="true" className="mb-3.5 overflow-hidden whitespace-pre font-mono text-[clamp(3.4px,0.62vw,7.4px)] leading-[1.08] text-acc-text/50" style={{ opacity: seen ? 1 : 0, transition: 'opacity 0.25s ease 250ms' }}>
          {TRUENT_ASCII}
        </pre>
        {lines.map((line, i) => (
          <div key={line.id} style={{ opacity: seen ? 1 : 0, transition: `opacity 0.25s ease ${250 + (i + 1) * 280}ms` }}>{line.el}</div>
        ))}
      </div>
    </div>
  )
}

function FeatureCard({ icon, title, children, span = false, featured = false, watermark, footer }: { icon: string; title: string; children: React.ReactNode; span?: boolean; featured?: boolean; watermark?: string; footer?: React.ReactNode }) {
  return (
    <div className={`relative overflow-hidden rounded-[18px] border p-[34px] transition-all duration-[250ms] hover:-translate-y-1 hover:shadow-[0_20px_50px_var(--overlay)] ${span ? 'md:col-span-2' : ''} ${featured ? 'border-acc-text/[0.22] bg-acc-text/[0.04] hover:border-acc-text/[0.45]' : 'border-hair bg-surface-2 hover:border-acc-text/[0.35]'}`}>
      {watermark && <div className="pointer-events-none absolute -bottom-[60px] -right-10 font-mono text-[120px] text-acc-text/[0.04]">{watermark}</div>}
      <div className="relative mb-5 flex h-11 w-11 items-center justify-center rounded-xl border border-acc-text/20 bg-acc-text/[0.08] text-[19px]">{icon}</div>
      <h3 className="relative m-0 mb-3 text-[18px] font-medium text-text">{title}</h3>
      <div className="relative text-[13.5px] leading-[1.7] text-sec">{children}</div>
      {footer}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function HomePage() {
  const [authOpen, setAuthOpen] = useState(false)
  const [authTab, setAuthTab] = useState<'signin' | 'signup'>('signin')
  const [sampleReportOpen, setSampleReportOpen] = useState(false)
  const startFree = () => {
    setAuthTab('signup')
    setAuthOpen(true)
  }
  const staticCount = ENGINE.totalDetectors - (ENGINE.byChain.runtime ?? 0)
  const engineCount = CHAIN_ORDER.length - 1

  return (
    <div className="min-h-screen bg-bg p-2.5">
      <div className="relative overflow-clip rounded-[22px] border border-hair bg-bg">
        <MarketingNav />

        <ParticleHero
          ascii={TRUENT_ASCII}
          wordmark="TRUENT"
          headline={
            <>
              Security findings you can act on.{' '}
              <span className="text-acc-text">Not a list of maybes.</span>
            </>
          }
          subline={
            <>
              Truent is one security engine for everything you ship — smart contracts, application code, infrastructure, dependencies and the live service. It tells you what
              it found, how sure it is, how likely an attacker is to reach it, and exactly how to close it.
            </>
          }
          bullets={
            <>
              {[
                ['◆', 'Lead or proven, on every finding'],
                ['◇', `${engineCount} engines, one command`],
                ['◇', 'The fix and how to verify it'],
                ['◇', 'Silent on correct code'],
              ].map(([mark, label]) => (
                <span key={label} className="flex items-center gap-1.5">
                  <span className="text-acc-text">{mark}</span>
                  {label}
                </span>
              ))}
            </>
          }
          actions={
            <>
              <PrimaryCta onClick={startFree} className="shadow-[0_0_40px_var(--acc-soft)]">Scan something free</PrimaryCta>
              <GhostCta href="#how-it-works">See how it works</GhostCta>
            </>
          }
          hint="Scroll ↓"
        />

        {/* ─── Coverage ─── */}
        <Reveal className="relative mx-auto max-w-[1180px] px-6 pb-24 pt-[110px]">
          <div className="grid items-end gap-14 md:grid-cols-[0.9fr_1.1fr]">
            <div>
              <SectionHeading>
                One engine for the whole system —{' '}
                <span className="text-acc-text">not five tools stitched together.</span>
              </SectionHeading>
            </div>
            <Lede className="max-w-[440px]">
              Most teams run a contract scanner here, a SAST tool there, a dependency bot, a header checker, and reconcile the results by hand. Truent runs all of it through one
              engine, one taxonomy and one report, so a finding in a Solidity vault and a finding in the Python service that calls it look, rank and fix the same way.
            </Lede>
          </div>

          <div className="mt-14 grid grid-cols-1 border-t border-hair sm:grid-cols-3">
            {[
              { value: ENGINE.totalDetectors, label: 'detectors, each mapped to CWE, MITRE ATT&CK and NIST CSF, each shipping its own fix' },
              { value: ENGINE.attackChains.length, label: 'attack chains the engine recognises when separate findings add up to a real attack path' },
              { value: ENGINE.pathways.length, label: 'security pathways covered, from design to recovery, with what is checked natively and what needs a person' },
            ].map((s, i) => (
              <div key={s.label} className={`py-[26px] ${i === 0 ? 'sm:pr-[30px]' : i === 1 ? 'sm:px-[30px]' : 'sm:pl-[30px]'} ${i < 2 ? 'sm:border-r sm:border-hair' : ''}`}>
                <div className="text-[clamp(34px,4vw,46px)] font-normal leading-none tracking-[-0.03em] text-text">
                  <AnimatedCounter value={s.value} decimals={0} />
                </div>
                <div className="mt-2.5 text-[12.5px] leading-[1.55] text-sec">{s.label}</div>
              </div>
            ))}
          </div>

          <CoverageChart />
          <NetworkBand />
        </Reveal>

        {/* ─── See it run ─── */}
        <Reveal className="mx-auto grid max-w-[1100px] items-center gap-14 px-6 pb-[100px] pt-16 md:grid-cols-[0.85fr_1.15fr]">
          <div>
            <SectionHeading>
              One command.
              <br />
              A verdict, not a pile.
            </SectionHeading>
            <Lede>
              <code className="text-acc-text">truent scan . --chain auto</code> picks the analyzer for each file, follows untrusted input across lines to the place it does damage, names
              the weakness and the technique behind it, and tells your pipeline whether this change is safe to merge. The output is the report — no second tool to interpret it.
            </Lede>
            <Link href="/docs#cli" className="mt-6 inline-flex items-center gap-2 rounded-full border border-hair-strong px-[22px] py-3 text-[13px] font-medium text-text transition-colors hover:border-acc-text/50 hover:text-text">
              Read the CLI reference →
            </Link>
          </div>
          <TerminalPanel />
        </Reveal>

        {/* ─── Capabilities ─── */}
        <Reveal className="mx-auto max-w-[1100px] px-6 pb-[100px] pt-10">
          <div id="features" className="mb-14 text-center">
            <SectionHeading>Built to be believed.</SectionHeading>
            <Lede className="mx-auto max-w-[560px]">
              A scanner that cries wolf gets ignored, and then the real one walks in. Truent is designed so that every line in a report is something you can stand behind.
            </Lede>
          </div>
          <div className="grid gap-3.5 md:grid-cols-3">
            <FeatureCard
              icon="◈"
              title="It never calls a guess a fact"
              span
              watermark="✓"
              footer={<Link href="/docs#honesty" className="relative mt-4 inline-block text-[13px] font-semibold text-acc-text">How evidence works →</Link>}
            >
              <p className="m-0 mb-3 max-w-[560px]">
                {staticCount} static detectors trace patterns, invariants, dataflows and advisories through your source. That is strong evidence, and Truent labels it exactly that:
                a <strong className="text-text">lead</strong>. Only two things earn the word <strong className="text-acc-text">proven</strong> — something the live probe observed
                on the wire, or an input a solver produced that breaks a property.
              </p>
              <p className="m-0 max-w-[560px]">And correct code stays quiet. Every analyzer is held to a corpus of known-good code that must produce zero findings, checked on every build.</p>
            </FeatureCard>
            <FeatureCard icon="◆" title="It tells you how likely, not just how bad">
              Severity says what an attack would cost. Exploitability says whether one is coming: from a network-reachable weakness that needs nothing in hand, down to a hardening gap
              behind a privileged role. Findings are ranked by both.
            </FeatureCard>
            <FeatureCard icon="⟁" title="It sees the attack, not just the bug">
              A cookie without <code className="text-acc-text">Secure</code> is a gap. The same cookie on a site that still answers plain HTTP is a session hijack. Truent knows{' '}
              {ENGINE.attackChains.length} of these shapes and shows you which step is cheapest to break.
            </FeatureCard>
            <FeatureCard icon="↺" title="It closes the loop">
              Each detector ships the change that fixes it and the command that proves the fix landed. <code className="text-acc-text">truent harden</code> then generates the controls —
              CI gates, dependency updates, secret hygiene, security headers — that keep the whole class from coming back.
            </FeatureCard>
            <FeatureCard icon="⟐" title="It brings in the heavy machinery honestly" featured>
              <code className="text-acc-text">truent symbolic</code> drives halmos, hevm or Mythril on your Foundry project. A counterexample comes back as a proven finding with the exact
              input; an undecided check stays a lead. If no solver is installed, you get an error — never a clean bill of health.
            </FeatureCard>
          </div>
        </Reveal>

        {/* ─── How it works ─── */}
        <Reveal id="how-it-works" className="border-y border-hair bg-surface-2 px-6 py-[100px]">
          <div className="mx-auto max-w-[1100px]">
            <div className="mb-[60px] text-center">
              <SectionHeading>From your tree to a release you can defend.</SectionHeading>
              <Lede className="mx-auto max-w-[520px]">Three steps, and the last one answers the only question that matters before you ship: are we ready?</Lede>
            </div>
            <div className="grid gap-3.5 md:grid-cols-3">
              {steps.map((s) => (
                <div key={s.num} className="rounded-[18px] border border-hair bg-surface-2 p-[34px]">
                  <div className="mb-[18px] text-[46px] font-light leading-none tracking-[-0.02em] text-acc-text/35">{s.num}</div>
                  <h3 className="m-0 mb-2.5 text-[16.5px] font-medium text-text">{s.title}</h3>
                  <p className="m-0 text-[13px] leading-[1.7] text-sec">{s.desc}</p>
                </div>
              ))}
            </div>
            <p className="mx-auto mt-10 max-w-[640px] text-center text-[13px] leading-[1.7] text-sec">
              <code className="text-acc-text">truent release-check</code> walks a 33-section safety checklist against your repository and reports every item as passed, failed, missing,
              or something only a person can sign off — and returns READY only when nothing is left hanging.
            </p>
          </div>
        </Reveal>

        {/* ─── Real incidents ─── */}
        <Reveal className="mx-auto max-w-[1100px] px-6 py-[100px]">
          <div className="mb-[52px] text-center">
            <SectionHeading>
              Every contract detector was written
              <br />
              against a loss that already happened.
            </SectionHeading>
            <Lede className="mx-auto max-w-[540px]">
              Not from a taxonomy — from post-mortems. Each one stays in the engine only as long as its reproduction case keeps failing when the check is turned off.
            </Lede>
          </div>
          <div className="grid gap-3.5 md:grid-cols-3">
            {exploits.map((e) => (
              <div key={e.protocol} className="relative overflow-hidden rounded-[18px] border border-hair bg-surface-2 p-[30px] transition-all duration-[250ms] hover:-translate-y-1 hover:border-critical-border hover:shadow-[0_20px_50px_var(--overlay)]">
                <div className="absolute left-0 right-0 top-0 h-0.5 bg-acc" />
                <div className="mb-4 flex items-start justify-between gap-3">
                  <div>
                    <div className="mb-1.5 font-mono text-[10.5px] tracking-[0.14em] text-sec">{e.year}</div>
                    <div className="text-[19px] font-medium text-text">{e.protocol}</div>
                  </div>
                  <span className="text-[23px] font-semibold tracking-[-0.02em] text-critical">{e.amount}</span>
                </div>
                <p className="m-0 mb-[18px] text-[13px] leading-[1.65] text-sec">{e.type}</p>
                <code className="break-all rounded-[5px] border border-hair bg-surface-2 px-2 py-[3px] font-mono text-[10.5px] text-sec">{e.invariant}</code>
              </div>
            ))}
          </div>
        </Reveal>

        {/* ─── Reports ─── */}
        <Reveal className="border-y border-hair bg-surface-2 px-6 py-[100px]">
          <div className="mx-auto grid max-w-[1100px] items-center gap-16 md:grid-cols-2">
            <div>
              <SectionHeading>A report that ends in a fix, not a meeting.</SectionHeading>
              <Lede className="mb-7">
                Open a finding and everything needed to close it is on the card: what the engine saw, how sure it is, who could reach it, the code change, and the check that proves the
                change worked. Triage it, hand it off, mark it resolved — the dashboard keeps the history.
              </Lede>
              <div className="mb-8 flex flex-col gap-3">
                {reportPerks.map((perk) => (
                  <div key={perk} className="flex items-center gap-3 text-[13.5px] text-text">
                    <span className="text-acc-text">✓</span>
                    {perk}
                  </div>
                ))}
              </div>
              <GhostCta onClick={() => setSampleReportOpen(true)}>View a sample report →</GhostCta>
            </div>

            <div className="rounded-[18px] border border-hair bg-panel/85 p-[26px] shadow-[0_30px_80px_var(--overlay)]">
              <div className="mb-[22px] flex items-start justify-between gap-3">
                <div>
                  <div className="mb-1.5 font-mono text-[10px] tracking-[0.16em] text-sec">REPORT</div>
                  <div className="text-[19px] font-medium text-text">vault-v2</div>
                  <div className="mt-1 text-[12px] text-sec">chain=auto · 0.4s · {ENGINE.version}</div>
                </div>
                <span className="whitespace-nowrap rounded-[5px] border border-acc-text/25 bg-acc-text/[0.08] px-[9px] py-1 font-mono text-[10px] tracking-[0.12em] text-acc-text">COMPLETE</span>
              </div>
              <div className="mb-5 grid grid-cols-4 gap-px overflow-hidden rounded-[10px] bg-hair">
                {[
                  { label: 'CRITICAL', count: 1, color: 'var(--critical)' },
                  { label: 'HIGH', count: 2, color: 'var(--high)' },
                  { label: 'PROVEN', count: 1, color: 'var(--acc-text)' },
                  { label: 'LIKELY', count: 2, color: 'var(--critical)' },
                ].map((sv) => (
                  <div key={sv.label} className="bg-bg px-2 py-4 text-center">
                    <div className="text-[26px] font-semibold" style={{ color: sv.color }}>{sv.count}</div>
                    <div className="mt-1 font-mono text-[9.5px] tracking-[0.14em] text-sec">{sv.label}</div>
                  </div>
                ))}
              </div>
              <div className="mb-5 flex flex-col gap-2">
                {[
                  { sev: 'CRITICAL', cls: 'border-critical-border bg-critical-bg text-critical', text: 'evm_reentrancy_classic · Vault.sol:88', tag: 'LEAD · LIKELY' },
                  { sev: 'HIGH', cls: 'border-high-border bg-high-bg text-high', text: 'gen_sql_injection · api/orders.py:41', tag: 'LEAD · LIKELY' },
                  { sev: 'HIGH', cls: 'border-high-border bg-high-bg text-high', text: 'rt_exposed_sensitive_path · /.env', tag: 'PROVEN' },
                ].map((f) => (
                  <div key={f.text} className="flex items-center gap-3 rounded-[10px] border border-hair bg-surface-2 px-3.5 py-[11px]">
                    <span className={`whitespace-nowrap rounded border px-[7px] py-0.5 font-mono text-[9.5px] tracking-[0.1em] ${f.cls}`}>{f.sev}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-text">{f.text}</span>
                    <span className="whitespace-nowrap font-mono text-[9.5px] tracking-[0.1em] text-sec">{f.tag}</span>
                  </div>
                ))}
              </div>
              <button onClick={() => setSampleReportOpen(true)} className="block w-full rounded-full border border-hair-strong py-[11px] text-center text-[12.5px] font-medium text-text transition-colors hover:border-acc-text/50 hover:text-text">
                ↓ View full report
              </button>
            </div>
          </div>
        </Reveal>

        {/* ─── Pricing preview ─── */}
        <Reveal className="mx-auto max-w-[1100px] px-6 pb-20 pt-[100px]">
          <div className="mb-14 text-center">
            <SectionHeading>The same engine on every plan.</SectionHeading>
            <Lede className="mx-auto max-w-[460px]">You pay for dashboard capacity and support — never for which detectors run. The free tier scans with all of them.</Lede>
          </div>
          <div className="grid overflow-hidden rounded-[18px] border border-hair md:grid-cols-3">
            {plans.map((plan, i) => (
              <Link key={plan.name} href={plan.href} className={`block px-[30px] py-7 transition-colors hover:bg-surface-2 ${i < 2 ? 'md:border-r md:border-hair' : ''} ${plan.featured ? 'bg-acc-text/[0.05]' : ''}`}>
                <div className={`font-mono text-[10.5px] uppercase tracking-[0.16em] ${plan.accent}`}>{plan.name}</div>
                <div className="mt-3.5 text-[34px] font-normal tracking-[-0.025em] text-text">
                  {plan.price}
                  <span className="text-[12.5px] text-sec">{plan.per}</span>
                </div>
                <p className="m-0 mt-2.5 text-[12.5px] leading-[1.6] text-sec">{plan.caption}</p>
              </Link>
            ))}
          </div>
          <div className="mt-7 text-center">
            <Link href="/pricing" className="inline-flex items-center gap-2.5 rounded-full border border-hair-strong px-5 py-[11px] font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-text transition-colors hover:border-acc-text/50 hover:text-text">
              Compare plans
              <span className="text-[13px] tracking-[-0.12em]">❯❯</span>
            </Link>
          </div>
        </Reveal>

        {/* ─── Let's talk band ─── */}
        <section className="relative mt-10">
          <div className="relative flex h-[190px] items-center justify-center overflow-hidden bg-acc">
            <Link href="/contact" className="relative whitespace-nowrap text-center text-[clamp(78px,13vw,190px)] font-bold leading-[0.92] tracking-[-0.05em] text-on-acc drop-shadow-[0_2px_40px_var(--overlay)]">
              LET&apos;S TALK
            </Link>
          </div>
        </section>

        {/* ─── Final CTA ─── */}
        <Reveal className="mx-auto max-w-[640px] px-6 pb-[90px] pt-[70px] text-center">
          <SectionHeading>Find out what is actually there.</SectionHeading>
          <Lede className="mx-auto max-w-[470px]">
            Paste a file into the dashboard and have a report in seconds — or install the CLI and run the entire engine against the tree you ship, on any plan, without an account.
          </Lede>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <PrimaryCta onClick={startFree}>Scan something free</PrimaryCta>
            <GhostCta href="/docs#getting-started">Install the CLI</GhostCta>
          </div>
        </Reveal>

        <MarketingFooter />
      </div>

      <AuthModal isOpen={authOpen} onClose={() => setAuthOpen(false)} defaultTab={authTab} />
      <SampleReportModal isOpen={sampleReportOpen} onClose={() => setSampleReportOpen(false)} />
    </div>
  )
}
