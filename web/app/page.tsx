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
import { CHAIN_LABEL, CHAIN_ORDER, ENGINE, type Chain } from '@/lib/engine'

// ─────────────────────────────────────────────────────────────────────────────
// Content — counts come from lib/catalog.json, regenerated from the binary.
// ─────────────────────────────────────────────────────────────────────────────

const steps = [
  { num: '01', icon: '⎇', title: 'Point it at the tree you ship', desc: 'Contracts, application code, Dockerfiles, Terraform, CI workflows, lockfiles — one command picks the engine per file. Or upload a file in the dashboard.' },
  { num: '02', icon: '◉', title: 'Every detector, every engine', desc: `${ENGINE.totalDetectors} detectors with taint tracking across lines, dependency advisories, a live probe for targets you own, and a driver for halmos / hevm / Mythril.` },
  { num: '03', icon: '▤', title: 'Findings you can act on', desc: 'Each one is a lead or proven, rated LIKELY → THEORETICAL, with the fix and the command that verifies it. Then release-check tells you if you are ready.' },
]

const exploits = [
  { protocol: 'Euler Finance', amount: '$197M', year: '2023', type: 'Flash loan + missing post-state health check', invariant: 'evm_missing_post_state_health_check' },
  { protocol: 'Nomad Bridge', amount: '$190M', year: '2022', type: 'Merkle root initialised to zero', invariant: 'evm_merkle_root_zero_default' },
  { protocol: 'KelpDAO', amount: '$292M', year: '2024', type: 'DVN single point of failure', invariant: 'evm_dvn_single_point_failure' },
]

const reportPerks = [
  'Lead or proven — never a guess',
  'Exploitability rating with the reasons',
  'Attack chains the findings complete',
  'Fix + verify step on every finding',
  'JSON, SARIF, HTML, Markdown',
]

const plans = [
  { name: 'Starter', price: '$0', per: ' / month', accent: '#8fdcb2', href: '/pricing', caption: 'Every engine, 5 dashboard scans a month' },
  { name: 'Professional', price: '$499', per: ' / month', accent: '#34d399', href: '/pricing', caption: '10,000 scans, priority support', featured: true },
  { name: 'Enterprise', price: 'Custom', per: '', accent: '#a3e635', href: '/contact', caption: 'Managed probes, SSO, on-premises' },
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

function Eyebrow({ children, tone = 'green' }: { children: React.ReactNode; tone?: 'green' | 'red' }) {
  const tones = {
    green: 'text-[#8fdcb2] border-acc-text/20 bg-acc-text/[0.06]',
    red: 'text-[#f87171] border-[#ef4444]/25 bg-[#ef4444]/[0.07]',
  }
  return <span className={`inline-block rounded-full border px-4 py-[7px] font-mono text-[11px] uppercase tracking-[0.2em] ${tones[tone]}`}>{children}</span>
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return <h2 className="m-0 mt-5 text-[clamp(30px,4vw,44px)] font-normal tracking-[-0.02em] text-[#f2f6f2]">{children}</h2>
}

function PrimaryCta({ onClick, children, className = '' }: { onClick?: () => void; children: React.ReactNode; className?: string }) {
  return (
    <button onClick={onClick} className={`inline-flex items-center gap-3 rounded-full bg-[#eef2ef] py-[7px] pl-[22px] pr-[7px] text-[14px] font-semibold text-[#0a0d0b] transition-all hover:-translate-y-0.5 hover:bg-white ${className}`}>
      {children}
      <span className="flex h-8 w-8 items-center justify-center rounded-full bg-acc-text text-[15px] text-on-acc">→</span>
    </button>
  )
}

function GhostCta({ onClick, href, children }: { onClick?: () => void; href?: string; children: React.ReactNode }) {
  const cls = 'inline-flex items-center rounded-full border border-white/[0.16] px-6 py-3.5 text-[14px] font-medium text-[#cfd6d1] transition-colors hover:border-acc-text/50 hover:text-text'
  return href ? <Link href={href} className={cls}>{children}</Link> : <button onClick={onClick} className={cls}>{children}</button>
}

function Reveal({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  const { ref, seen } = useInView<HTMLDivElement>(0.02)
  return (
    <div ref={ref} className={className} style={{ opacity: seen ? 1 : 0.06, transition: 'opacity 0.9s cubic-bezier(0.16,0.84,0.28,1)' }}>
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
    <div ref={ref} className="relative mt-12 overflow-hidden rounded-[20px] border border-hair bg-white/[0.015] px-[30px] pb-[22px] pt-[26px]">
      <div className="pointer-events-none absolute left-[12%] top-[16%] h-[260px] w-[420px]" style={{ background: 'radial-gradient(closest-side,rgba(52,211,153,0.1),transparent)', animation: 'glowpulse 6s ease-in-out infinite' }} />
      <div className="relative mb-[26px] flex flex-wrap items-baseline justify-between gap-2">
        <span className="font-mono text-[10.5px] uppercase tracking-[0.16em] text-[#8fdcb2]">Detectors in the engine, by analyzer</span>
        <span className="font-mono text-[11px] text-[#8a948d]">truent taxonomy --format json · {ENGINE.version}</span>
      </div>
      <div className="relative grid grid-cols-[34px_1fr] gap-3.5">
        <div className="relative h-[250px] font-mono text-[11px] text-[#8a948d]">
          {ticks.map((v, i) => (
            <span key={i} className="absolute right-0" style={{ top: `calc(${i * 25}% - 5px)` }}>{v}</span>
          ))}
        </div>
        <div>
          <div className="relative h-[250px]">
            <div className="pointer-events-none absolute inset-0">
              {[0, 25, 50, 75].map((t) => (
                <div key={t} className="absolute left-0 right-0 h-px" style={{ top: `${t}%`, background: t === 0 ? 'rgba(255,255,255,0.07)' : 'rgba(255,255,255,0.05)' }} />
              ))}
              <div className="absolute bottom-0 left-0 right-0 h-px bg-white/[0.14]" />
            </div>
            <div className="absolute bottom-px left-0 right-0 top-0 grid items-end gap-[14px]" style={{ gridTemplateColumns: `repeat(${bars.length}, minmax(0, 1fr))` }}>
              {bars.map((bar, i) => {
                const hot = bar.id === 'evm' || bar.id === 'general'
                return (
                  <div key={bar.id} className="relative flex h-full flex-col justify-end">
                    <div className="mb-[9px] text-center font-mono text-[12px] font-semibold" style={{ color: hot ? '#86efac' : '#8a948d', opacity: seen ? 1 : 0, transition: `opacity 0.5s ease ${180 + i * 110}ms` }}>
                      {bar.count}
                    </div>
                    <div
                      style={{
                        height: seen ? `${(bar.count / max) * 100}%` : '0%',
                        borderRadius: '6px 6px 0 0',
                        transition: `height 1.05s cubic-bezier(0.16,0.84,0.28,1) ${180 + i * 110}ms`,
                        background: `linear-gradient(to top, ${hot ? 'rgba(52,211,153,0.75)' : 'rgba(52,211,153,0.4)'}, rgba(134,239,172,0.07))`,
                        borderTop: `2px solid ${hot ? '#86efac' : 'rgba(134,239,172,0.6)'}`,
                        boxShadow: hot ? '0 -8px 40px rgba(52,211,153,0.35)' : undefined,
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
                <div className="font-mono text-[10.5px] tracking-[0.04em] text-[#c5cec8]">{bar.label}</div>
                <div className="mt-[5px] font-mono text-[10px] text-[#5c665f]">{bar.id}</div>
              </div>
            ))}
          </div>
        </div>
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
    { id: 'high', el: <><span className="text-[#fbbf24]">HIGH</span><span className="text-[#d8ddd9]">{'  '}gen_sql_injection  api/orders.py:41  <span className="text-[#8fa398]">LEAD · LIKELY</span></span></> },
    { id: 'h1', el: <span className="text-[#748078]">{'      '}tainted value `uid` reaches a SQL query (request.args → line 39 → execute)</span> },
    { id: 'h2', el: <span className="text-[#748078]">{'      '}fix: parameterized query · verify: taint test source→query no longer present</span> },
    { id: 'gap-1', el: <>&nbsp;</> },
    { id: 'crit', el: <><span className="text-[#ef4444]">CRITICAL</span><span className="text-[#d8ddd9]">{'  '}evm_reentrancy_classic  contracts/Vault.sol:88  <span className="text-[#8fa398]">LEAD · LIKELY</span></span></> },
    { id: 'c1', el: <span className="text-[#748078]">{'      '}external call before state update; no nonReentrant guard</span> },
    { id: 'gap-2', el: <>&nbsp;</> },
    { id: 'chain', el: <><span className="text-[#f87171]">CHAIN</span><span className="text-[#d8ddd9]">{'  '}injection-to-data-exfiltration · break at step 1</span></> },
    { id: 'done', el: <><span className="text-acc-text">GATE</span><span className="text-sec">{'  '}2 findings ≥ high. exit 1 — merge blocked.</span><span className="text-acc-text" style={{ animation: 'blink 1s infinite' }}>▊</span></> },
  ]
  return (
    <div className="rounded-[18px] border border-white/[0.08] bg-[rgba(6,10,8,0.9)] p-1.5 shadow-[0_30px_80px_rgba(0,0,0,0.5),0_0_60px_rgba(52,211,153,0.05)]">
      <div className="flex items-center gap-1.5 border-b border-white/[0.06] px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-[#ef4444] opacity-80" />
        <span className="h-2.5 w-2.5 rounded-full bg-[#fbbf24] opacity-80" />
        <span className="h-2.5 w-2.5 rounded-full bg-acc-text opacity-80" />
        <span className="ml-2.5 font-mono text-[11px] text-[#5c665f]">truent scan . --chain auto --fail-on high</span>
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
    <div className={`relative overflow-hidden rounded-[18px] border p-[34px] transition-all duration-[250ms] hover:-translate-y-1 hover:shadow-[0_20px_50px_rgba(0,0,0,0.4)] ${span ? 'md:col-span-2' : ''} ${featured ? 'border-acc-text/[0.22] bg-acc-text/[0.04] hover:border-acc-text/[0.45]' : 'border-hair bg-white/[0.02] hover:border-acc-text/[0.35]'}`}>
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
  const startTrial = () => {
    setAuthTab('signup')
    setAuthOpen(true)
  }
  const staticCount = ENGINE.totalDetectors - (ENGINE.byChain.runtime ?? 0)

  return (
    <div className="min-h-screen bg-bg p-2.5">
      <div className="relative overflow-clip rounded-[22px] border border-white/[0.05]" style={{ background: 'radial-gradient(1100px 600px at 50% -100px, rgba(52,211,153,0.16), rgba(6,9,8,0) 60%), #060908' }}>
        <MarketingNav />

        <ParticleHero
          ascii={TRUENT_ASCII}
          wordmark="TRUENT"
          headline={
            <>
              Don&apos;t get hacked.{' '}
              <span className="bg-clip-text text-transparent" style={{ backgroundImage: 'linear-gradient(100deg,#d7ffe9 0%,#34d399 55%,#8fdcb2 100%)' }}>Know what is real.</span>
            </>
          }
          subline={
            <>
              <span className="text-acc-text">{ENGINE.totalDetectors} detectors</span> across EVM, Solana, Move, Soroban, any repository, its dependencies and its live edge. Every finding is a{' '}
              <span className="text-acc-text">lead or proven</span> — never a guess — with an exploitability rating and the fix.
            </>
          }
          bullets={
            <>
              {[
                ['◆', 'Lead vs proven, always'],
                ['◇', `${CHAIN_ORDER.length - 1} engines, one command`],
                ['◇', 'Fix + verify on every finding'],
                ['◇', 'Zero false positives on correct code'],
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
              <PrimaryCta onClick={startTrial} className="shadow-[0_0_40px_rgba(52,211,153,0.15)]">Start free</PrimaryCta>
              <GhostCta onClick={() => setSampleReportOpen(true)}>View a sample report</GhostCta>
            </>
          }
        />

        {/* ─── Coverage ─── */}
        <Reveal className="relative mx-auto max-w-[1180px] px-6 pb-24 pt-[110px]">
          <div className="grid items-end gap-14 md:grid-cols-[0.9fr_1.1fr]">
            <div>
              <span className="font-mono text-[10.5px] tracking-[0.18em] text-[#4d564f]">[ The engine ]</span>
              <h2 className="m-0 mt-5 text-[clamp(28px,3.6vw,42px)] font-normal leading-[1.16] tracking-[-0.025em] text-[#f2f6f2]">
                One engine for the whole system, mapped to{' '}
                <span className="bg-clip-text text-transparent" style={{ backgroundImage: 'linear-gradient(96deg,#34d399 0%,#a3e635 45%,#fde047 100%)' }}>CWE, ATT&amp;CK and NIST CSF</span>
              </h2>
            </div>
            <p className="m-0 max-w-[420px] text-[13.5px] leading-[1.8] text-[#8a948d]">
              Every detector has a taxonomy row, an attack profile, a fix and a regression corpus; a build-time test fails if any of them drifts. The chart is the catalogue itself, regenerated from the binary.
            </p>
          </div>

          <div className="mt-14 grid grid-cols-1 border-t border-white/[0.09] sm:grid-cols-3">
            {[
              { value: ENGINE.totalDetectors, suffix: '', label: 'Detectors, each with a fix and a verify step' },
              { value: ENGINE.pathways.length, suffix: '', label: 'Security pathways mapped: native, hosted, manual' },
              { value: ENGINE.attackChains.length, suffix: '', label: 'Attack chains recognised across findings' },
            ].map((s, i) => (
              <div key={s.label} className={`py-[26px] ${i === 0 ? 'sm:pr-[30px]' : i === 1 ? 'sm:px-[30px]' : 'sm:pl-[30px]'} ${i < 2 ? 'sm:border-r sm:border-white/[0.07]' : ''}`}>
                <div className="text-[clamp(34px,4vw,46px)] font-normal leading-none tracking-[-0.03em] text-text">
                  <AnimatedCounter value={s.value} decimals={0} />
                  <span className="text-acc-text">{s.suffix}</span>
                </div>
                <div className="mt-2.5 text-[12.5px] leading-[1.5] text-[#748078]">{s.label}</div>
              </div>
            ))}
          </div>

          <CoverageChart />
        </Reveal>

        {/* ─── See it run ─── */}
        <Reveal className="mx-auto grid max-w-[1100px] items-center gap-14 px-6 pb-[100px] pt-16 md:grid-cols-[0.85fr_1.15fr]">
          <div>
            <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-acc-text">See it run</span>
            <h2 className="m-0 mt-[18px] text-[38px] font-normal leading-[1.15] tracking-[-0.02em] text-[#f2f6f2]">
              One command.
              <br />
              Every engine.
            </h2>
            <p className="m-0 mt-[18px] text-[14px] leading-[1.75] text-sec">
              <code className="text-acc-text">truent scan . --chain auto</code> picks the analyzer per file, follows tainted input across lines to the sink, names the detector, the CWE and the technique, rates how exploitable it is, and tells CI whether to block the merge.
            </p>
            <Link href="/docs#cli" className="mt-6 inline-flex items-center gap-2 rounded-full border border-white/[0.14] px-[22px] py-3 text-[13px] font-medium text-[#cfd6d1] transition-colors hover:border-acc-text/50 hover:text-text">
              Read the CLI reference →
            </Link>
          </div>
          <TerminalPanel />
        </Reveal>

        {/* ─── Capabilities ─── */}
        <Reveal className="mx-auto max-w-[1100px] px-6 pb-[100px] pt-10">
          <div id="features" className="mb-14 text-center">
            <Eyebrow>Capabilities</Eyebrow>
            <SectionHeading>Honest by construction.</SectionHeading>
            <p className="mx-auto mt-4 max-w-[560px] text-[14px] leading-[1.7] text-sec">
              Pattern matchers guess. Language models opine. Truent says exactly what it knows: a traced lead, or a concrete witness — and never calls one the other.
            </p>
          </div>
          <div className="grid gap-3.5 md:grid-cols-3">
            <FeatureCard
              icon="◈"
              title="Lead or proven — the evidence class is part of the finding"
              span
              watermark="✓"
              footer={<Link href="/docs#honesty" className="relative mt-4 inline-block text-[13px] font-semibold text-acc-text">Read the contract →</Link>}
            >
              <p className="m-0 mb-3 max-w-[560px]">
                {staticCount} static detectors trace patterns, invariants, taint flows and advisories: strong evidence, recorded as <strong className="text-text">leads</strong>. The live probe and the symbolic driver record what a target returned or what a solver produced: <strong className="text-acc-text">proven</strong>, with the witness.
              </p>
              <p className="m-0 max-w-[560px]">Correct code produces zero findings — every analyzer is held to a good/bad regression corpus, and a build fails if that ever changes.</p>
            </FeatureCard>
            <FeatureCard icon="◆" title="Exploitability, not exploitation">
              Every finding is rated LIKELY → THEORETICAL from its attack profile and evidence, and {ENGINE.attackChains.length} attack chains show which findings compose. Truent never fires an exploit.
            </FeatureCard>
            <FeatureCard icon="↺" title="Fix, verify, prevent">
              Each detector ships the change that closes it and the command that proves it. <code className="text-acc-text">harden</code> generates the controls that stop the class from returning.
            </FeatureCard>
            <FeatureCard icon="⎇" title="CI-native">
              SARIF with CWE / ATT&amp;CK tags and the fix in rule help; <code className="text-acc-text">--fail-on</code> gates; <code className="text-acc-text">release-check --strict</code> on the default branch.
            </FeatureCard>
            <FeatureCard icon="⟐" title="Symbolic execution, settled" featured>
              <code className="text-acc-text">truent symbolic</code> drives halmos, hevm or Mythril on a Foundry project. A counterexample becomes a proven finding with the exact input; an undecided check stays a lead.
            </FeatureCard>
          </div>
        </Reveal>

        {/* ─── How it works ─── */}
        <Reveal className="border-y border-white/[0.06] bg-white/[0.012] px-6 py-[100px]">
          <div className="mx-auto max-w-[1100px]">
            <div className="mb-[60px] text-center">
              <Eyebrow>How it works</Eyebrow>
              <SectionHeading>From tree to READY</SectionHeading>
            </div>
            <div className="grid gap-3.5 md:grid-cols-3">
              {steps.map((s) => (
                <div key={s.num} className="rounded-[18px] border border-hair bg-white/[0.02] p-[34px]">
                  <div className="mb-[18px] flex items-baseline gap-3.5">
                    <span className="text-[46px] font-light tracking-[-0.02em] text-[#8fdcb2]/35">{s.num}</span>
                    <span className="text-[20px]">{s.icon}</span>
                  </div>
                  <h3 className="m-0 mb-2.5 text-[16.5px] font-medium text-text">{s.title}</h3>
                  <p className="m-0 text-[13px] leading-[1.7] text-sec">{s.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </Reveal>

        {/* ─── Real exploits ─── */}
        <Reveal className="mx-auto max-w-[1100px] px-6 py-[100px]">
          <div className="mb-[52px] text-center">
            <Eyebrow tone="red">Written against real incidents</Eyebrow>
            <SectionHeading>
              Every contract detector maps
              <br />
              to an exploit that happened.
            </SectionHeading>
            <p className="mx-auto mt-4 max-w-[540px] text-[14px] leading-[1.7] text-sec">Each detector is kept alive by a regression case in the corpus. These are three of them.</p>
          </div>
          <div className="grid gap-3.5 md:grid-cols-3">
            {exploits.map((e) => (
              <div key={e.protocol} className="relative overflow-hidden rounded-[18px] border border-hair bg-white/[0.02] p-[30px] transition-all duration-[250ms] hover:-translate-y-1 hover:border-[#ef4444]/[0.35] hover:shadow-[0_20px_50px_rgba(0,0,0,0.4)]">
                <div className="absolute left-0 right-0 top-0 h-0.5" style={{ background: 'linear-gradient(90deg,#ef4444,rgba(239,68,68,0.3),transparent)' }} />
                <div className="mb-4 flex items-start justify-between gap-3">
                  <div>
                    <div className="mb-1.5 font-mono text-[10.5px] tracking-[0.14em] text-[#748078]">{e.year} EXPLOIT</div>
                    <div className="text-[19px] font-medium text-text">{e.protocol}</div>
                  </div>
                  <span className="text-[23px] font-semibold tracking-[-0.02em] text-[#ef4444]">{e.amount}</span>
                </div>
                <p className="m-0 mb-[18px] text-[13px] leading-[1.6] text-sec">{e.type}</p>
                <div className="mb-4 flex flex-wrap items-center gap-2">
                  <span className="rounded-[5px] border border-[#ef4444]/30 bg-[#ef4444]/10 px-2 py-[3px] font-mono text-[10px] tracking-[0.1em] text-[#ef4444]">CRITICAL</span>
                  <code className="break-all rounded-[5px] border border-white/[0.08] bg-white/[0.03] px-2 py-[3px] font-mono text-[10.5px] text-[#8fa398]">{e.invariant}</code>
                </div>
                <div className="flex items-center gap-[7px] text-[12px] font-semibold text-acc-text">✓ Truent detects this pattern</div>
              </div>
            ))}
          </div>
        </Reveal>

        {/* ─── Reports ─── */}
        <Reveal className="border-y border-white/[0.06] bg-white/[0.012] px-6 py-[100px]">
          <div className="mx-auto grid max-w-[1100px] items-center gap-16 md:grid-cols-2">
            <div>
              <Eyebrow>Reports</Eyebrow>
              <h2 className="m-0 mt-[22px] text-[clamp(30px,4vw,42px)] font-normal tracking-[-0.02em] text-[#f2f6f2]">Findings you can act on</h2>
              <p className="mb-7 mt-[18px] text-[14px] leading-[1.75] text-sec">
                The dashboard stores exactly what the engine emits. Triage by severity, evidence and exploitability; mark findings acknowledged or resolved; export JSON. The CLI adds SARIF, HTML and the release checklist.
              </p>
              <div className="mb-8 flex flex-col gap-3">
                {reportPerks.map((perk) => (
                  <div key={perk} className="flex items-center gap-3 text-[13.5px] text-[#c5cec8]">
                    <span className="text-acc-text">✓</span>
                    {perk}
                  </div>
                ))}
              </div>
              <GhostCta onClick={() => setSampleReportOpen(true)}>View sample report →</GhostCta>
            </div>

            <div className="rounded-[18px] border border-white/[0.08] bg-[rgba(6,10,8,0.85)] p-[26px] shadow-[0_30px_80px_rgba(0,0,0,0.45)]">
              <div className="mb-[22px] flex items-start justify-between gap-3">
                <div>
                  <div className="mb-1.5 font-mono text-[10px] tracking-[0.16em] text-[#748078]">REPORT</div>
                  <div className="text-[19px] font-medium text-text">vault-v2</div>
                  <div className="mt-1 text-[12px] text-[#748078]">chain=auto · 0.4s · {ENGINE.version}</div>
                </div>
                <span className="whitespace-nowrap rounded-[5px] border border-acc-text/25 bg-acc-text/[0.08] px-[9px] py-1 font-mono text-[10px] tracking-[0.12em] text-acc-text">COMPLETE</span>
              </div>
              <div className="mb-5 grid grid-cols-4 gap-px overflow-hidden rounded-[10px] bg-white/[0.07]">
                {[
                  { label: 'CRITICAL', count: 1, color: 'var(--critical)' },
                  { label: 'HIGH', count: 2, color: 'var(--high)' },
                  { label: 'PROVEN', count: 1, color: 'var(--acc-text)' },
                  { label: 'LIKELY', count: 2, color: 'var(--critical)' },
                ].map((sv) => (
                  <div key={sv.label} className="bg-[#0a0f0c] px-2 py-4 text-center">
                    <div className="text-[26px] font-semibold" style={{ color: sv.color }}>{sv.count}</div>
                    <div className="mt-1 font-mono text-[9.5px] tracking-[0.14em] text-[#748078]">{sv.label}</div>
                  </div>
                ))}
              </div>
              <div className="mb-5 flex flex-col gap-2">
                {[
                  { sev: 'CRITICAL', color: '#ef4444', text: 'evm_reentrancy_classic · Vault.sol:88', tag: 'LEAD · LIKELY' },
                  { sev: 'HIGH', color: '#fbbf24', text: 'gen_sql_injection · api/orders.py:41', tag: 'LEAD · LIKELY' },
                  { sev: 'HIGH', color: '#fbbf24', text: 'rt_exposed_sensitive_path · /.env', tag: 'PROVEN' },
                ].map((f) => (
                  <div key={f.text} className="flex items-center gap-3 rounded-[10px] border border-white/[0.05] bg-white/[0.02] px-3.5 py-[11px]">
                    <span className="whitespace-nowrap rounded border px-[7px] py-0.5 font-mono text-[9.5px] tracking-[0.1em]" style={{ color: f.color, borderColor: `${f.color}4d`, background: `${f.color}1a` }}>{f.sev}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-[#c5cec8]">{f.text}</span>
                    <span className="whitespace-nowrap font-mono text-[9.5px] tracking-[0.1em] text-[#8fa398]">{f.tag}</span>
                  </div>
                ))}
              </div>
              <button onClick={() => setSampleReportOpen(true)} className="block w-full rounded-full border border-white/[0.12] py-[11px] text-center text-[12.5px] font-medium text-[#cfd6d1] transition-colors hover:border-acc-text/50 hover:text-text">
                ↓ View full report
              </button>
            </div>
          </div>
        </Reveal>

        {/* ─── Pricing preview ─── */}
        <Reveal className="mx-auto max-w-[1100px] px-6 pb-20 pt-[100px]">
          <div className="mb-14 text-center">
            <Eyebrow>Pricing</Eyebrow>
            <SectionHeading>Same engine on every plan.</SectionHeading>
            <p className="mx-auto mt-4 max-w-[440px] text-[14px] leading-[1.7] text-sec">Plans differ in dashboard quota and support — never in what the engine checks.</p>
          </div>
          <div className="grid overflow-hidden rounded-[18px] border border-hair md:grid-cols-3">
            {plans.map((plan, i) => (
              <Link key={plan.name} href={plan.href} className={`block px-[30px] py-7 transition-colors hover:bg-white/[0.03] ${i < 2 ? 'md:border-r md:border-white/[0.07]' : ''} ${plan.featured ? 'bg-acc-text/[0.05]' : ''}`}>
                <div className="font-mono text-[10.5px] uppercase tracking-[0.16em]" style={{ color: plan.accent }}>{plan.name}</div>
                <div className="mt-3.5 text-[34px] font-normal tracking-[-0.025em] text-[#f2f6f2]">
                  {plan.price}
                  <span className="text-[12.5px] text-[#5c665f]">{plan.per}</span>
                </div>
                <p className="m-0 mt-2.5 text-[12.5px] leading-[1.6] text-[#8a948d]">{plan.caption}</p>
              </Link>
            ))}
          </div>
          <div className="mt-7 text-center">
            <Link href="/pricing" className="inline-flex items-center gap-2.5 rounded-full border border-white/[0.16] px-5 py-[11px] font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-[#cfd6d1] transition-colors hover:border-acc-text/50 hover:text-text">
              Compare plans in full
              <span className="text-[13px] tracking-[-0.12em]">❯❯</span>
            </Link>
          </div>
        </Reveal>

        {/* ─── Let's talk band ─── */}
        <section className="relative mt-10">
          <div className="relative flex h-[190px] items-center justify-center overflow-hidden" style={{ background: 'linear-gradient(104deg,#08301e 0%,#0d6b45 24%,#16915f 48%,#1fae74 64%,#0f7a4f 82%,#062418 100%)' }}>
            <div className="absolute inset-0" style={{ background: 'radial-gradient(60% 120% at 22% 40%, rgba(180,140,20,0.22), transparent 60%), radial-gradient(50% 120% at 68% 60%, rgba(16,120,80,0.45), transparent 65%)' }} />
            <Link href="/contact" className="relative whitespace-nowrap text-center text-[clamp(78px,13vw,190px)] font-bold leading-[0.92] tracking-[-0.05em] text-[#f4faf6] drop-shadow-[0_2px_40px_rgba(3,20,12,0.45)]">
              LET&apos;S TALK
            </Link>
          </div>
        </section>

        {/* ─── Final CTA ─── */}
        <Reveal className="mx-auto max-w-[640px] px-6 pb-[90px] pt-[70px] text-center">
          <h2 className="m-0 text-[clamp(26px,3.6vw,36px)] font-normal tracking-[-0.025em] text-[#f2f6f2]">Ready to know what is real?</h2>
          <p className="mx-auto mt-4 max-w-[470px] text-[13.5px] leading-[1.8] text-[#8a948d]">
            Scan a file in the dashboard in seconds, or install the CLI and run the whole engine — scan, deps, probe, exposure, harden, release-check — against the tree you ship.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <PrimaryCta onClick={startTrial}>Start free</PrimaryCta>
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
