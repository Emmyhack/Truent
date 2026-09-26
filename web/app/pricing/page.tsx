'use client'

import { useState } from 'react'
import Link from 'next/link'
import { MarketingNav } from '@/components/layout/MarketingNav'
import { PageShell } from '@/components/layout/PageShell'
import { SlimFooter } from '@/components/layout/SlimFooter'
import { AuthModal } from '@/components/ui/AuthModal'
import { PLANS, monthlyScanLimit } from '@/lib/plans'
import { ENGINE } from '@/lib/engine'

// ─────────────────────────────────────────────────────────────────────────────
// Content — quotas come from lib/plans.ts (what the API enforces), engine
// numbers from lib/catalog.json (what the binary reports). Plans differ in
// dashboard quota, support and deployment; never in what the engine checks.
// ─────────────────────────────────────────────────────────────────────────────

const starterQuota = monthlyScanLimit(null)
const proQuota = PLANS.professional.scansPerMonth
const proPrice = PLANS.professional.monthlyAmount / 100

const plans = [
  {
    id: 'starter',
    name: 'Starter',
    price: '$0',
    per: 'forever',
    cta: 'Start free',
    tagline: 'For solo builders and first audits.',
    quota: `${starterQuota} dashboard scans / month`,
    features: ['Every engine, every detector', 'Lead vs proven on each finding', 'Exploitability rating + fix and verify', 'JSON export', 'Community support'],
  },
  {
    id: 'professional',
    name: 'Professional',
    price: `$${proPrice}`,
    per: 'per month',
    cta: 'Go Professional',
    featured: true,
    tagline: 'For teams shipping to production.',
    quota: `${proQuota.toLocaleString()} dashboard scans / month`,
    features: ['Everything in Starter', 'Attack-chain reports across findings', 'Custom .sinv invariants', 'Help wiring probe, symbolic and release-check into CI', 'Priority support'],
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 'Custom',
    per: 'annual agreement',
    cta: 'Talk to us',
    href: '/contact',
    tagline: 'For regulated and large-scale deployments.',
    quota: 'Custom quota and rate limits',
    features: ['Everything in Professional', 'Managed live probes and symbolic runs', 'On-premises deployment', 'SSO / SAML, white-label reports', 'SLA and a named security engineer'],
  },
]

/** What every plan gets — the engine is the product; plans only meter the dashboard. */
const included = [
  { n: String(ENGINE.totalDetectors), label: 'detectors', sub: 'contracts, application code, infrastructure, supply chain, live probe, symbolic' },
  { n: String(ENGINE.attackChains.length), label: 'attack chains', sub: 'findings that compose into a real attack path' },
  { n: String(ENGINE.pathways.length), label: 'security pathways', sub: 'mapped to native detectors, hosted skills and manual controls' },
  { n: '33', label: 'checklist sections', sub: 'release-check decides READY or not, item by item' },
]

type Cell = boolean | string
const cell = (v: Cell) => ({ text: v === true ? '✓' : v === false ? '—' : v, className: v === true ? 'text-acc-text' : v === false ? 'text-hair-strong' : 'text-sec' })
const row = (feature: string, starter: Cell, pro: Cell, enterprise: Cell) => ({ feature, starter: cell(starter), pro: cell(pro), enterprise: cell(enterprise) })

const comparison = [
  {
    category: 'Dashboard',
    rows: [
      row('Scans per month', String(starterQuota), proQuota.toLocaleString(), 'Custom'),
      row('Submission rate limit', '5 / minute', '5 / minute', 'Custom'),
      row('Supported inputs', '12 languages', '12 languages', '12 languages'),
      row('Report workflow (open / acknowledged / resolved)', true, true, true),
    ],
  },
  {
    category: 'Engine (identical on every plan)',
    rows: [
      row('Static detectors: EVM, Solana, Move (Aptos & Sui), Soroban, any repository, supply chain', true, true, true),
      row('Taint tracking across lines', true, true, true),
      row('Evidence class on every finding (lead / proven)', true, true, true),
      row('Exploitability rating + attack chains', true, true, true),
      row('Fix + verify step on every finding', true, true, true),
      row('Custom .sinv invariants', false, true, true),
    ],
  },
  {
    category: 'CLI (unmetered)',
    rows: [
      row('scan · deps · exposure · harden · release-check', true, true, true),
      row('probe (live target you own)', true, true, 'Managed'),
      row('symbolic (halmos / hevm / Mythril)', true, true, 'Managed'),
      row('SARIF for GitHub / GitLab code scanning', true, true, true),
    ],
  },
  {
    category: 'Support & deployment',
    rows: [
      row('Community support', true, true, true),
      row('Priority support', false, true, true),
      row('Named security engineer, SLA', false, false, true),
      row('SSO / SAML, white-label reports', false, false, true),
      row('On-premises deployment', false, false, true),
    ],
  },
]

const faqs = [
  { q: 'Is the engine different on the free plan?', a: 'No. Every plan runs the same binary with every detector. Plans differ in monthly dashboard quota, support and deployment options.' },
  { q: 'What counts as a scan?', a: 'One submission through the dashboard: a file the engine runs every applicable detector over. Each finding is stored as a lead or proven, with an exploitability rating and a fix. The CLI is not metered.' },
  { q: 'Do I need an account to use the CLI?', a: 'No. cargo install truent-cli and run scan, deps, exposure, harden, release-check, probe and symbolic locally or in CI. The dashboard adds hosted history, triage and team access.' },
  { q: 'What does the engine cover?', a: 'Smart contracts (Ethereum and every EVM chain in Solidity, Solana in Anchor/Rust, Aptos and Sui in Move, Stellar in Soroban), application code (Python, JavaScript/TypeScript, Go, shell), infrastructure (Dockerfile, Kubernetes, Terraform, CloudFormation, CI workflows), dependencies (Cargo, npm, pip, Go — RustSec/OSV, pinning, confusion, typosquats), live targets you own, and Foundry projects under a symbolic executor.' },
  { q: 'What does Professional add if the engine is the same?', a: 'Quota (10,000 scans a month), custom .sinv invariants, attack-chain reports in the dashboard, priority support, and hands-on help wiring the probe, symbolic execution and the release check into your pipeline.' },
  { q: 'How does billing work?', a: 'Professional is billed monthly through Stripe and can be cancelled any time; access runs to the end of the paid period. Enterprise is an annual agreement with custom terms.' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function PricingPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(0)
  const [authOpen, setAuthOpen] = useState(false)

  return (
    <PageShell>
      <MarketingNav />

      {/* ─── Hero ─── */}
      <header className="mx-auto max-w-[900px] px-6 pb-14 pt-[90px] text-center">
        <h1 className="m-0 text-[clamp(38px,5.6vw,62px)] font-normal leading-[1.05] tracking-[-0.03em] text-text">
          Same engine on every plan.
          <br />
          <span className="text-acc-text">
            Pay for the dashboard, not the detectors.
          </span>
        </h1>
        <p className="mx-auto mt-5 max-w-[540px] text-[15px] leading-[1.7] text-sec">
          Every plan — including free — runs all {ENGINE.totalDetectors} detectors and labels every finding as a lead or proven. The CLI is never metered. Plans differ in
          dashboard quota, support and where it runs.
        </p>
      </header>

      {/* ─── Plan cards ─── */}
      <section className="mx-auto max-w-[1100px] px-6 pb-16">
        <div className="grid gap-3.5 md:grid-cols-3">
          {plans.map((plan) => (
            <div
              key={plan.id}
              className={`relative flex flex-col overflow-hidden rounded-[20px] border p-8 ${
                plan.featured ? 'border-acc-text/40 bg-acc-text/[0.05] shadow-[0_0_60px_var(--acc-soft)]' : 'border-hair bg-surface-2'
              }`}
            >
              {plan.featured && (
                <span className="absolute right-5 top-5 rounded-[5px] border border-acc-text/30 bg-acc-text/10 px-2 py-[3px] font-mono text-[9.5px] tracking-[0.14em] text-acc-text">
                  MOST TEAMS
                </span>
              )}
              <div className="font-mono text-[10.5px] uppercase tracking-[0.18em] text-acc-text">
                {plan.name}
              </div>
              <div className="mt-4 flex items-baseline gap-2">
                <span className="text-[44px] font-normal leading-none tracking-[-0.03em] text-text">{plan.price}</span>
                <span className="text-[12.5px] text-sec">{plan.per}</span>
              </div>
              <p className="m-0 mt-3 text-[13px] leading-[1.6] text-sec">{plan.tagline}</p>
              <div className="mt-5 rounded-[10px] border border-hair bg-bg px-4 py-3 font-mono text-[11.5px] text-text">{plan.quota}</div>

              <div className="mt-6 flex flex-col gap-[10px]">
                {plan.features.map((f) => (
                  <div key={f} className="flex gap-2.5 text-[13px] leading-[1.5] text-text">
                    <span className="text-acc-text">✓</span>
                    {f}
                  </div>
                ))}
              </div>

              <div className="mt-auto pt-8">
                {plan.href ? (
                  <Link
                    href={plan.href}
                    className="inline-flex w-full items-center justify-center rounded-full border border-hair-strong px-5 py-3 text-[13px] font-medium text-text transition-colors hover:border-acc-text/50 hover:text-text"
                  >
                    {plan.cta}
                  </Link>
                ) : (
                  <button
                    onClick={() => setAuthOpen(true)}
                    className={`inline-flex w-full items-center justify-center gap-2.5 rounded-full py-3 text-[13px] font-semibold transition-colors ${
                      plan.featured ? 'bg-text text-bg hover:bg-acc-text' : 'border border-hair-strong text-text hover:border-acc-text/50 hover:text-text'
                    }`}
                  >
                    {plan.cta} →
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ─── Included everywhere ─── */}
      <section className="mx-auto max-w-[1100px] px-6 pb-[90px]">
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-[18px] border border-hair bg-hair md:grid-cols-4">
          {included.map((s) => (
            <div key={s.label} className="bg-bg px-6 py-6">
              <div className="text-[34px] font-normal leading-none tracking-[-0.03em] text-text">{s.n}</div>
              <div className="mt-2 font-mono text-[10.5px] uppercase tracking-[0.14em] text-acc-text">{s.label}</div>
              <p className="m-0 mt-2 text-[12px] leading-[1.55] text-sec">{s.sub}</p>
            </div>
          ))}
        </div>
        <p className="m-0 mt-4 text-center font-mono text-[11px] text-sec">Included on every plan · counts regenerated from the binary ({ENGINE.version})</p>
      </section>

      {/* ─── Comparison ─── */}
      <section className="border-y border-hair bg-surface-2 px-6 py-[90px]">
        <div className="mx-auto max-w-[900px]">
          <div className="mb-12 text-center">
            <h2 className="m-0 text-[clamp(26px,3.5vw,36px)] font-normal tracking-[-0.02em] text-text">What differs, exactly</h2>
            <p className="m-0 mt-3 text-[13px] text-sec">Quota, support and deployment. The engine rows are identical by design.</p>
          </div>
          <div className="overflow-x-auto">
            <div className="min-w-[620px]">
              <div className="grid grid-cols-[1.8fr_1fr_1fr_1fr] px-4 pb-3.5">
                <div />
                <div className="text-center font-mono text-[10.5px] uppercase tracking-[0.14em] text-sec">Starter</div>
                <div className="text-center font-mono text-[10.5px] uppercase tracking-[0.14em] text-acc-text">Professional</div>
                <div className="text-center font-mono text-[10.5px] uppercase tracking-[0.14em] text-sec">Enterprise</div>
              </div>
              {comparison.map((group) => (
                <div key={group.category} className="mb-[18px] overflow-hidden rounded-[14px] border border-hair">
                  <div className="border-b border-hair bg-acc-text/[0.05] px-4 py-[11px] font-mono text-[10.5px] uppercase tracking-[0.16em] text-acc-text">{group.category}</div>
                  {group.rows.map((r) => (
                    <div key={r.feature} className="grid grid-cols-[1.8fr_1fr_1fr_1fr] items-center border-b border-hair px-4 py-[11px] last:border-b-0">
                      <span className="text-[13px] text-sec">{r.feature}</span>
                      {[r.starter, r.pro, r.enterprise].map((c, i) => (
                        <span key={i} className={`text-center text-[12.5px] ${c.className}`}>{c.text}</span>
                      ))}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ─── FAQ ─── */}
      <section className="mx-auto max-w-[720px] px-6 py-[90px]">
        <div className="mb-11 text-center">
          <h2 className="m-0 text-[clamp(26px,3.5vw,36px)] font-normal tracking-[-0.02em] text-text">Questions</h2>
        </div>
        <div className="flex flex-col gap-2.5">
          {faqs.map((faq, i) => {
            const open = openFaq === i
            return (
              <div key={faq.q} className="overflow-hidden rounded-[14px] border border-hair bg-surface-2">
                <button onClick={() => setOpenFaq(open ? null : i)} aria-expanded={open} className="flex w-full items-center justify-between gap-4 px-[22px] py-[18px] text-left">
                  <span className="text-[14.5px] font-medium text-text">{faq.q}</span>
                  <span className="flex-shrink-0 text-[13px] text-sec">{open ? '▲' : '▼'}</span>
                </button>
                {open && <p className="m-0 px-[22px] pb-[18px] text-[13px] leading-[1.7] text-sec">{faq.a}</p>}
              </div>
            )
          })}
        </div>
      </section>

      {/* ─── CTA ─── */}
      <section className="mx-auto max-w-[760px] px-6 pb-[100px]">
        <div className="relative overflow-hidden rounded-[22px] border border-acc-text/[0.22] bg-acc-text/[0.04] px-10 py-14 text-center">
          <div className="relative">
            <h2 className="m-0 text-[clamp(24px,3.5vw,34px)] font-normal tracking-[-0.02em] text-text">Start with the free plan. Upgrade when the quota is the limit.</h2>
            <p className="mx-auto mt-3.5 max-w-[440px] text-[13.5px] leading-[1.7] text-sec">Or skip the dashboard entirely: the CLI runs the whole engine locally and in CI, on any plan.</p>
            <div className="mt-[30px] flex flex-wrap justify-center gap-3">
              <button onClick={() => setAuthOpen(true)} className="inline-flex items-center gap-2.5 rounded-full bg-text py-1.5 pl-5 pr-1.5 text-[13px] font-semibold text-bg transition-colors hover:bg-acc-text">
                Start free
                <span className="flex h-[30px] w-[30px] items-center justify-center rounded-full bg-acc-text text-[14px] text-on-acc">→</span>
              </button>
              <Link href="/docs#getting-started" className="inline-flex items-center rounded-full border border-hair-strong px-[22px] py-3 text-[13px] font-medium text-text transition-colors hover:border-acc-text/50 hover:text-text">
                Install the CLI
              </Link>
            </div>
          </div>
        </div>
      </section>

      <SlimFooter omit={['Pricing']} />
      <AuthModal isOpen={authOpen} onClose={() => setAuthOpen(false)} defaultTab="signup" />
    </PageShell>
  )
}
