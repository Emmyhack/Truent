'use client'

import { useState } from 'react'
import Link from 'next/link'
import { useSession } from 'next-auth/react'
import { MarketingNav } from '@/components/layout/MarketingNav'
import { PageShell } from '@/components/layout/PageShell'
import { SlimFooter } from '@/components/layout/SlimFooter'
import { AuthModal } from '@/components/ui/AuthModal'
import { formatPrice, PLAN_ORDER, PLANS, PRODUCTS, TRIAL_DAYS, TRIAL_PLAN, type Plan, type PlanId, type ProductId } from '@/lib/plans'
import { ENGINE } from '@/lib/engine'

// ─────────────────────────────────────────────────────────────────────────────
// Everything priced here is read from lib/plans.ts, the table the API
// enforces, and every engine number from lib/catalog.json. Plans differ in
// dashboard quota, seats, retention and support; never in what the engine checks.
// ─────────────────────────────────────────────────────────────────────────────

const cards: PlanId[] = ['free', 'builder', 'team', 'professional']
const pack = PRODUCTS.scan_pack_25
const trial = PLANS[TRIAL_PLAN]

const quotaLine = (p: Plan) => (p.scansPerMonth === null ? 'Custom quota and rate limits' : `${p.scansPerMonth.toLocaleString()} dashboard scans / month`)
const retention = (p: Plan) => (p.retentionDays === null ? 'Reports kept indefinitely' : `Reports kept ${p.retentionDays} days`)
const seats = (p: Plan) => (p.seats === null ? 'Unlimited seats' : p.seats === 1 ? '1 seat' : `${p.seats} seats`)

const highlights: Record<PlanId, string[]> = {
  free: ['Every engine, every detector', 'Lead vs proven on each finding', 'Exploitability rating, fix and verify', 'JSON export'],
  builder: ['Everything in Free', 'Whole-repository uploads', '1 API key for CI', 'Attack-chain reports'],
  team: ['Everything in Builder', '5 seats', 'Custom .sinv invariants', 'Priority queue'],
  professional: ['Everything in Team', '20 seats', 'Priority support', 'Help wiring probe, symbolic and release-check into CI'],
  enterprise: ['Managed live probes and symbolic runs', 'On-premises deployment', 'SSO / SAML, white-label reports', 'SLA and a named security engineer'],
}

const cta: Record<PlanId, string> = { free: 'Start free', builder: 'Choose Builder', team: 'Choose Team', professional: 'Choose Professional', enterprise: 'Talk to us' }

const included = [
  { n: String(ENGINE.totalDetectors), label: 'detectors', sub: 'contracts, application code, infrastructure, supply chain, live probe, symbolic' },
  { n: String(ENGINE.attackChains.length), label: 'attack chains', sub: 'findings that compose into a real attack path' },
  { n: String(ENGINE.pathways.length), label: 'security pathways', sub: 'mapped to native detectors, hosted skills and manual controls' },
  { n: '33', label: 'checklist sections', sub: 'release-check decides READY or not, item by item' },
]

type Cell = boolean | string
const cell = (v: Cell) => ({ text: v === true ? '✓' : v === false ? '—' : v, className: v === true ? 'text-acc-text' : v === false ? 'text-hair-strong' : 'text-sec' })
const row = (feature: string, pick: (p: Plan) => Cell) => ({ feature, cells: PLAN_ORDER.map((id) => cell(pick(PLANS[id]))) })

const comparison = [
  {
    category: 'Dashboard',
    rows: [
      row('Scans per month', (p) => (p.scansPerMonth === null ? 'Custom' : p.scansPerMonth.toLocaleString())),
      row('Seats', (p) => (p.seats === null ? 'Unlimited' : String(p.seats))),
      row('Report retention', (p) => (p.retentionDays === null ? 'Indefinite' : `${p.retentionDays} days`)),
      row('Whole-repository uploads', (p) => p.features.repoScans),
      row('API keys for CI and the CLI', (p) => (p.features.apiKeys ? String(p.features.apiKeys) : false)),
      row('Attack-chain reports', (p) => p.features.attackChainReports),
      row('Priority queue', (p) => p.features.priorityQueue),
    ],
  },
  {
    category: 'Engine (identical on every plan)',
    rows: [
      row('Static detectors: EVM, Solana, Move (Aptos & Sui), Soroban, any repository, supply chain', () => true),
      row('Taint tracking across lines', () => true),
      row('Evidence class on every finding (lead / proven)', () => true),
      row('Exploitability rating + fix and verify step', () => true),
      row('Custom .sinv invariants', (p) => p.features.customInvariants),
    ],
  },
  {
    category: 'CLI (unmetered)',
    rows: [
      row('scan · deps · exposure · harden · release-check', () => true),
      row('probe (live target you own)', (p) => (p.id === 'enterprise' ? 'Managed' : true)),
      row('symbolic (halmos / hevm / Mythril)', (p) => (p.id === 'enterprise' ? 'Managed' : true)),
      row('SARIF for GitHub / GitLab code scanning', () => true),
    ],
  },
  {
    category: 'Support & deployment',
    rows: [
      row('Community support', () => true),
      row('Priority support', (p) => p.features.prioritySupport),
      row('SSO / SAML, white-label reports', (p) => p.features.sso),
      row('On-premises deployment', (p) => p.features.onPrem),
    ],
  },
]

const faqs = [
  { q: 'Is the engine different on the free plan?', a: 'No. Every plan runs the same binary with every detector. Plans differ in monthly dashboard quota, seats, how long reports are kept, and support.' },
  { q: 'What happens when my trial ends?', a: `Every new account gets ${TRIAL_DAYS} days of ${trial.name} with no card. When it ends the account moves to Free. Nothing is deleted and nothing is charged.` },
  { q: 'I only need to check one contract. Do I have to subscribe?', a: `No. A ${pack.name.toLowerCase()} is ${pack.credits} scans for ${formatPrice(pack.amount)}, paid once. The credits never expire and are spent only after your monthly quota.` },
  { q: 'What counts as a scan?', a: 'One submission through the dashboard: a file the engine runs every applicable detector over. Each finding is stored as a lead or proven, with an exploitability rating and a fix. The CLI is not metered.' },
  { q: 'Do I need an account to use the CLI?', a: 'No. cargo install truent-cli and run scan, deps, exposure, harden, release-check, probe and symbolic locally or in CI. The dashboard adds hosted history, triage and team access.' },
  { q: 'How does billing work?', a: 'Monthly plans are billed through Stripe and can be changed or cancelled any time from the billing portal; access runs to the end of the paid period. Scan packs are a single charge. Enterprise is an annual agreement.' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function PricingPage() {
  const { status } = useSession()
  const [openFaq, setOpenFaq] = useState<number | null>(0)
  const [authOpen, setAuthOpen] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState('')

  /** Signed out: create an account (the trial starts). Signed in: straight to checkout. */
  const choose = async (body: { planId: PlanId } | { productId: ProductId }) => {
    if (status !== 'authenticated') {
      setAuthOpen(true)
      return
    }
    const key = 'planId' in body ? body.planId : body.productId
    if ('planId' in body && !PLANS[body.planId].purchasable) {
      window.location.assign('/dashboard')
      return
    }
    setBusy(key)
    setError('')
    try {
      const r = await fetch('/api/payment/create-checkout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      const d = await r.json()
      if (!r.ok || !d.url) throw new Error(d.error || 'Unable to start checkout')
      window.location.assign(d.url)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to start checkout')
      setBusy(null)
    }
  }

  return (
    <PageShell>
      <MarketingNav />

      {/* ─── Hero ─── */}
      <header className="mx-auto max-w-[900px] px-6 pb-14 pt-[90px] text-center">
        <h1 className="m-0 text-[clamp(38px,5.6vw,62px)] font-normal leading-[1.05] tracking-[-0.03em] text-text">
          Same engine on every plan.
          <br />
          <span className="text-acc-text">Pay for the dashboard, not the detectors.</span>
        </h1>
        <p className="mx-auto mt-5 max-w-[560px] text-[15px] leading-[1.7] text-sec">
          Every plan, including free, runs all {ENGINE.totalDetectors} detectors and labels every finding as a lead or proven. New accounts start with {TRIAL_DAYS} days of{' '}
          {trial.name}, no card. The CLI is never metered.
        </p>
      </header>

      {/* ─── Plan cards ─── */}
      <section className="mx-auto max-w-[1180px] px-6 pb-10">
        {error && <p className="mb-4 text-center text-[13px] text-critical">{error}</p>}
        <div className="grid gap-3.5 md:grid-cols-2 xl:grid-cols-4">
          {cards.map((id) => {
            const plan = PLANS[id]
            return (
              <div
                key={id}
                className={`relative flex flex-col overflow-hidden rounded-[20px] border p-7 ${
                  plan.featured ? 'border-acc-text/40 bg-acc-text/[0.05] shadow-[0_0_60px_var(--acc-soft)]' : 'border-hair bg-surface-2'
                }`}
              >
                {plan.featured && (
                  <span className="absolute right-5 top-5 rounded-[5px] border border-acc-text/30 bg-acc-text/10 px-2 py-[3px] font-mono text-[9.5px] tracking-[0.14em] text-acc-text">
                    MOST TEAMS
                  </span>
                )}
                {id === TRIAL_PLAN && (
                  <span className="absolute right-5 top-5 rounded-[5px] border border-hair-strong px-2 py-[3px] font-mono text-[9.5px] tracking-[0.14em] text-sec">
                    {TRIAL_DAYS}-DAY TRIAL
                  </span>
                )}
                <div className="font-mono text-[10.5px] uppercase tracking-[0.18em] text-acc-text">{plan.name}</div>
                <div className="mt-4 flex items-baseline gap-2">
                  <span className="text-[40px] font-normal leading-none tracking-[-0.03em] text-text">{formatPrice(plan.monthlyAmount)}</span>
                  <span className="text-[12.5px] text-sec">{plan.monthlyAmount ? 'per month' : 'forever'}</span>
                </div>
                <p className="m-0 mt-3 min-h-[40px] text-[13px] leading-[1.6] text-sec">{plan.tagline}</p>
                <div className="mt-5 rounded-[10px] border border-hair bg-bg px-4 py-3 font-mono text-[11.5px] text-text">
                  {quotaLine(plan)}
                  <div className="mt-1 text-[10.5px] text-sec">{seats(plan)} · {retention(plan)}</div>
                </div>
                <div className="mt-6 flex flex-col gap-[10px]">
                  {highlights[id].map((f) => (
                    <div key={f} className="flex gap-2.5 text-[13px] leading-[1.5] text-text">
                      <span className="text-acc-text">✓</span>
                      {f}
                    </div>
                  ))}
                </div>
                <div className="mt-auto pt-8">
                  <button
                    onClick={() => choose({ planId: id })}
                    disabled={busy === id}
                    className={`inline-flex w-full items-center justify-center gap-2.5 rounded-full py-3 text-[13px] font-semibold transition-colors disabled:opacity-60 ${
                      plan.featured ? 'bg-text text-bg hover:bg-acc-text' : 'border border-hair-strong text-text hover:border-acc-text/50'
                    }`}
                  >
                    {busy === id ? 'Opening checkout…' : `${cta[id]} →`}
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      {/* ─── One-off and enterprise ─── */}
      <section id="packs" className="mx-auto max-w-[1180px] px-6 pb-16">
        <div className="grid gap-3.5 md:grid-cols-2">
          <div className="flex flex-col justify-between gap-5 rounded-[20px] border border-hair bg-surface-2 p-7 md:flex-row md:items-center">
            <div>
              <div className="font-mono text-[10.5px] uppercase tracking-[0.18em] text-acc-text">{pack.name} · one-off</div>
              <div className="mt-2 text-[28px] font-normal leading-none tracking-[-0.03em] text-text">
                {formatPrice(pack.amount)} <span className="text-[12.5px] text-sec">once</span>
              </div>
              <p className="m-0 mt-2.5 max-w-[380px] text-[13px] leading-[1.6] text-sec">{pack.tagline}</p>
            </div>
            <button
              onClick={() => choose({ productId: pack.id })}
              disabled={busy === pack.id}
              className="inline-flex flex-shrink-0 items-center justify-center rounded-full border border-hair-strong px-5 py-3 text-[13px] font-semibold text-text transition-colors hover:border-acc-text/50 disabled:opacity-60"
            >
              {busy === pack.id ? 'Opening checkout…' : `Buy ${pack.credits} scans →`}
            </button>
          </div>
          <div className="flex flex-col justify-between gap-5 rounded-[20px] border border-hair bg-surface-2 p-7 md:flex-row md:items-center">
            <div>
              <div className="font-mono text-[10.5px] uppercase tracking-[0.18em] text-acc-text">{PLANS.enterprise.name}</div>
              <div className="mt-2 text-[28px] font-normal leading-none tracking-[-0.03em] text-text">
                Custom <span className="text-[12.5px] text-sec">annual agreement</span>
              </div>
              <p className="m-0 mt-2.5 max-w-[380px] text-[13px] leading-[1.6] text-sec">{highlights.enterprise.join('. ')}.</p>
            </div>
            <Link href="/contact" className="inline-flex flex-shrink-0 items-center justify-center rounded-full border border-hair-strong px-5 py-3 text-[13px] font-semibold text-text transition-colors hover:border-acc-text/50">
              {cta.enterprise} →
            </Link>
          </div>
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
        <div className="mx-auto max-w-[1000px]">
          <div className="mb-12 text-center">
            <h2 className="m-0 text-[clamp(26px,3.5vw,36px)] font-normal tracking-[-0.02em] text-text">What differs, exactly</h2>
            <p className="m-0 mt-3 text-[13px] text-sec">Quota, seats, retention and support. The engine rows are identical by design.</p>
          </div>
          <div className="overflow-x-auto">
            <div className="min-w-[760px]">
              <div className="grid grid-cols-[1.8fr_repeat(5,0.8fr)] px-4 pb-3.5">
                <div />
                {PLAN_ORDER.map((id) => (
                  <div key={id} className={`text-center font-mono text-[10.5px] uppercase tracking-[0.14em] ${PLANS[id].featured ? 'text-acc-text' : 'text-sec'}`}>
                    {PLANS[id].name}
                  </div>
                ))}
              </div>
              {comparison.map((group) => (
                <div key={group.category} className="mb-[18px] overflow-hidden rounded-[14px] border border-hair">
                  <div className="border-b border-hair bg-acc-text/[0.05] px-4 py-[11px] font-mono text-[10.5px] uppercase tracking-[0.16em] text-acc-text">{group.category}</div>
                  {group.rows.map((r) => (
                    <div key={r.feature} className="grid grid-cols-[1.8fr_repeat(5,0.8fr)] items-center border-b border-hair px-4 py-[11px] last:border-b-0">
                      <span className="text-[13px] text-sec">{r.feature}</span>
                      {r.cells.map((c, i) => (
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
            <h2 className="m-0 text-[clamp(24px,3.5vw,34px)] font-normal tracking-[-0.02em] text-text">Start with {TRIAL_DAYS} days of {trial.name}. Upgrade when the quota is the limit.</h2>
            <p className="mx-auto mt-3.5 max-w-[440px] text-[13.5px] leading-[1.7] text-sec">Or skip the dashboard entirely: the CLI runs the whole engine locally and in CI, on any plan.</p>
            <div className="mt-[30px] flex flex-wrap justify-center gap-3">
              <button onClick={() => choose({ planId: 'free' })} className="inline-flex items-center gap-2.5 rounded-full bg-text py-1.5 pl-5 pr-1.5 text-[13px] font-semibold text-bg transition-colors hover:bg-acc-text">
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
