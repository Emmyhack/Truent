'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import clsx from 'clsx'
import { formatPrice, PLANS, PRODUCTS, type Entitlement } from '@/lib/plans'

/** Serialised over JSON: dates arrive as strings. */
type Wire = Omit<Entitlement, 'renewsAt'> & { renewsAt: string | null }

/**
 * What the account may do right now, in one line: plan and its source,
 * quota used this month, credits, and the next step when it is the limit.
 */
export function UsageMeter({ className, refreshKey, detailed = false }: { className?: string; refreshKey?: unknown; detailed?: boolean }) {
  const [e, setE] = useState<Wire | null>(null)
  useEffect(() => {
    fetch('/api/account/entitlement', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setE(d.entitlement))
      .catch(() => {})
  }, [refreshKey])
  if (!e) return null

  const pct = e.quota === null ? 0 : Math.min(100, Math.round((e.used / e.quota) * 100))
  const low = e.quota !== null && e.remaining !== null && e.remaining <= Math.max(1, Math.floor(e.quota * 0.1))
  const renews = e.renewsAt ? new Date(e.renewsAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : null
  const source =
    e.source === 'trial' ? `${e.plan.name} trial · ${e.trialDaysLeft} day${e.trialDaysLeft === 1 ? '' : 's'} left`
    : e.source === 'subscription' ? `${e.plan.name}${renews ? ` · renews ${renews}` : ''}`
    : `${e.plan.name} plan`
  const next = e.nextPlan ? PLANS[e.nextPlan] : null
  const pack = PRODUCTS.scan_pack_25

  return (
    <div className={clsx('rounded-[18px] border border-hair bg-surface-2 px-5 py-4', className)}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="font-mono text-[10.5px] uppercase tracking-[0.16em] text-acc-text">{source}</div>
          <div className="mt-1 text-[13px] text-text">
            {e.quota === null ? 'Unmetered scans' : <>{e.used.toLocaleString()} of {e.quota.toLocaleString()} scans used this month</>}
            {e.credits > 0 && <span className="text-sec"> · {e.credits} credit{e.credits === 1 ? '' : 's'}</span>}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {next && (
            <Link href="/pricing" className="rounded-full border border-hair-strong px-3.5 py-1.5 text-[12px] font-medium text-text transition-colors hover:border-acc-text/50">
              {e.source === 'free' || low ? `Upgrade to ${next.name} · ${formatPrice(next.monthlyAmount)}/mo` : 'Compare plans'}
            </Link>
          )}
          {(low || e.credits > 0 || detailed) && (
            <Link href="/pricing#packs" className="text-[12px] text-sec hover:text-text">
              {pack.name}: {pack.credits} scans, {formatPrice(pack.amount)} once
            </Link>
          )}
        </div>
      </div>
      {e.quota !== null && (
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-hair">
          <div className={clsx('h-full rounded-full transition-[width]', low ? 'bg-high' : 'bg-acc-text')} style={{ width: `${pct}%` }} />
        </div>
      )}
      {detailed && (
        <p className="m-0 mt-3 text-[12px] leading-[1.6] text-sec">
          {e.plan.tagline} Reports kept {e.plan.retentionDays === null ? 'indefinitely' : `${e.plan.retentionDays} days`}.
          {e.source === 'trial' && ' When the trial ends the account moves to Free; nothing is deleted.'}
        </p>
      )}
    </div>
  )
}
