import test from 'node:test'
import assert from 'node:assert/strict'
import { entitlementFor, effectivePlan, periodKey, quotaMessage, PLANS, PLAN_ORDER, PRODUCTS, TRIAL_PLAN, formatPrice } from '../lib/plans.ts'

const now = new Date('2026-09-27T12:00:00Z')
const base = { subscriptionPlan: null, subscriptionStatus: null, subscriptionPeriodEnd: null, trialEndsAt: null, credits: 0, used: 0, now }

test('the ladder is ordered and every step is priced or custom', () => {
  assert.deepEqual(PLAN_ORDER, ['free', 'builder', 'team', 'professional', 'enterprise'])
  let last = -1
  for (const id of PLAN_ORDER) {
    const p = PLANS[id]
    if (p.monthlyAmount !== null) { assert.ok(p.monthlyAmount > last, `${id} costs more than the step below`); last = p.monthlyAmount }
    assert.equal(p.purchasable, p.monthlyAmount !== null && p.monthlyAmount > 0, `${id}: only paid plans go through checkout`)
  }
  assert.equal(formatPrice(2900), '$29')
  assert.equal(formatPrice(null), 'Custom')
})

test('a new account is on the trial plan, then falls to free, never locked', () => {
  const trial = entitlementFor({ ...base, trialEndsAt: new Date('2026-10-05T12:00:00Z') })
  assert.equal(trial.plan.id, TRIAL_PLAN)
  assert.equal(trial.source, 'trial')
  assert.equal(trial.trialDaysLeft, 8)
  assert.equal(trial.quota, PLANS.builder.scansPerMonth)

  const expired = entitlementFor({ ...base, trialEndsAt: new Date('2026-09-01T00:00:00Z') })
  assert.equal(expired.plan.id, 'free')
  assert.equal(expired.source, 'free')
  assert.equal(expired.trialDaysLeft, null)
  assert.equal(expired.canScan, true)
})

test('an active subscription beats the trial; a cancelled one does not', () => {
  const active = effectivePlan({ ...base, subscriptionPlan: 'team', subscriptionStatus: 'active', trialEndsAt: new Date('2027-01-01') })
  assert.equal(active.plan.id, 'team')
  assert.equal(active.source, 'subscription')
  const canceled = effectivePlan({ ...base, subscriptionPlan: 'team', subscriptionStatus: 'canceled' })
  assert.equal(canceled.plan.id, 'free')
  const unknown = effectivePlan({ ...base, subscriptionPlan: 'gold', subscriptionStatus: 'active' })
  assert.equal(unknown.plan.id, 'free', 'a plan id the table does not know grants nothing')
})

test('quota is spent first, credits keep the account scanning after it', () => {
  const e = entitlementFor({ ...base, used: 5, credits: 0 })
  assert.equal(e.remaining, 0)
  assert.equal(e.canScan, false)
  assert.equal(e.nextPlan, 'builder')
  assert.match(quotaMessage(e), /all 5 Free scans/)
  assert.match(quotaMessage(e), /Upgrade to Builder/)
  assert.match(quotaMessage(e), new RegExp(`${PRODUCTS.scan_pack_25.credits} scans`))

  const withCredits = entitlementFor({ ...base, used: 5, credits: 3 })
  assert.equal(withCredits.remaining, 0)
  assert.equal(withCredits.credits, 3)
  assert.equal(withCredits.canScan, true)
})

test('enterprise is unmetered', () => {
  const e = entitlementFor({ ...base, subscriptionPlan: 'enterprise', subscriptionStatus: 'active', used: 1_000_000 })
  assert.equal(e.quota, null)
  assert.equal(e.remaining, null)
  assert.equal(e.canScan, true)
  assert.equal(e.nextPlan, null)
})

test('the metering period is the UTC calendar month', () => {
  assert.equal(periodKey(new Date('2026-09-30T23:59:59Z')), '2026-09')
  assert.equal(periodKey(new Date('2026-10-01T00:00:00Z')), '2026-10')
  assert.equal(entitlementFor(base).period, '2026-09')
})
