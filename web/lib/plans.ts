/**
 * The plan ladder — one table read by the pricing page, the home page
 * preview, the dashboard meter and the API that enforces it, so the site can
 * never promise what the code does not grant.
 *
 * Pure module: no imports, so it also runs under Node's type stripping in the
 * test suite. Amounts are USD cents.
 */

export type PlanId = 'free' | 'builder' | 'team' | 'professional' | 'enterprise'

export interface PlanFeatures {
  /** Whole-repository uploads (arrives with the repository scanner). */
  repoScans: boolean
  /** API keys for CI and the CLI to push results into the dashboard. */
  apiKeys: number
  customInvariants: boolean
  attackChainReports: boolean
  priorityQueue: boolean
  prioritySupport: boolean
  sso: boolean
  onPrem: boolean
}

export interface Plan {
  id: PlanId
  name: string
  tagline: string
  /** Monthly price in cents. 0 is free; null is "talk to us". */
  monthlyAmount: number | null
  /** Dashboard scans per calendar month (UTC). null is unmetered. */
  scansPerMonth: number | null
  /** Team members. null is unlimited. */
  seats: number | null
  /** Days a report is kept. null is indefinitely. */
  retentionDays: number | null
  /** Sold through Stripe checkout; false for free and enterprise. */
  purchasable: boolean
  featured?: boolean
  features: PlanFeatures
}

export const PLAN_ORDER: PlanId[] = ['free', 'builder', 'team', 'professional', 'enterprise']

export const PLANS: Record<PlanId, Plan> = {
  free: {
    id: 'free',
    name: 'Free',
    tagline: 'Try the whole engine on a file.',
    monthlyAmount: 0,
    scansPerMonth: 5,
    seats: 1,
    retentionDays: 7,
    purchasable: false,
    features: { repoScans: false, apiKeys: 0, customInvariants: false, attackChainReports: false, priorityQueue: false, prioritySupport: false, sso: false, onPrem: false },
  },
  builder: {
    id: 'builder',
    name: 'Builder',
    tagline: 'For the solo developer or hackathon team shipping their first contract.',
    monthlyAmount: 2900,
    scansPerMonth: 100,
    seats: 1,
    retentionDays: 90,
    purchasable: true,
    features: { repoScans: true, apiKeys: 1, customInvariants: false, attackChainReports: true, priorityQueue: false, prioritySupport: false, sso: false, onPrem: false },
  },
  team: {
    id: 'team',
    name: 'Team',
    tagline: 'For a team that scans on every pull request.',
    monthlyAmount: 14900,
    scansPerMonth: 1000,
    seats: 5,
    retentionDays: 365,
    purchasable: true,
    featured: true,
    features: { repoScans: true, apiKeys: 5, customInvariants: true, attackChainReports: true, priorityQueue: true, prioritySupport: false, sso: false, onPrem: false },
  },
  professional: {
    id: 'professional',
    name: 'Professional',
    tagline: 'For teams shipping to production with help on call.',
    monthlyAmount: 49900,
    scansPerMonth: 10000,
    seats: 20,
    retentionDays: null,
    purchasable: true,
    features: { repoScans: true, apiKeys: 20, customInvariants: true, attackChainReports: true, priorityQueue: true, prioritySupport: true, sso: false, onPrem: false },
  },
  enterprise: {
    id: 'enterprise',
    name: 'Enterprise',
    tagline: 'For regulated and large-scale deployments.',
    monthlyAmount: null,
    scansPerMonth: null,
    seats: null,
    retentionDays: null,
    purchasable: false,
    features: { repoScans: true, apiKeys: 100, customInvariants: true, attackChainReports: true, priorityQueue: true, prioritySupport: true, sso: true, onPrem: true },
  },
}

/** One-off purchases: no subscription, credits never expire. */
export type ProductId = 'scan_pack_25'

export interface Product {
  id: ProductId
  name: string
  tagline: string
  /** Price in cents, charged once. */
  amount: number
  /** Scan credits granted. */
  credits: number
}

export const PRODUCTS: Record<ProductId, Product> = {
  scan_pack_25: {
    id: 'scan_pack_25',
    name: 'Scan pack',
    tagline: 'Twenty-five scans that never expire. Check one contract before launch without a subscription.',
    amount: 1500,
    credits: 25,
  },
}

/** New accounts get this plan for this many days, no card required. */
export const TRIAL_DAYS = 14
export const TRIAL_PLAN: PlanId = 'builder'

/** Stripe subscription statuses that still grant the plan. */
export const ACTIVE_STATUSES = ['active', 'trialing', 'past_due']

export const isPlanId = (value: unknown): value is PlanId =>
  typeof value === 'string' && Object.prototype.hasOwnProperty.call(PLANS, value)
export const isProductId = (value: unknown): value is ProductId =>
  typeof value === 'string' && Object.prototype.hasOwnProperty.call(PRODUCTS, value)

export const formatPrice = (cents: number | null): string =>
  cents === null ? 'Custom' : cents === 0 ? '$0' : `$${(cents / 100).toLocaleString('en-US', { maximumFractionDigits: 2 })}`

/** The calendar month, in UTC, that meters a scan: "2026-09". */
export const periodKey = (d: Date): string => `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`

/** Everything the metering decision needs, as read from the database. */
export interface AccountState {
  subscriptionPlan: string | null
  subscriptionStatus: string | null
  subscriptionPeriodEnd: Date | null
  trialEndsAt: Date | null
  /** Unexpired scan credits remaining. */
  credits: number
  /** Scans consumed from the monthly quota this period. */
  used: number
  now?: Date
}

export type PlanSource = 'subscription' | 'trial' | 'free'

export interface Entitlement {
  plan: Plan
  source: PlanSource
  period: string
  /** Monthly quota; null is unmetered. */
  quota: number | null
  used: number
  /** Quota left this period; null is unmetered. */
  remaining: number | null
  credits: number
  canScan: boolean
  trialDaysLeft: number | null
  renewsAt: Date | null
  /** The plan to suggest when this one is the limit; null at the top. */
  nextPlan: PlanId | null
}

export function effectivePlan(s: AccountState): { plan: Plan; source: PlanSource } {
  const now = s.now ?? new Date()
  if (s.subscriptionPlan && isPlanId(s.subscriptionPlan) && s.subscriptionStatus && ACTIVE_STATUSES.includes(s.subscriptionStatus)) {
    return { plan: PLANS[s.subscriptionPlan], source: 'subscription' }
  }
  if (s.trialEndsAt && s.trialEndsAt.getTime() > now.getTime()) {
    return { plan: PLANS[TRIAL_PLAN], source: 'trial' }
  }
  return { plan: PLANS.free, source: 'free' }
}

export function nextPlan(id: PlanId): PlanId | null {
  const i = PLAN_ORDER.indexOf(id)
  return i >= 0 && i < PLAN_ORDER.length - 1 ? PLAN_ORDER[i + 1] : null
}

export function entitlementFor(s: AccountState): Entitlement {
  const now = s.now ?? new Date()
  const { plan, source } = effectivePlan(s)
  const quota = plan.scansPerMonth
  const remaining = quota === null ? null : Math.max(0, quota - s.used)
  const credits = Math.max(0, s.credits)
  const trialDaysLeft =
    source === 'trial' && s.trialEndsAt ? Math.max(1, Math.ceil((s.trialEndsAt.getTime() - now.getTime()) / 86_400_000)) : null
  return {
    plan,
    source,
    period: periodKey(now),
    quota,
    used: s.used,
    remaining,
    credits,
    canScan: remaining === null || remaining > 0 || credits > 0,
    trialDaysLeft,
    renewsAt: source === 'subscription' ? s.subscriptionPeriodEnd : source === 'trial' ? s.trialEndsAt : null,
    nextPlan: nextPlan(plan.id),
  }
}

/** The sentence shown when a scan is refused for quota. */
export function quotaMessage(e: Entitlement): string {
  const step = e.nextPlan ? `Upgrade to ${PLANS[e.nextPlan].name}` : 'Contact us for more capacity'
  const pack = `${PRODUCTS.scan_pack_25.name.toLowerCase()} (${PRODUCTS.scan_pack_25.credits} scans, ${formatPrice(PRODUCTS.scan_pack_25.amount)} once)`
  const what = e.quota === null ? 'no scans are available' : `you have used all ${e.quota} ${e.plan.name} scans for this month`
  return `${what[0].toUpperCase()}${what.slice(1)} and have no scan credits. ${step} or buy a ${pack}.`
}
