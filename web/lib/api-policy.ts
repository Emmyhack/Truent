/** Pure request-policy helpers shared by API routes and their tests. */

export const DEFAULT_SCAN_LIST_LIMIT = 20
export const MAX_SCAN_LIST_LIMIT = 100
export const MAX_SCANS_PER_MINUTE = 5

export function scanListLimit(raw: string | null): number {
  if (raw === null || raw.trim() === '') return DEFAULT_SCAN_LIST_LIMIT
  const requested = Number(raw)
  if (!Number.isFinite(requested)) return DEFAULT_SCAN_LIST_LIMIT
  return Math.min(Math.max(Math.trunc(requested), 1), MAX_SCAN_LIST_LIMIT)
}

export function scanRateLimited(recentCount: number): boolean {
  return recentCount >= MAX_SCANS_PER_MINUTE
}

export type CheckoutLike = {
  id: string
  payment_status?: string | null
  subscription?: string | { id: string } | null
  customer?: string | { id: string } | null
  metadata?: Record<string, string | undefined> | null
}

export type CheckoutAction =
  | { kind: 'subscription'; userId: string; planId: string; subscriptionId: string; customerId: string }
  | { kind: 'credits'; userId: string; productId: string }

/**
 * Turn an untrusted Stripe checkout payload into the one fulfillment action
 * it requests. Product/plan allow-list checks remain in the route.
 */
export function checkoutAction(checkout: CheckoutLike): CheckoutAction | null {
  const userId = checkout.metadata?.userId
  if (!userId) return null

  const kind = checkout.metadata?.kind
  if (kind === 'credits') {
    const productId = checkout.metadata?.productId
    return checkout.payment_status === 'paid' && productId
      ? { kind: 'credits', userId, productId }
      : null
  }

  if (kind === 'subscription' || (!kind && checkout.subscription)) {
    const planId = checkout.metadata?.planId
    const subscriptionId = typeof checkout.subscription === 'string'
      ? checkout.subscription
      : checkout.subscription?.id
    if (!planId || !subscriptionId) return null
    const customerId = typeof checkout.customer === 'string'
      ? checkout.customer
      : (checkout.customer?.id ?? '')
    return { kind: 'subscription', userId, planId, subscriptionId, customerId }
  }

  return null
}
