import Stripe from 'stripe'
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import prisma from '@/lib/prisma'
import { getCurrentUser } from '@/lib/current-user'
import { ACTIVE_STATUSES, isPlanId, isProductId, PLANS, PRODUCTS, type PlanId, type ProductId } from '@/lib/plans'

const checkoutSchema = z
  .object({ planId: z.string().min(1).optional(), productId: z.string().min(1).optional() })
  .refine((v) => Boolean(v.planId) !== Boolean(v.productId), 'Pass exactly one of planId or productId')

function stripeClient() {
  const key = process.env.STRIPE_SECRET_KEY
  if (!key) throw new Error('STRIPE_SECRET_KEY is not configured')
  return new Stripe(key)
}

type Session = { url: string | null; id?: string; via: 'portal' | 'checkout' }

/** An account that already subscribes changes plan in the billing portal, so Stripe never holds two subscriptions for one user. */
async function portalSession(stripe: Stripe, customer: string, base: string | undefined): Promise<Session> {
  const portal = await stripe.billingPortal.sessions.create({ customer, return_url: `${base}/dashboard/settings` })
  return { url: portal.url, via: 'portal' }
}

async function planCheckout(stripe: Stripe, user: { id: string; email: string }, planId: PlanId, base: string | undefined): Promise<Session> {
  const plan = PLANS[planId]
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    customer_email: user.email,
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: `Truent ${plan.name}`, description: plan.tagline },
        unit_amount: plan.monthlyAmount ?? 0,
        recurring: { interval: 'month', interval_count: 1 },
      },
      quantity: 1,
    }],
    subscription_data: { metadata: { userId: user.id, planId } },
    success_url: `${base}/dashboard?payment=success`,
    cancel_url: `${base}/pricing?payment=cancelled`,
    metadata: { kind: 'subscription', planId, userId: user.id },
  })
  return { id: session.id, url: session.url, via: 'checkout' }
}

async function creditsCheckout(stripe: Stripe, user: { id: string; email: string }, productId: ProductId, base: string | undefined): Promise<Session> {
  const product = PRODUCTS[productId]
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    payment_method_types: ['card'],
    customer_email: user.email,
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: `Truent ${product.name}`, description: `${product.credits} scan credits. They never expire.` },
        unit_amount: product.amount,
      },
      quantity: 1,
    }],
    success_url: `${base}/dashboard?payment=success`,
    cancel_url: `${base}/pricing?payment=cancelled`,
    metadata: { kind: 'credits', productId, userId: user.id },
  })
  return { id: session.id, url: session.url, via: 'checkout' }
}

/**
 * Start a Stripe checkout for a subscription plan or a one-off product.
 * Each path creates exactly one Stripe object; the handler only routes.
 */
export async function POST(request: NextRequest) {
  try {
    const user = await getCurrentUser()
    if (!user?.email) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const stripe = stripeClient()
    const { planId, productId } = checkoutSchema.parse(await request.json())
    const base = process.env.NEXTAUTH_URL
    const account = { id: user.id, email: user.email }

    let session: Session
    if (planId) {
      if (!isPlanId(planId) || !PLANS[planId].purchasable) {
        return NextResponse.json({ error: 'That plan is not sold through checkout' }, { status: 400 })
      }
      const existing = await prisma.subscription.findUnique({ where: { userId: user.id } })
      session =
        existing?.provider === 'stripe' && existing.providerCustomerId && ACTIVE_STATUSES.includes(existing.status)
          ? await portalSession(stripe, existing.providerCustomerId, base)
          : await planCheckout(stripe, account, planId, base)
    } else {
      if (!isProductId(productId)) return NextResponse.json({ error: 'Unknown product' }, { status: 400 })
      session = await creditsCheckout(stripe, account, productId, base)
    }
    return NextResponse.json({ sessionId: session.id, url: session.url, via: session.via })
  } catch (error) {
    if (error instanceof z.ZodError) return NextResponse.json({ error: error.issues[0].message }, { status: 400 })
    console.error('Stripe error:', error)
    return NextResponse.json({ error: 'Payment processing failed' }, { status: 500 })
  }
}
