import Stripe from 'stripe'
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import prisma from '@/lib/prisma'
import { getCurrentUser } from '@/lib/current-user'
import { ACTIVE_STATUSES, isPlanId, isProductId, PLANS, PRODUCTS } from '@/lib/plans'

const checkoutSchema = z
  .object({ planId: z.string().min(1).optional(), productId: z.string().min(1).optional() })
  .refine((v) => Boolean(v.planId) !== Boolean(v.productId), 'Pass exactly one of planId or productId')

function stripeClient() {
  const key = process.env.STRIPE_SECRET_KEY
  if (!key) throw new Error('STRIPE_SECRET_KEY is not configured')
  return new Stripe(key)
}

/**
 * Start a Stripe checkout for a subscription plan or a one-off product.
 * An account that already subscribes is sent to the billing portal to change
 * plan there, so Stripe never holds two subscriptions for one user.
 */
export async function POST(request: NextRequest) {
  try {
    const user = await getCurrentUser()
    if (!user?.email) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const stripe = stripeClient()
    const { planId, productId } = checkoutSchema.parse(await request.json())
    const base = process.env.NEXTAUTH_URL
    const existing = await prisma.subscription.findUnique({ where: { userId: user.id } })

    if (planId) {
      if (!isPlanId(planId) || !PLANS[planId].purchasable) {
        return NextResponse.json({ error: 'That plan is not sold through checkout' }, { status: 400 })
      }
      const plan = PLANS[planId]
      if (existing?.provider === 'stripe' && existing.providerCustomerId && ACTIVE_STATUSES.includes(existing.status)) {
        const portal = await stripe.billingPortal.sessions.create({ customer: existing.providerCustomerId, return_url: `${base}/dashboard/settings` })
        return NextResponse.json({ url: portal.url, via: 'portal' })
      }
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
      return NextResponse.json({ sessionId: session.id, url: session.url, via: 'checkout' })
    }

    if (!isProductId(productId)) return NextResponse.json({ error: 'Unknown product' }, { status: 400 })
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
    return NextResponse.json({ sessionId: session.id, url: session.url, via: 'checkout' })
  } catch (error) {
    if (error instanceof z.ZodError) return NextResponse.json({ error: error.issues[0].message }, { status: 400 })
    console.error('Stripe error:', error)
    return NextResponse.json({ error: 'Payment processing failed' }, { status: 500 })
  }
}
