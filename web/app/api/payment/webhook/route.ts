import { NextRequest, NextResponse } from 'next/server'
import Stripe from 'stripe'
import prisma from '@/lib/prisma'
import { isPlanId, isProductId, PRODUCTS } from '@/lib/plans'

export const runtime = 'nodejs'

function stripeClient() {
  if (!process.env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY is not configured')
  return new Stripe(process.env.STRIPE_SECRET_KEY)
}

/** Record the money once; Stripe retries webhooks, so every write here is idempotent. */
async function recordPayment(checkout: Stripe.Checkout.Session, userId: string, plan: string) {
  await prisma.payment.upsert({
    where: { providerPaymentId: checkout.id },
    create: {
      userId,
      provider: 'stripe',
      providerPaymentId: checkout.id,
      plan,
      amount: checkout.amount_total ?? 0,
      currency: checkout.currency ?? 'usd',
      status: checkout.payment_status,
    },
    update: { status: checkout.payment_status },
  })
}

export async function POST(request: NextRequest) {
  const signature = request.headers.get('stripe-signature')
  const secret = process.env.STRIPE_WEBHOOK_SECRET
  if (!signature || !secret) return NextResponse.json({ error: 'Webhook is not configured' }, { status: 503 })

  let event: Stripe.Event
  try {
    event = stripeClient().webhooks.constructEvent(await request.text(), signature, secret)
  } catch (error) {
    console.error('Invalid Stripe webhook', error)
    return NextResponse.json({ error: 'Invalid signature' }, { status: 400 })
  }

  if (event.type === 'checkout.session.completed') {
    const checkout = event.data.object
    const userId = checkout.metadata?.userId
    const kind = checkout.metadata?.kind
    if (!userId) return NextResponse.json({ received: true })

    if (kind === 'subscription' || (!kind && checkout.subscription)) {
      const plan = checkout.metadata?.planId
      if (plan && isPlanId(plan) && checkout.subscription) {
        const providerSubscriptionId = typeof checkout.subscription === 'string' ? checkout.subscription : checkout.subscription.id
        const providerCustomerId = typeof checkout.customer === 'string' ? checkout.customer : (checkout.customer?.id ?? '')
        await prisma.subscription.upsert({
          where: { userId },
          create: { userId, provider: 'stripe', providerCustomerId, providerSubscriptionId, plan, status: 'active' },
          update: { provider: 'stripe', providerCustomerId, providerSubscriptionId, plan, status: 'active' },
        })
        await recordPayment(checkout, userId, plan)
      }
    }

    if (kind === 'credits' && checkout.payment_status === 'paid') {
      const productId = checkout.metadata?.productId
      if (isProductId(productId)) {
        const product = PRODUCTS[productId]
        // `source` is unique: a retried webhook cannot grant the pack twice.
        await prisma.scanCredit.upsert({
          where: { source: checkout.id },
          create: { userId, source: checkout.id, product: productId, granted: product.credits, remaining: product.credits },
          update: {},
        })
        await recordPayment(checkout, userId, productId)
      }
    }
  }

  if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object
    const plan = subscription.metadata?.planId
    const periodEnd = subscription.items.data[0]?.current_period_end
    await prisma.subscription.updateMany({
      where: { providerSubscriptionId: subscription.id },
      data: {
        status: event.type === 'customer.subscription.deleted' ? 'canceled' : subscription.status,
        cancelAtPeriodEnd: subscription.cancel_at_period_end,
        currentPeriodEnd: periodEnd ? new Date(periodEnd * 1000) : null,
        ...(isPlanId(plan) ? { plan } : {}),
      },
    })
  }

  return NextResponse.json({ received: true })
}
