import Stripe from 'stripe'
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getCurrentUser } from '@/lib/current-user'

/** Send the user to Stripe's billing portal: invoices, card, plan changes, cancellation. */
export async function POST() {
  const user = await getCurrentUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const key = process.env.STRIPE_SECRET_KEY
  if (!key) return NextResponse.json({ error: 'Billing is not configured' }, { status: 503 })

  const sub = await prisma.subscription.findUnique({ where: { userId: user.id }, select: { provider: true, providerCustomerId: true } })
  if (sub?.provider !== 'stripe' || !sub.providerCustomerId) {
    return NextResponse.json({ error: 'No billing account yet. Choose a plan first.' }, { status: 400 })
  }
  try {
    const session = await new Stripe(key).billingPortal.sessions.create({
      customer: sub.providerCustomerId,
      return_url: `${process.env.NEXTAUTH_URL}/dashboard/settings`,
    })
    return NextResponse.json({ url: session.url })
  } catch (error) {
    console.error('Stripe portal error:', error)
    return NextResponse.json({ error: 'Unable to open billing' }, { status: 500 })
  }
}
