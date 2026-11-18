import { NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth-options'

/**
 * Crypto checkout is intentionally unavailable until it is invoice-bound.
 *
 * A safe implementation must persist a server-priced invoice, verify the
 * exact asset and amount, bind the payer and receiver, require confirmations,
 * and consume each transaction hash exactly once. The previous placeholder
 * only proved that some successful transaction existed between two addresses
 * and then reported "Payment confirmed"; that is not payment verification.
 */
async function unavailable() {
  const session = await getServerSession(authOptions)
  if (!session?.user?.email) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  return NextResponse.json(
    {
      error: 'Crypto payments are not available yet. Use Stripe checkout.',
      code: 'crypto_payments_unavailable',
    },
    { status: 501 },
  )
}

export const POST = unavailable
export const PATCH = unavailable
