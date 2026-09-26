import { NextResponse } from 'next/server'
import { getCurrentUser } from '@/lib/current-user'
import { getEntitlement } from '@/lib/entitlements'

export const dynamic = 'force-dynamic'

/** What this account may do right now: plan, quota used, credits, trial. */
export async function GET() {
  const user = await getCurrentUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  return NextResponse.json({ entitlement: await getEntitlement(user.id) })
}
