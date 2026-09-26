import prisma from '@/lib/prisma'
import { entitlementFor, periodKey, type Entitlement } from '@/lib/plans'

export class QuotaExceeded extends Error {
  entitlement: Entitlement
  constructor(entitlement: Entitlement) {
    super('Scan quota exhausted')
    this.name = 'QuotaExceeded'
    this.entitlement = entitlement
  }
}

const liveCredits = (userId: string, now: Date) => ({
  userId,
  remaining: { gt: 0 },
  OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
})

/**
 * The usage row for this period. The first time an account is seen in a
 * period the row is seeded from scans already created in it, so the switch
 * from counting the scans table to metering loses nothing.
 */
async function ensureUsage(userId: string, now: Date) {
  const period = periodKey(now)
  const existing = await prisma.usage.findUnique({ where: { userId_period: { userId, period } } })
  if (existing) return existing
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1))
  const scans = await prisma.scan.count({ where: { userId, createdAt: { gte: start } } })
  try {
    return await prisma.usage.create({ data: { userId, period, scans } })
  } catch {
    // A concurrent request created it first.
    return (await prisma.usage.findUnique({ where: { userId_period: { userId, period } } }))!
  }
}

export async function getEntitlement(userId: string, now = new Date()): Promise<Entitlement> {
  const [user, usage, credits] = await Promise.all([
    prisma.user.findUnique({
      where: { id: userId },
      select: { trialEndsAt: true, subscription: { select: { plan: true, status: true, currentPeriodEnd: true } } },
    }),
    ensureUsage(userId, now),
    prisma.scanCredit.aggregate({ _sum: { remaining: true }, where: liveCredits(userId, now) }),
  ])
  return entitlementFor({
    subscriptionPlan: user?.subscription?.plan ?? null,
    subscriptionStatus: user?.subscription?.status ?? null,
    subscriptionPeriodEnd: user?.subscription?.currentPeriodEnd ?? null,
    trialEndsAt: user?.trialEndsAt ?? null,
    credits: credits._sum.remaining ?? 0,
    used: usage.scans,
    now,
  })
}

export type Consumed = { from: 'quota' | 'credit' | 'unmetered'; creditId?: string; entitlement: Entitlement }

/**
 * Take one scan from the account: the monthly quota first, then the oldest
 * credit. Each take is a conditional update, so two concurrent requests can
 * never both spend the last scan.
 */
export async function consumeScan(userId: string, now = new Date()): Promise<Consumed> {
  const period = periodKey(now)
  const ent = await getEntitlement(userId, now)
  if (!ent.canScan) throw new QuotaExceeded(ent)

  if (ent.quota === null) {
    await prisma.usage.update({ where: { userId_period: { userId, period } }, data: { scans: { increment: 1 } } })
    return { from: 'unmetered', entitlement: await getEntitlement(userId, now) }
  }
  if (ent.remaining !== null && ent.remaining > 0) {
    const r = await prisma.usage.updateMany({ where: { userId, period, scans: { lt: ent.quota } }, data: { scans: { increment: 1 } } })
    if (r.count === 1) return { from: 'quota', entitlement: await getEntitlement(userId, now) }
  }
  const credit = await prisma.scanCredit.findFirst({ where: liveCredits(userId, now), orderBy: { createdAt: 'asc' } })
  if (credit) {
    const r = await prisma.scanCredit.updateMany({ where: { id: credit.id, remaining: { gt: 0 } }, data: { remaining: { decrement: 1 } } })
    if (r.count === 1) return { from: 'credit', creditId: credit.id, entitlement: await getEntitlement(userId, now) }
  }
  throw new QuotaExceeded(await getEntitlement(userId, now))
}

/** Give back a scan that was taken but never queued. */
export async function refundScan(userId: string, consumed: Consumed, now = new Date()) {
  if (consumed.from === 'credit' && consumed.creditId) {
    await prisma.scanCredit.update({ where: { id: consumed.creditId }, data: { remaining: { increment: 1 } } })
    return
  }
  await prisma.usage.updateMany({ where: { userId, period: periodKey(now), scans: { gt: 0 } }, data: { scans: { decrement: 1 } } })
}
