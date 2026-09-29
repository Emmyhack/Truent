import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { ENGINE } from '@/lib/engine'

export const dynamic = 'force-dynamic'

/** Liveness for the container and the load balancer: the app is up and can reach its database. */
export async function GET() {
  try {
    await prisma.$queryRaw`SELECT 1`
    return NextResponse.json({ ok: true, db: 'ok', engine: ENGINE.version })
  } catch {
    return NextResponse.json({ ok: false, db: 'unreachable', engine: ENGINE.version }, { status: 503 })
  }
}
