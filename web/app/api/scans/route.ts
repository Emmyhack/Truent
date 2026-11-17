import { NextRequest, NextResponse } from 'next/server'
import { getCurrentUser } from '@/lib/current-user'
import prisma from '@/lib/prisma'
import { scanListLimit } from '@/lib/api-policy'

export async function GET(request: NextRequest) {
  const user = await getCurrentUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const limit = scanListLimit(request.nextUrl.searchParams.get('limit'))
  const scans = await prisma.scan.findMany({
    where: { userId: user.id },
    orderBy: { createdAt: 'desc' },
    take: limit,
    select: {
      id: true, projectName: true, language: true, status: true, error: true,
      durationMs: true, createdAt: true, completedAt: true,
      findings: { select: { severity: true, status: true, evidence: true } },
    },
  })

  return NextResponse.json({ scans })
}
