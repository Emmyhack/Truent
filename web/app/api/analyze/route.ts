import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import prisma from '@/lib/prisma'
import { getCurrentUser } from '@/lib/current-user'
import { monthlyScanLimit } from '@/lib/plans'

const submissionSchema = z.object({
  code: z.string().min(1, 'Code is required').max(500_000, 'Code exceeds maximum size'),
  language: z.enum(['solidity', 'rust', 'move', 'soroban', 'python', 'javascript', 'typescript', 'go', 'shell', 'dockerfile', 'terraform', 'yaml']).default('solidity'),
  projectName: z.string().trim().min(1).max(120).optional(),
})

export async function POST(request: NextRequest) {
  try {
    const user = await getCurrentUser()
    if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

    const minuteAgo = new Date(Date.now() - 60_000)
    if (await prisma.scan.count({ where: { userId: user.id, createdAt: { gte: minuteAgo } } }) >= 5) {
      return NextResponse.json(
        { error: 'Rate limit exceeded. Please wait before submitting another scan.' },
        { status: 429, headers: { 'Retry-After': '60' } },
      )
    }

    const monthStart = new Date()
    monthStart.setUTCDate(1)
    monthStart.setUTCHours(0, 0, 0, 0)
    const activePlan = user.subscription?.status === 'active' ? user.subscription.plan : null
    const used = await prisma.scan.count({ where: { userId: user.id, createdAt: { gte: monthStart } } })
    if (used >= monthlyScanLimit(activePlan)) {
      return NextResponse.json({ error: 'Monthly scan quota exceeded' }, { status: 403 })
    }

    const input = submissionSchema.parse(await request.json())
    const scan = await prisma.scan.create({
      data: {
        userId: user.id,
        projectName: input.projectName || 'Untitled scan',
        sourceType: 'code',
        sourceContent: input.code,
        language: input.language,
        status: 'queued',
      },
      select: { id: true, status: true, createdAt: true },
    })

    return NextResponse.json(
      { success: true, scanId: scan.id, status: scan.status, createdAt: scan.createdAt },
      { status: 202, headers: { Location: `/api/scans/${scan.id}` } },
    )
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues[0].message }, { status: 400 })
    }
    console.error('Scan submission failed', error)
    return NextResponse.json({ error: 'Unable to queue scan' }, { status: 500 })
  }
}
