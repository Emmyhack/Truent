import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import prisma from '@/lib/prisma'
import { getCurrentUser } from '@/lib/current-user'
import { consumeScan, QuotaExceeded, refundScan } from '@/lib/entitlements'
import { quotaMessage } from '@/lib/plans'

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

    // Validate before metering, so a malformed request never costs a scan.
    const input = submissionSchema.parse(await request.json())

    let consumed
    try {
      consumed = await consumeScan(user.id)
    } catch (error) {
      if (error instanceof QuotaExceeded) {
        return NextResponse.json(
          { error: quotaMessage(error.entitlement), code: 'quota_exceeded', entitlement: error.entitlement },
          { status: 402 },
        )
      }
      throw error
    }

    let scan
    try {
      scan = await prisma.scan.create({
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
    } catch (error) {
      await refundScan(user.id, consumed).catch(() => {})
      throw error
    }

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
