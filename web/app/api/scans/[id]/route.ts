import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { getCurrentUser } from '@/lib/current-user'
import prisma from '@/lib/prisma'

const updateSchema = z.object({
  findingId: z.string().min(1),
  status: z.enum(['open', 'acknowledged', 'resolved']),
})

export async function GET(_: NextRequest, { params }: { params: { id: string } }) {
  const user = await getCurrentUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const scan = await prisma.scan.findFirst({
    where: { id: params.id, userId: user.id },
    select: {
      id: true, projectName: true, language: true, status: true, error: true,
      durationMs: true, createdAt: true, completedAt: true,
      findings: { orderBy: { createdAt: 'asc' } },
    },
  })
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  return NextResponse.json({ scan })
}

export async function PATCH(request: NextRequest, { params }: { params: { id: string } }) {
  const user = await getCurrentUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  try {
    const { findingId, status } = updateSchema.parse(await request.json())
    const result = await prisma.finding.updateMany({
      where: { id: findingId, scanId: params.id, scan: { userId: user.id } },
      data: { status },
    })
    if (!result.count) return NextResponse.json({ error: 'Finding not found' }, { status: 404 })
    return NextResponse.json({ success: true })
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues[0].message }, { status: 400 })
    }
    console.error('Finding update failed', error)
    return NextResponse.json({ error: 'Update failed' }, { status: 500 })
  }
}
