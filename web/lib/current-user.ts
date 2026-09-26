import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth-options'
import prisma from '@/lib/prisma'

export async function getCurrentUser() {
  const session = await getServerSession(authOptions)
  if (!session?.user?.email) return null

  return prisma.user.findUnique({
    where: { email: session.user.email.toLowerCase() },
    select: { id: true, email: true, name: true, trialEndsAt: true, subscription: true },
  })
}
