import type { User as CivicUser } from '@civic/auth'
import prisma from '@/lib/prisma'
import { newUserDefaults } from '@/lib/new-user'

export type LinkedUser = { id: string; email: string | null; name: string | null; image: string | null }

/**
 * Map a verified Civic identity onto an application user.
 *
 * Order of resolution:
 *   1. a user already linked to this Civic id;
 *   2. an existing account with the same (verified) email — linked on first use
 *      so someone who signed up with a password keeps their scans and plan;
 *   3. a new account.
 *
 * The caller must only pass a user obtained from Civic's server-side session
 * (`getUser()` from `@civic/auth/nextjs`), never from the request body.
 */
export async function resolveCivicUser(civic: CivicUser): Promise<LinkedUser> {
  const select = { id: true, email: true, name: true, image: true }
  const email = civic.email?.trim().toLowerCase() || null
  const name = civic.name || civic.username || (email ? email.split('@')[0] : `Civic ${civic.id.slice(0, 6)}`)

  const linked = await prisma.user.findUnique({ where: { civicId: civic.id }, select })
  if (linked) return linked

  if (email) {
    const byEmail = await prisma.user.findUnique({ where: { email }, select })
    if (byEmail) {
      return prisma.user.update({
        where: { id: byEmail.id },
        data: { civicId: civic.id, emailVerified: new Date(), image: byEmail.image ?? civic.picture ?? null },
        select,
      })
    }
  }

  return prisma.user.create({
    data: {
      civicId: civic.id,
      email,
      emailVerified: email ? new Date() : null,
      name,
      image: civic.picture ?? null,
      ...newUserDefaults(),
    },
    select,
  })
}
