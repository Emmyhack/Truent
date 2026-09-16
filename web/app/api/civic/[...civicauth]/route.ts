// Civic Auth endpoints (login, challenge, callback, refresh, user, logout,
// clearsession). They live under /api/civic so they cannot collide with the
// NextAuth catch-all at /api/auth, which owns the application session.
import { handler } from '@civic/auth/nextjs'

export const GET = handler()
export const POST = handler()
