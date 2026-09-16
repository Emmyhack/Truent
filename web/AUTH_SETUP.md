# Truent Web Authentication Setup

How sign-in works in the Truent dashboard and how to configure it.

## Overview

- **Civic Auth** (`@civic/auth`) is the primary sign-in: Google, email, passkeys and
  embedded wallets through one provider, rendered in Civic's own modal.
- **Email / password** (bcrypt, constant-time compare against a dummy hash so an unknown
  email cannot be told apart from a wrong password by response time).
- **Web3 wallet** (MetaMask-style `personal_sign` over a server-issued, single-use nonce).
- **NextAuth 4** owns the application session (a JWT cookie, 7-day lifetime). Every
  provider above, Civic included, ends in the same NextAuth session, so API routes,
  the middleware and billing never have to know which provider signed the user in.
- **Prisma 7 + PostgreSQL** store users, scans and subscriptions.

Provider and session config lives in `web/lib/auth-options.ts`. Civic's route config
lives in `web/next.config.js` and `web/lib/civic.ts`.

## How the Civic bridge works

1. The user clicks **Continue with Civic** in the auth modal. The Civic React SDK opens
   its modal and completes the OAuth flow against `https://auth.civic.com`.
2. Civic's Next.js route handler (`/api/civic/*`) validates the tokens and sets Civic's
   own signed session cookies.
3. The modal then calls NextAuth's `civic` provider. That provider reads **nothing** from
   the request body: it calls `getUser()` from `@civic/auth/nextjs`, which verifies the
   Civic cookie server-side, and maps the identity onto an application user
   (`web/lib/civic-user.ts`):
   - a user already linked by `civicId`, or
   - an existing account with the same email (linked on first use, so a password user
     keeps their scans and plan), or
   - a new account.
4. NextAuth issues the application session. `session.user.provider` is `"civic"`.

Sign-out ends the NextAuth session first, then Civic's, so a failed Civic round-trip can
never leave the dashboard session alive.

Civic's routes are deliberately under `/api/civic`, not `/api/auth`, because NextAuth's
catch-all owns `/api/auth`. Route protection stays with the NextAuth middleware
(`web/middleware.ts`); Civic's middleware is not used.

## Setup

### 1. Environment

```bash
cd web
cp .env.example .env.local
```

Required:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `NEXTAUTH_URL` | Public URL of the site (`http://localhost:3000` in development) |
| `NEXTAUTH_SECRET` | `openssl rand -base64 32` |
| `NEXT_PUBLIC_CIVIC_CLIENT_ID` | Civic client id (public). Empty hides the Civic button. |

### 2. Civic client id

1. Create an app at <https://auth.civic.com>.
2. Add the redirect URL `http://localhost:3000/api/civic/callback` (and the production
   equivalent, `https://<your-domain>/api/civic/callback`).
3. Put the client id in `NEXT_PUBLIC_CIVIC_CLIENT_ID`. The value is baked in at build
   time by the Civic Next.js plugin, so rebuild after changing it.

### 3. Database

```bash
npx prisma migrate deploy   # or `migrate dev` while developing
```

The `20260914120000_civic_id` migration adds the nullable, unique `User.civicId` column.

## Usage

### Client components

```tsx
'use client'
import { useSession } from 'next-auth/react'

export function Greeting() {
  const { data: session, status } = useSession()
  if (status === 'loading') return null
  if (status === 'unauthenticated') return <p>Not signed in</p>
  return <p>Welcome {session?.user?.name} ({session?.user?.provider})</p>
}
```

### Server (API routes)

```ts
import { getCurrentUser } from '@/lib/current-user'

const user = await getCurrentUser() // null when signed out
```

### Sign out

`AppShell` already does this; if you need it elsewhere, sign out of NextAuth first
(`signOut({ redirect: false })`), then call `signOut()` from `useUser()` in
`@civic/auth/react`, then navigate.

### Protected routes

`/dashboard/*` and `/reports/*` are protected by `web/middleware.ts` (NextAuth JWT).

## Endpoints

| Route | Owner | Purpose |
|---|---|---|
| `POST /api/auth/signup` | app | Create an email/password account |
| `POST /api/auth/callback/credentials` | NextAuth | Email/password sign-in |
| `POST /api/auth/callback/wallet` | NextAuth | Wallet signature sign-in |
| `POST /api/auth/callback/civic` | NextAuth | Bridge a verified Civic session into the app session |
| `GET /api/auth/session` | NextAuth | Current session |
| `GET /api/civic/login`, `/callback`, `/refresh`, `/user`, `/logout`, `/clearsession` | Civic | Civic's own OAuth flow and cookies |

## Content-Security-Policy

`next.config.js` allows `https://auth.civic.com` in `frame-src` and `connect-src` for
the Civic modal. Nothing else changed.

## Security notes

1. The Civic bridge trusts only Civic's server-verified cookie, never a client-supplied
   profile. Posting to `/api/auth/callback/civic` without a valid Civic session yields
   `CredentialsSignin` and no session.
2. Email linking on first Civic sign-in relies on Civic having verified the email.
3. Passwords are bcrypt-hashed; wallet nonces are single-use and expire.
4. Keep `NEXTAUTH_SECRET` out of git. `NEXT_PUBLIC_CIVIC_CLIENT_ID` is not secret.

## Troubleshooting

- **No "Continue with Civic" button** — `NEXT_PUBLIC_CIVIC_CLIENT_ID` was empty at build
  time. Set it and rebuild.
- **Civic modal completes but the dashboard does not open** — check the server log for
  `Civic sign-in error`; usually the Civic callback URL registered in the Civic dashboard
  does not match `/api/civic/callback` on this origin.
- **`NO_SECRET` in the log** — `NEXTAUTH_SECRET` is unset.
- **Database connection error** — verify `DATABASE_URL` and that PostgreSQL is running.

## Not yet implemented

1. "Forgot password" flow for email/password accounts
2. Email verification for email/password accounts (Civic accounts arrive verified)
3. Role-based access control

## Resources

- [Civic Auth docs](https://docs.civic.com/)
- [NextAuth documentation](https://next-auth.js.org/)
- [Prisma documentation](https://www.prisma.io/docs/)
