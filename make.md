# Making Web3 Wallet Sign-In and Sign-Up Work: Session Log

**Date:** 2026-09-24
**Scope:** `web/`, the Next.js dashboard
**Goal:** run the dev server, then make Web3 wallet sign-in and sign-up work
**Result:** working, verified end to end against the running server with a real secp256k1 signature
**Committed:** nothing. Every change is uncommitted in the working tree.

---

## Contents

1. [Summary](#1-summary)
2. [Starting state](#2-starting-state)
3. [Step 1: Running the dev server](#3-step-1-running-the-dev-server)
4. [Step 2: Reading the auth design](#4-step-2-reading-the-auth-design)
5. [Step 3: Reading the wallet code](#5-step-3-reading-the-wallet-code)
6. [Step 4: Reproducing the failure](#6-step-4-reproducing-the-failure)
7. [Step 5: Finding the database](#7-step-5-finding-the-database)
8. [Step 6: Starting Postgres and checking migrations](#8-step-6-starting-postgres-and-checking-migrations)
9. [Step 7: Port 3000 and the environment file](#9-step-7-port-3000-and-the-environment-file)
10. [Step 8: Middleware and CSP review](#10-step-8-middleware-and-csp-review)
11. [Step 9: Client fixes in AuthModal](#11-step-9-client-fixes-in-authmodal)
12. [Step 10: Restart and typecheck](#12-step-10-restart-and-typecheck)
13. [Step 11: End-to-end verification](#13-step-11-end-to-end-verification)
14. [Step 12: Email sign-up check](#14-step-12-email-sign-up-check)
15. [Step 13: Cleanup attempt](#15-step-13-cleanup-attempt)
16. [How wallet authentication works](#16-how-wallet-authentication-works)
17. [Security properties checked](#17-security-properties-checked)
18. [Full diff](#18-full-diff)
19. [Operating the local setup](#19-operating-the-local-setup)
20. [Troubleshooting](#20-troubleshooting)
21. [Open items](#21-open-items)

---

## 1. Summary

The wallet code was already correct end to end: the server issued a nonce, the client signed it, the server verified it, and the account was found or created. **Nothing worked because no database was running.** Each auth path writes to Postgres through Prisma, so every request to `/api/auth/wallet-nonce` returned HTTP 500 with `ECONNREFUSED`.

What changed:

| # | Change | Kind | Why |
|---|---|---|---|
| 1 | Started Homebrew `postgresql@16` | Local environment | Prisma could not connect; the `truent` DB and role already existed and were fully migrated |
| 2 | Created `web/.env.local` | Local environment (gitignored) | No env file existed; NextAuth needs `NEXTAUTH_SECRET` and a `NEXTAUTH_URL` matching the real port |
| 3 | `redirect: true` → `redirect: false` in all three sign-in handlers | Code, `web/components/ui/AuthModal.tsx` | Failures bounced the page to `/?error=CredentialsSignin`, so the modal never showed an error |
| 4 | Hex-encode the `personal_sign` payload | Code, same file | MetaMask accepts plain text; several other wallets accept only `0x` hex |
| 5 | Handle EIP-1193 error `4001` (user rejected) | Code, same file | Rejecting in the wallet showed a generic "connection error" |
| 6 | Removed the redundant `setIsLoading(false)` calls before `return` | Code, same file | `finally` already resets it |

Verification: a throwaway ethers wallet created an account, signed in to the same account again, and was rejected when a different key signed. A dashboard request without a session was redirected (307). Email sign-up returned HTTP 201.

---

## 2. Starting state

- Workspace `/Users/dextonicx/truent` contains the repository `Truent/`, which is a git repo.
- `Truent/` is a Rust workspace (`Cargo.toml`, `crates/`, …) plus a Next.js app in `web/`.
- `web/` was in scope. It had been off-limits until 2026-09-12, when the frontend was brought into scope.
- `web/package.json` scripts:

```json
"dev": "next dev --turbo",
"build": "next build",
"start": "next start",
"worker": "node scripts/scan-worker.mjs",
"lint": "next lint",
"typecheck": "tsc --noEmit",
"test": "node --test tests/*.test.mjs",
"postinstall": "prisma generate"
```

- Relevant dependencies: `next` 14.2.35, `next-auth` ^4.24.14, `ethers` ^6.13.1, `@civic/auth` ^0.15.5, Prisma 7 (client 7.9.1) with `@prisma/adapter-pg`.
- `web/` contained only `.env.example`. There was **no `.env` or `.env.local`**.

---

## 3. Step 1: Running the dev server

The request was "run dev server". The workspace root had no `package.json`, so I looked one level down and found the Next.js app in `Truent/web/`.

```bash
cd /Users/dextonicx/truent/Truent/web && npm run dev   # run in background
```

Output:

```
> truent-web@0.1.0 dev
> next dev --turbo

 ⚠ Port 3000 is in use, trying 3001 instead.
  ▲ Next.js 14.2.35 (turbo)
  - Local:        http://localhost:3001

 ✓ Starting...
 ✓ Compiled in 134ms
 ✓ Ready in 1390ms
```

**Observation:** port 3000 was taken, so Next.js fell back to 3001. Step 7 identifies what held port 3000.

---

## 4. Step 2: Reading the auth design

The second request was "I want the web3wallet sign in and signup to start working."

First I read the standing project rules and confirmed that `web/` is in scope. Then I read `web/AUTH_SETUP.md`, which describes the intended design:

- **Civic Auth** is the primary sign-in (Google, email, passkeys, embedded wallets). Its button is hidden when `NEXT_PUBLIC_CIVIC_CLIENT_ID` is empty.
- **Email / password** uses bcrypt with a constant-time dummy-hash comparison.
- **Web3 wallet** uses MetaMask-style `personal_sign` over a server-issued, single-use nonce.
- **NextAuth 4** owns the session: a JWT cookie with a 7-day lifetime. Every provider ends in the same session.
- **Prisma 7 + PostgreSQL** stores users, scans and subscriptions.

Endpoints relevant to the wallet flow:

| Route | Owner | Purpose |
|---|---|---|
| `POST /api/auth/wallet-nonce` | app | Issue a challenge message for an address |
| `POST /api/auth/callback/wallet` | NextAuth | Verify the signature and create the session |
| `GET /api/auth/session` | NextAuth | Current session |

Required environment variables: `DATABASE_URL`, `NEXTAUTH_URL`, `NEXTAUTH_SECRET`, and optionally `NEXT_PUBLIC_CIVIC_CLIENT_ID`.

---

## 5. Step 3: Reading the wallet code

I searched `app`, `components`, `lib`, `middleware.ts`, `types` and `prisma` for `wallet|nonce|personal_sign|ethereum`. Relevant hits:

- `web/app/api/auth/wallet-nonce/route.ts`: the challenge endpoint
- `web/lib/auth-options.ts`: the NextAuth providers, including `wallet`
- `web/components/ui/AuthModal.tsx`: the client UI and flow
- `web/prisma/schema.prisma`: the `AuthNonce` model
- `web/types/next-auth.d.ts`: session typing (`walletAddress`, `provider`)
- `web/global.d.ts`: the `window.ethereum` typing

### 5.1 Nonce endpoint (`app/api/auth/wallet-nonce/route.ts`)

- Validates `address` against `^0x[a-fA-F0-9]{40}$` with zod, then lowercases it.
- Generates a nonce with `randomBytes(24).toString('hex')`: 48 hex characters, 192 bits.
- Builds the message:
  ```
  Truent sign-in
  Address: <lowercased address>
  Nonce: <48 hex chars>
  ```
- Upserts `AuthNonce { address, nonceHash = sha256(nonce), expiresAt = now + 5 min }`. Only the hash is stored.
- Returns `{ message, expiresIn: 300 }`, or 400 for a bad address and 500 on any other error.

### 5.2 Verification (`lib/auth-options.ts`, `verifyWalletSignature`)

1. Parses the message with a strict anchored regex:
   `^Truent sign-in\nAddress: (0x[a-f0-9]{40})\nNonce: ([a-f0-9]{48})$`
2. Requires the address in the message to equal the claimed address.
3. Loads the `AuthNonce` row for the address. The row must exist, be unexpired, and its hash must match `sha256(nonce)`.
4. `ethers.verifyMessage(message, signature)` recovers the signer. It must equal the address.
5. Deletes the nonce row, which makes the nonce single-use.

The `wallet` provider's `authorize()` then **finds or creates** a user. The user's `email` field holds the lowercased address and the name is `Wallet 0x1234`. **One code path therefore serves both sign-up and sign-in.** No separate wallet sign-up form is needed.

Callbacks: `jwt()` stores `token.id`, `token.provider`, and `token.walletAddress` for wallet logins; `session()` copies them onto `session.user`.

### 5.3 Client (`components/ui/AuthModal.tsx`, before changes)

1. Checks `window.ethereum`.
2. Calls `eth_requestAccounts`.
3. POSTs to `/api/auth/wallet-nonce`.
4. Calls `personal_sign` with `[message, address]`, where `message` is plain text.
5. Calls `signIn('wallet', { address, message, signature, redirect: true, callbackUrl: '/dashboard' })`.

**Assessment:** the protocol was sound. Two client problems needed fixing: `redirect: true` hid failures, and signing plain text worked only with some wallets. Neither explained a complete failure, so the next step was to reproduce it.

---

## 6. Step 4: Reproducing the failure

I probed the running server directly:

```bash
curl -X POST localhost:3001/api/auth/wallet-nonce \
  -H 'content-type: application/json' \
  -d '{"address":"0x0000000000000000000000000000000000000001"}'
# {"error":"Unable to create nonce"}   HTTP 500

curl localhost:3001/api/auth/providers
# civic, credentials, wallet all registered.   HTTP 200
```

Server log for the 500 (trimmed):

```
Wallet nonce creation failed PrismaClientKnownRequestError:
Invalid `prisma.authNonce.upsert()` invocation
  ...
  code: 'ECONNREFUSED',
  meta: { modelName: 'AuthNonce' },
  clientVersion: '7.9.1'
}
 POST /api/auth/wallet-nonce 500 in 277ms
```

**Root cause confirmed:** Prisma could not open a TCP connection to Postgres, so the wallet flow failed at its first server step. Email sign-in and sign-up hit the same database and would fail the same way.

---

## 7. Step 5: Finding the database

I read `web/lib/prisma.ts`, `web/prisma.config.ts` and `web/compose.yaml`.

- `lib/prisma.ts` builds `PrismaClient` with `PrismaPg`. When `DATABASE_URL` is unset it falls back to `postgresql://postgres:postgres@localhost:5432/truent`, so with no env file the app was trying `localhost:5432`.
  - The comment at the top of `lib/prisma.ts` still says the schema provider is `sqlite`. It is out of date: the datasource reports PostgreSQL. I left it unchanged because it wasn't needed for this task.
- `prisma.config.ts` loads `.env` (via `dotenv/config`, **not** `.env.local`) and uses the same fallback URL.
- `compose.yaml` defines a `postgres:17-alpine` service with database `truent`, user `truent`, a local-only password, and port `5432:5432`.

What was available on the machine:

```
docker:      installed, daemon NOT running
psql/postgres/pg_ctl: /opt/homebrew/bin (Homebrew)
port 5432:   nothing listening
brew services: postgresql@16   none      (installed, stopped)
data dir:    /opt/homebrew/var/postgresql@16 exists
version:     postgres (PostgreSQL) 16.15 (Homebrew)
```

**Decision:** start the Postgres that was already installed rather than start Docker and pull a new image. The existing data directory might already hold the `truent` database.

---

## 8. Step 6: Starting Postgres and checking migrations

```bash
brew services start postgresql@16
# ==> Successfully started `postgresql@16` (label: sh.brew.postgresql@16)

pg_isready -h localhost -p 5432
# localhost:5432 - no response        (first poll, still starting)
# localhost:5432 - accepting connections
```

Role and database check:

```sql
select rolname from pg_roles where rolname in ('truent','postgres');   -- truent
select datname from pg_database where datname='truent';                -- truent
```

Both existed. Login with the compose credentials:

```bash
PGPASSWORD=<compose password> psql -h localhost -U truent -d truent -tAc 'select 1'
# 1
```

Migration status (with `DATABASE_URL` passed inline, because `prisma.config.ts` does not read `.env.local`):

```
Datasource "db": PostgreSQL database "truent", schema "public" at "localhost:5432"
4 migrations found in prisma/migrations
Database schema is up to date!
```

The four migrations:

| Migration | Adds |
|---|---|
| `20260621132501_init` | Base NextAuth tables (`User`, `Account`, `Session`, …) |
| `20260806000000_scans_billing` | Scans, billing, and the `AuthNonce` table plus its `expiresAt` index |
| `20260912160000_engine_fields` | Engine-related scan fields |
| `20260914120000_civic_id` | Nullable, unique `User.civicId` |

**Outcome:** no migration was needed. The database had simply not been started.

---

## 9. Step 7: Port 3000 and the environment file

### 9.1 Port 3000

```
PID    STARTED                    COMMAND
58549  Sat Sep 19 05:08:14 2026   next-server (v15.5.25)
cwd:   /Users/dextonicx/netfall/Netfall
```

Port 3000 was held by a **different project (Netfall)**, so I did not stop it. Truent runs on 3001, and `NEXTAUTH_URL` has to match that. Otherwise NextAuth builds callback URLs for port 3000, which point at Netfall.

### 9.2 `web/.env.local`

I created the file only after confirming it did not already exist. I wrote it with `umask 077` so only the owner can read it:

```dotenv
# Local development only. Not committed (.env*.local is gitignored).
DATABASE_URL=postgresql://truent:<compose password>@localhost:5432/truent
NEXTAUTH_URL=http://localhost:3001
NEXTAUTH_SECRET=<generated with `openssl rand -base64 32`, never printed>
NEXT_PUBLIC_CIVIC_CLIENT_ID=
```

I confirmed that both `.gitignore` files cover it:

- `web/.gitignore:26` → `.env*.local`
- `.gitignore:27` → `.env.local`

`NEXT_PUBLIC_CIVIC_CLIENT_ID` is left empty on purpose: there is no Civic app for localhost:3001, and an empty value hides the Civic button cleanly.

---

## 10. Step 8: Middleware and CSP review

Before touching the client code, I checked two layers that could block the flow in the browser.

### 10.1 `web/middleware.ts`

```ts
matcher: ['/dashboard/:path*', '/reports/:path*', '/api/auth/session'],
authorized: ({ token }) => !!token,
```

`/api/auth/session` is in the matcher, so it could have redirected signed-out users and broken `useSession()`. I tested it:

```
GET /api/auth/session  →  HTTP 200, no redirect
```

NextAuth's `withAuth` lets its own `/api/auth/*` routes through, so this doesn't break anything. I left it alone.

### 10.2 Content-Security-Policy (`web/next.config.js`)

```
default-src 'self'
script-src 'self' 'unsafe-inline' https://js.stripe.com
connect-src 'self' https://api.stripe.com https://auth.civic.com
...
```

The wallet flow only makes same-origin requests: the nonce endpoint and the NextAuth callback. `window.ethereum` is injected by the browser extension and isn't subject to `connect-src`. **The CSP doesn't block the wallet flow.** No change.

### 10.3 `web/global.d.ts`

`window.ethereum` is typed with `request({ method, params })`, which is enough for `eth_requestAccounts` and `personal_sign`. No change.

---

## 11. Step 9: Client fixes in AuthModal

File: `web/components/ui/AuthModal.tsx`. The full diff is in [section 18](#18-full-diff).

### 11.1 `redirect: true` → `redirect: false` (wallet, email sign-in, email sign-up)

**Problem.** With `redirect: true`, NextAuth navigates away whether the login succeeds or not. A failed credentials login goes to the configured sign-in page (`pages.signIn: '/'`) with `?error=CredentialsSignin`. The modal's `setError(...)` branch never ran, so a bad signature or wrong password looked like the modal had simply closed.

**Fix.** Call `signIn(..., { redirect: false })`, check the result, and navigate only on success:

```ts
if (!result?.ok || result.error) {
  setError('Wallet signature could not be verified. Please try again.')
  return
}
window.location.href = result.url || '/dashboard'
```

`result.error` is checked as well as `result.ok` because NextAuth 4 can return `ok: true` with an `error` for credentials providers.

I used a full navigation (`window.location.href`) rather than `router.push` so the dashboard loads with the new session cookie and the middleware sees it. The existing Civic handler already did this.

### 11.2 Hex-encoding the `personal_sign` payload

**Problem.** Plain-text `personal_sign` works in MetaMask. Several other wallets expect the data parameter to be `0x`-prefixed hex and fail or show unreadable text otherwise.

**Fix.** A small module-level helper, with no new dependency and no `ethers` in the client bundle:

```ts
function toHex(text: string): string {
  return '0x' + Array.from(new TextEncoder().encode(text), (b) => b.toString(16).padStart(2, '0')).join('')
}
```

```ts
params: [toHex(message), address],
```

**Why the server needed no change:** `personal_sign` signs the underlying bytes with the EIP-191 prefix (`"\x19Ethereum Signed Message:\n" + len + bytes`). The hex string decodes to the same UTF-8 bytes as the plain message. The server's `ethers.verifyMessage(message, signature)` hashes those same UTF-8 bytes, so both forms produce the same digest. MetaMask still displays the decoded text to the user.

### 11.3 Handling "user rejected"

```ts
if ((err as { code?: number })?.code === 4001) {
  setError('Request rejected in your wallet.')
} else {
  setError('Wallet connection error. Please try again.')
}
```

`4001` is the standard EIP-1193 "User Rejected Request" code. It is raised whether the user cancels the connection prompt or the signature prompt.

### 11.4 Smaller cleanups inside the wallet handler

- Removed the `setIsLoading(false)` calls before early `return`s. The `finally` block already resets loading state.
- A failed nonce request now shows "Could not start wallet sign-in. Please try again." instead of throwing into the generic handler.
- Clearer "no wallet" message: "No Web3 wallet detected. Install MetaMask (or another browser wallet) and reload." The old text suggested WalletConnect, which this modal doesn't support.
- Typed `accounts` as `string[]`.
- Added a comment explaining that one button covers both sign-in and sign-up.

### 11.5 What I deliberately left alone

- **Server-side wallet code.** It already verified correctly.
- **The middleware matcher.** It was verified harmless (§10.1).
- **Multiple injected wallets (`window.ethereum.providers`, EIP-6963).** This is a feature, not a fix. See the open items.
- **The stale `sqlite` comment in `lib/prisma.ts`.** Not related to this task.

---

## 12. Step 10: Restart and typecheck

Environment changes need a restart. Next.js reads `.env.local` at startup, and in dev the Prisma client is cached on `globalThis`. After adding the env file and before restarting, the nonce endpoint still returned 500, which confirmed this.

1. Stopped the Truent dev server on 3001 only, leaving Netfall on 3000 running, and confirmed nothing was listening on 3001.
2. Started `npm run dev` again in the background. It came up on `http://localhost:3001`.
3. Typecheck:
   ```bash
   cd web && npx tsc --noEmit
   ```
   No output: **clean**.

---

## 13. Step 11: End-to-end verification

Instead of only reasoning about the code, I drove the real HTTP flow against the running server with a Node script in the session scratchpad (`wallet-e2e.mjs`), not in the repository. The script uses the project's own `ethers`.

What it does for each login:

1. `POST /api/auth/wallet-nonce` with the wallet's address, then reads `message`.
2. Signs `ethers.toUtf8Bytes(message)`, the same bytes the modal now sends in hex.
3. `GET /api/auth/csrf` to get the CSRF token and cookie.
4. `POST /api/auth/callback/wallet` as form data (`address`, `message`, `signature`, `csrfToken`, `callbackUrl`, `json=true`), keeping cookies in a jar.
5. `GET /api/auth/session` with the cookies, then reports the session.

Scenarios and results:

```
signup (new wallet):    signed in: provider=wallet wallet=0xe0c34949c7c730e06e74c42a791eb9c6a6aab644 id=cmufr7zmg0000d24ai23ffyfl
signin (same wallet):   signed in: provider=wallet wallet=0xe0c34949c7c730e06e74c42a791eb9c6a6aab644 id=cmufr7zmg0000d24ai23ffyfl
wrong signer rejected:  no session
dashboard w/o session:  HTTP 307
```

What each line shows:

| Scenario | Shows |
|---|---|
| Sign-up, new wallet | Nonce issued and stored, signature recovered, **user created**, JWT session set with `provider=wallet` and `walletAddress` |
| Sign-in, same wallet | **Same user id**: the existing account was found, not duplicated. A fresh nonce was needed, since the first one was deleted on use |
| Wrong signer | A valid-format signature from a different key is **rejected**, and no session is set |
| Dashboard without a session | The middleware redirects (307) an unauthenticated request for `/dashboard` |

**Not covered by the script:** clicking through the modal in a real browser with a wallet extension. The script signed the same bytes and posted the same fields as the modal, but the browser path, including the wallet's hex handling, still needs one manual click-through.

---

## 14. Step 12: Email sign-up check

Email sign-up used the same database, so I checked that it now works too:

```bash
curl -X POST localhost:3001/api/auth/signup \
  -H 'content-type: application/json' \
  -d '{"name":"E2E","email":"e2e-<timestamp>@example.test","password":"<test password>"}'
```

```
{"id":"cmufr85700001d24aikud8qbj","name":"E2E","email":"e2e-1790267802@example.test",
 "emailVerified":null,"civicId":null,"image":null, ...}   HTTP 201
```

The response doesn't include the password hash. The server log showed no errors apart from the intentional wrong-signer rejection.

---

## 15. Step 13: Cleanup attempt

I tried to:

1. delete the two test users (`cmufr7zmg0000d24ai23ffyfl`, `cmufr85700001d24aikud8qbj`) from the local database, and
2. update a stale line in my own notes index.

**The command was blocked by the permission system and not run.** I didn't retry it another way. The two test accounts are still in the **local** dev database. They're harmless, and removing them is left to you (see §21).

---

## 16. How wallet authentication works

```
Browser (AuthModal)                  Next.js server                          Postgres
───────────────────                  ──────────────                          ────────
click "Web3 Wallet"
eth_requestAccounts ──► wallet
        ◄── [address]
POST /api/auth/wallet-nonce {address} ──►
                                     validate + lowercase address
                                     nonce = randomBytes(24) (hex)
                                     upsert AuthNonce(address,
                                       sha256(nonce), now+5m)  ───────────► row
        ◄── {message, expiresIn:300}
personal_sign(hex(message), address) ──► wallet (user approves)
        ◄── signature
signIn('wallet', {address, message,
  signature, redirect:false}) ──► POST /api/auth/callback/wallet
                                     regex-parse message
                                     address in message == address
                                     load AuthNonce ◄────────────────────── row
                                     unexpired && hash matches
                                     ethers.verifyMessage → signer == address
                                     delete AuthNonce ─────────────────────► gone
                                     find user by email=address
                                       or create "Wallet 0x1234" ─────────► User
                                     issue JWT cookie (7 days)
        ◄── {ok, url}
window.location = /dashboard ──► middleware: token present → allowed
```

---

## 17. Security properties checked

| Property | How it is enforced | Checked |
|---|---|---|
| Signature proves control of the address | `ethers.verifyMessage` recovers the signer, which must equal the address | Yes: wrong signer rejected |
| Replay protection | Nonce row deleted on successful verification; a later login needs a new nonce | Indirectly: second login needed and got a fresh nonce |
| Expiry | `expiresAt = now + 5 min`, checked on verify | By reading the code |
| No nonce disclosure from the DB | Only `sha256(nonce)` is stored | By reading the code |
| Message cannot be swapped | Anchored regex over the exact message format; address must match | By reading the code |
| CSRF on the callback | NextAuth CSRF token and cookie required | Yes: the script had to fetch `/api/auth/csrf` |
| Secrets not exposed | `NEXTAUTH_SECRET` generated into a mode-600 gitignored file, never printed | Yes |
| Protected routes | Middleware redirects `/dashboard` without a token | Yes: HTTP 307 |

**Known limitation, not introduced by this change:** a wallet user's address is stored in the `User.email` column. A wallet account and an email account can't collide, because an address is not a valid email, but the design is unusual. A dedicated `walletAddress` column on `User` would be cleaner. See §21.

---

## 18. Full diff

`git diff --stat`:

```
 web/components/ui/AuthModal.tsx | 58 ++++++++++++++++++++++++++---------------
 1 file changed, 37 insertions(+), 21 deletions(-)
```

`web/.env.local` is also new but gitignored, so it doesn't appear in the diff.

```diff
diff --git a/web/components/ui/AuthModal.tsx b/web/components/ui/AuthModal.tsx
index c5a83c3..9e1f891 100644
--- a/web/components/ui/AuthModal.tsx
+++ b/web/components/ui/AuthModal.tsx
@@ -8,6 +8,10 @@ import { CIVIC_ENABLED } from '@/lib/civic'
 import { Button } from './Button'
 import { useEscapeKey } from '@/components/hooks/useEscapeKey'
 
+function toHex(text: string): string {
+  return '0x' + Array.from(new TextEncoder().encode(text), (b) => b.toString(16).padStart(2, '0')).join('')
+}
+
 interface AuthModalProps {
   isOpen: boolean
   onClose: () => void
@@ -35,13 +39,15 @@ export function AuthModal({ isOpen, onClose, defaultTab = 'signin' }: AuthModalP
       const result = await signIn('credentials', {
         email,
         password,
-        redirect: true,
+        redirect: false,
         callbackUrl: '/dashboard',
       })
-      
-      if (!result?.ok) {
+
+      if (!result?.ok || result.error) {
         setError('Invalid email or password')
+        return
       }
+      window.location.href = result.url || '/dashboard'
     } catch (err) {
       setError('An error occurred. Please try again.')
       console.error('Sign in error:', err)
@@ -74,13 +80,15 @@ export function AuthModal({ isOpen, onClose, defaultTab = 'signin' }: AuthModalP
       const signInResult = await signIn('credentials', {
         email,
         password,
-        redirect: true,
+        redirect: false,
         callbackUrl: '/dashboard',
       })
 
-      if (!signInResult?.ok) {
+      if (!signInResult?.ok || signInResult.error) {
         setError('Account created but sign in failed. Please try signing in.')
+        return
       }
+      window.location.href = signInResult.url || '/dashboard'
     } catch (err) {
       setError('An error occurred. Please try again.')
       console.error('Sign up error:', err)
@@ -112,25 +120,22 @@ export function AuthModal({ isOpen, onClose, defaultTab = 'signin' }: AuthModalP
     }
   }
 
+  // One button covers both sign-in and sign-up: the wallet provider creates the
+  // account on the first verified signature for an address.
   const handleWalletConnect = async () => {
     setIsLoading(true)
     setError(null)
     try {
-      // Request wallet connection (MetaMask, WalletConnect, etc.)
       if (!window.ethereum) {
-        setError('Web3 wallet not detected. Please install MetaMask or use WalletConnect.')
-        setIsLoading(false)
+        setError('No Web3 wallet detected. Install MetaMask (or another browser wallet) and reload.')
         return
       }
 
-      // Request account access
-      const accounts = await window.ethereum.request({
+      const accounts: string[] = await window.ethereum.request({
         method: 'eth_requestAccounts',
       })
-
       if (!accounts || accounts.length === 0) {
         setError('Wallet connection denied')
-        setIsLoading(false)
         return
       }
 
@@ -140,29 +145,40 @@ export function AuthModal({ isOpen, onClose, defaultTab = 'signin' }: AuthModalP
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ address }),
       })
-      if (!nonceResponse.ok) throw new Error('Unable to create wallet challenge')
+      if (!nonceResponse.ok) {
+        setError('Could not start wallet sign-in. Please try again.')
+        return
+      }
       const { message } = await nonceResponse.json()
 
-      // Request signature
+      // Hex-encode the message: MetaMask accepts plain text, but several other
+      // wallets only accept personal_sign data as 0x-prefixed hex.
       const signature = await window.ethereum.request({
         method: 'personal_sign',
-        params: [message, address],
+        params: [toHex(message), address],
       })
 
-      // Sign in with wallet
+      // redirect: false so a rejected signature surfaces here instead of
+      // bouncing the page to /?error=CredentialsSignin.
       const result = await signIn('wallet', {
         address,
         message,
         signature,
-        redirect: true,
+        redirect: false,
         callbackUrl: '/dashboard',
       })
-
-      if (!result?.ok) {
-        setError('Wallet authentication failed')
+      if (!result?.ok || result.error) {
+        setError('Wallet signature could not be verified. Please try again.')
+        return
       }
+      window.location.href = result.url || '/dashboard'
     } catch (err) {
-      setError('Wallet connection error. Please try again.')
+      // EIP-1193 code 4001: the user rejected the request in their wallet.
+      if ((err as { code?: number })?.code === 4001) {
+        setError('Request rejected in your wallet.')
+      } else {
+        setError('Wallet connection error. Please try again.')
+      }
       console.error('Wallet error:', err)
     } finally {
       setIsLoading(false)
```

---

## 19. Operating the local setup

```bash
# Database (Homebrew service; starts at login now)
brew services start postgresql@16
brew services stop postgresql@16
pg_isready -h localhost -p 5432

# Dev server (runs on 3001 while Netfall holds 3000)
cd web && npm run dev

# Migrations: prisma.config.ts reads .env, not .env.local, so pass the URL
cd web && DATABASE_URL='postgresql://truent:<password>@localhost:5432/truent' npx prisma migrate status

# Typecheck
cd web && npx tsc --noEmit
```

If Truent moves back to port 3000 (for example, once Netfall is stopped), change `NEXTAUTH_URL` in `web/.env.local` to `http://localhost:3000` and restart. NextAuth builds its callback URLs from that value.

Manual browser check:

1. Open http://localhost:3001 and open the auth modal.
2. Click **Web3 Wallet**, approve the connection, and approve the signature. The message shows "Truent sign-in", your address and a nonce.
3. You should land on `/dashboard`.
4. Repeat, but reject the signature. The modal should say "Request rejected in your wallet."

---

## 20. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "Could not start wallet sign-in" | Nonce endpoint 500, usually because the DB is down | `brew services start postgresql@16`; check the dev server log for `ECONNREFUSED` |
| Nonce still 500 after fixing env | Server started before the env changed; Prisma client cached | Restart `npm run dev` |
| "Wallet signature could not be verified" | Nonce expired (>5 min), reused, or signed by a different account than the one connected | Click again for a fresh nonce; make sure the wallet's active account matches |
| Redirected to port 3000 / Netfall after login | `NEXTAUTH_URL` doesn't match the real port | Set it to the port Next.js printed and restart |
| "No Web3 wallet detected" | No injected provider | Install or enable a browser wallet and reload |
| `prisma migrate` connects to the wrong DB | `prisma.config.ts` reads `.env`, not `.env.local` | Pass `DATABASE_URL=` inline |
| Civic button missing | `NEXT_PUBLIC_CIVIC_CLIENT_ID` empty | Expected locally; set it and rebuild to enable |

---

## 21. Open items

1. **Manual browser test with a real wallet.** Not done by me; this is the one path the script couldn't cover.
2. **Two test users in the local database.** Cleanup was blocked. To remove them:
   ```sql
   DELETE FROM "User" WHERE id IN ('cmufr7zmg0000d24ai23ffyfl', 'cmufr85700001d24aikud8qbj');
   ```
3. **Stale comment in `web/lib/prisma.ts`.** It says the schema is `sqlite`, but it is PostgreSQL.
4. **Optional:** support multiple injected wallets (EIP-6963 discovery) instead of whichever extension owns `window.ethereum`.
5. **Optional:** move wallet identity from `User.email` into a dedicated `walletAddress` column.
6. **Optional:** add a `node --test` case for `verifyWalletSignature`, based on the e2e script (fresh nonce, wrong signer, expired, replay).
7. **Nothing is committed.** Review `git diff web/components/ui/AuthModal.tsx` and commit when ready.
