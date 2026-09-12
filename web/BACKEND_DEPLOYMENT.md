# Backend deployment

The web backend is implemented as Next.js route handlers backed by Prisma. It
stores users, database sessions, scans, findings, subscriptions, and payment
records. Every scan/report query is scoped to the authenticated user.

## Required production configuration

- `DATABASE_URL`: a PostgreSQL connection string. Use separate application and
  migration credentials in production where the platform supports it.
- `TRUENT_BINARY`: absolute path to the prebuilt `truent` CLI executable used by
  scan workers.
- `NEXTAUTH_URL` and a randomly generated `NEXTAUTH_SECRET`.
- OAuth credentials for each enabled provider.
- `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`. Configure Stripe to deliver
  `checkout.session.completed`, `customer.subscription.updated`, and
  `customer.subscription.deleted` to `/api/payment/webhook`.

The site's detector library, docs and counts come from `lib/catalog.json`; regenerate it after upgrading the binary with `TRUENT_BINARY=/path/to/truent node scripts/sync-catalog.mjs`.

Deploy migrations before starting an application release:

```bash
npx prisma migrate deploy
npm run build
npm start
```

For local development, `docker compose up -d postgres` starts the database in
`compose.yaml`; set `DATABASE_URL=postgresql://truent:truent-local-only@localhost:5432/truent`.

Run at least one independent worker process alongside the web process:

```bash
npm run worker
```

Workers claim jobs atomically with `FOR UPDATE SKIP LOCKED`; multiple replicas
can run concurrently. Submitted source is removed from PostgreSQL as soon as a
scan succeeds or permanently fails. Configure worker CPU/memory limits and run
the binary inside a container or sandbox with no cloud metadata access.

The crypto payment route remains fail-closed and must not be used to provision
subscriptions until invoice amount and ERC-20 transfer verification are added.
GitHub repository scans remain disabled until the GitHub App installation/token
flow is implemented; direct code and file scans are available now.

## API surface

- `POST /api/analyze`: authenticated asynchronous scan submission and durable quotas. `language` is one of solidity, rust, soroban, move, python, javascript, typescript, go, shell, dockerfile, terraform, yaml; the worker writes the source under the file name that language's detectors classify by and runs `truent scan --chain <engine> --output json`.
- `POST /api/auth/wallet-nonce`: one-time, five-minute wallet sign-in challenge.
- `GET /api/scans`: authenticated scan history.
- `GET /api/scans/:id`: owned report and findings.
- `PATCH /api/scans/:id`: update an owned finding's workflow status.
- `POST /api/payment/create-checkout`: server-priced Stripe checkout.
- `POST /api/payment/webhook`: signature-verified subscription provisioning.
