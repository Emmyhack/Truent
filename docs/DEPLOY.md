# Running and deploying Truent

The dashboard is four processes: PostgreSQL, a one-shot migration, the web
app, and the scan worker that runs the engine. `docker-compose.yml` runs all
four from one `Dockerfile`, and the same two files go unchanged from your
laptop to a free always-on VM to a paid host. Nothing here costs money until
the last section.

## 1. On your own machine (free)

Requirements: Docker Desktop.

```bash
cp deploy/env.example .env          # then set POSTGRES_PASSWORD and NEXTAUTH_SECRET
openssl rand -base64 32             # a value for NEXTAUTH_SECRET
docker compose up -d --build        # first build compiles the engine: several minutes
docker compose ps                   # web healthy, worker running, migrate exited 0
open http://localhost:3080
```

Useful commands:

```bash
docker compose logs -f worker       # watch scans run
docker compose exec db psql -U truent truent
docker compose down                 # stop; data stays in the pgdata volume
docker compose down -v              # stop and delete the database
```

The web container answers `/api/health` with `{ ok, db, engine }`; Compose
uses it to decide the app is up.

## 2. A public URL for testers (free, no server, no domain)

Cloudflare's quick tunnel exposes the local stack over HTTPS with no account:

```bash
brew install cloudflared
cloudflared tunnel --url http://localhost:3080
```

It prints an address like `https://<random>.trycloudflare.com`. Put that value
in `.env` as `NEXTAUTH_URL`, run `docker compose up -d web` to restart the app
with it, and share the address. The address changes each time the tunnel
starts; a free Cloudflare account with a named tunnel keeps it stable.

## 3. Always on, still free

Oracle Cloud's Always Free tier gives an ARM VM (up to 4 cores, 24 GB) that
never expires. It asks for a card to verify identity and does not charge for
free-tier resources. On the VM:

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git
sudo usermod -aG docker $USER && newgrp docker
git clone https://github.com/Emmyhack/Truent.git && cd Truent
cp deploy/env.example .env && nano .env      # secrets, NEXTAUTH_URL = the public URL
docker compose up -d --build
```

Open port 80/443 in the VM's security list and put Caddy in front for TLS
(`caddy reverse-proxy --from your.domain --to localhost:3080`), or run
`cloudflared` on the VM exactly as in section 2.

If you would rather not give a card: Koyeb (free web service) plus Neon
(free PostgreSQL) run the same images, with slower cold starts.

## 4. Third-party services in test mode (free)

- **Stripe.** Use test-mode keys in `.env`. Forward webhooks while testing:
  `stripe listen --forward-to localhost:3080/api/payment/webhook`, and put
  the printed signing secret in `STRIPE_WEBHOOK_SECRET`. Test card
  `4242 4242 4242 4242`.
- **Civic.** Create an app at auth.civic.com, register
  `<NEXTAUTH_URL>/api/civic/callback`, set `NEXT_PUBLIC_CIVIC_CLIENT_ID`,
  then rebuild the web image (the id is compiled in): `docker compose up -d --build web`.

## 5. Going live (paid)

The same Compose file runs on any host with Docker. Use a managed PostgreSQL
if you can (set `DATABASE_URL` and drop the `db` service), a real domain with
TLS, live Stripe and Civic keys, and set `NEXTAUTH_URL` to the public origin.
Before announcing, run the engine against the live site and require READY:

```bash
truent probe https://your.domain --authorized
truent release-check --strict
```

## Operations

- **Upgrade:** `git pull && docker compose up -d --build`. Migrations run
  before the new web and worker start.
- **Roll back:** `git checkout <previous tag> && docker compose up -d --build`.
  Migrations are additive; a rollback keeps the columns and ignores them.
- **Back up:** `docker compose exec db pg_dump -U truent truent > backup.sql`.
- **Restore:** `docker compose exec -T db psql -U truent truent < backup.sql`.
- **Rotate a secret:** change it in `.env`, `docker compose up -d`.
- **More scan throughput:** `WORKER_REPLICAS=2` in `.env`; claims are
  row-locked, so workers never process the same scan twice.
