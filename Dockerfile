# ─────────────────────────────────────────────────────────────────────────────
# Truent — one Dockerfile, four targets, used unchanged from a laptop to a host.
#
#   engine   the Rust CLI, built from this tree (what the worker runs)
#   migrate  applies prisma/migrations, then exits
#   web      the Next.js dashboard (standalone output, non-root)
#   worker   the scan worker: node + the engine binary
#
# Build a target with `docker build --target web .`; docker-compose.yml does it.
# ─────────────────────────────────────────────────────────────────────────────

# ── engine ───────────────────────────────────────────────────────────────────
FROM rust:1-bookworm AS engine
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
# truent-core's build script compiles invariants/*.sinv into the binary; without
# the directory it would silently build an empty registry.
COPY invariants ./invariants
COPY crates ./crates
# Registry and build caches survive between builds; only the binary is copied out.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin truent \
 && install -m 0755 target/release/truent /usr/local/bin/truent

# ── web-build ────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS web-build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY web/package.json web/package-lock.json ./
# The npm cache persists between builds, and a slow link gets patience and
# retries rather than an idle-timeout failure halfway through.
RUN --mount=type=cache,target=/root/.npm \
    npm config set fetch-retries 6 fetch-retry-mintimeout 20000 fetch-retry-maxtimeout 180000 fetch-timeout 900000 maxsockets 4 \
 && for i in 1 2 3 4 5; do npm ci --ignore-scripts --no-audit --no-fund --prefer-offline && break || { echo "npm ci failed (attempt $i), retrying"; sleep 20; }; done \
 && test -d node_modules/next
COPY web ./
# Next.js expects a public/ directory; this project ships none.
RUN mkdir -p public
# Public values are compiled into the bundle; pass them at build time.
ARG NEXT_PUBLIC_CIVIC_CLIENT_ID=""
ARG NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=""
ENV NEXT_PUBLIC_CIVIC_CLIENT_ID=$NEXT_PUBLIC_CIVIC_CLIENT_ID \
    NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=$NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY \
    NEXT_OUTPUT=standalone
# `prisma generate` fetches a small artifact; on a slow link that can reset, so retry.
RUN for i in 1 2 3 4 5; do npx prisma generate && break || { echo "prisma generate failed (attempt $i), retrying"; sleep 15; }; done \
 && npx prisma generate \
 && npx next build

# ── migrate ──────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS migrate
WORKDIR /app
ENV NODE_ENV=production
COPY --from=web-build /app/node_modules ./node_modules
COPY --from=web-build /app/package.json /app/prisma.config.ts ./
COPY --from=web-build /app/prisma ./prisma
USER node
CMD ["npx", "prisma", "migrate", "deploy"]

# ── web ──────────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS web
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
COPY --from=web-build --chown=node:node /app/.next/standalone ./
COPY --from=web-build --chown=node:node /app/.next/static ./.next/static
COPY --from=web-build --chown=node:node /app/public ./public
# The generated Prisma client and its adapter are loaded at runtime, not traced.
COPY --from=web-build --chown=node:node /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=web-build --chown=node:node /app/node_modules/@prisma ./node_modules/@prisma
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]

# ── worker ───────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS worker
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV NODE_ENV=production TRUENT_BINARY=/usr/local/bin/truent
COPY --from=engine /usr/local/bin/truent /usr/local/bin/truent
COPY --from=web-build --chown=node:node /app/node_modules ./node_modules
COPY --from=web-build --chown=node:node /app/package.json ./
COPY --from=web-build --chown=node:node /app/lib/scan-worker-core.mjs ./lib/scan-worker-core.mjs
COPY --from=web-build --chown=node:node /app/scripts/scan-worker.mjs ./scripts/scan-worker.mjs
USER node
CMD ["node", "scripts/scan-worker.mjs"]
