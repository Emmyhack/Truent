# Disaster-recovery runbook

**Scope:** the Truent web application (`web/`, Next.js + Prisma on PostgreSQL)
and the release artifacts (crates.io, npm, GitHub Releases).
**RTO target:** 5 minutes for the database (drilled: see below) · 60 minutes
for the web service (redeploy from a tagged release).
**RPO target:** 15 minutes (automated snapshots every 15 minutes).
**Last drill:** run automatically by `.github/workflows/harness.yml` → `dr-drill`
on every push to `main`; the job log records RTO and RPO for that run.

## What is backed up

| Asset | Mechanism | Where | Retention |
|---|---|---|---|
| PostgreSQL (users, accounts, scans, billing) | provider snapshots every 15 min + nightly `pg_dump --format=custom` | separate region, object-locked bucket | 35 days |
| Prisma migrations | git (`web/prisma/migrations`) | GitHub | forever |
| Release artifacts | GitHub Releases + crates.io + npm (immutable) | — | forever |
| Secrets (DB URL, NextAuth secret, OAuth client secrets) | secret manager with versioning | provider | 90 days of versions |
| Signing identity | GitHub OIDC (keyless, sigstore) | — | n/a — nothing to lose |

## Restore procedure (rehearsed by `tests/dr/backup-restore-drill.sh`)

1. Declare the incident (see `incident-response.md`); put the web service in
   maintenance mode so no writes land on a database that is about to be replaced.
2. Provision a fresh PostgreSQL instance; set `DATABASE_URL` in the secret manager.
3. Verify the backup's checksum, then `pg_restore --no-owner --dbname="$DATABASE_URL" backup.dump`.
4. `cd web && npx prisma migrate deploy` — idempotent; proves the restored
   schema matches the shipped migrations.
5. Integrity: row counts per table against the last known snapshot; billing
   reconciliation (`scans` vs invoices) must balance.
6. Rotate any secret that could have been exposed by the incident; redeploy
   the web service from the last tagged release; remove maintenance mode.
7. Watch error rate and latency for 30 minutes; write the post-mortem.

## Key recovery

There are no long-lived signing keys: releases are attested with GitHub OIDC
(`actions/attest-build-provenance`) and npm `--provenance`. Losing a machine
loses nothing. crates.io / npm publish tokens are scoped, stored in GitHub
Environments, and rotated by `truent-keys` procedure.

## Drill record

| Date | RTO | RPO | Result | Notes |
|---|---|---|---|---|
| (CI writes a line per run to the `dr-drill` job summary) | | | | |
