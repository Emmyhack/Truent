#!/usr/bin/env bash
# Backup → destroy → restore drill for the web application's PostgreSQL
# database (web/prisma). Runs in CI against a throwaway Postgres and records
# RTO (time to restore) and RPO (rows lost) — the two numbers the
# disaster-recovery runbook promises.
#
# Requires: DATABASE_URL, psql, pg_dump, pg_restore, node (for prisma).
#   tests/dr/backup-restore-drill.sh
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required, e.g. postgresql://postgres:postgres@localhost:5432/truent}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
RTO_TARGET_S="${RTO_TARGET_S:-300}"

echo "▶ 1. apply migrations (schema as shipped)"
( cd web && npx --yes prisma migrate deploy --schema prisma/schema.prisma )

echo "▶ 2. seed known rows"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q <<'SQL'
CREATE TABLE IF NOT EXISTS dr_drill (id serial PRIMARY KEY, payload text NOT NULL, created_at timestamptz DEFAULT now());
INSERT INTO dr_drill (payload) SELECT 'row-' || g FROM generate_series(1, 1000) g;
SQL
BEFORE=$(psql "$DATABASE_URL" -tAc "SELECT count(*) FROM dr_drill")
echo "  rows before backup: $BEFORE"

echo "▶ 3. backup"
pg_dump --format=custom --no-owner "$DATABASE_URL" > "$WORK/backup.dump"
sha256sum "$WORK/backup.dump" | tee "$WORK/backup.sha256"

echo "▶ 4. write after the backup (this is the RPO window) and then destroy"
psql "$DATABASE_URL" -q -c "INSERT INTO dr_drill (payload) VALUES ('after-backup')"
psql "$DATABASE_URL" -q -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
echo "  schema dropped"

echo "▶ 5. restore (RTO clock starts)"
START=$(date +%s)
sha256sum -c "$WORK/backup.sha256"
pg_restore --no-owner --dbname="$DATABASE_URL" "$WORK/backup.dump"
( cd web && npx --yes prisma migrate deploy --schema prisma/schema.prisma )   # idempotent: proves the restored schema matches
END=$(date +%s)
RTO=$((END - START))

echo "▶ 6. verify integrity"
AFTER=$(psql "$DATABASE_URL" -tAc "SELECT count(*) FROM dr_drill")
LOST=$(( BEFORE + 1 - AFTER ))
echo "  rows after restore: $AFTER (RPO: $LOST row(s) written after the backup were lost, as expected)"
echo "  RTO: ${RTO}s (target ${RTO_TARGET_S}s)"

[ "$AFTER" -eq "$BEFORE" ] || { echo "✗ restore lost rows that were in the backup"; exit 1; }
[ "$RTO" -le "$RTO_TARGET_S" ] || { echo "✗ restore exceeded RTO target"; exit 1; }
echo "✓ backup/restore drill passed — record RTO=${RTO}s RPO=${LOST} row(s) in docs/runbooks/disaster-recovery.md"
