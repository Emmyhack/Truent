import { PrismaClient } from '@prisma/client'
import { PrismaPg } from '@prisma/adapter-pg'
import { randomUUID } from 'node:crypto'
import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { chainFor, fileNameFor, mapFinding } from '../lib/scan-worker-core.mjs'

const execFileAsync = promisify(execFile)
const databaseUrl = process.env.DATABASE_URL
if (!databaseUrl) throw new Error('DATABASE_URL is required')

const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: databaseUrl }) })
const workerId = process.env.HOSTNAME || `worker-${randomUUID()}`
const pollMs = Math.max(Number(process.env.SCAN_WORKER_POLL_MS || 1000), 100)
const maxAttempts = Math.max(Number(process.env.SCAN_MAX_ATTEMPTS || 3), 1)
const binary = process.env.TRUENT_BINARY || 'truent'
let stopping = false

async function claim() {
  await prisma.$executeRaw`
    UPDATE "Scan"
    SET "status" = 'failed', "error" = 'Worker stopped before completing the scan',
        "completedAt" = NOW(), "sourceContent" = NULL, "updatedAt" = NOW()
    WHERE "status" = 'processing' AND "attempts" >= ${maxAttempts}
      AND "claimedAt" < NOW() - INTERVAL '10 minutes'
  `
  const rows = await prisma.$queryRaw`
    UPDATE "Scan"
    SET "status" = 'processing', "claimedAt" = NOW(), "workerId" = ${workerId},
        "attempts" = "attempts" + 1, "updatedAt" = NOW()
    WHERE "id" = (
      SELECT "id" FROM "Scan"
      WHERE "attempts" < ${maxAttempts}
        AND ("status" = 'queued'
         OR ("status" = 'processing' AND "claimedAt" < NOW() - INTERVAL '10 minutes'))
      ORDER BY "createdAt" ASC
      FOR UPDATE SKIP LOCKED LIMIT 1
    )
    RETURNING *
  `
  return rows[0] || null
}

async function run(scan) {
  const chain = chainFor(scan.language)
  const fileName = fileNameFor(scan.language)
  if (!chain || !fileName || !scan.sourceContent) throw new Error('Scan source or language is invalid')

  const work = await mkdtemp(path.join(tmpdir(), 'truent-scan-'))
  // Detectors classify by file name (Dockerfile, *.tf, *.py …), so the
  // submission is written under the name its language expects.
  const source = path.join(work, fileName)
  const started = Date.now()
  try {
    await writeFile(source, scan.sourceContent, { mode: 0o600 })
    let stdout
    try {
      // Run from the scratch directory and pass the bare file name, so the
      // engine reports `app.py:7`, not a temp path the user never sees.
      ;({ stdout } = await execFileAsync(
        binary,
        ['scan', fileName, '--chain', chain, '--output', 'json', '--no-color'],
        { cwd: work, timeout: 5 * 60_000, maxBuffer: 20 * 1024 * 1024, env: { ...process.env, NO_COLOR: '1' } },
      ))
    } catch (error) {
      // The CLI intentionally exits non-zero when a proven finding crosses its
      // gate. That is a valid report, not a worker failure.
      if (!error.stdout) throw error
      stdout = error.stdout
    }
    const report = JSON.parse(stdout)
    if (!Array.isArray(report.violations)) throw new Error('Analyzer returned an invalid report')
    const findings = report.violations.map((finding) => mapFinding(scan.id, finding))
    await prisma.$transaction([
      prisma.finding.deleteMany({ where: { scanId: scan.id } }),
      ...findings.map((data) => prisma.finding.create({ data })),
      prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: 'complete', completedAt: new Date(), durationMs: Date.now() - started,
          error: null, sourceContent: null,
        },
      }),
    ])
  } finally {
    await rm(work, { recursive: true, force: true })
  }
}

async function fail(scan, error) {
  const retry = scan.attempts < maxAttempts
  await prisma.scan.update({
    where: { id: scan.id },
    data: {
      status: retry ? 'queued' : 'failed',
      error: error instanceof Error ? error.message.slice(0, 1000) : 'Analyzer failed',
      claimedAt: null, workerId: null,
      ...(!retry ? { completedAt: new Date(), sourceContent: null } : {}),
    },
  })
}

async function main() {
  while (!stopping) {
    const scan = await claim()
    if (!scan) {
      if (process.argv.includes('--once')) break
      await new Promise((resolve) => setTimeout(resolve, pollMs))
      continue
    }
    try { await run(scan) } catch (error) { console.error(`Scan ${scan.id} failed`, error); await fail(scan, error) }
    if (process.argv.includes('--once')) break
  }
}

for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stopping = true })
main().catch((error) => { console.error('Worker crashed', error); process.exitCode = 1 }).finally(() => prisma.$disconnect())
