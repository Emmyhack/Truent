-- Engine contract fields on Finding: honesty (evidence), exploitability,
-- fix/verify from the exposure table, detector id, engine, CWE, snippet.
ALTER TABLE "Finding"
  ADD COLUMN "invariantId" TEXT,
  ADD COLUMN "chain" TEXT,
  ADD COLUMN "evidence" TEXT NOT NULL DEFAULT 'lead',
  ADD COLUMN "exploitability" TEXT,
  ADD COLUMN "fix" TEXT,
  ADD COLUMN "verify" TEXT,
  ADD COLUMN "cwe" TEXT,
  ADD COLUMN "snippet" TEXT;
