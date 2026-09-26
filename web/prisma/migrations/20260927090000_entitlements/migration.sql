-- Entitlements: a real trial on every new account, metered monthly usage, and
-- one-off scan credits that sit beside the subscription quota.
ALTER TABLE "User" ADD COLUMN "trialEndsAt" TIMESTAMP(3);

CREATE TABLE "Usage" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "period" TEXT NOT NULL,
    "scans" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "Usage_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "Usage_userId_period_key" ON "Usage"("userId", "period");
ALTER TABLE "Usage" ADD CONSTRAINT "Usage_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "ScanCredit" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "product" TEXT NOT NULL,
    "granted" INTEGER NOT NULL,
    "remaining" INTEGER NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ScanCredit_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "ScanCredit_source_key" ON "ScanCredit"("source");
CREATE INDEX "ScanCredit_userId_idx" ON "ScanCredit"("userId");
ALTER TABLE "ScanCredit" ADD CONSTRAINT "ScanCredit_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
