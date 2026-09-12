CREATE TABLE "Scan" (
  "id" TEXT NOT NULL, "userId" TEXT NOT NULL, "projectName" TEXT,
  "sourceType" TEXT NOT NULL DEFAULT 'code', "sourceRef" TEXT, "sourceContent" TEXT,
  "language" TEXT NOT NULL, "status" TEXT NOT NULL DEFAULT 'queued', "error" TEXT,
  "attempts" INTEGER NOT NULL DEFAULT 0, "claimedAt" TIMESTAMP(3), "workerId" TEXT,
  "durationMs" INTEGER, "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "completedAt" TIMESTAMP(3), "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL, CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "Finding" (
  "id" TEXT NOT NULL, "scanId" TEXT NOT NULL, "severity" TEXT NOT NULL,
  "title" TEXT NOT NULL, "description" TEXT NOT NULL, "location" TEXT,
  "line" INTEGER, "impact" TEXT, "recommendation" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'open', "fingerprint" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL, CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "Subscription" (
  "id" TEXT NOT NULL, "userId" TEXT NOT NULL, "provider" TEXT NOT NULL,
  "providerCustomerId" TEXT, "providerSubscriptionId" TEXT, "plan" TEXT NOT NULL,
  "status" TEXT NOT NULL, "currentPeriodEnd" TIMESTAMP(3),
  "cancelAtPeriodEnd" BOOLEAN NOT NULL DEFAULT false,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL, CONSTRAINT "Subscription_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "Payment" (
  "id" TEXT NOT NULL, "userId" TEXT NOT NULL, "provider" TEXT NOT NULL,
  "providerPaymentId" TEXT NOT NULL, "plan" TEXT NOT NULL, "amount" INTEGER NOT NULL,
  "currency" TEXT NOT NULL, "status" TEXT NOT NULL, "walletAddress" TEXT,
  "transactionHash" TEXT, "expiresAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL, CONSTRAINT "Payment_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "AuthNonce" (
  "address" TEXT NOT NULL, "nonceHash" TEXT NOT NULL, "expiresAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AuthNonce_pkey" PRIMARY KEY ("address")
);
CREATE INDEX "Scan_userId_createdAt_idx" ON "Scan"("userId", "createdAt");
CREATE INDEX "Scan_status_idx" ON "Scan"("status");
CREATE UNIQUE INDEX "Finding_scanId_fingerprint_key" ON "Finding"("scanId", "fingerprint");
CREATE INDEX "Finding_scanId_severity_idx" ON "Finding"("scanId", "severity");
CREATE UNIQUE INDEX "Subscription_userId_key" ON "Subscription"("userId");
CREATE UNIQUE INDEX "Subscription_providerSubscriptionId_key" ON "Subscription"("providerSubscriptionId");
CREATE INDEX "Subscription_status_idx" ON "Subscription"("status");
CREATE UNIQUE INDEX "Payment_providerPaymentId_key" ON "Payment"("providerPaymentId");
CREATE UNIQUE INDEX "Payment_transactionHash_key" ON "Payment"("transactionHash");
CREATE INDEX "Payment_userId_createdAt_idx" ON "Payment"("userId", "createdAt");
CREATE INDEX "Payment_status_idx" ON "Payment"("status");
CREATE INDEX "AuthNonce_expiresAt_idx" ON "AuthNonce"("expiresAt");
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Subscription" ADD CONSTRAINT "Subscription_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Payment" ADD CONSTRAINT "Payment_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
