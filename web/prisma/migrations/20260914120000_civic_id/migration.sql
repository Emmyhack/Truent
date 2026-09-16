-- Link application users to their Civic Auth identity.
ALTER TABLE "User" ADD COLUMN "civicId" TEXT;
CREATE UNIQUE INDEX "User_civicId_key" ON "User"("civicId");
