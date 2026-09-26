-- The Move analyzer reports which dialect it parsed; keep it so a Sui finding is tagged Sui, not "move".
ALTER TABLE "Finding" ADD COLUMN "network" TEXT;
