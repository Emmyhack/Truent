import { PrismaClient } from '@prisma/client'
import { PrismaPg } from '@prisma/adapter-pg'

// Since Prisma 7, PrismaClient must be constructed with an explicit driver
// adapter (there's no more "resolve automatically from schema.prisma" magic).
// schema.prisma currently declares `provider = "sqlite"`, so this must be a
// SQLite-compatible adapter, not @prisma/adapter-pg (which is installed as a
// dependency but unused today - see prisma.config.ts for the note on what a
// real Postgres migration would require: changing the schema provider and
// regenerating migrations, not just swapping the adapter here).
const prismaClientSingleton = () => {
  // The fallback permits `next build` to statically inspect route modules;
  // deployed processes must always provide DATABASE_URL.
  const url = process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@localhost:5432/truent'
  const adapter = new PrismaPg({ connectionString: url })
  return new PrismaClient({ adapter })
}

declare global {
  var prisma: undefined | ReturnType<typeof prismaClientSingleton>
}

const prisma = globalThis.prisma ?? prismaClientSingleton()

if (process.env.NODE_ENV !== 'production') globalThis.prisma = prisma

export default prisma
