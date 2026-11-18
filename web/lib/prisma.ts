import { PrismaClient } from '@prisma/client'
import { PrismaPg } from '@prisma/adapter-pg'

// Prisma 7 requires an explicit driver adapter. Keep this PostgreSQL adapter in
// sync with the `provider = "postgresql"` datasource in schema.prisma.
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
