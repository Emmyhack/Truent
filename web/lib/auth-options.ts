import { type NextAuthOptions } from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'
import { PrismaAdapter } from '@next-auth/prisma-adapter'
import { getUser as getCivicUser } from '@civic/auth/nextjs'
import prisma from '@/lib/prisma'
import { CIVIC_ENABLED } from '@/lib/civic'
import { resolveCivicUser } from '@/lib/civic-user'
import { newUserDefaults } from '@/lib/new-user'
import bcrypt from 'bcrypt'
import { ethers } from 'ethers'
import { createHash } from 'crypto'

// A precomputed hash with no matching password, compared against when a user
// isn't found so that bcrypt.compare() always runs and takes roughly the same
// time either way. Without this, an unknown email short-circuits before the
// (comparatively slow) bcrypt.compare call, letting an attacker distinguish
// "wrong password" from "no such account" by response time (email enumeration).
const DUMMY_PASSWORD_HASH = bcrypt.hashSync('truent-timing-safety-dummy', 10)

/**
 * Verify wallet signature for Web3 authentication
 */
async function verifyWalletSignature(
  address: string,
  message: string,
  signature: string
): Promise<boolean> {
  try {
    const normalizedAddress = address.toLowerCase()
    const match = message.match(/^Truent sign-in\nAddress: (0x[a-f0-9]{40})\nNonce: ([a-f0-9]{48})$/)
    if (!match || match[1] !== normalizedAddress) return false
    const challenge = await prisma.authNonce.findUnique({ where: { address: normalizedAddress } })
    if (
      !challenge ||
      challenge.expiresAt <= new Date() ||
      challenge.nonceHash !== createHash('sha256').update(match[2]).digest('hex')
    ) return false
    const recoveredAddress = ethers.verifyMessage(message, signature)
    if (recoveredAddress.toLowerCase() !== normalizedAddress) return false
    await prisma.authNonce.delete({ where: { address: normalizedAddress } })
    return true
  } catch (error) {
    console.error('Wallet signature verification error:', error)
    return false
  }
}

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      id: 'civic',
      name: 'Civic',
      // Nothing is read from the request body. The only input is Civic's own
      // signed session cookie, validated server-side, so a caller cannot mint
      // an application session by posting a made-up profile.
      credentials: {},
      async authorize() {
        if (!CIVIC_ENABLED) return null
        try {
          const civic = await getCivicUser()
          if (!civic?.id) return null
          const user = await resolveCivicUser(civic)
          return { id: user.id, email: user.email, name: user.name, image: user.image }
        } catch (error) {
          console.error('Civic sign-in error:', error)
          return null
        }
      },
    }),
    CredentialsProvider({
      id: 'credentials',
      name: 'Email & Password',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          return null
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
        })

        // Always call bcrypt.compare, even for an unknown email, so response
        // timing doesn't reveal whether the account exists.
        const passwordMatch = await bcrypt.compare(
          credentials.password,
          user?.password || DUMMY_PASSWORD_HASH
        )

        if (!user || !passwordMatch) {
          return null
        }

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          image: user.image,
        }
      },
    }),
    CredentialsProvider({
      id: 'wallet',
      name: 'Web3 Wallet',
      credentials: {
        address: { label: 'Wallet Address', type: 'text' },
        message: { label: 'Message', type: 'text' },
        signature: { label: 'Signature', type: 'text' },
      },
      async authorize(credentials) {
        if (!credentials?.address || !credentials?.message || !credentials?.signature) {
          return null
        }

        // Verify wallet signature
        const isValid = await verifyWalletSignature(
          credentials.address,
          credentials.message,
          credentials.signature
        )

        if (!isValid) {
          return null
        }

        // Find or create user with wallet address
        let user = await prisma.user.findUnique({
          where: { email: credentials.address.toLowerCase() },
        })

        if (!user) {
          user = await prisma.user.create({
            data: {
              email: credentials.address.toLowerCase(),
              name: `Wallet ${credentials.address.slice(0, 6)}`,
              ...newUserDefaults(),
            },
          })
        }

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          image: user.image,
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, account }) {
      if (user) {
        token.id = user.id
      }
      if (account?.provider === 'wallet') {
        token.walletAddress = user?.email
      }
      if (account?.provider) {
        token.provider = account.provider
      }
      return token
    },
    async session({ session, token, user }) {
      if (session.user) {
        session.user.id = user?.id || (token.id as string)
        session.user.walletAddress = token.walletAddress
        session.user.provider = token.provider
      }
      return session
    },
  },
  pages: {
    signIn: '/',
  },
  session: {
    // JWT sessions are required by NextAuth middleware, which runs before the
    // database-backed route handlers and cannot resolve opaque session tokens.
    strategy: 'jwt',
    maxAge: 7 * 24 * 60 * 60, // 7 days (reduced from 30 for security)
  },
}
