import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth-options'
import { ethers } from 'ethers'
import { z } from 'zod'

const WALLET_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/
const TX_HASH_REGEX = /^0x[a-fA-F0-9]{64}$/

const createPaymentSchema = z.object({
  planId: z.string().min(1, 'planId is required'),
  planName: z.string().min(1, 'planName is required'),
  priceUSD: z.number().positive('priceUSD must be greater than 0'),
  currency: z.string().optional(),
  walletAddress: z.string().regex(WALLET_ADDRESS_REGEX, 'Invalid wallet address'),
})

const verifyPaymentSchema = z.object({
  transactionHash: z.string().regex(TX_HASH_REGEX, 'Invalid transaction hash'),
  walletAddress: z.string().regex(WALLET_ADDRESS_REGEX, 'Invalid wallet address'),
  planId: z.string().min(1, 'planId is required'),
})

/**
 * Creates a crypto payment request for subscription
 * Supports ETH, USDC, and other ERC-20 tokens
 * Verified directly against an Ethereum JSON-RPC endpoint (ETHEREUM_RPC_URL);
 * no payment-gateway account is involved.
 */
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)
    if (!session?.user?.email) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const { planId, planName, priceUSD, walletAddress } = createPaymentSchema.parse(
      await request.json()
    )

    // Convert USD price to crypto amounts
    // These are approximate conversions and should be updated dynamically
    const cryptoPrices = {
      ETH: priceUSD * 0.00052, // Approximate ETH price conversion
      USDC: priceUSD,
      USDT: priceUSD,
      DAI: priceUSD,
    }

    // Generate payment request
    const paymentRequest = {
      id: `payment_${Date.now()}`,
      planId,
      planName,
      priceUSD,
      cryptoPrices,
      walletAddress,
      chain: 'ethereum', // or polygon, arbitrum, etc.
      tokens: ['ETH', 'USDC', 'USDT', 'DAI'],
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      status: 'pending',
    }

    // Store payment request in database (optional)
    // await storePaymentRequest(paymentRequest)

    return NextResponse.json(paymentRequest, { status: 200 })
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.issues[0].message },
        { status: 400 }
      )
    }

    console.error('Crypto payment error:', error)
    return NextResponse.json(
      { error: 'Payment request generation failed' },
      { status: 500 }
    )
  }
}

/**
 * Verify crypto payment transaction
 */
export async function PATCH(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)
    if (!session?.user?.email) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const { transactionHash, walletAddress, planId } = verifyPaymentSchema.parse(
      await request.json()
    )

    // Verify transaction on blockchain
    // This would check the actual blockchain for the transaction
    // Using Alchemy, Etherscan API, or similar

    // For now, return a mock response
    const isValid = await verifyBlockchainTransaction(transactionHash, walletAddress)

    if (!isValid) {
      return NextResponse.json(
        { error: 'Transaction verification failed' },
        { status: 400 }
      )
    }

    // Update user subscription in database
    // await updateUserSubscription(session.user.email, planId)

    return NextResponse.json(
      { success: true, message: 'Payment confirmed' },
      { status: 200 }
    )
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.issues[0].message },
        { status: 400 }
      )
    }

    console.error('Transaction verification error:', error)
    return NextResponse.json(
      { error: 'Verification failed' },
      { status: 500 }
    )
  }
}

/**
 * Verify a crypto payment transaction on-chain.
 *
 * Fails closed: if the RPC endpoint or receiver address isn't configured, this
 * returns false rather than approving the payment. A payment gate must never
 * default to "approved" when unconfigured.
 */
async function verifyBlockchainTransaction(
  transactionHash: string,
  walletAddress: string
): Promise<boolean> {
  const rpcUrl = process.env.ETHEREUM_RPC_URL
  const receiverAddress = process.env.PAYMENT_RECEIVER_ADDRESS

  if (!rpcUrl || !receiverAddress) {
    console.error(
      'Crypto payment verification is not configured (ETHEREUM_RPC_URL / PAYMENT_RECEIVER_ADDRESS missing)'
    )
    return false
  }

  if (!/^0x([A-Fa-f0-9]{64})$/.test(transactionHash)) {
    return false
  }

  try {
    const provider = new ethers.JsonRpcProvider(rpcUrl)
    const receipt = await provider.getTransactionReceipt(transactionHash)

    if (!receipt || receipt.status !== 1) {
      return false
    }

    if (receipt.to?.toLowerCase() !== receiverAddress.toLowerCase()) {
      return false
    }

    const tx = await provider.getTransaction(transactionHash)
    if (!tx || tx.from.toLowerCase() !== walletAddress.toLowerCase()) {
      return false
    }

    // NOTE: this confirms the transaction succeeded and moved funds between the
    // claimed wallet and receiver address, but does not yet verify the paid
    // amount/token matches the invoice (ERC-20 token transfers require decoding
    // the Transfer event log, not just the native tx value). Until that's added,
    // treat this as "a real transaction between these two addresses happened",
    // not "the correct amount was paid".
    const confirmations = await receipt.confirmations()
    return confirmations >= 1
  } catch (error) {
    console.error('Blockchain verification error:', error)
    return false
  }
}
