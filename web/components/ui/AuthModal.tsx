'use client'

import { useState } from 'react'
import { signIn } from 'next-auth/react'
import { useUser } from '@civic/auth/react'
import { X, Eye, EyeOff, Mail, Lock, User, Wallet, ShieldCheck } from 'lucide-react'
import { CIVIC_ENABLED } from '@/lib/civic'
import { Button } from './Button'
import { useEscapeKey } from '@/components/hooks/useEscapeKey'

function toHex(text: string): string {
  return '0x' + Array.from(new TextEncoder().encode(text), (b) => b.toString(16).padStart(2, '0')).join('')
}

interface AuthModalProps {
  isOpen: boolean
  onClose: () => void
  defaultTab?: 'signin' | 'signup'
}

export function AuthModal({ isOpen, onClose, defaultTab = 'signin' }: AuthModalProps) {
  const [tab, setTab] = useState<'signin' | 'signup'>(defaultTab)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [fullName, setFullName] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const civic = useUser()

  useEscapeKey(isOpen, onClose)

  if (!isOpen) return null

  const handleSignIn = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const result = await signIn('credentials', {
        email,
        password,
        redirect: false,
        callbackUrl: '/dashboard',
      })

      if (!result?.ok || result.error) {
        setError('Invalid email or password')
        return
      }
      window.location.href = result.url || '/dashboard'
    } catch (err) {
      setError('An error occurred. Please try again.')
      console.error('Sign in error:', err)
    } finally {
      setIsLoading(false)
    }
  }

  const handleSignUp = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: fullName,
          email,
          password,
        }),
      })

      if (!response.ok) {
        const data = await response.json()
        setError(data.error || 'Sign up failed')
        return
      }

      // Sign in after successful signup
      const signInResult = await signIn('credentials', {
        email,
        password,
        redirect: false,
        callbackUrl: '/dashboard',
      })

      if (!signInResult?.ok || signInResult.error) {
        setError('Account created but sign in failed. Please try signing in.')
        return
      }
      window.location.href = signInResult.url || '/dashboard'
    } catch (err) {
      setError('An error occurred. Please try again.')
      console.error('Sign up error:', err)
    } finally {
      setIsLoading(false)
    }
  }

  // Civic opens its own modal (Google, email, passkey or wallet). Once Civic
  // has set its session cookie, the NextAuth 'civic' provider reads that cookie
  // server-side and issues the application session — nothing about the
  // identity travels through this client.
  const handleCivicSignIn = async () => {
    setIsLoading(true)
    setError(null)
    try {
      await civic.signIn()
      const result = await signIn('civic', { redirect: false, callbackUrl: '/dashboard' })
      if (!result?.ok) {
        setError('Civic signed you in, but the session could not be created. Please try again.')
        return
      }
      window.location.href = result.url || '/dashboard'
    } catch (err) {
      setError('Civic sign-in was cancelled or failed. Please try again.')
      console.error('Civic sign-in error:', err)
    } finally {
      setIsLoading(false)
    }
  }

  // One button covers both sign-in and sign-up: the wallet provider creates the
  // account on the first verified signature for an address.
  const handleWalletConnect = async () => {
    setIsLoading(true)
    setError(null)
    try {
      if (!window.ethereum) {
        setError('No Web3 wallet detected. Install MetaMask (or another browser wallet) and reload.')
        return
      }

      const accounts: string[] = await window.ethereum.request({
        method: 'eth_requestAccounts',
      })
      if (!accounts || accounts.length === 0) {
        setError('Wallet connection denied')
        return
      }

      const address = accounts[0]
      const nonceResponse = await fetch('/api/auth/wallet-nonce', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address }),
      })
      if (!nonceResponse.ok) {
        setError('Could not start wallet sign-in. Please try again.')
        return
      }
      const { message } = await nonceResponse.json()

      // Hex-encode the message: MetaMask accepts plain text, but several other
      // wallets only accept personal_sign data as 0x-prefixed hex.
      const signature = await window.ethereum.request({
        method: 'personal_sign',
        params: [toHex(message), address],
      })

      // redirect: false so a rejected signature surfaces here instead of
      // bouncing the page to /?error=CredentialsSignin.
      const result = await signIn('wallet', {
        address,
        message,
        signature,
        redirect: false,
        callbackUrl: '/dashboard',
      })
      if (!result?.ok || result.error) {
        setError('Wallet signature could not be verified. Please try again.')
        return
      }
      window.location.href = result.url || '/dashboard'
    } catch (err) {
      // EIP-1193 code 4001: the user rejected the request in their wallet.
      if ((err as { code?: number })?.code === 4001) {
        setError('Request rejected in your wallet.')
      } else {
        setError('Wallet connection error. Please try again.')
      }
      console.error('Wallet error:', err)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-overlay flex items-center justify-center z-50" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
        className="bg-bg rounded-card shadow-2xl w-full max-w-md relative"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close button */}
        <button
          onClick={onClose}
          aria-label="Close dialog"
          className="absolute top-3 right-3 p-2 hover:bg-panel rounded-lg transition"
        >
          <X className="w-5 h-5 text-text" />
        </button>

        {/* Logo / Header */}
        <div className="px-6 pt-6 pb-2">
          <h2 id="auth-modal-title" className="text-2xl font-bold text-text mb-1">Truent</h2>
          <p className="text-sm text-sec">One security engine for contracts, code and infrastructure</p>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-hair px-6">
          <button
            onClick={() => setTab('signin')}
            className={`flex-1 py-4 text-sm font-medium transition ${
              tab === 'signin'
                ? 'text-acc-text border-b-2 border-brand'
                : 'text-sec hover:text-text'
            }`}
          >
            Sign In
          </button>
          <button
            onClick={() => setTab('signup')}
            className={`flex-1 py-4 text-sm font-medium transition ${
              tab === 'signup'
                ? 'text-acc-text border-b-2 border-brand'
                : 'text-sec hover:text-text'
            }`}
          >
            Sign Up
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-6 space-y-4">
          {/* OAuth Buttons */}
          <div className="space-y-2">
            <p className="text-xs text-sec text-center mb-3">
              {CIVIC_ENABLED ? 'Google, email, passkey or wallet' : 'Quick sign in'}
            </p>
            {CIVIC_ENABLED && (
              <Button
                className="w-full justify-center gap-2"
                onClick={handleCivicSignIn}
                disabled={isLoading || civic.isLoading}
              >
                <ShieldCheck className="w-4 h-4" />
                Continue with Civic
              </Button>
            )}
            <Button
              variant="secondary"
              className="w-full justify-center gap-2"
              onClick={handleWalletConnect}
              disabled={isLoading}
            >
              <Wallet className="w-4 h-4" />
              Web3 Wallet
            </Button>
          </div>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-hair"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-bg text-sec">or</span>
            </div>
          </div>

          {/* Email / Password Form */}
          <div className="space-y-4">
            {tab === 'signup' && (
              <div>
                <label htmlFor="auth-fullname" className="block text-sm font-medium text-text mb-2">
                  Full Name
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-sec" />
                  <input
                    id="auth-fullname"
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="John Doe"
                    className="w-full pl-10 pr-4 py-2.5 bg-surface-2 text-text placeholder-on-surface-variant rounded-lg border border-hair focus:outline-none focus:border-brand transition"
                  />
                </div>
              </div>
            )}

            <div>
              <label htmlFor="auth-email" className="block text-sm font-medium text-text mb-2">
                Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-sec" />
                <input
                  id="auth-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  className="w-full pl-10 pr-4 py-2.5 bg-surface-2 text-text placeholder-on-surface-variant rounded-lg border border-hair focus:outline-none focus:border-brand transition"
                />
              </div>
            </div>

            <div>
              <label htmlFor="auth-password" className="block text-sm font-medium text-text mb-2">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-sec" />
                <input
                  id="auth-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full pl-10 pr-10 py-2.5 bg-surface-2 text-text placeholder-on-surface-variant rounded-lg border border-hair focus:outline-none focus:border-brand transition"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showPassword}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-sec hover:text-text transition"
                >
                  {showPassword ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Forgot Password / Links */}
          {tab === 'signin' && (
            <div className="text-right">
              <button className="text-sm text-acc-text hover:text-text transition">
                Forgot password?
              </button>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="bg-critical-bg border border-critical-border text-critical text-sm px-3 py-2 rounded-lg">
              {error}
            </div>
          )}

          {/* CTA Button */}
          <Button
            className="w-full"
            onClick={tab === 'signin' ? handleSignIn : handleSignUp}
            disabled={isLoading}
          >
            {isLoading 
              ? (tab === 'signin' ? 'Signing in...' : 'Creating account...')
              : (tab === 'signin' ? 'Sign In' : 'Create Account')
            }
          </Button>

          {/* Trial Disclaimer */}
          <p className="text-xs text-sec text-center">
            {tab === 'signup' ? (
              <>
                Start your free 14-day trial.
                <br />
                No credit card required.
              </>
            ) : (
              <>
                Don&apos;t have an account?{' '}
                <button
                  onClick={() => setTab('signup')}
                  className="text-acc-text hover:text-text transition"
                >
                  Sign up
                </button>
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  )
}
