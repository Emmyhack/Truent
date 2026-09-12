'use client'

import { useEffect, useState } from 'react'
import { useSession } from 'next-auth/react'
import { AppShell } from '@/components/layout/AppShell'
import { Button } from '@/components/ui/Button'
import { Copy, Eye, EyeOff, Check, AlertCircle } from 'lucide-react'

export default function SettingsPage() {
  const { data: session } = useSession()
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [apiKey, setApiKey] = useState('')
  useEffect(() => {
    setFullName(session?.user?.name || '')
    setEmail(session?.user?.email || '')
  }, [session])
  const [showApiKey, setShowApiKey] = useState(false)
  const [saveSuccess, setSaveSuccess] = useState(false)
  const [copiedApiKey, setCopiedApiKey] = useState(false)

  const handleSaveProfile = () => {
    setSaveSuccess(true)
    setTimeout(() => setSaveSuccess(false), 3000)
  }

  const handleCopyApiKey = () => {
    navigator.clipboard.writeText(apiKey)
    setCopiedApiKey(true)
    setTimeout(() => setCopiedApiKey(false), 2000)
  }

  const handleRegenerateApiKey = () => {
    // Key material must come from a CSPRNG; Math.random() is predictable.
    const bytes = new Uint8Array(24)
    crypto.getRandomValues(bytes)
    setApiKey('truent_sk_' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''))
  }

  return (
    <AppShell currentPage="settings">
      <div className="p-8 max-w-4xl">
        <h1 className="font-display text-4xl font-[600] text-text mb-2">
          Settings
        </h1>
        <p className="text-body-lg text-sec mb-8">
          Manage your account preferences, API keys, and subscription.
        </p>

        {/* Profile Section */}
        <div className="bg-panel border border-hair rounded-lg p-8 mb-6">
          <h2 className="font-display text-2xl font-[600] text-text mb-6">
            Profile
          </h2>

          <div className="space-y-6">
            {/* Full Name */}
            <div>
              <label htmlFor="settings-fullname" className="block text-sm font-medium text-text mb-2">
                Full Name
              </label>
              <input
                id="settings-fullname"
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="w-full px-4 py-2.5 bg-surface-2 border border-hair rounded-lg text-text placeholder-on-surface-variant focus:outline-none focus:border-brand transition"
              />
            </div>

            {/* Email */}
            <div>
              <label htmlFor="settings-email" className="block text-sm font-medium text-text mb-2">
                Email Address
              </label>
              <input
                id="settings-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-2.5 bg-surface-2 border border-hair rounded-lg text-text placeholder-on-surface-variant focus:outline-none focus:border-brand transition"
              />
              <p className="text-xs text-sec mt-2">
                Your email is used for account recovery and important notifications.
              </p>
            </div>

            {/* Save Success Message */}
            {saveSuccess && (
              <div className="flex items-center gap-2 p-3 bg-medium/10 border border-medium rounded-lg">
                <Check className="w-5 h-5 text-medium" />
                <span className="text-sm text-text">Profile updated successfully</span>
              </div>
            )}

            <Button variant="primary" onClick={handleSaveProfile}>
              Save Changes
            </Button>
          </div>
        </div>

        {/* API Keys Section */}
        <div className="bg-panel border border-hair rounded-lg p-8 mb-6">
          <h2 className="font-display text-2xl font-[600] text-text mb-6">
            API Keys
          </h2>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-text mb-2">
                Secret Key
              </label>
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <input
                    type={showApiKey ? 'text' : 'password'}
                    value={apiKey}
                    readOnly
                    className="w-full px-4 py-2.5 bg-surface-2 border border-hair rounded-lg text-text font-mono text-sm focus:outline-none focus:border-brand transition"
                  />
                  <button
                    onClick={() => setShowApiKey(!showApiKey)}
                    aria-label={showApiKey ? 'Hide API key' : 'Show API key'}
                    aria-pressed={showApiKey}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-sec hover:text-text transition"
                  >
                    {showApiKey ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={copiedApiKey ? <Check size={16} /> : <Copy size={16} />}
                  onClick={handleCopyApiKey}
                  className="flex-shrink-0"
                >
                  {copiedApiKey ? 'Copied' : 'Copy'}
                </Button>
              </div>
              <p className="text-xs text-sec mt-2">
                Keep this key secure. Don&apos;t share it with anyone or commit it to version control.
              </p>
            </div>

            <div className="border-t border-hair pt-4">
              <Button
                variant="secondary"
                onClick={handleRegenerateApiKey}
              >
                Regenerate Key
              </Button>
              <p className="text-xs text-sec mt-2">
                Regenerating your key will invalidate the current one. Update your applications immediately.
              </p>
            </div>
          </div>
        </div>

        {/* Subscription Section */}
        <div className="bg-panel border border-hair rounded-lg p-8">
          <h2 className="font-display text-2xl font-[600] text-text mb-6">
            Subscription
          </h2>

          <div className="space-y-6">
            {/* Current Plan */}
            <div className="bg-brand-container border border-brand rounded-lg p-4">
              <p className="text-sm text-sec mb-1">Current Plan</p>
              <h3 className="font-display text-2xl font-[700] text-text mb-2">
                Professional
              </h3>
              <p className="text-body-sm text-sec mb-4">
                $499/month • 10,000 scans • Priority support
              </p>
              <p className="text-xs text-sec">
                Billing date: Jun 15, 2026 • Next renewal: Aug 15, 2026
              </p>
            </div>

            {/* Features */}
            <div>
              <h4 className="text-sm font-[600] text-text mb-3">Included Features</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {[
                  '10,000 scans / month',
                  'Every engine: contracts, application code, infrastructure',
                  'Exploitability rating and attack chains',
                  'Fix + verify step on every finding',
                  'SARIF export for code scanning',
                  'Priority support',
                ].map((feature) => (
                  <div key={feature} className="flex items-center gap-2 p-2 rounded bg-panel">
                    <Check className="w-4 h-4 text-medium flex-shrink-0" />
                    <span className="text-sm text-sec">{feature}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-3 pt-4 border-t border-hair">
              <Button variant="secondary" disabled title="Coming soon">
                View Invoice History
              </Button>
              <Button variant="secondary" disabled title="Coming soon">
                Manage Billing
              </Button>
            </div>
          </div>
        </div>

        {/* Danger Zone */}
        <div className="bg-critical/5 border border-critical rounded-lg p-8 mt-6">
          <h2 className="font-display text-2xl font-[600] text-critical mb-4 flex items-center gap-2">
            <AlertCircle className="w-6 h-6" />
            Danger Zone
          </h2>
          <p className="text-body-md text-sec mb-4">
            These actions cannot be undone. Please proceed with caution.
          </p>
          <Button variant="secondary" disabled title="Coming soon" className="text-critical border-critical hover:bg-critical/10">
            Delete Account
          </Button>
        </div>
      </div>
    </AppShell>
  )
}
