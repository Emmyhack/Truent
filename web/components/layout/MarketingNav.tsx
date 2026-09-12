'use client'

import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Menu, X } from 'lucide-react'
import { AuthModal } from '../ui/AuthModal'
import clsx from 'clsx'

interface MarketingNavProps {
  className?: string
}

const navLinks = [
  { label: 'Home', href: '/' },
  { label: 'Pricing', href: '/pricing' },
  { label: 'Docs', href: '/docs' },
  { label: 'Contact', href: '/contact' },
]

/** Brand lockup: gradient tile + wordmark. */
function Wordmark() {
  return (
    <Link href="/" className="flex items-center gap-[9px] text-text">
      <span className="flex h-[26px] w-[26px] items-center justify-center rounded-lg bg-gradient-to-br from-acc to-acc-text text-[14px] font-bold text-on-acc">
        T
      </span>
      <span className="text-[15px] font-semibold tracking-[-0.01em]">truent</span>
    </Link>
  )
}

export function MarketingNav({ className }: MarketingNavProps) {
  const [authOpen, setAuthOpen] = useState(false)
  const [authTab, setAuthTab] = useState<'signin' | 'signup'>('signin')
  const [mobileOpen, setMobileOpen] = useState(false)
  const pathname = usePathname()

  const handleLogIn = () => { setAuthTab('signin'); setAuthOpen(true) }
  const handleStartTrial = () => { setAuthTab('signup'); setAuthOpen(true) }

  const isActive = (href: string) =>
    href === '/' ? pathname === '/' : pathname?.startsWith(href)

  return (
    <>
      <nav className={clsx('sticky top-3 z-50 flex justify-center px-5 pt-3', className)}>
        <div className="flex w-full max-w-site items-center justify-between gap-4 rounded-full border border-white/[0.08] bg-[rgba(8,12,10,0.6)] py-2 pl-[18px] pr-2 backdrop-blur-[18px]">
          <Wordmark />

          {/* Link cluster — its own inset pill. */}
          <div className="hidden items-center gap-0.5 rounded-full border border-white/[0.06] bg-white/[0.03] p-1 lg:flex">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={clsx(
                  'flex items-center gap-[7px] whitespace-nowrap rounded-full px-3.5 py-[7px] text-[13px] transition-colors',
                  isActive(link.href)
                    ? 'bg-acc-text/10 font-medium text-text'
                    : 'text-[#8a948d] hover:text-text',
                )}
              >
                {isActive(link.href) && (
                  <span className="inline-block h-[5px] w-[5px] rounded-full bg-acc-text" />
                )}
                {link.label}
              </Link>
            ))}
            <button
              onClick={handleLogIn}
              className="ml-1 whitespace-nowrap rounded-full border-l border-white/[0.07] px-3.5 py-[7px] text-[13px] text-[#8a948d] transition-colors hover:text-text"
            >
              Log in / Register
            </button>
          </div>

          <div className="hidden items-center gap-2 md:flex">
            <button
              onClick={handleStartTrial}
              className="inline-flex items-center gap-2.5 rounded-full bg-[#eef2ef] py-[5px] pl-4 pr-[5px] text-[13px] font-semibold text-[#0a0d0b] transition-colors hover:bg-white"
            >
              Start a scan
              <span className="flex h-7 w-7 items-center justify-center rounded-full bg-acc-text text-[14px] text-on-acc">
                →
              </span>
            </button>
            <Link
              href="/pricing"
              className="whitespace-nowrap rounded-full border border-white/[0.14] px-[18px] py-[11px] text-[13px] font-medium text-[#cfd6d1] transition-colors hover:border-acc-text/50 hover:text-text"
            >
              Free trial
            </Link>
          </div>

          {/* The design is desktop-only; this is the small-screen affordance. */}
          <button
            className="rounded-full p-2 text-text transition-colors hover:bg-white/5 lg:hidden"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label="Toggle navigation"
            aria-expanded={mobileOpen}
          >
            {mobileOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </nav>

      {mobileOpen && (
        <div className="sticky top-[76px] z-50 mx-5 mt-2 rounded-2xl border border-white/[0.08] bg-[rgba(8,12,10,0.95)] p-3 backdrop-blur-[18px] lg:hidden">
          <div className="flex flex-col">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                onClick={() => setMobileOpen(false)}
                className="rounded-xl px-4 py-2.5 text-[14px] text-[#8a948d] transition-colors hover:bg-white/5 hover:text-text"
              >
                {link.label}
              </Link>
            ))}
          </div>
          <div className="mt-2 flex flex-col gap-2 border-t border-white/[0.07] pt-3">
            <button
              onClick={() => { handleLogIn(); setMobileOpen(false) }}
              className="rounded-full border border-white/[0.14] px-4 py-2.5 text-[13px] font-medium text-[#cfd6d1]"
            >
              Log in / Register
            </button>
            <button
              onClick={() => { handleStartTrial(); setMobileOpen(false) }}
              className="rounded-full bg-[#eef2ef] px-4 py-2.5 text-[13px] font-semibold text-[#0a0d0b]"
            >
              Start a scan
            </button>
          </div>
        </div>
      )}

      <AuthModal isOpen={authOpen} onClose={() => setAuthOpen(false)} defaultTab={authTab} />
    </>
  )
}
