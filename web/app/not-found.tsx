'use client'

import { useEffect, useRef } from 'react'
import Link from 'next/link'
import { MarketingNav } from '@/components/layout/MarketingNav'
import { PageShell } from '@/components/layout/PageShell'
import { AsciiLogo } from '@/components/ui/AsciiLogo'

const shortcuts = [
  { icon: '⬡', label: 'Homepage', href: '/' },
  { icon: '▦', label: 'Dashboard', href: '/dashboard' },
]

export default function NotFound() {
  const sparkleRef = useRef<HTMLDivElement | null>(null)

  // Seeded on the client so the randomised positions never mismatch SSR.
  useEffect(() => {
    const host = sparkleRef.current
    if (!host || host.childElementCount) return
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    for (let i = 0; i < 26; i++) {
      const d = document.createElement('div')
      const sz = 1 + Math.random() * 2
      d.style.cssText =
        `position:absolute;left:${Math.random() * 100}%;top:${Math.random() * 100}%;` +
        `width:${sz}px;height:${sz}px;border-radius:50%;` +
        `background:var(--acc-text);opacity:${(0.25 + Math.random() * 0.5).toFixed(2)};` +
        `animation:sparkle ${2.5 + Math.random() * 4}s ease-in-out ${Math.random() * 4}s infinite;`
      host.appendChild(d)
    }
  }, [])

  return (
    <PageShell fullHeight>
      <MarketingNav />

      <main className="relative flex flex-1 items-center justify-center px-6 py-[70px]">
        <div ref={sparkleRef} className="pointer-events-none absolute inset-0" />

        <div className="relative max-w-[520px] text-center">
          <span className="inline-flex items-center gap-2 rounded-full border border-critical-border bg-critical-bg px-4 py-[7px] font-mono text-[11px] uppercase tracking-[0.18em] text-critical">
            <span className="inline-block h-[5px] w-[5px] rounded-full bg-critical" />
            404 · page not found
          </span>

          <div className="mt-[30px] overflow-hidden opacity-[0.28]">
            <AsciiLogo className="text-[clamp(4px,1.5vw,11px)] !leading-[1.08]" />
          </div>

          <h1
            className="m-0 mt-[18px] text-[clamp(78px,14vw,140px)] font-light leading-[0.9] tracking-[-0.05em] text-acc-text"
          >
            404
          </h1>
          <h2 className="m-0 mt-3.5 text-[22px] font-normal tracking-[-0.02em] text-sec">
            Nothing to audit here
          </h2>
          <p className="mx-auto mt-4 max-w-[400px] text-[14px] leading-[1.75] text-sec">
            This page doesn&apos;t exist or was moved. Let&apos;s get you somewhere useful.
          </p>

          <div className="mt-9 grid grid-cols-3 gap-2.5">
            {shortcuts.map((s) => (
              <Link
                key={s.href}
                href={s.href}
                className="flex items-center justify-center gap-2 rounded-[14px] border border-hair bg-surface-2 px-2.5 py-3.5 text-[12.5px] text-sec transition-colors hover:border-acc-text/40 hover:text-text"
              >
                <span className="text-acc-text">{s.icon}</span>
                {s.label}
              </Link>
            ))}
          </div>

          <div className="mt-[26px] flex flex-wrap justify-center gap-3">
            <Link
              href="/"
              className="inline-flex items-center gap-[11px] rounded-full bg-text py-1.5 pl-5 pr-1.5 text-[13.5px] font-semibold text-bg transition-colors hover:bg-acc-text"
            >
              Back to home
              <span className="flex h-[30px] w-[30px] items-center justify-center rounded-full bg-acc-text text-[14px] text-on-acc">
                →
              </span>
            </Link>
            <a
              href="mailto:support@truent.dev"
              className="inline-flex items-center rounded-full border border-hair-strong px-[22px] py-[13px] text-[13.5px] font-medium text-text transition-colors hover:border-acc-text/50 hover:text-text"
            >
              Contact support
            </a>
          </div>

          <div className="mt-10 rounded-2xl border border-hair bg-panel px-5 py-[18px] text-left font-mono text-[11.5px] leading-[1.9]">
            <div className="mb-3 flex gap-1.5">
              <span className="h-[9px] w-[9px] rounded-full bg-critical opacity-80" />
              <span className="h-[9px] w-[9px] rounded-full bg-high opacity-80" />
              <span className="h-[9px] w-[9px] rounded-full bg-acc-text opacity-80" />
            </div>
            <div className="text-sec">
              <span className="text-acc-text">$</span> truent check --url /404
            </div>
            <div className="text-critical">[CRITICAL] Route not found in manifest</div>
            <div className="text-sec">[INFO] Suggestion: navigate to /dashboard</div>
            <div className="text-acc-text">
              [DONE] Redirecting you to safety…{' '}
              <span style={{ animation: 'blink 1s infinite' }}>▊</span>
            </div>
          </div>
        </div>
      </main>

      <footer className="border-t border-hair bg-surface-2 px-6 py-7">
        <div className="mx-auto flex max-w-[1100px] flex-wrap items-center justify-between gap-3.5">
          <p className="m-0 text-[11.5px] text-sec">© 2026 Truent Security, Inc.</p>
          <div className="flex gap-[22px] text-[12px]">
            <Link href="/privacy" className="text-sec transition-colors hover:text-text">Privacy</Link>
            <Link href="/terms" className="text-sec transition-colors hover:text-text">Terms</Link>
            <a href="mailto:contact@truent.dev" className="text-sec transition-colors hover:text-text">
              contact@truent.dev
            </a>
          </div>
        </div>
      </footer>
    </PageShell>
  )
}
