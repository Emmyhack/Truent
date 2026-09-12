import Link from 'next/link'
import { AsciiLogo } from '../ui/AsciiLogo'

const columns = [
  {
    heading: 'Product',
    links: [
      { label: 'Features', href: '/#features' },
      { label: 'Pricing', href: '/pricing' },
      { label: 'Dashboard', href: '/dashboard' },
    ],
  },
  {
    heading: 'Resources',
    links: [
      { label: 'Documentation', href: '/docs' },
      { label: 'Getting Started', href: '/docs#getting-started' },
      { label: 'CLI Reference', href: '/docs#cli' },
      { label: 'CI/CD Guide', href: '/docs#ci-cd' },
      { label: 'GitHub ↗', href: 'https://github.com/geekstrancend/Truent', external: true },
    ],
  },
  {
    heading: 'Company',
    links: [
      { label: 'Contact Sales', href: '/contact' },
      { label: 'Privacy Policy', href: '/privacy' },
      { label: 'Terms of Service', href: '/terms' },
      // The design pointed this at its 404 mock; sent to the real policy instead.
      { label: 'Security Disclosure', href: 'https://github.com/geekstrancend/Truent/security/policy', external: true },
    ],
  },
]

const socials = [
  { label: 'GH', href: 'https://github.com/geekstrancend/Truent', name: 'GitHub' },
  { label: '𝕏', href: 'https://twitter.com/truentsec', name: 'X' },
]

export function MarketingFooter() {
  const currentYear = new Date().getFullYear()

  return (
    <footer className="border-t border-hair bg-white/[0.012] px-6 pb-8 pt-16">
      <div className="mx-auto max-w-[1100px]">
        <div className="mb-14 grid grid-cols-2 gap-10 md:grid-cols-[2fr_1fr_1fr_1fr]">
          <div className="col-span-2 md:col-span-1">
            <div className="mb-4 flex items-center gap-[9px]">
              <span className="flex h-[26px] w-[26px] items-center justify-center rounded-lg bg-gradient-to-br from-acc to-acc-text text-[14px] font-bold text-on-acc">
                T
              </span>
              <span className="text-[15px] font-semibold text-text">truent</span>
            </div>
            <p className="mb-5 max-w-[280px] text-[13px] leading-[1.7] text-[#748078]">
              The invariant-driven smart contract security platform. Don&apos;t get hacked.
            </p>
            <div className="flex gap-2">
              {socials.map((s) => (
                <a
                  key={s.name}
                  href={s.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={s.name}
                  className="flex h-[34px] w-[34px] items-center justify-center rounded-[10px] border border-white/10 text-[13px] text-sec transition-colors hover:border-acc-text/50 hover:text-text"
                >
                  {s.label}
                </a>
              ))}
            </div>
          </div>

          {columns.map((col) => (
            <div key={col.heading}>
              <div className="mb-5 text-[25px] font-normal tracking-[-0.02em] text-text">
                {col.heading}
              </div>
              <div className="flex flex-col gap-[11px]">
                {col.links.map((link) =>
                  'external' in link && link.external ? (
                    <a
                      key={link.label}
                      href={link.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[13px] text-sec transition-colors hover:text-text"
                    >
                      {link.label}
                    </a>
                  ) : (
                    <Link
                      key={link.label}
                      href={link.href}
                      className="text-[13px] text-sec transition-colors hover:text-text"
                    >
                      {link.label}
                    </Link>
                  ),
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Oversized watermark of the wordmark, sized to the viewport. */}
        <div className="mb-6 overflow-hidden opacity-[0.16]">
          <AsciiLogo className="text-[clamp(4px,1.1vw,13px)] !leading-[1.08]" />
        </div>

        <div className="mb-6 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />

        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="m-0 text-[11.5px] text-[#5c665f]">
            © {currentYear} Truent Security, Inc. All rights reserved.
          </p>
          <div className="flex gap-[22px] text-[11.5px]">
            <Link href="/privacy" className="text-[#5c665f] transition-colors hover:text-text">Privacy</Link>
            <Link href="/terms" className="text-[#5c665f] transition-colors hover:text-text">Terms</Link>
            <a href="mailto:contact@truent.dev" className="text-[#5c665f] transition-colors hover:text-text">
              contact@truent.dev
            </a>
          </div>
        </div>
      </div>
    </footer>
  )
}
