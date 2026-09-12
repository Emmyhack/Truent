import Link from 'next/link'

const links = [
  { label: 'Home', href: '/' },
  { label: 'Pricing', href: '/pricing' },
  { label: 'Docs', href: '/docs' },
  { label: 'Contact', href: '/contact' },
  { label: 'Privacy', href: '/privacy' },
  { label: 'Terms', href: '/terms' },
]

/**
 * Single-row footer used by the interior screens. The homepage keeps the full
 * four-column `MarketingFooter`.
 */
export function SlimFooter({ omit = [] }: { omit?: string[] }) {
  const currentYear = new Date().getFullYear()

  return (
    <footer className="border-t border-white/[0.06] bg-white/[0.012] px-6 py-9">
      <div className="mx-auto flex max-w-[1100px] flex-wrap items-center justify-between gap-3.5">
        <Link href="/" className="flex items-center gap-[9px] text-text">
          <span className="flex h-6 w-6 items-center justify-center rounded-[7px] bg-gradient-to-br from-acc to-acc-text text-[13px] font-bold text-on-acc">
            T
          </span>
          <span className="text-[14px] font-semibold">truent</span>
        </Link>
        <div className="flex flex-wrap gap-[22px] text-[12.5px]">
          {links
            .filter((l) => !omit.includes(l.label))
            .map((l) => (
              <Link key={l.href} href={l.href} className="text-sec transition-colors hover:text-text">
                {l.label}
              </Link>
            ))}
        </div>
        <p className="m-0 text-[11.5px] text-[#5c665f]">© {currentYear} Truent Security, Inc.</p>
      </div>
    </footer>
  )
}
