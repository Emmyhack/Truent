'use client'

import Link from 'next/link'
import { Search, X, Menu, ShieldCheck, ArrowLeft, Github } from 'lucide-react'
import { useState } from 'react'
import { usePathname } from 'next/navigation'
import clsx from 'clsx'

interface DocsSidebarItem {
  label: string
  href: string
  badge?: string
}

interface DocsSidebarSection {
  title: string
  items: DocsSidebarItem[]
}

interface TableOfContentsItem {
  label: string
  href: string
}

interface DocsShellProps {
  children: React.ReactNode
  pageTitle?: string
  tableOfContents?: TableOfContentsItem[]
  editPath?: string
}

export function DocsShell({
  children,
  pageTitle = 'Documentation',
  tableOfContents,
  editPath,
}: DocsShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const pathname = usePathname()

  const sections: DocsSidebarSection[] = [
    {
      title: 'GETTING STARTED',
      items: [
        { label: 'Introduction', href: '/docs' },
        { label: 'Quick Start', href: '/docs/getting-started' },
        { label: 'CLI Reference', href: '/docs/cli' },
      ],
    },
    {
      title: 'SECURITY',
      items: [
        { label: 'AI Co-Auditor', href: '/docs/ai', badge: 'Pro' },
        { label: 'Audit Report Guide', href: '/docs/reports' },
      ],
    },
    {
      title: 'INTEGRATIONS',
      items: [
        { label: 'CI/CD Integration', href: '/docs/ci-cd' },
        { label: 'REST API', href: '/docs/api' },
      ],
    },
  ]

  const isActive = (href: string) => pathname === href

  const filteredSections = searchQuery
    ? sections.map((s) => ({
        ...s,
        items: s.items.filter((i) => i.label.toLowerCase().includes(searchQuery.toLowerCase())),
      })).filter((s) => s.items.length > 0)
    : sections

  return (
    <div className="flex h-screen bg-bg overflow-hidden">
      {/* Left Sidebar */}
      <aside
        className={clsx(
          'fixed inset-y-0 left-0 z-40 w-64 bg-surface-2 border-r border-hair flex flex-col',
          'transform transition-transform duration-300',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
        )}
      >
        {/* Sidebar header */}
        <div className="flex-shrink-0 p-4 border-b border-hair">
          <Link href="/" className="flex items-center gap-2 mb-4 hover:opacity-80 transition-opacity">
            <ShieldCheck size={18} className="text-acc-text" />
            <span className="font-mono font-[600] text-text text-sm">Truent</span>
            <span className="text-label-sm text-sec ml-1">Docs</span>
          </Link>
          {/* Sidebar search */}
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-sec" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search docs…"
              className="w-full bg-panel border border-hair rounded-md px-3 pl-8 py-1.5 text-xs text-text placeholder-outline-variant focus:outline-none focus:border-brand transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                aria-label="Clear search"
                className="absolute right-1 top-1/2 -translate-y-1/2 p-1.5 text-sec hover:text-text"
              >
                <X size={12} />
              </button>
            )}
          </div>
        </div>

        {/* Nav sections */}
        <nav className="flex-1 overflow-y-auto p-4 space-y-6">
          {filteredSections.map((section, idx) => (
            <div key={idx}>
              <p className="text-label-sm text-sec mb-2 px-2">{section.title}</p>
              <ul className="space-y-0.5">
                {section.items.map((item) => (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      onClick={() => setSidebarOpen(false)}
                      className={clsx(
                        'flex items-center justify-between px-3 py-2 rounded-lg text-body-md transition-colors',
                        isActive(item.href)
                          ? 'bg-brand/10 text-text font-[500] border-l-2 border-brand pl-[10px]'
                          : 'text-sec hover:bg-panel hover:text-text',
                      )}
                    >
                      <span>{item.label}</span>
                      {item.badge && (
                        <span className="text-xs text-acc-text bg-brand/15 border border-brand/20 px-1.5 py-0.5 rounded font-[600]">
                          {item.badge}
                        </span>
                      )}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        {/* Sidebar footer */}
        <div className="flex-shrink-0 p-4 border-t border-hair space-y-2">
          <Link href="https://github.com/geekstrancend/Truent" target="_blank" rel="noopener"
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sec hover:text-text hover:bg-panel transition-colors text-body-md">
            <Github size={14} />
            <span>GitHub</span>
          </Link>
          <Link href="/" className="flex items-center gap-2 px-3 py-2 rounded-lg text-sec hover:text-text hover:bg-panel transition-colors text-body-md">
            <ArrowLeft size={14} />
            <span>Back to home</span>
          </Link>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col md:ml-64 overflow-hidden">
        {/* Top bar */}
        <header className="flex-shrink-0 border-b border-hair bg-surface-2/95 backdrop-blur-sm sticky top-0 z-20">
          <div className="px-6 py-3 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                aria-label={sidebarOpen ? 'Close menu' : 'Open menu'}
                className="md:hidden p-1.5 hover:bg-panel rounded-lg text-sec transition-colors"
              >
                {sidebarOpen ? <X size={18} /> : <Menu size={18} />}
              </button>
              <div className="hidden md:flex items-center gap-2 text-sec text-body-md">
                <Link href="/docs" className="hover:text-text transition-colors">Docs</Link>
                {pathname !== '/docs' && (
                  <>
                    <span>/</span>
                    <span className="text-text">{pageTitle}</span>
                  </>
                )}
              </div>
            </div>

            <div className="flex items-center gap-3">
              {editPath && (
                <Link href={editPath} target="_blank" rel="noopener"
                  className="hidden md:inline-flex items-center gap-1.5 text-xs text-sec hover:text-text transition-colors border border-hair rounded-md px-2.5 py-1">
                  Edit on GitHub
                </Link>
              )}
              <Link href="/dashboard"
                className="text-xs font-[600] bg-acc/15 border border-brand text-acc-text px-3 py-1.5 rounded-lg hover:bg-brand/90 transition-colors">
                Dashboard →
              </Link>
            </div>
          </div>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          <div className="flex max-w-5xl mx-auto">
            <main className="flex-1 px-6 lg:px-12 py-12 min-w-0">
              {children}
            </main>

            {/* Table of contents */}
            {tableOfContents && tableOfContents.length > 0 && (
              <aside className="hidden xl:block w-52 flex-shrink-0 py-12 pr-6">
                <nav className="sticky top-8">
                  <p className="text-label-sm text-sec mb-4">ON THIS PAGE</p>
                  <ul className="space-y-2.5">
                    {tableOfContents.map((item, idx) => (
                      <li key={idx}>
                        <Link href={item.href} className="text-body-sm text-sec hover:text-text transition-colors block">
                          {item.label}
                        </Link>
                      </li>
                    ))}
                  </ul>
                </nav>
              </aside>
            )}
          </div>
        </div>
      </div>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-30 md:hidden" onClick={() => setSidebarOpen(false)} />
      )}
    </div>
  )
}
