'use client'

import { Moon, Sun } from 'lucide-react'
import clsx from 'clsx'
import { useTheme } from './ThemeProvider'

interface ThemeToggleProps {
  className?: string
  /** Show "Light" / "Dark" next to the icon (sidebars); icon-only in tight navs. */
  withLabel?: boolean
}

/** Switches between light and dark. Reads and writes the shared theme context. */
export function ThemeToggle({ className, withLabel = false }: ThemeToggleProps) {
  const { theme, toggle } = useTheme()
  const dark = theme === 'dark'
  const label = dark ? 'Switch to light mode' : 'Switch to dark mode'
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={label}
      title={label}
      className={clsx(
        'inline-flex items-center gap-2 rounded-full border border-hair text-sec transition-colors hover:border-brand hover:text-text',
        withLabel ? 'px-3 py-2 text-body-md' : 'h-8 w-8 justify-center',
        className,
      )}
    >
      {dark ? <Sun size={15} /> : <Moon size={15} />}
      {withLabel && <span>{dark ? 'Light mode' : 'Dark mode'}</span>}
    </button>
  )
}
