'use client'

import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { THEME_STORAGE_KEY } from './constants'

export type Theme = 'light' | 'dark'

interface ThemeContextValue {
  theme: Theme
  setTheme: (theme: Theme) => void
  toggle: () => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

function readCurrent(): Theme {
  if (typeof document === 'undefined') return 'light'
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
}

function apply(theme: Theme) {
  const cls = document.documentElement.classList
  if (theme === 'dark') cls.add('dark')
  else cls.remove('dark')
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  // The init script has already set the class; mirror it into state after
  // mount so server and client markup agree.
  const [theme, setThemeState] = useState<Theme>('light')

  useEffect(() => {
    setThemeState(readCurrent())
  }, [])

  // Follow the OS while the user has not chosen explicitly.
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (e: MediaQueryListEvent) => {
      let saved: string | null = null
      try { saved = localStorage.getItem(THEME_STORAGE_KEY) } catch { /* private mode */ }
      if (saved) return
      const next: Theme = e.matches ? 'dark' : 'light'
      apply(next)
      setThemeState(next)
    }
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  const setTheme = useCallback((next: Theme) => {
    apply(next)
    setThemeState(next)
    try { localStorage.setItem(THEME_STORAGE_KEY, next) } catch { /* private mode */ }
  }, [])

  const toggle = useCallback(() => {
    setTheme(readCurrent() === 'dark' ? 'light' : 'dark')
  }, [setTheme])

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggle }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used inside <ThemeProvider>')
  return ctx
}
