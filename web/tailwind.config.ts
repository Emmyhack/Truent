import type { Config } from 'tailwindcss'

/**
 * Colour tokens are CSS variables so light and dark mode swap them at
 * runtime. Tailwind cannot apply an opacity modifier (`bg-acc/15`,
 * `text-sec/70`) to a bare `var()`, so each token is a function that emits
 * `color-mix()` when a modifier is present and the plain variable otherwise.
 */
function token(map: Record<string, string>): Record<string, string> {
  const out: Record<string, (opts: { opacityValue?: string }) => string> = {}
  for (const [name, variable] of Object.entries(map)) {
    out[name] = ({ opacityValue }) =>
      opacityValue === undefined || opacityValue === '1'
        ? `var(--${variable})`
        : `color-mix(in srgb, var(--${variable}) calc(${opacityValue} * 100%), transparent)`
  }
  // Tailwind resolves function values at build time; its Config type only
  // declares the string form.
  return out as unknown as Record<string, string>
}

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        display: ['var(--font-display)', 'serif'],
        body: ['var(--font-body)', 'monospace'],
        fraunces: 'var(--font-fraunces), serif',
        mono: ['var(--font-mono)', 'monospace'],
      },
      maxWidth: {
        site: '1200px',
        narrow: '860px',
      },
      colors: token({
        bg: 'bg',
        panel: 'panel',
        'surface-2': 'surface-2',
        hair: 'hair',
        'hair-strong': 'hair-strong',
        text: 'text',
        sec: 'sec',
        acc: 'acc',
        'acc-text': 'acc-text',
        'on-acc': 'on-acc',
        'acc-soft': 'acc-soft',
        overlay: 'overlay',
        surface: 'surface',
        'surface-dim': 'surface-dim',
        'surface-bright': 'surface-bright',
        'surface-container-lowest': 'surface-container-lowest',
        'surface-container-low': 'surface-container-low',
        'surface-container': 'surface-container',
        'surface-container-high': 'surface-container-high',
        'surface-container-highest': 'surface-container-highest',
        'on-surface': 'on-surface',
        'on-surface-variant': 'on-surface-variant',
        outline: 'outline',
        'outline-variant': 'outline-variant',
        primary: 'primary',
        'primary-container': 'primary-container',
        secondary: 'secondary',
        'secondary-container': 'secondary-container',
        'on-secondary': 'on-secondary',
        'on-secondary-container': 'on-secondary-container',
        error: 'error',
        'error-container': 'error-container',
        background: 'background',
        'on-background': 'on-background',
        'surface-variant': 'surface-variant',
        critical: 'critical',
        'critical-bg': 'critical-bg',
        'critical-border': 'critical-border',
        high: 'high',
        'high-bg': 'high-bg',
        'high-border': 'high-border',
        medium: 'medium',
        'medium-bg': 'medium-bg',
        'medium-border': 'medium-border',
        low: 'low',
        'low-bg': 'low-bg',
        'low-border': 'low-border',
        brand: 'brand',
        'brand-container': 'brand-container',
      }),
      spacing: {
        xs: '4px',
        sm: '8px',
        md: '16px',
        lg: '24px',
        xl: '40px',
        xxl: '64px',
        gutter: '16px',
        margin: '24px',
      },
      borderRadius: {
        card: '18px',
        pill: '100px',
        xs: '2px',
        sm: '2px',
        DEFAULT: '4px',
        md: '6px',
        lg: '8px',
        xl: '12px',
        full: '9999px',
      },
      typography: {
        DEFAULT: {
          css: {
            color: 'var(--on-surface)',
            a: {
              color: 'var(--brand)',
            },
            code: {
              color: 'var(--secondary)',
              backgroundColor: 'var(--surface-container)',
              padding: '0.2em 0.4em',
              borderRadius: '0.25em',
            },
            pre: {
              backgroundColor: 'var(--surface-container-lowest)',
              borderColor: 'var(--outline-variant)',
            },
          },
        },
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
}

export default config
