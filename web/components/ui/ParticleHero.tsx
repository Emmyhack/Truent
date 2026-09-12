'use client'

import { useEffect, useRef } from 'react'

/**
 * Scroll-scrubbed particle hero.
 *
 * One `progress` value (0 → 1, driven by scroll through the pinned runway)
 * choreographs everything:
 *
 * - **0** — dust scattered across the viewport, headline set large.
 * - **→1** — the dust converges into the ASCII wordmark while the headline
 *   shrinks and lifts clear of it.
 * - **1** — the wordmark is resolved and the supporting copy has faded in.
 *
 * Everything animates imperatively inside a single rAF loop — the headline is
 * written via `style`, never React state — so scrolling never re-renders.
 *
 * The headline stays a real `<h1>` and the wordmark a real `<pre>`, so both
 * remain selectable and legible to crawlers; the canvas is decorative and
 * `aria-hidden`.
 */

type Particle = {
  /** scattered origin, in CSS px */
  hx: number
  hy: number
  /** glyph-pixel target */
  tx: number
  ty: number
  amp: number
  driftPhase: number
  driftSpeed: number
  twPhase: number
  twSpeed: number
}

interface ParticleHeroProps {
  /** ASCII block art the particles resolve into. */
  ascii: string
  /** Accessible name for the ASCII art. */
  wordmark?: string
  eyebrow?: React.ReactNode
  headline: React.ReactNode
  /** Revealed once the wordmark resolves. */
  subline?: React.ReactNode
  bullets?: React.ReactNode
  actions?: React.ReactNode
  hint?: string
  accent?: string
  base?: string
}

const rand = (min: number, max: number) => min + Math.random() * (max - min)
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))
/** power3.out — quick departure, long settle. */
const easeOutCubic = (x: number) => 1 - Math.pow(1 - x, 3)

export function ParticleHero({
  ascii,
  wordmark = 'TRUENT',
  eyebrow,
  headline,
  subline,
  bullets,
  actions,
  hint = 'Scroll to explore ↓',
  accent = '#34D399',
  base = '#9ab4a9',
}: ParticleHeroProps) {
  const sectionRef = useRef<HTMLElement | null>(null)
  const stageRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const headlineRef = useRef<HTMLHeadingElement | null>(null)
  const copyRef = useRef<HTMLDivElement | null>(null)
  const revealRef = useRef<HTMLDivElement | null>(null)
  const hintRef = useRef<HTMLDivElement | null>(null)
  const markRef = useRef<HTMLPreElement | null>(null)
  const sparkleRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const section = sectionRef.current
    const stage = stageRef.current
    const canvas = canvasRef.current
    const h1 = headlineRef.current
    const copy = copyRef.current
    const reveal = revealRef.current
    const hintEl = hintRef.current
    const mark = markRef.current
    const ctx = canvas?.getContext('2d')
    if (!section || !stage || !canvas || !ctx || !h1 || !copy || !reveal || !mark) return

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const rows = mark.textContent?.split('\n') ?? []
    if (!rows.length) return

    let width = 0
    let height = 0
    let dust: Particle[] = []
    let sparks: Particle[] = []
    let raf = 0
    let visible = true
    /** Headline size at each end of the tween. */
    let bigSize = 0
    let smallSize = 0

    /** Fit the headline to the centre track, and record both tween endpoints. */
    const measureHeadline = () => {
      const probe = document.createElement('canvas').getContext('2d')
      if (!probe) return
      const text = h1.textContent?.trim() ?? ''
      probe.font = `400 100px ${getComputedStyle(document.documentElement).getPropertyValue('--font-display').trim() || 'sans-serif'}`
      const w = probe.measureText(text).width
      if (w <= 0) return
      // Fit against the centre grid track, not the full stage.
      const track = Math.max(copy.clientWidth - 48, 240)
      // Two lines at this measure, so allow twice the track before capping.
      bigSize = Math.min(((track * 2) / w) * 100, height * 0.19, 96)
      smallSize = clamp(track * 0.05, 22, 38)
    }

    /** Rasterise the ASCII wordmark and sample its lit pixels into targets. */
    const build = () => {
      const rect = stage.getBoundingClientRect()
      width = rect.width
      height = rect.height
      if (width <= 0 || height <= 0) return

      canvas.width = Math.floor(width * dpr)
      canvas.height = Math.floor(height * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      measureHeadline()

      const off = document.createElement('canvas')
      off.width = Math.floor(width)
      off.height = Math.floor(height)
      const octx = off.getContext('2d', { willReadFrequently: true })
      if (!octx) return

      const cols = Math.max(...rows.map((s) => s.length))
      // Monospace advance ≈ 0.6em, so size follows the target band width.
      const size = Math.min((width * (width < 720 ? 0.92 : 0.62)) / (cols * 0.6), height * 0.13)
      const lh = size * 1.06
      octx.fillStyle = '#fff'
      octx.font = `500 ${size}px ${getComputedStyle(document.documentElement).getPropertyValue('--font-mono').trim() || 'monospace'}`
      octx.textAlign = 'center'
      octx.textBaseline = 'middle'
      const top = height * 0.5 - ((rows.length - 1) * lh) / 2
      rows.forEach((line, i) => octx.fillText(line, width / 2, top + i * lh))

      const data = octx.getImageData(0, 0, off.width, off.height).data
      const hits: Array<[number, number]> = []
      for (let y = 0; y < off.height; y += 3) {
        for (let x = 0; x < off.width; x += 3) {
          if (data[(y * off.width + x) * 4 + 3] > 128) hits.push([x, y])
        }
      }

      const cap = window.innerWidth < 768 ? 2000 : 5200
      const stride = hits.length > cap ? hits.length / cap : 1
      const count = Math.min(hits.length, cap)

      dust = []
      sparks = []
      for (let i = 0; i < count; i++) {
        const [tx, ty] = hits[Math.floor(i * stride)]
        const p: Particle = {
          hx: Math.random() * width,
          hy: Math.random() * height,
          tx,
          ty,
          amp: rand(6, 20),
          driftPhase: rand(0, Math.PI * 2),
          driftSpeed: rand(0.25, 0.8),
          twPhase: rand(0, Math.PI * 2),
          twSpeed: rand(1, 3),
        }
        ;(i % 7 === 0 ? sparks : dust).push(p)
      }
    }

    const paint = (list: Particle[], colour: string, t: number, p: number, dot: number) => {
      ctx.fillStyle = colour
      const inv = 1 - p
      for (let i = 0; i < list.length; i++) {
        const s = list[i]
        const dx = s.hx + s.amp * Math.sin(t * s.driftSpeed + s.driftPhase) * inv
        const dy = s.hy + s.amp * Math.cos(t * s.driftSpeed * 0.85 + s.driftPhase) * inv
        const x = dx + (s.tx - dx) * p
        const y = dy + (s.ty - dy) * p
        const tw = 0.4 + 0.6 * (0.5 + 0.5 * Math.sin(t * s.twSpeed + s.twPhase))
        ctx.globalAlpha = tw + (1 - tw) * p
        ctx.fillRect(x, y, dot, dot)
      }
    }

    const render = (now: number, p: number) => {
      const dot = window.innerWidth < 768 ? 1.7 : 2
      const t = now * 0.001
      ctx.clearRect(0, 0, width, height)
      paint(dust, base, t, p, dot)
      paint(sparks, accent, t, p, dot)
      ctx.globalAlpha = 1
    }

    // The headline shrinks from a fitted display size to a supporting one and
    // lifts clear of the wordmark — it never fades. The subline and CTAs are a
    // separate block that fades in at 0.72.
    const layout = (p: number) => {
      if (bigSize && smallSize) {
        h1.style.fontSize = `${(bigSize + (smallSize - bigSize) * p).toFixed(1)}px`
      }
      copy.style.transform = `translateY(-${(p * height * 0.27).toFixed(1)}px)`
      reveal.style.opacity = String(clamp((p - 0.72) / 0.28, 0, 1))
      if (hintEl) hintEl.style.opacity = String(clamp(1 - p * 1.8, 0, 1))
    }

    // The rounded page wrapper uses overflow:clip, which makes it the sticky
    // scrollport and defeats position:sticky. Pin manually with position:fixed
    // instead — overflow:clip only clips a fixed child outside the wrapper box,
    // and that box spans the whole page.
    let pinned: string | null = null
    const pin = () => {
      const r = section.getBoundingClientRect()
      const runway = Math.max(r.height - window.innerHeight, 1)
      const past = -r.top
      const mode = past <= 0 ? 'top' : past >= runway ? 'bottom' : 'fixed'
      if (mode === 'fixed') {
        stage.style.position = 'fixed'
        stage.style.top = '0px'
        stage.style.left = `${r.left}px`
        stage.style.width = `${r.width}px`
      } else if (mode !== pinned) {
        stage.style.position = 'absolute'
        stage.style.left = '0px'
        stage.style.width = '100%'
        stage.style.top = mode === 'bottom' ? `${runway}px` : '0px'
      }
      pinned = mode
    }

    const progressAt = () => {
      const r = section.getBoundingClientRect()
      const runway = Math.max(r.height - window.innerHeight, 1)
      return easeOutCubic(clamp(clamp(-r.top, 0, runway) / (runway * 0.7), 0, 1))
    }

    build()
    if (reduced) {
      layout(1)
      render(0, 1)
    } else {
      layout(0)
      pin()
      const loop = (now: number) => {
        pin()
        if (visible) {
          const p = progressAt()
          render(now, p)
          layout(p)
        }
        raf = requestAnimationFrame(loop)
      }
      raf = requestAnimationFrame(loop)
    }

    let timer: ReturnType<typeof setTimeout>
    const settle = () => {
      build()
      const p = reduced ? 1 : progressAt()
      layout(p)
      if (reduced) render(0, 1)
    }
    const onResize = () => {
      clearTimeout(timer)
      timer = setTimeout(settle, 150)
    }
    window.addEventListener('resize', onResize)
    // Metrics shift once the webfonts land, so re-fit when they do.
    document.fonts?.ready.then(settle).catch(() => {})

    const io = new IntersectionObserver(([e]) => {
      visible = e ? e.isIntersecting : true
    })
    io.observe(stage)

    return () => {
      cancelAnimationFrame(raf)
      clearTimeout(timer)
      window.removeEventListener('resize', onResize)
      io.disconnect()
    }
  }, [ascii, accent, base])

  // Ambient sparkles, seeded once on the client to keep SSR output stable.
  useEffect(() => {
    const host = sparkleRef.current
    if (!host || host.childElementCount) return
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    for (let i = 0; i < 34; i++) {
      const d = document.createElement('div')
      const sz = 1 + Math.random() * 2.2
      d.style.cssText =
        `position:absolute;left:${Math.random() * 100}%;top:${8 + Math.random() * 84}%;` +
        `width:${sz}px;height:${sz}px;border-radius:50%;` +
        `background:rgba(134,239,172,${0.3 + Math.random() * 0.5});` +
        `animation:sparkle ${2.5 + Math.random() * 4}s ease-in-out ${Math.random() * 4}s infinite;`
      host.appendChild(d)
    }
  }, [])

  return (
    <header ref={sectionRef} className="relative h-[230vh]">
      <div
        ref={stageRef}
        className="absolute left-0 top-0 grid h-screen w-full items-center justify-items-center overflow-hidden text-center"
        style={{ gridTemplateColumns: 'minmax(0,1fr) minmax(0,720px) minmax(0,1fr)' }}
      >
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              'radial-gradient(700px 420px at 50% 8%, rgba(52,211,153,0.14), transparent 65%)',
          }}
        />
        <canvas
          ref={canvasRef}
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 h-full w-full"
        />
        <div ref={sparkleRef} className="pointer-events-none absolute inset-0" />

        {/* Headline block: shrinks and lifts clear of the resolving wordmark. */}
        <div
          ref={copyRef}
          className="relative flex w-full flex-col items-center px-6 will-change-transform"
          style={{ gridColumn: 2, gridRow: 1 }}
        >
          {eyebrow && <div className="mb-[26px] flex items-center gap-2.5">{eyebrow}</div>}

          {/* Particle target: rasterised, then visually hidden. Kept in the DOM
              so the wordmark stays selectable and legible to crawlers. */}
          <pre
            ref={markRef}
            aria-label={wordmark}
            className="absolute m-0 h-px w-px overflow-hidden whitespace-pre font-mono"
            style={{ clipPath: 'inset(50%)' }}
          >
            {ascii}
          </pre>

          <h1
            ref={headlineRef}
            className="m-0 max-w-[1180px] text-[clamp(34px,7vw,96px)] font-normal leading-[0.98] tracking-[-0.03em]"
            style={{ color: '#f2f6f2', textWrap: 'balance' } as React.CSSProperties}
          >
            {headline}
          </h1>
        </div>

        {/* Scroll hint, inside the centre track. */}
        {hint && (
          <div
            ref={hintRef}
            className="relative mb-[14vh] self-end justify-self-center font-mono text-[11px] tracking-[0.08em] text-[#5c665f]"
            style={{ gridColumn: 2, gridRow: 1 }}
          >
            {hint}
          </div>
        )}

        {/* Revealed once the wordmark is legible. */}
        <div
          ref={revealRef}
          className="absolute bottom-[9vh] left-0 right-0 flex flex-col items-center gap-5 px-6 opacity-0"
        >
          {subline && (
            <p className="m-0 max-w-[560px] text-[15px] leading-[1.65] text-sec" style={{ textWrap: 'pretty' } as React.CSSProperties}>
              {subline}
            </p>
          )}
          {bullets && (
            <div className="flex flex-wrap justify-center gap-5 font-mono text-[11.5px] text-[#748078]">
              {bullets}
            </div>
          )}
          {actions && <div className="flex flex-wrap justify-center gap-3">{actions}</div>}
        </div>

        <div
          className="pointer-events-none absolute bottom-0 left-0 right-0 h-[120px]"
          style={{ background: 'linear-gradient(to bottom,transparent,#060908)' }}
        />
      </div>
    </header>
  )
}
