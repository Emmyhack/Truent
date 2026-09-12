'use client'

import { useState } from 'react'
import Link from 'next/link'
import { MarketingNav } from '@/components/layout/MarketingNav'
import { PageShell } from '@/components/layout/PageShell'
import { SlimFooter } from '@/components/layout/SlimFooter'
import { AsciiLogo } from '@/components/ui/AsciiLogo'

const REASONS = [
  'Enterprise plan inquiry',
  'On-premises deployment',
  'Custom .sinv invariants',
  'Integration partnership',
  'Security research collaboration',
  'Other',
]

const channels = [
  { icon: '✉', label: 'Email', href: 'mailto:sales@truent.dev', value: 'sales@truent.dev' },
  { icon: '▤', label: 'Enterprise', text: 'Custom contracts & SLAs available' },
  { icon: '⬡', label: 'Security disclosure', href: 'mailto:security@truent.dev', value: 'security@truent.dev' },
]

const nextSteps = [
  'We’ll reply within 1 business day',
  'A security engineer will join the call',
  'We’ll provide a custom proof-of-concept scan',
]

const fieldClass =
  'w-full rounded-xl border border-white/[0.09] bg-white/[0.03] px-4 py-3 font-[inherit] text-[13.5px] text-text outline-none transition-colors placeholder:text-[#4d564f] focus:border-acc-text/50'

const labelClass = 'mb-2 block text-[12.5px] font-medium text-[#d7e2da]'

export default function ContactPage() {
  const [form, setForm] = useState({ name: '', email: '', company: '', reason: '', message: '' })
  const [loading, setLoading] = useState(false)
  const [submitted, setSubmitted] = useState(false)

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }))

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (loading) return
    setLoading(true)
    // The design mocks the round-trip; wire this to the real endpoint when it exists.
    setTimeout(() => {
      setLoading(false)
      setSubmitted(true)
    }, 1000)
  }

  const reset = () => {
    setForm({ name: '', email: '', company: '', reason: '', message: '' })
    setSubmitted(false)
  }

  return (
    <PageShell glow="radial-gradient(1100px 560px at 50% -110px, rgba(52,211,153,0.14), rgba(6,9,8,0) 60%)">
      <MarketingNav />

      <header className="mx-auto max-w-[1100px] border-b border-white/[0.06] px-6 pb-12 pt-[84px]">
        <h1 className="m-0 text-[clamp(36px,5.5vw,60px)] font-normal tracking-[-0.03em] text-[#f2f6f2]">
          Let&apos;s{' '}
          <span
            className="bg-clip-text text-transparent"
            style={{ backgroundImage: 'linear-gradient(100deg,#d7ffe9,#34d399)' }}
          >
            secure your protocol
          </span>
        </h1>
        <p className="m-0 mt-[18px] max-w-[520px] text-[14.5px] leading-[1.75] text-sec">
          Reach out to discuss Enterprise plans, custom deployments, or research partnerships. Our team
          responds within 24 hours.
        </p>
      </header>

      <section className="mx-auto grid max-w-[1100px] items-start gap-14 px-6 pb-[100px] pt-14 md:grid-cols-[0.85fr_1.6fr]">
        {/* ─── Channels ─── */}
        <div className="flex flex-col gap-[26px]">
          {channels.map((c) => (
            <div key={c.label} className="flex gap-3.5">
              <span className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl border border-acc-text/20 bg-acc-text/[0.08] text-[15px]">
                {c.icon}
              </span>
              <div>
                <div className="mb-[5px] font-mono text-[9.5px] uppercase tracking-[0.16em] text-[#5c665f]">
                  {c.label}
                </div>
                {c.href ? (
                  <a href={c.href} className="text-[13.5px] text-[#d7e2da] transition-colors hover:text-acc-text">
                    {c.value}
                  </a>
                ) : (
                  <p className="m-0 text-[13.5px] text-sec">{c.text}</p>
                )}
              </div>
            </div>
          ))}

          <div className="relative mt-2 overflow-hidden rounded-2xl border border-hair bg-white/[0.02] p-6">
            <div className="pointer-events-none absolute -bottom-1.5 -right-2.5 opacity-[0.14]">
              <AsciiLogo className="text-[4.4px] !leading-[1.08]" />
            </div>
            <div className="relative mb-4 font-mono text-[9.5px] uppercase tracking-[0.16em] text-[#5c665f]">
              What happens next
            </div>
            <div className="flex flex-col gap-3">
              {nextSteps.map((s, i) => (
                <div key={s} className="flex gap-3 text-[13px] leading-[1.6] text-sec">
                  <span className="flex-shrink-0 font-mono text-acc-text">0{i + 1}</span>
                  {s}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ─── Form ─── */}
        <div>
          {submitted ? (
            <div className="flex flex-col items-center rounded-[20px] border border-acc-text/[0.22] bg-acc-text/[0.04] px-10 py-[76px] text-center">
              <div className="mb-[22px] flex h-[62px] w-[62px] items-center justify-center rounded-full border border-acc-text/30 bg-acc-text/10 text-[26px] text-acc-text">
                ✓
              </div>
              <h2 className="m-0 text-[26px] font-normal tracking-[-0.02em] text-[#f2f6f2]">Message sent</h2>
              <p className="mx-auto mt-3.5 max-w-[340px] text-[13.5px] leading-[1.7] text-sec">
                Thanks for reaching out. A member of our team will get back to you within 24 hours.
              </p>
              <button
                onClick={reset}
                className="mt-[26px] text-[13px] font-semibold text-acc-text"
              >
                Send another message
              </button>
            </div>
          ) : (
            <form onSubmit={submit} className="flex flex-col gap-[18px]">
              <div className="grid gap-[18px] sm:grid-cols-2">
                <div>
                  <label htmlFor="name" className={labelClass}>Full name *</label>
                  <input id="name" required value={form.name} onChange={set('name')} placeholder="Jane Smith" className={fieldClass} />
                </div>
                <div>
                  <label htmlFor="email" className={labelClass}>Work email *</label>
                  <input id="email" type="email" required value={form.email} onChange={set('email')} placeholder="jane@protocol.io" className={fieldClass} />
                </div>
              </div>

              <div>
                <label htmlFor="company" className={labelClass}>Company / protocol</label>
                <input id="company" value={form.company} onChange={set('company')} placeholder="Acme Protocol" className={fieldClass} />
              </div>

              <div>
                <span className="mb-2.5 block text-[12.5px] font-medium text-[#d7e2da]">Reason for inquiry</span>
                <div className="flex flex-wrap gap-[7px]">
                  {REASONS.map((r) => {
                    const active = form.reason === r
                    return (
                      <button
                        key={r}
                        type="button"
                        aria-pressed={active}
                        onClick={() => setForm((f) => ({ ...f, reason: r }))}
                        className={`rounded-full border px-3.5 py-2 text-[12px] transition-colors ${
                          active
                            ? 'border-acc-text/50 bg-acc-text/[0.08] text-acc-text'
                            : 'border-white/[0.09] text-[#8a948d] hover:text-text'
                        }`}
                      >
                        {r}
                      </button>
                    )
                  })}
                </div>
              </div>

              <div>
                <label htmlFor="message" className={labelClass}>Message *</label>
                <textarea
                  id="message"
                  required
                  rows={6}
                  value={form.message}
                  onChange={set('message')}
                  placeholder="Tell us about your protocol, team size, and what you'd like to achieve with Truent…"
                  className={`${fieldClass} resize-y leading-[1.6]`}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="mt-1.5 w-full rounded-full bg-[#eef2ef] py-[15px] text-[14px] font-semibold text-[#0a0d0b] transition-opacity disabled:cursor-default disabled:opacity-50"
              >
                {loading ? 'Sending…' : 'Send message  →'}
              </button>
              <p className="m-0 text-center text-[11.5px] text-[#5c665f]">
                By submitting, you agree to our{' '}
                <Link href="/privacy" className="text-[#748078] underline">Privacy Policy</Link>.
              </p>
            </form>
          )}
        </div>
      </section>

      <SlimFooter omit={['Contact']} />
    </PageShell>
  )
}
