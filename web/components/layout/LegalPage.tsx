import { MarketingNav } from './MarketingNav'
import { PageShell } from './PageShell'
import { SlimFooter } from './SlimFooter'

export interface LegalSection {
  num: string
  title: string
  body: string
  items?: string[]
}

interface LegalPageProps {
  title: string
  updated: string
  sections: LegalSection[]
  /** Numbered like the others, but rendered as a contact card. */
  contact: { num: string; title: string; body: string; email: string }
  omitFooterLink?: string
}

/**
 * Shared chrome for Privacy and Terms: numbered sections with optional bullet
 * lists, closing with a contact card.
 */
export function LegalPage({ title, updated, sections, contact, omitFooterLink }: LegalPageProps) {
  return (
    <PageShell>
      <MarketingNav />

      <main className="mx-auto max-w-[760px] px-6 pb-[100px] pt-[84px]">
        <span className="inline-flex items-center gap-2 rounded-full border border-acc-text/20 bg-acc-text/[0.07] px-4 py-[7px] font-mono text-[11px] uppercase tracking-[0.18em] text-acc-text">
          Legal
        </span>
        <h1 className="m-0 mt-6 text-[clamp(34px,5vw,52px)] font-normal tracking-[-0.03em] text-text">
          {title}
        </h1>
        <p className="mb-[52px] mt-3.5 font-mono text-[11.5px] tracking-[0.1em] text-sec">
          LAST UPDATED: {updated}
        </p>

        <div className="flex flex-col gap-[38px]">
          {sections.map((s) => (
            <section key={s.num}>
              <h2 className="m-0 mb-3.5 text-[20px] font-normal tracking-[-0.02em] text-text">
                <span className="mr-3 font-mono text-[13px] text-acc-text">{s.num}</span>
                {s.title}
              </h2>
              <p
                className="m-0 text-[13.5px] leading-[1.85] text-sec"
                style={{ textWrap: 'pretty' } as React.CSSProperties}
              >
                {s.body}
              </p>
              {s.items && s.items.length > 0 && (
                <div className="mt-4 flex flex-col gap-[9px]">
                  {s.items.map((item) => (
                    <div key={item} className="flex gap-3 text-[13px] leading-[1.7] text-sec">
                      <span className="flex-shrink-0 text-acc-text">·</span>
                      {item}
                    </div>
                  ))}
                </div>
              )}
            </section>
          ))}

          <section>
            <h2 className="m-0 mb-3.5 text-[20px] font-normal tracking-[-0.02em] text-text">
              <span className="mr-3 font-mono text-[13px] text-acc-text">{contact.num}</span>
              {contact.title}
            </h2>
            <p className="m-0 mb-4 text-[13.5px] leading-[1.85] text-sec">{contact.body}</p>
            <div className="flex flex-col gap-2 rounded-[14px] border border-hair bg-surface-2 p-5">
              <div className="font-mono text-[12.5px] text-sec">
                Email:{' '}
                <a href={`mailto:${contact.email}`} className="text-acc-text hover:text-text">
                  {contact.email}
                </a>
              </div>
              <div className="font-mono text-[12.5px] text-sec">Truent Security, Inc.</div>
            </div>
          </section>
        </div>
      </main>

      <SlimFooter omit={omitFooterLink ? [omitFooterLink] : []} />
    </PageShell>
  )
}
