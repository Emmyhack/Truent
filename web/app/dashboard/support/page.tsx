'use client'

import Link from 'next/link'
import { AppShell } from '@/components/layout/AppShell'
import { Mail, BookOpen, Github, ArrowUpRight } from 'lucide-react'
import { Button } from '@/components/ui/Button'

const FAQS = [
  { q: 'How do I integrate Truent into GitHub Actions?', a: 'Add our official action to your workflow YAML. See the CI/CD Integration guide for a full example with blocking on critical findings.' },
  { q: 'Why is my scan taking longer than expected?', a: 'Deep scans with symbolic execution on large contracts can take 5-15 minutes. Standard scans complete in under 5 minutes. Check the scan depth setting in your scan configuration.' },
  { q: 'Can I scan private repositories?', a: 'Yes. Pro and Enterprise plans support private repo scanning via our GitHub App installation. The app requests minimal read-only permissions.' },
  { q: 'How do I dispute a finding I believe is a false positive?', a: 'Open the finding in your report, click "Mark as False Positive", and add a note. Your feedback helps improve our detection engine.' },
]

export default function SupportPage() {
  return (
    <AppShell currentPage="support">
      <div className="p-6 lg:p-8 max-w-4xl">
        <h1 className="font-display text-3xl font-[600] text-text mb-2">Help & Support</h1>
        <p className="text-body-md text-sec mb-10">Find answers, reach our team, or browse the documentation.</p>

        {/* Quick links */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-10">
          {[
            { icon: <BookOpen size={20} className="text-acc-text" />, title: 'Documentation', desc: 'Browse guides and the CLI reference', href: '/docs' },
            { icon: <Mail size={20} className="text-acc-text" />, title: 'Email Support', desc: 'support@truent.dev · 24h response', href: 'mailto:support@truent.dev' },
            { icon: <Github size={20} className="text-acc-text" />, title: 'GitHub Issues', desc: 'Report bugs or request features', href: 'https://github.com/Emmyhack/Truent/issues' },
          ].map((card, i) => (
            <Link key={i} href={card.href}
              target={card.href.startsWith('http') ? '_blank' : undefined}
              rel={card.href.startsWith('http') ? 'noopener noreferrer' : undefined}
              className="bg-panel border border-hair rounded-card p-6 hover:border-brand transition-colors group">
              <div className="w-10 h-10 rounded-lg bg-brand/10 border border-brand/20 flex items-center justify-center mb-4">{card.icon}</div>
              <h3 className="font-display text-base font-[600] text-text mb-1 group-hover:text-acc-text transition-colors">{card.title}</h3>
              <p className="text-body-md text-sec">{card.desc}</p>
            </Link>
          ))}
        </div>

        {/* FAQ */}
        <h2 className="font-display text-xl font-[600] text-text mb-5">Common Questions</h2>
        <div className="space-y-3 mb-10">
          {FAQS.map((faq, i) => (
            <div key={i} className="bg-panel border border-hair rounded-card p-5">
              <p className="font-display text-base font-[600] text-text mb-2">{faq.q}</p>
              <p className="text-body-md text-sec leading-6">{faq.a}</p>
            </div>
          ))}
        </div>

        <div className="bg-brand/5 border border-brand/20 rounded-card p-6 flex items-center justify-between">
          <div>
            <p className="font-display text-base font-[600] text-text mb-1">Still need help?</p>
            <p className="text-body-md text-sec">Our team is available Mon–Fri, 9am–6pm UTC.</p>
          </div>
          <Link href="/contact">
            <Button variant="primary" size="sm" icon={<ArrowUpRight size={14} />} iconPosition="right">Contact Sales</Button>
          </Link>
        </div>
      </div>
    </AppShell>
  )
}
