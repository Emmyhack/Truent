'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ChevronDown, ChevronUp, ArrowLeft, CheckCircle2, Circle, AlertTriangle, Download } from 'lucide-react'
import clsx from 'clsx'
import { AppShell } from '@/components/layout/AppShell'
import { Button } from '@/components/ui/Button'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { EvidenceBadge, ExploitabilityBadge, ChainTag } from '@/components/ui/EngineBadges'
import { detectorById } from '@/lib/engine'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type FindingStatus = 'open' | 'acknowledged' | 'resolved'

/** One row of the `Finding` table, as `/api/scans/:id` returns it. */
interface Finding {
  id: string
  severity: Severity
  title: string
  description: string
  location: string | null
  line: number | null
  impact: string | null
  recommendation: string
  status: FindingStatus
  invariantId: string | null
  chain: string | null
  evidence: 'lead' | 'proven'
  exploitability: string | null
  fix: string | null
  verify: string | null
  cwe: string | null
  snippet: string | null
}

interface Scan {
  id: string
  projectName?: string | null
  language: string
  status: string
  error?: string | null
  durationMs?: number | null
  createdAt: string
  completedAt?: string | null
}

const STATUS_CONFIG: Record<FindingStatus, { label: string; cls: string; icon: React.ReactNode }> = {
  open: { label: 'Open', cls: 'text-critical bg-critical/10 border-critical/20', icon: <Circle size={12} /> },
  acknowledged: { label: 'Acknowledged', cls: 'text-high bg-high/10 border-high/20', icon: <AlertTriangle size={12} /> },
  resolved: { label: 'Resolved', cls: 'text-low bg-low/10 border-low/20', icon: <CheckCircle2 size={12} /> },
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const EXPLOIT_ORDER = ['likely', 'possible', 'unlikely', 'theoretical']

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-label-sm text-sec mb-2">{label}</p>
      <div className="text-body-md text-sec leading-6">{children}</div>
    </div>
  )
}

function FindingCard({ finding, onStatus }: { finding: Finding; onStatus: (id: string, status: FindingStatus) => void }) {
  const [expanded, setExpanded] = useState(finding.severity === 'critical' || finding.severity === 'high' || finding.evidence === 'proven')
  const status = STATUS_CONFIG[finding.status]
  const detector = finding.invariantId ? detectorById(finding.invariantId) : undefined
  const sev = (SEV_ORDER.includes(finding.severity) ? finding.severity : 'low') as Exclude<Severity, 'info'>

  return (
    <div className={clsx('bg-panel border rounded-card overflow-hidden transition-all', finding.status === 'resolved' ? 'border-hair opacity-70' : 'border-hair')}>
      <div
        className={clsx('h-0.5', {
          'bg-critical': finding.severity === 'critical',
          'bg-high': finding.severity === 'high',
          'bg-medium': finding.severity === 'medium',
          'bg-low': finding.severity === 'low' || finding.severity === 'info',
        })}
      />

      <button onClick={() => setExpanded(!expanded)} className="w-full flex items-center justify-between px-6 py-4 text-left hover:bg-panel/40 transition-colors">
        <div className="flex items-center gap-4 flex-1 min-w-0">
          <SeverityBadge level={sev} />
          <div className="flex-1 min-w-0">
            <p className="text-body-md font-[600] text-text">{finding.title}</p>
            <p className="text-xs text-sec mt-0.5 font-mono truncate">{finding.location || 'Location unavailable'}</p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 ml-4">
          <ExploitabilityBadge level={finding.exploitability} className="hidden sm:inline-block" />
          <EvidenceBadge evidence={finding.evidence} />
          <span className={clsx('hidden md:inline-flex items-center gap-1 text-xs font-[600] px-2 py-0.5 rounded border', status.cls)}>
            {status.icon} {status.label}
          </span>
          {expanded ? <ChevronUp size={16} className="text-sec" /> : <ChevronDown size={16} className="text-sec" />}
        </div>
      </button>

      {expanded && (
        <div className="px-6 pb-6 border-t border-hair/50 pt-5 space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            {finding.invariantId && (
              <code className="rounded-[5px] border border-white/[0.08] bg-white/[0.03] px-2 py-[3px] font-mono text-[10.5px] text-[#8fa398]">{finding.invariantId}</code>
            )}
            <ChainTag chain={finding.chain} />
            {finding.cwe && <span className="font-mono text-[10.5px] text-[#748078]">{finding.cwe}</span>}
            {detector?.attack.map((a) => (
              <span key={a} className="rounded-[5px] border border-white/[0.06] px-2 py-[3px] font-mono text-[10px] text-[#5c665f]" title="MITRE ATT&CK">
                {a}
              </span>
            ))}
          </div>

          <Field label="WHAT THE ENGINE FOUND">{finding.description}</Field>

          {finding.impact && (
            <Field label={finding.evidence === 'proven' ? 'EVIDENCE' : 'WHY IT IS RATED THIS WAY'}>
              <div className="flex flex-wrap items-center gap-2 mb-1.5">
                <EvidenceBadge evidence={finding.evidence} />
                <ExploitabilityBadge level={finding.exploitability} />
              </div>
              {finding.impact}
            </Field>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <Field label="FIX">{finding.fix || finding.recommendation}</Field>
            {finding.verify && <Field label="VERIFY">{finding.verify}</Field>}
          </div>

          {finding.snippet && (
            <div>
              <p className="text-label-sm text-sec mb-2">SOURCE{finding.line ? ` · LINE ${finding.line}` : ''}</p>
              <pre className="bg-surface-2 border border-hair rounded-lg p-4 text-xs font-mono text-sec overflow-x-auto leading-5 whitespace-pre">{finding.snippet}</pre>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2 border-t border-hair/50 pt-4">
            <span className="text-xs text-sec mr-1">Workflow:</span>
            {(Object.keys(STATUS_CONFIG) as FindingStatus[]).map((s) => (
              <button
                key={s}
                onClick={() => onStatus(finding.id, s)}
                aria-pressed={finding.status === s}
                className={clsx(
                  'inline-flex items-center gap-1 text-xs font-[600] px-2.5 py-1 rounded border transition-colors',
                  finding.status === s ? STATUS_CONFIG[s].cls : 'border-hair text-sec hover:text-text',
                )}
              >
                {STATUS_CONFIG[s].icon} {STATUS_CONFIG[s].label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default function ReportDetailPage({ params }: { params: { id: string } }) {
  const reportId = params.id
  const [filter, setFilter] = useState<'all' | Severity | 'proven'>('all')
  const [findings, setFindings] = useState<Finding[]>([])
  const [scan, setScan] = useState<Scan | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const load = async () => {
      try {
        const response = await fetch(`/api/scans/${encodeURIComponent(reportId)}`, { cache: 'no-store' })
        if (!response.ok) throw new Error(response.status === 404 ? 'Report not found' : 'Unable to load report')
        const data = await response.json()
        if (cancelled) return
        setScan(data.scan)
        setFindings(data.scan.findings)
        setLoading(false)
        if (data.scan.status === 'queued' || data.scan.status === 'processing') timer = setTimeout(load, 2000)
      } catch (error) {
        if (!cancelled) {
          setLoadError(error instanceof Error ? error.message : 'Unable to load report')
          setLoading(false)
        }
      }
    }
    load()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [reportId])

  const setStatus = async (findingId: string, status: FindingStatus) => {
    const previous = findings
    setFindings((all) => all.map((f) => (f.id === findingId ? { ...f, status } : f)))
    const response = await fetch(`/api/scans/${encodeURIComponent(reportId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findingId, status }),
    })
    if (!response.ok) setFindings(previous)
  }

  const stats = Object.fromEntries(SEV_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length])) as Record<Severity, number>
  const proven = findings.filter((f) => f.evidence === 'proven').length
  const likely = findings.filter((f) => f.exploitability === 'likely').length
  const open = findings.filter((f) => f.status === 'open').length
  const resolved = findings.filter((f) => f.status === 'resolved').length

  const sorted = [...findings].sort(
    (a, b) =>
      SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) ||
      EXPLOIT_ORDER.indexOf(a.exploitability || 'theoretical') - EXPLOIT_ORDER.indexOf(b.exploitability || 'theoretical') ||
      (a.line || 0) - (b.line || 0),
  )
  const visible = filter === 'all' ? sorted : filter === 'proven' ? sorted.filter((f) => f.evidence === 'proven') : sorted.filter((f) => f.severity === filter)

  const exportJson = () => {
    const blob = new Blob([JSON.stringify({ scan, findings }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `truent-${reportId}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const running = scan?.status === 'queued' || scan?.status === 'processing'

  return (
    <AppShell currentPage="audits">
      <div className="max-w-4xl mx-auto p-6 lg:p-8 space-y-8">
        <Link href="/dashboard" className="inline-flex items-center gap-2 text-sec hover:text-text text-body-md transition-colors">
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>

        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className="text-label-sm text-sec bg-panel border border-hair px-2 py-0.5 rounded font-mono">{reportId}</span>
              <span
                className={clsx(
                  'text-xs px-2 py-0.5 rounded font-mono border',
                  scan?.status === 'complete' ? 'text-low bg-low/10 border-low/20' : scan?.status === 'failed' ? 'text-critical bg-critical/10 border-critical/20' : 'text-high bg-high/10 border-high/20',
                )}
              >
                {(scan?.status || 'loading').toUpperCase()}
              </span>
              {scan?.language && <ChainTag chain={scan.language} />}
            </div>
            <h1 className="font-display text-3xl font-[600] text-text mb-2">{scan?.projectName || 'Security report'}</h1>
            <p className="text-body-md text-sec">
              {scan ? new Date(scan.createdAt).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' }) : '—'}
              {scan?.durationMs ? ` · ${(scan.durationMs / 1000).toFixed(1)}s` : ''}
            </p>
          </div>
          <div className="flex gap-2 flex-shrink-0">
            <Button variant="secondary" size="sm" icon={<Download size={14} />} onClick={exportJson} disabled={!findings.length}>
              Export JSON
            </Button>
          </div>
        </div>

        {/* Honesty strip: what is proven vs inferred, and how many are likely exploitable. */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-px bg-hair rounded-card overflow-hidden">
          {[
            { label: 'Proven findings', value: proven, hint: 'concrete witness — observed or solved', accent: 'text-acc-text' },
            { label: 'Rated LIKELY', value: likely, hint: 'reachable by anyone, nothing in hand', accent: 'text-critical' },
            { label: 'Open / resolved', value: `${open} / ${resolved}`, hint: `${findings.length} total`, accent: 'text-text' },
          ].map((m) => (
            <div key={m.label} className="bg-panel p-5">
              <div className="text-[12px] text-[#748078]">{m.label}</div>
              <div className={clsx('mt-1 text-[28px] font-medium tracking-[-0.02em]', m.accent)}>{m.value}</div>
              <div className="mt-1 font-mono text-[10.5px] text-[#5c665f]">{m.hint}</div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-px bg-hair rounded-card overflow-hidden">
          {(
            [
              ['critical', 'text-critical', 'bg-critical/5'],
              ['high', 'text-high', 'bg-high/5'],
              ['medium', 'text-medium', 'bg-medium/5'],
              ['low', 'text-low', 'bg-low/5'],
              ['proven', 'text-acc-text', 'bg-acc-text/5'],
            ] as const
          ).map(([key, color, bg]) => (
            <button
              key={key}
              onClick={() => setFilter(filter === key ? 'all' : key)}
              className={clsx('p-5 text-center transition-colors', bg, filter === key ? 'ring-1 ring-inset ring-outline' : 'hover:bg-panel')}
            >
              <div className={clsx('font-display text-4xl font-[700] mb-1', color)}>{key === 'proven' ? proven : stats[key]}</div>
              <div className="text-label-sm text-sec">{key.toUpperCase()}</div>
            </button>
          ))}
        </div>

        <div className="space-y-3">
          {loading && <div className="py-12 text-center text-sec">Loading report…</div>}
          {running && !loading && <div className="rounded-lg border border-high/30 bg-high/10 p-4 text-high text-sm">The engine is still running this scan. This page refreshes on its own.</div>}
          {(loadError || scan?.error) && <div className="rounded-lg border border-critical/30 bg-critical/10 p-4 text-critical">{loadError || scan?.error}</div>}
          {!loading && !running && !loadError && !scan?.error && findings.length === 0 && (
            <div className="rounded-card border border-hair bg-panel p-8 text-center">
              <CheckCircle2 className="w-10 h-10 text-low mx-auto mb-3" />
              <p className="text-text font-[600]">No findings.</p>
              <p className="text-sec text-sm mt-1">Every applicable detector ran and reported nothing. A clean scan is a lead, not a proof of safety — pair it with tests and a live probe.</p>
            </div>
          )}
          {visible.map((finding) => (
            <FindingCard key={finding.id} finding={finding} onStatus={setStatus} />
          ))}
        </div>
      </div>
    </AppShell>
  )
}
