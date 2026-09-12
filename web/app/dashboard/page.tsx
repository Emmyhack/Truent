'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useSession } from 'next-auth/react'
import { AppShell } from '@/components/layout/AppShell'
import { ScanModal } from '@/components/ui/ScanModal'

interface Scan {
  id: string
  project: string
  chain: string
  date: string
  findings: { critical: number; high: number; medium: number; low: number }
  proven: number
  status: 'complete' | 'scanning' | 'failed'
  duration: string
}

interface Activity {
  type: 'finding' | 'shared' | 'complete' | 'updated' | 'failed'
  title: string
  description: string
  time: string
}

const ACTIVITY_ICON: Record<Activity['type'], { cls: string; symbol: string }> = {
  finding: { cls: 'bg-[#ef4444]/20 text-[#ef4444]', symbol: '!' },
  shared: { cls: 'bg-[#818cf8]/20 text-[#818cf8]', symbol: '↗' },
  complete: { cls: 'bg-[#4ade80]/20 text-[#4ade80]', symbol: '✓' },
  updated: { cls: 'bg-[#fbbf24]/20 text-[#fbbf24]', symbol: '↺' },
  failed: { cls: 'bg-[#ef4444]/20 text-[#ef4444]', symbol: '✗' },
}

/** Coloured finding counts, or a dash while a scan is still running. */
function Findings({ scan }: { scan: Scan }) {
  if (scan.status === 'scanning') return <span className="text-[#5c665f]">—</span>
  const { critical, high, medium, low } = scan.findings
  const parts: Array<[number, string]> = [
    [critical, '#ef4444'],
    [high, '#fbbf24'],
    [medium, '#818cf8'],
    [low, '#4ade80'],
  ]
  return (
    <span className="flex gap-1.5">
      {parts.map(([n, c], i) => (
        <span key={i} style={{ color: n > 0 ? c : '#3d453f' }}>{n}</span>
      ))}
    </span>
  )
}

export default function DashboardPage() {
  const { data: session } = useSession()
  const [showScanModal, setShowScanModal] = useState(false)
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/scans?limit=50')
      .then(async (response) => {
        if (!response.ok) throw new Error('Unable to load scans')
        const data = await response.json()
        setScans(data.scans.map((scan: any) => {
          const counts = { critical: 0, high: 0, medium: 0, low: 0 }
          let proven = 0
          scan.findings.forEach((finding: any) => {
            if (finding.severity in counts) counts[finding.severity as keyof typeof counts]++
            if (finding.evidence === 'proven') proven++
          })
          return {
            id: scan.id,
            project: scan.projectName || 'Untitled scan',
            chain: scan.language,
            date: new Date(scan.createdAt).toLocaleDateString(),
            findings: counts,
            proven,
            status: scan.status === 'queued' || scan.status === 'processing' ? 'scanning' : scan.status,
            duration: scan.durationMs ? `${(scan.durationMs / 1000).toFixed(1)}s` : '–',
          }
        }))
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [showScanModal])

  const metrics = useMemo(() => {
    const completed = scans.filter((scan) => scan.status === 'complete')
    const critical = scans.reduce((sum, scan) => sum + scan.findings.critical, 0)
    const proven = scans.reduce((sum, scan) => sum + scan.proven, 0)
    const average = completed.length
      ? completed.reduce((sum, scan) => sum + (Number.parseFloat(scan.duration) || 0), 0) / completed.length
      : 0
    return [
      { label: 'Total scans', value: String(scans.length), delta: `${completed.length} completed`, icon: '▤' },
      { label: 'Critical findings', value: String(critical), delta: 'Across all scans', icon: '⚠' },
      { label: 'Proven findings', value: String(proven), delta: 'Concrete witness, not inference', icon: '◆' },
      { label: 'Avg scan time', value: average ? `${average.toFixed(1)}s` : '–', delta: 'Completed scans', icon: '◔' },
    ]
  }, [scans])

  const activity: Activity[] = scans.slice(0, 5).map((scan) => ({
    type: scan.status === 'failed' ? 'failed' : scan.status === 'complete' ? 'complete' : 'updated',
    title: scan.status === 'complete' ? 'Scan complete' : scan.status === 'failed' ? 'Scan failed' : 'Scan queued',
    description: `${scan.project} — ${Object.values(scan.findings).reduce((a, b) => a + b, 0)} findings`,
    time: scan.date,
  }))

  return (
    <AppShell currentPage="dashboard" onNewScan={() => setShowScanModal(true)}>
      <div className="max-w-[1080px] px-6 pb-16 pt-8 lg:px-9">
        {/* ─── Header ─── */}
        <div className="mb-8 flex items-start justify-between gap-5">
          <div>
            <h1 className="m-0 text-[30px] font-normal tracking-[-0.02em] text-[#f2f6f2]">Dashboard</h1>
            <p className="m-0 mt-2 text-[13.5px] text-sec">
              {session?.user?.name ? `Welcome back, ${session.user.name.split(' ')[0]}.` : 'Welcome back.'} Here&apos;s your security overview.
            </p>
          </div>
          <button
            onClick={() => setShowScanModal(true)}
            className="inline-flex flex-shrink-0 items-center gap-2.5 rounded-full bg-[#eef2ef] py-[5px] pl-[18px] pr-[5px] text-[13px] font-semibold text-[#0a0d0b] transition-colors hover:bg-white"
          >
            New scan
            <span className="flex h-7 w-7 items-center justify-center rounded-full bg-acc-text text-[14px] text-on-acc">
              +
            </span>
          </button>
        </div>

        {/* ─── Metrics: single hairline grid ─── */}
        <div className="relative mb-[34px]">
          <div
            className="pointer-events-none absolute left-[34%] top-[38%] h-[180px] w-[280px]"
            style={{ background: 'radial-gradient(closest-side,rgba(52,211,153,0.1),transparent)' }}
          />
          <div className="relative grid grid-cols-2 overflow-hidden rounded-[18px] border border-white/[0.06] lg:grid-cols-4">
            {metrics.map((m, i) => (
              <div
                key={m.label}
                className={`p-5 ${i < 3 ? 'lg:border-r lg:border-white/[0.06]' : ''} ${
                  i % 2 === 0 ? 'border-r border-white/[0.06] lg:border-r' : ''
                } ${i < 2 ? 'border-b border-white/[0.06] lg:border-b-0' : ''}`}
              >
                <div className="mb-3 flex items-center justify-between">
                  <span className="text-[12px] text-[#748078]">{m.label}</span>
                  <span className="text-[14px]">{m.icon}</span>
                </div>
                <div className="text-[31px] font-medium tracking-[-0.02em] text-text">{m.value}</div>
                <div className="mt-1.5 font-mono text-[10.5px] text-acc-text">{m.delta}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="grid items-start gap-3.5 lg:grid-cols-[1.9fr_1fr]">
          {/* ─── Recent scans ─── */}
          <div className="overflow-hidden rounded-[18px] border border-hair bg-white/[0.02]">
            <div className="flex items-center justify-between border-b border-white/[0.06] px-[22px] py-[18px]">
              <h2 className="m-0 text-[16px] font-medium text-text">Recent scans</h2>
              <span className="font-mono text-[10.5px] tracking-[0.1em] text-acc-text">
                {scans.length} TOTAL
              </span>
            </div>
            <div className="overflow-x-auto">
              <div className="min-w-[540px]">
                <div className="grid grid-cols-[1.6fr_0.7fr_1fr_0.9fr_0.9fr] border-b border-white/[0.05] px-[22px] py-[11px] font-mono text-[9.5px] uppercase tracking-[0.14em] text-[#4d564f]">
                  <span>Project</span>
                  <span>Engine</span>
                  <span>Findings</span>
                  <span>Date</span>
                  <span>Status</span>
                </div>
                {scans.map((scan) => (
                  <Link
                    key={scan.id}
                    href={`/reports/${scan.id}`}
                    className="grid grid-cols-[1.6fr_0.7fr_1fr_0.9fr_0.9fr] items-center border-b border-white/[0.04] px-[22px] py-[15px] last:border-b-0"
                  >
                    <div>
                      <div className="text-[13px] font-medium text-text">{scan.project}</div>
                      <div className="mt-[3px] font-mono text-[10px] text-[#5c665f]">{scan.id}</div>
                    </div>
                    <span className="font-mono text-[10px] text-[#8fa398]">{scan.chain}</span>
                    <span className="font-mono text-[11px]">
                      <Findings scan={scan} />
                    </span>
                    <span className="whitespace-nowrap text-[12px] text-[#748078]">{scan.date}</span>
                    <span
                      className={`w-fit rounded-[5px] border px-2 py-[3px] font-mono text-[9.5px] tracking-[0.1em] ${
                        scan.status === 'complete'
                          ? 'border-acc-text/25 bg-acc-text/10 text-acc-text'
                          : scan.status === 'scanning'
                            ? 'border-[#fbbf24]/25 bg-[#fbbf24]/10 text-[#fbbf24]'
                            : 'border-[#ef4444]/25 bg-[#ef4444]/10 text-[#ef4444]'
                      }`}
                    >
                      {scan.status.toUpperCase()}
                    </span>
                  </Link>
                ))}
                {!loading && scans.length === 0 && <div className="px-6 py-10 text-center text-sm text-sec">No scans yet. Start your first analysis.</div>}
              </div>
            </div>
          </div>

          {/* ─── Activity ─── */}
          <div className="overflow-hidden rounded-[18px] border border-hair bg-white/[0.02]">
            <div className="border-b border-white/[0.06] px-5 py-[18px]">
              <h2 className="m-0 text-[16px] font-medium text-text">Activity</h2>
            </div>
            {activity.map((a, i) => {
              const { cls, symbol } = ACTIVITY_ICON[a.type]
              return (
                <div key={i} className="flex gap-3 border-b border-white/[0.04] px-5 py-[15px] last:border-b-0">
                  <span
                    className={`flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full text-xs font-bold ${cls}`}
                  >
                    {symbol}
                  </span>
                  <div className="min-w-0">
                    <div className="text-[12.5px] font-medium text-text">{a.title}</div>
                    <p className="m-0 mt-[3px] text-[11.5px] leading-[1.55] text-[#748078]">
                      {a.description}
                    </p>
                    <div className="mt-[5px] font-mono text-[9.5px] text-[#4d564f]">{a.time}</div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      <ScanModal isOpen={showScanModal} onClose={() => setShowScanModal(false)} />
    </AppShell>
  )
}
