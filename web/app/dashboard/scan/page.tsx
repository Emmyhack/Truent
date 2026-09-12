'use client'

import { useMemo, useState } from 'react'
import Link from 'next/link'
import { Upload, Code, Check, AlertCircle, ShieldCheck, Workflow, Radar } from 'lucide-react'
import { AppShell } from '@/components/layout/AppShell'
import { Button } from '@/components/ui/Button'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { EvidenceBadge, ExploitabilityBadge } from '@/components/ui/EngineBadges'
import { ENGINE, LANGUAGES, languageForExtension, staticDetectorCount, type LanguageId } from '@/lib/engine'

type SubmissionMethod = 'code' | 'file'

interface Finding {
  id: string
  severity: string
  title: string
  description: string
  location: string | null
  line: number | null
  evidence: string
  exploitability: string | null
  fix: string | null
  recommendation: string
}

const MAX_CHARS = 500_000

export default function ScanPage() {
  const [method, setMethod] = useState<SubmissionMethod>('code')
  const [code, setCode] = useState('')
  const [fileName, setFileName] = useState<string | null>(null)
  const [projectName, setProjectName] = useState('')
  const [language, setLanguage] = useState<LanguageId>('solidity')
  const [isScanning, setIsScanning] = useState(false)
  const [phase, setPhase] = useState('')
  const [result, setResult] = useState<{ id: string; findings: Finding[]; durationMs?: number } | null>(null)
  const [formError, setFormError] = useState('')

  const lang = useMemo(() => LANGUAGES.find((l) => l.id === language)!, [language])
  const groups = useMemo(() => Array.from(new Set(LANGUAGES.map((l) => l.group))), [])

  const resetForm = () => {
    setCode('')
    setFileName(null)
    setResult(null)
    setFormError('')
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setFileName(file.name)
    setLanguage(languageForExtension(file.name))
    if (!projectName) setProjectName(file.name)
    const reader = new FileReader()
    reader.onload = (event) => setCode(String(event.target?.result || ''))
    reader.readAsText(file)
  }

  const handleScan = async () => {
    setFormError('')
    if (!code.trim()) {
      setFormError('Paste code or upload a file to scan')
      return
    }
    setIsScanning(true)
    setResult(null)
    setPhase('Queued')
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, language, projectName: projectName || fileName || undefined }),
      })
      if (!response.ok) {
        const problem = await response.json().catch(() => ({}))
        throw new Error(problem.error || 'Scan failed')
      }
      const data = await response.json()
      let report: any
      for (let attempt = 0; attempt < 150; attempt++) {
        const statusResponse = await fetch(`/api/scans/${data.scanId}`, { cache: 'no-store' })
        if (!statusResponse.ok) throw new Error('Unable to read scan status')
        report = (await statusResponse.json()).scan
        setPhase(report.status === 'processing' ? `Running ${lang.chain} detectors` : 'Queued')
        if (report.status === 'complete') break
        if (report.status === 'failed') throw new Error(report.error || 'Analyzer failed')
        await new Promise((resolve) => setTimeout(resolve, 2000))
      }
      if (!report || report.status !== 'complete') throw new Error('Scan is still processing — it stays available on your dashboard')
      setResult({ id: report.id, findings: report.findings, durationMs: report.durationMs })
    } catch (error) {
      setFormError(error instanceof Error ? error.message : 'Error scanning code. Please try again.')
    } finally {
      setIsScanning(false)
      setPhase('')
    }
  }

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, proven: 0, likely: 0 }
    for (const f of result?.findings || []) {
      if (f.severity in c) c[f.severity as 'critical' | 'high' | 'medium' | 'low']++
      if (f.evidence === 'proven') c.proven++
      if (f.exploitability === 'likely') c.likely++
    }
    return c
  }, [result])

  const languageSelect = (id: string) => (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-text mb-2">
        Language
      </label>
      <select
        id={id}
        value={language}
        onChange={(e) => setLanguage(e.target.value as LanguageId)}
        className="w-full px-4 py-2 bg-surface-2 text-text rounded-lg border border-hair focus:outline-none focus:border-brand"
      >
        {groups.map((g) => (
          <optgroup key={g} label={g}>
            {LANGUAGES.filter((l) => l.group === g).map((l) => (
              <option key={l.id} value={l.id}>
                {l.label}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
      <p className="text-xs text-sec mt-2">
        Runs the <span className="font-mono text-acc-text">{lang.chain}</span> engine — {ENGINE.byChain[lang.chain] ?? 0} detectors
        {lang.chain === 'general' ? ', including taint tracking across lines' : ''}.
      </p>
    </div>
  )

  return (
    <AppShell currentPage="dashboard" onNewScan={resetForm}>
      <div className="max-w-6xl mx-auto p-6 space-y-8">
        <div className="space-y-3">
          <h1 className="text-4xl font-[700] text-text font-display">Security analyzer</h1>
          <p className="text-body-lg text-sec max-w-2xl">
            Submit a contract, a source file or an infrastructure file. The engine runs every applicable detector and returns
            findings that are either a <span className="text-text">lead</span> (a traced pattern or dataflow) or{' '}
            <span className="text-acc-text">proven</span> — never a guess — each with an exploitability rating and the fix.
          </p>
        </div>

        <div className="bg-panel border border-hair rounded-lg p-6">
          <h2 className="text-lg font-[600] text-text mb-4">Submission</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(
              [
                ['code', Code, 'Paste code', 'Direct input, one file'],
                ['file', Upload, 'Upload a file', '.sol .rs .move .py .js .ts .go .sh .tf Dockerfile .yml'],
              ] as const
            ).map(([id, Icon, title, desc]) => (
              <button
                key={id}
                onClick={() => setMethod(id)}
                className={`p-4 rounded-lg border-2 text-left transition ${method === id ? 'border-brand bg-brand/10' : 'border-hair hover:border-brand'}`}
              >
                <Icon className="w-7 h-7 text-acc-text mb-2" />
                <h3 className="font-[600] text-text mb-1">{title}</h3>
                <p className="text-sm text-sec">{desc}</p>
              </button>
            ))}
          </div>
          <p className="text-xs text-sec mt-4">
            Whole repositories, dependency analysis, live probes and symbolic execution run from the CLI:{' '}
            <Link href="/docs#cli" className="text-acc-text">
              see the CLI reference
            </Link>
            .
          </p>
        </div>

        <div className="bg-panel border border-hair rounded-lg p-6 space-y-4">
          {formError && (
            <div className="flex items-center gap-2 p-3 bg-critical-bg border border-critical-border rounded-lg">
              <AlertCircle size={16} className="text-critical flex-shrink-0" />
              <span className="text-sm text-critical">{formError}</span>
            </div>
          )}

          <div>
            <label htmlFor="scan-project" className="block text-sm font-medium text-text mb-2">
              Project name <span className="text-sec font-normal">(optional)</span>
            </label>
            <input
              id="scan-project"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              maxLength={120}
              placeholder="vault-v2"
              className="w-full px-4 py-2 bg-surface-2 text-text placeholder-on-surface-variant rounded-lg border border-hair focus:outline-none focus:border-brand"
            />
          </div>

          {method === 'code' && (
            <>
              {languageSelect('scan-language-code')}
              <div>
                <label htmlFor="scan-code-input" className="block text-sm font-medium text-text mb-2">
                  Source
                </label>
                <textarea
                  id="scan-code-input"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder={`Paste ${lang.label} here…`}
                  className="w-full h-96 px-4 py-3 bg-surface-2 text-text placeholder-on-surface-variant rounded-lg border border-hair focus:outline-none focus:border-brand font-mono text-sm resize-none"
                  maxLength={MAX_CHARS}
                  spellCheck={false}
                />
                <p className="text-xs text-sec mt-1">
                  {code.length.toLocaleString()} / {MAX_CHARS.toLocaleString()} characters
                </p>
              </div>
            </>
          )}

          {method === 'file' && (
            <>
              {languageSelect('scan-language-file')}
              <div>
                <label className="block text-sm font-medium text-text mb-2">File</label>
                <div className="border-2 border-dashed border-hair rounded-lg p-8 text-center hover:border-brand transition">
                  <input
                    type="file"
                    onChange={handleFileUpload}
                    className="hidden"
                    id="file-upload"
                    accept=".sol,.rs,.move,.py,.js,.mjs,.cjs,.jsx,.ts,.tsx,.go,.sh,.bash,.tf,.yml,.yaml,.txt,Dockerfile"
                  />
                  <label htmlFor="file-upload" className="cursor-pointer">
                    <Upload className="w-8 h-8 text-acc-text mx-auto mb-2" />
                    <p className="text-text font-medium">{fileName || 'Click to choose a file'}</p>
                    <p className="text-sm text-sec mt-1">The language is detected from the name; you can change it above.</p>
                  </label>
                </div>
              </div>
            </>
          )}

          <Button className="w-full" size="lg" onClick={handleScan} disabled={isScanning || !code.trim()}>
            {isScanning ? `${phase || 'Scanning'}…` : 'Run the engine'}
          </Button>
        </div>

        {result && (
          <div className="bg-panel border border-hair rounded-lg p-6 space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-2xl font-[700] text-text font-display">Results</h2>
              <div className="flex items-center gap-3 text-xs text-sec font-mono">
                {result.durationMs ? <span>{(result.durationMs / 1000).toFixed(1)}s</span> : null}
                <Link href={`/reports/${result.id}`} className="text-acc-text">
                  Open the full report →
                </Link>
              </div>
            </div>

            <div className="grid grid-cols-3 md:grid-cols-6 gap-px bg-hair rounded-lg overflow-hidden">
              {[
                ['CRITICAL', counts.critical, 'text-critical'],
                ['HIGH', counts.high, 'text-high'],
                ['MEDIUM', counts.medium, 'text-medium'],
                ['LOW', counts.low, 'text-low'],
                ['PROVEN', counts.proven, 'text-acc-text'],
                ['LIKELY', counts.likely, 'text-critical'],
              ].map(([label, n, color]) => (
                <div key={label as string} className="bg-panel p-4 text-center">
                  <div className={`text-3xl font-[700] ${color}`}>{n as number}</div>
                  <div className="text-[10px] font-mono tracking-[0.12em] text-sec mt-1">{label as string}</div>
                </div>
              ))}
            </div>

            {result.findings.length > 0 ? (
              <div className="space-y-3">
                {result.findings.map((f) => (
                  <div key={f.id} className="bg-surface-2 border border-hair rounded-lg p-4 flex gap-4 items-start">
                    <SeverityBadge level={(['critical', 'high', 'medium', 'low'].includes(f.severity) ? f.severity : 'low') as any} />
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h4 className="font-[600] text-text">{f.title}</h4>
                        <EvidenceBadge evidence={f.evidence} />
                        <ExploitabilityBadge level={f.exploitability} />
                      </div>
                      <p className="text-sm text-sec mt-1">{f.description}</p>
                      {f.location && <p className="text-xs text-sec mt-2 font-mono">{f.location}</p>}
                      <p className="text-xs text-text mt-2">
                        <span className="text-acc-text font-[600]">Fix · </span>
                        {f.fix || f.recommendation}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <Check className="w-12 h-12 text-low mx-auto mb-3" />
                <p className="text-text font-[600]">No findings.</p>
                <p className="text-sec text-sm mt-1">Every applicable detector ran and reported nothing.</p>
              </div>
            )}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            {
              icon: <ShieldCheck size={20} className="text-acc-text" />,
              title: `${staticDetectorCount()} static detectors`,
              description: `EVM ${ENGINE.byChain.evm}, Solana ${ENGINE.byChain.solana}, Move ${ENGINE.byChain.move}, Soroban ${ENGINE.byChain.soroban}, any repository ${ENGINE.byChain.general}, supply chain ${ENGINE.byChain['supply-chain']}.`,
            },
            {
              icon: <Workflow size={20} className="text-acc-text" />,
              title: 'Lead or proven, rated',
              description: 'Every finding carries its evidence class, an exploitability rating from its attack profile, and the fix plus how to verify it.',
            },
            {
              icon: <Radar size={20} className="text-acc-text" />,
              title: 'Live and symbolic from the CLI',
              description: `\`truent probe\` (${ENGINE.byChain.runtime} live checks) and \`truent symbolic\` (halmos / hevm / Mythril) produce proven findings on a target you own.`,
            },
          ].map((feature) => (
            <div key={feature.title} className="bg-panel border border-hair rounded-lg p-4">
              {feature.icon}
              <h3 className="font-[600] text-text mt-3 mb-1">{feature.title}</h3>
              <p className="text-sm text-sec">{feature.description}</p>
            </div>
          ))}
        </div>
      </div>
    </AppShell>
  )
}
