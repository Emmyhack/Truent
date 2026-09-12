'use client'

import { useState, useRef, useEffect } from 'react'
import { X, Github, FolderOpen, Upload, ArrowRight, CheckCircle, AlertCircle, Loader } from 'lucide-react'
import { Button } from './Button'
import { useEscapeKey } from '@/components/hooks/useEscapeKey'
import { ENGINE, languageForExtension, staticDetectorCount } from '@/lib/engine'

type ScanStatus = 'idle' | 'uploading' | 'scanning' | 'complete' | 'error'

interface ScanModalProps {
  isOpen: boolean
  onClose: () => void
}

export function ScanModal({ isOpen, onClose }: ScanModalProps) {
  const [scanMode, setScanMode] = useState<'github' | 'upload'>('github')
  const [githubUrl, setGithubUrl] = useState('')
  const [uploadedFile, setUploadedFile] = useState<File | null>(null)
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle')
  const [progress, setProgress] = useState(0)
  const [findings, setFindings] = useState<{ severity: string; count: number }[] | null>(null)
  const [error, setError] = useState('')
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([])

  const clearAllTimers = () => {
    timersRef.current.forEach((t) => {
      clearInterval(t)
      clearTimeout(t)
    })
    timersRef.current = []
  }

  useEffect(() => clearAllTimers, [])

  const handleGitHubSubmit = () => {
    if (!githubUrl.trim()) {
      setError('Please enter a GitHub repository URL')
      return
    }

    setError('GitHub App ingestion is not enabled yet. Upload a contract file to run the production analyzer.')
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setUploadedFile(file)
      setError('')
    }
  }

  const handleUploadSubmit = async () => {
    if (!uploadedFile) {
      setError('Please select a file to upload')
      return
    }

    setScanStatus('scanning')
    setProgress(15)
    setError('')
    try {
      const language = languageForExtension(uploadedFile.name)
      const response = await fetch('/api/analyze', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: await uploadedFile.text(), language, projectName: uploadedFile.name }),
      })
      const result = await response.json()
      if (!response.ok) throw new Error(result.error || 'Unable to queue scan')
      setProgress(40)
      for (let attempt = 0; attempt < 150; attempt++) {
        const statusResponse = await fetch(`/api/scans/${result.scanId}`, { cache: 'no-store' })
        const { scan } = await statusResponse.json()
        if (scan.status === 'failed') throw new Error(scan.error || 'Analyzer failed')
        if (scan.status === 'complete') {
          setProgress(100)
          window.location.assign(`/reports/${result.scanId}`)
          return
        }
        setProgress((current) => Math.min(current + 2, 90))
        await new Promise((resolve) => setTimeout(resolve, 2000))
      }
      throw new Error('Scan is taking longer than expected. It remains available on your dashboard.')
    } catch (error) {
      setScanStatus('error')
      setError(error instanceof Error ? error.message : 'Unable to run scan')
    }
  }

  const handleReset = () => {
    clearAllTimers()
    setScanStatus('idle')
    setProgress(0)
    setGithubUrl('')
    setUploadedFile(null)
    setFindings(null)
    setError('')
  }

  const handleClose = () => {
    handleReset()
    onClose()
  }

  useEscapeKey(isOpen, handleClose)

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={handleClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="scan-modal-title"
        className="bg-bg rounded-card shadow-2xl w-full max-w-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex justify-between items-center px-6 py-4 border-b border-hair">
          <h2 id="scan-modal-title" className="text-xl font-bold text-text">Start New Scan</h2>
          <button
            onClick={handleClose}
            aria-label="Close dialog"
            className="p-2 hover:bg-panel rounded-lg transition"
          >
            <X className="w-5 h-5 text-text" />
          </button>
        </div>

        <div className="px-6 py-6">
          {scanStatus === 'idle' && (
            <>
              {/* Mode Selection */}
              <div className="flex gap-3 mb-6">
                <button
                  onClick={() => setScanMode('github')}
                  className={`flex-1 p-4 rounded-lg border-2 transition ${
                    scanMode === 'github'
                      ? 'bg-brand-container border-brand'
                      : 'bg-panel border-hair hover:border-brand'
                  }`}
                >
                  <Github className="w-5 h-5 mx-auto mb-2 text-text" />
                  <p className="text-sm font-[600] text-text">GitHub Repository</p>
                </button>
                <button
                  onClick={() => setScanMode('upload')}
                  className={`flex-1 p-4 rounded-lg border-2 transition ${
                    scanMode === 'upload'
                      ? 'bg-brand-container border-brand'
                      : 'bg-panel border-hair hover:border-brand'
                  }`}
                >
                  <FolderOpen className="w-5 h-5 mx-auto mb-2 text-text" />
                  <p className="text-sm font-[600] text-text">Upload a file</p>
                </button>
              </div>

              {error && (
                <div className="mb-4 p-3 bg-critical/10 border border-critical rounded-lg">
                  <p className="text-sm text-critical">{error}</p>
                </div>
              )}

              {/* GitHub Mode */}
              {scanMode === 'github' && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-text mb-2">
                      Repository URL
                    </label>
                    <input
                      type="url"
                      value={githubUrl}
                      onChange={(e) => setGithubUrl(e.target.value)}
                      placeholder="https://github.com/user/repo"
                      className="w-full px-4 py-2.5 bg-surface-2 border border-hair rounded-lg text-text placeholder-on-surface-variant focus:outline-none focus:border-brand transition"
                    />
                    <p className="text-xs text-sec mt-2">
                      Repository ingestion is not enabled in the hosted dashboard yet. Scan a repository with the CLI (truent scan . --chain auto) or upload a single file here.
                    </p>
                  </div>

                  <Button
                    variant="primary"
                    fullWidth
                    onClick={handleGitHubSubmit}
                    className="gap-2"
                  >
                    Start Scan
                    <ArrowRight size={16} />
                  </Button>
                </div>
              )}

              {/* Upload Mode */}
              {scanMode === 'upload' && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-text mb-3">
                      Upload a file
                    </label>
                    <div className="relative">
                      <input
                        type="file"
                        onChange={handleFileUpload}
                        aria-label="Upload smart contract folder"
                        className="absolute inset-0 opacity-0 cursor-pointer"
                        accept=".sol,.rs,.move,.py,.js,.mjs,.cjs,.jsx,.ts,.tsx,.go,.sh,.bash,.tf,.yml,.yaml,.txt,Dockerfile"
                      />
                      <div className="px-4 py-6 bg-surface-2 border-2 border-dashed border-hair rounded-lg text-center hover:border-brand transition">
                        <Upload className="w-8 h-8 mx-auto mb-2 text-sec" />
                        <p className="text-sm text-text font-[600] mb-1">
                          Click to upload or drag and drop
                        </p>
                        <p className="text-xs text-sec">
                          {uploadedFile ? uploadedFile.name : 'Contract, source or infrastructure file: .sol .rs .move .py .js .ts .go .sh .tf Dockerfile .yml'}
                        </p>
                      </div>
                    </div>
                  </div>

                  <Button
                    variant="primary"
                    fullWidth
                    onClick={handleUploadSubmit}
                    className="gap-2"
                    disabled={!uploadedFile}
                  >
                    Start Scan
                    <ArrowRight size={16} />
                  </Button>
                </div>
              )}
            </>
          )}

          {/* Scanning/Progress States */}
          {(scanStatus === 'uploading' || scanStatus === 'scanning') && (
            <div className="space-y-4">
              <div>
                <div className="flex justify-between items-center mb-2">
                  <p className="text-sm font-[600] text-text">
                    {scanStatus === 'uploading' ? 'Uploading' : 'Scanning'}...
                  </p>
                  <p className="text-sm text-sec">{progress}%</p>
                </div>
                <div className="w-full h-2 bg-panel rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-brand to-secondary transition-all"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>

              <div className="flex items-center gap-2 text-sm text-sec">
                <Loader className="w-4 h-4 animate-spin" />
                {scanStatus === 'uploading'
                  ? 'Uploading your code to our secure servers...'
                  : `Running the engine: ${staticDetectorCount()} static detectors across ${Object.keys(ENGINE.byChain).length - 2} analyzers…`}
              </div>
            </div>
          )}

          {scanStatus === 'error' && (
            <div className="space-y-4">
              <div className="flex items-start gap-3 rounded-lg border border-critical/30 bg-critical/10 p-4">
                <AlertCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-critical" />
                <p className="text-sm text-critical">{error}</p>
              </div>
              <Button variant="secondary" fullWidth onClick={handleReset}>Try again</Button>
            </div>
          )}

          {/* Complete State */}
          {scanStatus === 'complete' && findings && (
            <div className="space-y-4">
              <div className="bg-medium/10 border border-medium rounded-lg p-4 flex items-center gap-3">
                <CheckCircle className="w-6 h-6 text-medium flex-shrink-0" />
                <div>
                  <p className="font-[600] text-text">Scan Complete!</p>
                  <p className="text-sm text-sec">
                    {findings.reduce((acc, f) => acc + f.count, 0)} findings detected
                  </p>
                </div>
              </div>

              {/* Findings Summary */}
              <div className="grid grid-cols-4 gap-2 bg-panel rounded-lg p-4">
                {[
                  { label: 'CRITICAL', key: 'critical' },
                  { label: 'HIGH', key: 'high' },
                  { label: 'MEDIUM', key: 'medium' },
                  { label: 'LOW', key: 'low' },
                ].map((severity) => {
                  const finding = findings.find((f) => f.severity === severity.key)
                  return (
                    <div key={severity.key} className="text-center">
                      <div
                        className={`font-display text-2xl font-[700] mb-1 ${
                          severity.key === 'critical'
                            ? 'text-critical'
                            : severity.key === 'high'
                              ? 'text-high'
                              : severity.key === 'medium'
                                ? 'text-medium'
                                : 'text-low'
                        }`}
                      >
                        {finding?.count || 0}
                      </div>
                      <p className="text-xs text-sec">{severity.label}</p>
                    </div>
                  )
                })}
              </div>

              <div className="flex gap-3 pt-2 border-t border-hair">
                <Button variant="secondary" fullWidth onClick={handleReset}>
                  Scan Another
                </Button>
                <Button variant="primary" fullWidth onClick={handleClose}>
                  View Full Report
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
