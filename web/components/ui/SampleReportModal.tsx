'use client'

import { X, Download, BarChart3, Check } from 'lucide-react'
import { Button } from './Button'
import { SeverityBadge } from './SeverityBadge'
import { useEscapeKey } from '@/components/hooks/useEscapeKey'

interface SampleReportModalProps {
  isOpen: boolean
  onClose: () => void
}

export function SampleReportModal({ isOpen, onClose }: SampleReportModalProps) {
  useEscapeKey(isOpen, onClose)

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="sample-report-title"
        className="bg-bg rounded-card shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close button */}
        <div className="sticky top-0 flex justify-between items-center px-6 py-4 border-b border-hair bg-bg">
          <div className="flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-acc-text" />
            <h2 id="sample-report-title" className="text-xl font-bold text-text">Sample Audit Report</h2>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="p-2 hover:bg-panel rounded-lg transition"
          >
            <X className="w-5 h-5 text-text" />
          </button>
        </div>

        <div className="px-6 py-6 space-y-6">
          {/* Report Header */}
          <div>
            <div className="flex justify-between items-start mb-4">
              <div>
                <p className="text-label-sm text-sec mb-2">SAMPLE AUDIT</p>
                <h3 className="font-display text-2xl font-[600] text-text">
                  VaultToken ERC-4626
                </h3>
              </div>
              <div className="text-right text-xs text-sec">
                <p>Contract Version 2.1.0</p>
                <p>Scan Date: Jul 10, 2026</p>
              </div>
            </div>
          </div>

          {/* Severity Grid */}
          <div className="grid grid-cols-4 gap-2 bg-panel rounded-lg p-4">
            <div className="text-center">
              <div className="font-display text-3xl font-[600] text-critical mb-1">3</div>
              <div className="text-label-sm text-sec">CRITICAL</div>
            </div>
            <div className="text-center">
              <div className="font-display text-3xl font-[600] text-high mb-1">5</div>
              <div className="text-label-sm text-sec">HIGH</div>
            </div>
            <div className="text-center">
              <div className="font-display text-3xl font-[600] text-medium mb-1">8</div>
              <div className="text-label-sm text-sec">MEDIUM</div>
            </div>
            <div className="text-center">
              <div className="font-display text-3xl font-[600] text-low mb-1">12</div>
              <div className="text-label-sm text-sec">LOW</div>
            </div>
          </div>

          {/* Key Findings */}
          <div>
            <h4 className="font-display text-lg font-[600] text-text mb-3">Key Findings</h4>
            <div className="space-y-3">
              {[
                {
                  severity: 'critical',
                  title: 'Reentrancy in deposit()',
                  description: 'The contract transfers funds before updating state, allowing reentrancy attacks.',
                },
                {
                  severity: 'high',
                  title: 'Unchecked external call',
                  description: 'No validation of return value from underlying token transfer.',
                },
                {
                  severity: 'medium',
                  title: 'Integer overflow potential',
                  description: 'totalSupply calculation could overflow in extreme scenarios.',
                },
              ].map((finding, idx) => (
                <div key={idx} className="flex gap-3 p-3 bg-panel rounded-lg">
                  <div className="flex-shrink-0 pt-1">
                    <SeverityBadge level={finding.severity as any} />
                  </div>
                  <div>
                    <h5 className="font-[600] text-text mb-1">{finding.title}</h5>
                    <p className="text-sm text-sec">{finding.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recommendations */}
          <div>
            <h4 className="font-display text-lg font-[600] text-text mb-3">Recommendations</h4>
            <div className="space-y-2 text-sm text-sec">
              <div className="flex gap-2">
                <Check size={16} className="text-acc-text flex-shrink-0 mt-0.5" />
                <p>Use Checks-Effects-Interactions pattern to prevent reentrancy</p>
              </div>
              <div className="flex gap-2">
                <Check size={16} className="text-acc-text flex-shrink-0 mt-0.5" />
                <p>Implement OpenZeppelin&apos;s ReentrancyGuard for additional protection</p>
              </div>
              <div className="flex gap-2">
                <Check size={16} className="text-acc-text flex-shrink-0 mt-0.5" />
                <p>Add require() statements to validate all external call return values</p>
              </div>
            </div>
          </div>

          {/* Scan Details */}
          <div className="bg-panel rounded-lg p-4">
            <h4 className="text-sm font-[600] text-text mb-3">Scan Details</h4>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-sec">Lines Analyzed</span>
                <p className="font-[600] text-text">2,847</p>
              </div>
              <div>
                <span className="text-sec">Functions Checked</span>
                <p className="font-[600] text-text">34</p>
              </div>
              <div>
                <span className="text-sec">Invariants Applied</span>
                <p className="font-[600] text-text">174</p>
              </div>
              <div>
                <span className="text-sec">Scan Duration</span>
                <p className="font-[600] text-text">12.3 seconds</p>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3 pt-4 border-t border-hair">
            <Button
              variant="secondary"
              fullWidth
              className="gap-2"
              disabled
              title="Available after signing up"
              aria-label="Download Full PDF — available after signing up"
            >
              <Download size={16} />
              Download Full PDF
            </Button>
            <Button variant="primary" fullWidth onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
