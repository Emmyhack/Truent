'use client'

import { useState } from 'react'
import { Copy, Check } from 'lucide-react'
import clsx from 'clsx'

interface CodeBlockProps {
  code: string
  language?: string
  highlightLines?: number[]
}

export function CodeBlock({ code, language, highlightLines = [] }: CodeBlockProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const lines = code.split('\n')

  return (
    <div className="bg-surface-2 border border-hair rounded overflow-hidden">
      {language && (
        <div className="bg-panel h-9 px-4 flex items-center justify-between border-b border-hair">
          <div className="flex gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-critical" />
            <div className="w-1.5 h-1.5 rounded-full bg-high" />
            <div className="w-1.5 h-1.5 rounded-full bg-low" />
          </div>
          <div className="flex items-center gap-3">
            <span className="text-label-sm bg-panel border border-hair px-2 py-0.5 rounded-full text-sec">
              {language}
            </span>
            <button
              onClick={handleCopy}
              className="text-sec hover:text-text transition-colors p-1.5 -m-0.5"
              aria-label={copied ? 'Copied to clipboard' : 'Copy code'}
              title="Copy code"
            >
              {copied ? (
                <Check size={16} />
              ) : (
                <Copy size={16} />
              )}
            </button>
          </div>
        </div>
      )}
      <div className="overflow-x-auto">
        <pre className="p-5 font-mono text-code-block leading-5 text-sec">
          {lines.map((line, idx) => (
            <div
              key={idx}
              className={clsx(
                'transition-colors',
                highlightLines.includes(idx + 1) &&
                  'bg-critical-bg border-l-2 border-critical pl-4 -ml-5',
              )}
            >
              {line}
            </div>
          ))}
        </pre>
      </div>
    </div>
  )
}
