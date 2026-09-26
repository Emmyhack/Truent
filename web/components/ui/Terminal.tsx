'use client'
import { useEffect, useState } from 'react'

interface TerminalProps {
  title?: string
  showBanner?: boolean
  output: Array<{
    prefix?: string
    text: string
    type?: 'info' | 'scan' | 'critical' | 'high' | 'done'
  }>
}

export function Terminal({ title = 'truent-cli --scan ./contracts/Vault.sol', showBanner = false, output }: TerminalProps) {
  const [visibleLines, setVisibleLines] = useState(0)

  useEffect(() => {
    if (visibleLines >= output.length) return
    const delay = output[visibleLines]?.text === '' ? 200 : 500
    const timer = setTimeout(() => setVisibleLines((v) => v + 1), delay)
    return () => clearTimeout(timer)
    // `output` is intentionally omitted: callers pass an inline array literal
    // (a fresh reference every render), and this reveal animation should run
    // once against that transcript, not restart from scratch whenever the
    // parent re-renders for an unrelated reason. `output.length` and the
    // current line's text (read via `visibleLines`) are the only values that
    // actually need to retrigger this effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleLines, output.length])

  const getPrefixStyles = (type?: string) => {
    const baseStyles = 'inline-block px-1.5 py-0.5 rounded-xs font-[600] text-label-sm'
    
    switch (type) {
      case 'critical':
        return `${baseStyles} bg-critical text-on-acc`
      case 'high':
        return `${baseStyles} bg-high text-on-acc`
      case 'scan':
      case 'info':
      case 'done':
        return 'text-sec'
      default:
        return ''
    }
  }

  const getTextColor = (type?: string) => {
    switch (type) {
      case 'done':
        return 'text-low'
      default:
        return 'text-sec'
    }
  }

  return (
    <div className="bg-surface-2 border border-hair rounded-lg overflow-hidden">
      {/* Title Bar */}
      <div className="bg-panel h-8 px-4 flex items-center justify-between border-b border-hair">
        <div className="flex gap-1.5">
          <div className="w-1.5 h-1.5 rounded-full bg-critical" />
          <div className="w-1.5 h-1.5 rounded-full bg-high" />
          <div className="w-1.5 h-1.5 rounded-full bg-low" />
        </div>
        <span className="text-sec text-label-sm text-center flex-1">{title}</span>
        <div className="w-12" />
      </div>

      {/* Content */}
      <div className="p-5 font-mono text-code-block leading-5">
        {showBanner && (
          <pre className="font-mono text-[8px] sm:text-[10px] leading-tight
                           text-acc-text mb-3 select-none whitespace-pre">
{`████████╗██████╗ ██╗   ██╗███████╗███╗   ██╗████████╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝████╗  ██║╚══██╔══╝
   ██║   ██████╔╝██║   ██║█████╗  ██╔██╗ ██║   ██║   
   ██║   ██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║   ██║   
   ██║   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   `}
            <span className="block text-sec text-[9px] sm:text-[11px] mt-1
                              normal-case font-normal">
              Multi-chain Smart Contract Invariant Checker · v0.2.1
            </span>
          </pre>
        )}
        {output.slice(0, visibleLines).map((line, idx) => (
          <div key={idx} className="flex gap-2 mb-1">
            {line.prefix && (
              <span className={getPrefixStyles(line.type)}>
                [{line.prefix}]
              </span>
            )}
            <span className={getTextColor(line.type)}>{line.text}</span>
            {idx === visibleLines - 1 && (
              <span className="animate-blink-cursor">▊</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
