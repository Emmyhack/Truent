import clsx from 'clsx'
import { EVIDENCE, EXPLOITABILITY, networksForTag, type ExploitabilityId } from '@/lib/engine'
import { ChainLogo } from '@/components/ui/ChainLogo'

/** The honesty contract: a finding is a LEAD (static inference) or PROVEN (concrete witness). */
export function EvidenceBadge({ evidence, className }: { evidence: 'lead' | 'proven' | string; className?: string }) {
  const proven = evidence === 'proven'
  const meta = proven ? EVIDENCE.proven : EVIDENCE.lead
  return (
    <span
      title={meta.title}
      className={clsx(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-2 py-0.5 font-mono text-[9.5px] tracking-[0.12em]',
        proven
          ? 'border-acc-text/40 bg-acc-text/10 text-acc-text'
          : 'border-hair-strong bg-surface-2 text-sec',
        className,
      )}
    >
      <span className={clsx('inline-block h-[5px] w-[5px] rounded-full', proven ? 'bg-acc-text' : 'bg-sec')} />
      {meta.label}
    </span>
  )
}

type ExploitabilityTone = (typeof EXPLOITABILITY)[ExploitabilityId]['tone']

const TONE_CLASSES: Record<ExploitabilityTone, string> = {
  critical: 'border-critical-border bg-critical-bg text-critical',
  high: 'border-high-border bg-high-bg text-high',
  medium: 'border-medium-border bg-medium-bg text-medium',
  low: 'border-low-border bg-low-bg text-low',
}

/** LIKELY → THEORETICAL: how possible exploitation is, judged from the attack profile — never by exploiting. */
export function ExploitabilityBadge({ level, className }: { level: ExploitabilityId | string | null | undefined; className?: string }) {
  if (!level || !(level in EXPLOITABILITY)) return null
  const meta = EXPLOITABILITY[level as ExploitabilityId]
  return (
    <span
      title={meta.title}
      className={clsx(
        'inline-block whitespace-nowrap rounded border px-2 py-0.5 font-mono text-[9.5px] tracking-[0.12em]',
        TONE_CLASSES[meta.tone],
        className,
      )}
    >
      {meta.label}
    </span>
  )
}

/** Engine / chain tag: `evm`, `general`, `runtime`… carrying the network marks it covers. */
export function ChainTag({ chain, className }: { chain?: string | null; className?: string }) {
  if (!chain) return null
  const networks = networksForTag(chain)
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-[5px] border border-hair bg-surface-2 px-2 py-[3px] font-mono text-[10px] text-sec',
        className,
      )}
    >
      {networks.map((n) => (
        <ChainLogo key={n} network={n} size={12} decorative />
      ))}
      {chain}
    </span>
  )
}
