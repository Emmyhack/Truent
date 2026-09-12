import clsx from 'clsx'
import { EVIDENCE, EXPLOITABILITY, type ExploitabilityId } from '@/lib/engine'

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
          : 'border-white/[0.12] bg-white/[0.03] text-[#8fa398]',
        className,
      )}
    >
      <span className={clsx('inline-block h-[5px] w-[5px] rounded-full', proven ? 'bg-acc-text' : 'bg-[#8fa398]')} />
      {meta.label}
    </span>
  )
}

/** LIKELY → THEORETICAL: how possible exploitation is, judged from the attack profile — never by exploiting. */
export function ExploitabilityBadge({ level, className }: { level: ExploitabilityId | string | null | undefined; className?: string }) {
  if (!level || !(level in EXPLOITABILITY)) return null
  const meta = EXPLOITABILITY[level as ExploitabilityId]
  return (
    <span
      title={meta.title}
      className={clsx('inline-block whitespace-nowrap rounded border px-2 py-0.5 font-mono text-[9.5px] tracking-[0.12em]', className)}
      style={{ color: meta.color, borderColor: `${meta.color}4d`, background: `${meta.color}14` }}
    >
      {meta.label}
    </span>
  )
}

/** Engine / chain tag: `evm`, `general`, `runtime`… */
export function ChainTag({ chain, className }: { chain?: string | null; className?: string }) {
  if (!chain) return null
  return (
    <span className={clsx('inline-block rounded-[5px] border border-white/[0.08] bg-white/[0.03] px-2 py-[3px] font-mono text-[10px] text-[#8fa398]', className)}>
      {chain}
    </span>
  )
}
