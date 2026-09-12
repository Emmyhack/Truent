// The engine, as the site describes it. Everything here is derived from
// `lib/catalog.json`, which `scripts/sync-catalog.mjs` regenerates from the
// binary (`truent taxonomy / pathways / exposure --format json`), so the site
// can never claim a detector, pathway or attack chain the engine does not
// have. Copy that names counts should read them from here.

import catalog from './catalog.json'

export type Chain =
  | 'evm'
  | 'solana'
  | 'move'
  | 'soroban'
  | 'general'
  | 'supply-chain'
  | 'runtime'
  | 'chain-agnostic'

export interface Detector {
  invariant_id: string
  chain: Chain | null
  cwe: string[]
  cwe_names: string[]
  swc: string[]
  owasp_sc: string[]
  dasp: string[]
  attack: string[]
  attack_names: string[]
  nist_csf: string[]
  vector: 'network' | 'adjacent' | 'local' | null
  prereq: 'none' | 'authenticated' | 'condition' | 'privileged' | null
  interaction: 'none' | 'required' | null
  impact: 'full' | 'partial' | 'information' | null
  fix: string | null
  verify: string | null
}

export interface Pathway {
  id: string
  name: string
  purpose: string
  stage: 'design' | 'build' | 'deploy' | 'runtime' | 'response' | 'recovery'
  controls: Array<{ kind: 'native' | 'hosted' | 'assess'; value: string }>
}

export interface AttackChain {
  id: string
  name: string
  narrative: string
  tactics: string[]
  steps: Array<{ role: string; any_of: string[] }>
  break_at: number
}

export const ENGINE = {
  version: catalog.generated_from as string,
  totalDetectors: catalog.total_detectors as number,
  byChain: catalog.by_chain as Record<string, number>,
  detectors: catalog.detectors as Detector[],
  pathways: catalog.pathways as Pathway[],
  attackChains: catalog.attack_chains as AttackChain[],
}

/** Human names for the engine's chains / analyzers. */
export const CHAIN_LABEL: Record<Chain, string> = {
  evm: 'EVM',
  solana: 'Solana',
  move: 'Move',
  soroban: 'Soroban',
  general: 'Any repository',
  'supply-chain': 'Supply chain',
  runtime: 'Live probe',
  'chain-agnostic': 'Chain-agnostic',
}

export const CHAIN_ORDER: Chain[] = ['evm', 'solana', 'move', 'soroban', 'general', 'supply-chain', 'runtime', 'chain-agnostic']

export const detectorCount = (chain: Chain) => ENGINE.byChain[chain] ?? 0

/** Detectors whose ids the web analyzer can run (static engines, not probe/symbolic). */
export const staticDetectorCount = () =>
  (['evm', 'solana', 'move', 'soroban', 'general', 'supply-chain', 'chain-agnostic'] as Chain[]).reduce(
    (n, c) => n + detectorCount(c),
    0,
  )

export const detectorById = (id: string) => ENGINE.detectors.find((d) => d.invariant_id === id)

/** `evm_reentrancy_classic` → `Reentrancy classic`. */
export const humanize = (id: string) =>
  id
    .replace(/^(evm|sol|move|sor|gen|sca|rt)_/, '')
    .replace(/_/g, ' ')
    .replace(/^./, (c) => c.toUpperCase())

// ─── Languages the dashboard accepts, and how the worker maps them ────────
// Keep in sync with lib/scan-worker-core.mjs (the worker cannot import TS).

export const LANGUAGES = [
  { id: 'solidity', label: 'Solidity', chain: 'evm', ext: '.sol', group: 'Smart contracts' },
  { id: 'rust', label: 'Solana / Anchor (Rust)', chain: 'solana', ext: '.rs', group: 'Smart contracts' },
  { id: 'soroban', label: 'Soroban (Rust)', chain: 'soroban', ext: '.rs', group: 'Smart contracts' },
  { id: 'move', label: 'Move (Aptos / Sui)', chain: 'move', ext: '.move', group: 'Smart contracts' },
  { id: 'python', label: 'Python', chain: 'general', ext: '.py', group: 'Application code' },
  { id: 'javascript', label: 'JavaScript', chain: 'general', ext: '.js', group: 'Application code' },
  { id: 'typescript', label: 'TypeScript', chain: 'general', ext: '.ts', group: 'Application code' },
  { id: 'go', label: 'Go', chain: 'general', ext: '.go', group: 'Application code' },
  { id: 'shell', label: 'Shell', chain: 'general', ext: '.sh', group: 'Application code' },
  { id: 'dockerfile', label: 'Dockerfile', chain: 'general', ext: 'Dockerfile', group: 'Infrastructure' },
  { id: 'terraform', label: 'Terraform', chain: 'general', ext: '.tf', group: 'Infrastructure' },
  { id: 'yaml', label: 'Kubernetes / CI workflow (YAML)', chain: 'general', ext: '.yml', group: 'Infrastructure' },
] as const

export type LanguageId = (typeof LANGUAGES)[number]['id']

export const languageForExtension = (name: string): LanguageId => {
  const lower = name.toLowerCase()
  if (lower === 'dockerfile' || lower.startsWith('dockerfile.')) return 'dockerfile'
  const ext = lower.split('.').pop() || ''
  const table: Record<string, LanguageId> = {
    sol: 'solidity', rs: 'rust', move: 'move', py: 'python', js: 'javascript', mjs: 'javascript', cjs: 'javascript',
    jsx: 'javascript', ts: 'typescript', tsx: 'typescript', go: 'go', sh: 'shell', bash: 'shell', tf: 'terraform',
    yml: 'yaml', yaml: 'yaml',
  }
  return table[ext] ?? 'solidity'
}

// ─── The CLI surface, for docs and marketing ───────────────────────────────

export const COMMANDS = [
  { cmd: 'scan', args: '<path> --chain evm|solana|move|soroban|general|auto', what: 'Static analysis with every applicable detector; --sarif for code scanning, --fail-on to gate CI.' },
  { cmd: 'deps', args: '<path> --advisory-db DIR --sbom FILE', what: 'Dependency analysis: RustSec/OSV matching, pinning, lockfile integrity, dependency confusion, typosquats; CycloneDX SBOM.' },
  { cmd: 'probe', args: '<url> --authorized', what: 'Live, non-exploitative check of a target you own: TLS, security headers, cookies, exposed files, open ports. Findings are proven.' },
  { cmd: 'symbolic', args: '<foundry-project>', what: 'Drives halmos / hevm / Mythril; a solver counterexample becomes a proven finding with the concrete input.' },
  { cmd: 'exposure', args: '<path> --probe-report FILE', what: 'How possible each finding is (LIKELY → THEORETICAL), which findings compose into attack chains, and the fix + verify step for each.' },
  { cmd: 'harden', args: '<path> --write', what: 'Generates preventive controls: secrets .gitignore, Dependabot, pre-commit, CI gate, security headers, test harnesses, runbooks.' },
  { cmd: 'release-check', args: '<path> --probe-report FILE --symbolic-report FILE --strict', what: 'The 33-section codebase safety checklist, item by item: PASS / FAIL / PARTIAL / MISSING / NEEDS-TOOL / ASSESS.' },
  { cmd: 'pathways', args: '[id]', what: 'The 21-class security-pathway map and how each class is covered: native detectors, hosted skills, manual controls.' },
  { cmd: 'assess', args: '<path>', what: 'Assessment of a repository against the whole pathway model.' },
  { cmd: 'threat-model', args: '<path>', what: 'STRIDE threat model from discovered routes, stores, outbound calls, secrets and auth markers.' },
  { cmd: 'taxonomy', args: '--format markdown|json', what: 'Every detector mapped to CWE, SWC, OWASP SC Top 10, DASP, MITRE ATT&CK and NIST CSF 2.0.' },
  { cmd: 'doctor', args: '', what: 'Self-tests every component with real fixtures; exits non-zero on failure.' },
] as const

export const EVIDENCE = {
  lead: { label: 'LEAD', title: 'Static inference — a pattern or dataflow the engine traced in source. Not demonstrated by execution.' },
  proven: { label: 'PROVEN', title: 'Observed on the wire (probe) or produced by a solver (symbolic): a concrete witness exists.' },
} as const

export const EXPLOITABILITY = {
  likely: { label: 'LIKELY', color: '#ef4444', title: 'Reachable from the network by anyone with nothing in hand — or observed live.' },
  possible: { label: 'POSSIBLE', color: '#fbbf24', title: 'Reachable from the network with a common precondition.' },
  unlikely: { label: 'UNLIKELY', color: '#818cf8', title: 'Needs a foothold, a condition, or a victim’s action.' },
  theoretical: { label: 'THEORETICAL', color: '#96a19a', title: 'Requires privileged access or an unusual condition; a hardening gap more than an attack path.' },
} as const

export type ExploitabilityId = keyof typeof EXPLOITABILITY
