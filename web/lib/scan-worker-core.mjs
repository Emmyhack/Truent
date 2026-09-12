import { createHash } from 'node:crypto'

// Keep in sync with lib/engine.ts LANGUAGES (the worker cannot import TS).
const LANGUAGES = {
  solidity: { chain: 'evm', file: 'contract.sol' },
  rust: { chain: 'solana', file: 'program.rs' },
  soroban: { chain: 'soroban', file: 'contract.rs' },
  move: { chain: 'move', file: 'module.move' },
  python: { chain: 'general', file: 'app.py' },
  javascript: { chain: 'general', file: 'app.js' },
  typescript: { chain: 'general', file: 'app.ts' },
  go: { chain: 'general', file: 'main.go' },
  shell: { chain: 'general', file: 'script.sh' },
  dockerfile: { chain: 'general', file: 'Dockerfile' },
  terraform: { chain: 'general', file: 'main.tf' },
  yaml: { chain: 'general', file: 'deployment.yaml' },
}

export const SUPPORTED_LANGUAGES = Object.keys(LANGUAGES)
export const chainFor = (language) => LANGUAGES[language]?.chain
/** The file name the source is written to; detectors classify by name. */
export const fileNameFor = (language) => LANGUAGES[language]?.file
/** Kept for callers that only want the extension. */
export const extensionFor = (language) => {
  const f = fileNameFor(language)
  if (!f) return undefined
  const i = f.lastIndexOf('.')
  return i === -1 ? '' : f.slice(i)
}

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info'])
const EXPLOITABILITY = new Set(['likely', 'possible', 'unlikely', 'theoretical'])

/**
 * Map one `violations[]` entry of `truent scan --output json` to a durable
 * Finding row. The engine emits `file`/`line` separately from the display
 * `location`, its `recommendation` is the exposure table's fix, and
 * `evidence` is the honesty contract ("lead" | "proven").
 */
export function mapFinding(scanId, finding) {
  const rawSeverity = String(finding.severity || 'low').toLowerCase()
  const severity = SEVERITIES.has(rawSeverity) ? rawSeverity : 'low'
  const invariantId = typeof finding.invariant_id === 'string' && finding.invariant_id ? finding.invariant_id : null
  const title = finding.title || (invariantId ? invariantId.replaceAll('_', ' ') : 'security finding')
  const description = String(finding.message || 'Security issue detected')

  // Older engine output carried only `location: "file:line"`.
  let file = typeof finding.file === 'string' && finding.file ? finding.file : null
  let line = Number.isInteger(finding.line) && finding.line > 0 ? finding.line : null
  if (!file && typeof finding.location === 'string') {
    const m = finding.location.match(/^(.*):(\d+)$/)
    if (m) { file = m[1]; line = Number(m[2]) || null } else file = finding.location || null
  }
  const location = file ? `${file}${line ? ` · Line ${line}` : ''}` : null

  const evidence = finding.evidence === 'proven' ? 'proven' : 'lead'
  const exploitability = EXPLOITABILITY.has(finding.exploitability) ? finding.exploitability : null
  const fix = typeof finding.fix === 'string' && finding.fix ? finding.fix : null
  const verify = typeof finding.verify === 'string' && finding.verify ? finding.verify : null
  const recommendation = fix || finding.recommendation || 'Review this finding and apply the relevant invariant guidance.'
  const reasons = Array.isArray(finding.exploit_reasons) ? finding.exploit_reasons.filter((r) => typeof r === 'string') : []
  const impact = reasons.length
    ? `${evidence === 'proven' ? 'Proven. ' : ''}${reasons.join('; ')}`
    : evidence === 'proven' ? 'Proven: observed on the wire or produced by a solver.' : null

  const fingerprint = createHash('sha256')
    .update(`${severity}\0${invariantId || title}\0${file || ''}\0${line || ''}`)
    .digest('hex')

  return {
    scanId, severity, title, description, location, line, impact, recommendation, fingerprint,
    invariantId,
    chain: typeof finding.chain === 'string' ? finding.chain : null,
    evidence, exploitability, fix, verify,
    cwe: typeof finding.cwe === 'string' && finding.cwe ? finding.cwe : null,
    snippet: typeof finding.code_snippet === 'string' && finding.code_snippet ? finding.code_snippet.slice(0, 2000) : null,
  }
}
