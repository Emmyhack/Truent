// Regenerate lib/catalog.json from the engine so the site never describes
// detectors, pathways or attack chains the binary does not have.
//
//   TRUENT_BINARY=../target/release/truent node scripts/sync-catalog.mjs
import { execFileSync } from 'node:child_process'
import { writeFileSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const bin = process.env.TRUENT_BINARY || 'truent'
const run = (...args) => JSON.parse(execFileSync(bin, args, { encoding: 'utf8', maxBuffer: 64 << 20 }))

const tax = run('taxonomy', '--format', 'json')
const pathways = run('pathways', '--format', 'json')
const exposure = run('exposure', path.join(here, '..', '..', 'examples', 'foundry'), '--format', 'json')
const version = execFileSync(bin, ['--version'], { encoding: 'utf8' }).trim()

const byChain = {}
for (const d of tax.detectors) byChain[d.chain || 'chain-agnostic'] = (byChain[d.chain || 'chain-agnostic'] || 0) + 1

const catalog = {
  generated_from: version,
  total_detectors: tax.total,
  by_chain: byChain,
  detectors: tax.detectors,
  pathways,
  attack_chains: exposure.known_chains.map(({ id, name, narrative, tactics, steps, break_at }) => ({ id, name, narrative, tactics, steps, break_at })),
}
const out = path.join(here, '..', 'lib', 'catalog.json')
const before = (() => { try { return readFileSync(out, 'utf8') } catch { return '' } })()
const next = JSON.stringify(catalog, null, 1) + '\n'
writeFileSync(out, next)
console.log(`${before === next ? 'unchanged' : 'updated'}: ${catalog.total_detectors} detectors, ${pathways.length} pathways, ${catalog.attack_chains.length} attack chains (${version})`)
