import test from 'node:test'
import assert from 'node:assert/strict'
import { chainFor, extensionFor, fileNameFor, mapFinding, SUPPORTED_LANGUAGES } from '../lib/scan-worker-core.mjs'

test('maps every supported language to an engine and a file name', () => {
  assert.deepEqual(
    ['solidity', 'rust', 'move', 'soroban', 'python', 'go'].map((l) => [chainFor(l), extensionFor(l)]),
    [['evm', '.sol'], ['solana', '.rs'], ['move', '.move'], ['soroban', '.rs'], ['general', '.py'], ['general', '.go']],
  )
  assert.equal(fileNameFor('dockerfile'), 'Dockerfile')
  assert.equal(extensionFor('dockerfile'), '')
  assert.equal(chainFor('cairo'), undefined)
  assert.equal(SUPPORTED_LANGUAGES.length, 12)
})

test('maps the engine JSON contract to a durable finding', () => {
  const finding = mapFinding('scan-1', {
    invariant_id: 'gen_command_injection', title: 'Gen Command Injection', severity: 'high', chain: 'general',
    file: 'app.py', line: 9, location: 'app.py:9', evidence: 'lead', exploitability: 'likely',
    exploit_reasons: ['reachable by anyone who can reach the service', 'no account, token or role needed'],
    message: 'tainted value `host` reaches a shell command',
    fix: 'Invoke programs with an argument array (no shell).', verify: 'Taint test: source→shell flow no longer present.',
    recommendation: 'Invoke programs with an argument array (no shell).',
    cwe: "CWE-78 · Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    code_snippet: 'subprocess.run(f"ping -c 1 {host}", shell=True)',
  })
  assert.equal(finding.title, 'Gen Command Injection')
  assert.equal(finding.invariantId, 'gen_command_injection')
  assert.equal(finding.location, 'app.py · Line 9')
  assert.equal(finding.line, 9)
  assert.equal(finding.evidence, 'lead')
  assert.equal(finding.exploitability, 'likely')
  assert.equal(finding.recommendation, 'Invoke programs with an argument array (no shell).')
  assert.equal(finding.verify, 'Taint test: source→shell flow no longer present.')
  assert.match(finding.impact, /reachable by anyone/)
  assert.equal(finding.chain, 'general')
  assert.match(finding.cwe, /^CWE-78/)
  assert.equal(finding.fingerprint.length, 64)
})

test('legacy output with only location still yields file and line', () => {
  const f = mapFinding('s', { invariant_id: 'evm_reentrancy_classic', severity: 'critical', location: 'Vault.sol:42', message: 'm' })
  assert.equal(f.location, 'Vault.sol · Line 42')
  assert.equal(f.line, 42)
  assert.equal(f.evidence, 'lead')
  assert.equal(f.exploitability, null)
})

test('proven findings and unknown values fail safe', () => {
  const p = mapFinding('s', { invariant_id: 'rt_missing_hsts', severity: 'medium', file: 'https://x', line: 1, evidence: 'proven', exploitability: 'weird', message: 'm' })
  assert.equal(p.evidence, 'proven')
  assert.equal(p.exploitability, null)
  assert.match(p.impact, /^Proven/)
  const input = { invariant_id: 'x', severity: 'unknown', file: 'x.sol', line: 1, message: 'x' }
  assert.equal(mapFinding('a', input).severity, 'low')
  assert.equal(mapFinding('a', input).fingerprint, mapFinding('a', input).fingerprint)
})
