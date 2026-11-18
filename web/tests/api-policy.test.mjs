import test from 'node:test'
import assert from 'node:assert/strict'
import { checkoutAction, isUniqueConstraintError, scanListLimit, scanRateLimited } from '../lib/api-policy.ts'
import { spendFirstAvailable } from '../lib/credit-spend.ts'

test('scan list limits are finite integers clamped to the API bounds', () => {
  assert.equal(scanListLimit(null), 20)
  assert.equal(scanListLimit(''), 20)
  assert.equal(scanListLimit('nonsense'), 20)
  assert.equal(scanListLimit('-4'), 1)
  assert.equal(scanListLimit('2.9'), 2)
  assert.equal(scanListLimit('1000'), 100)
})

test('the sixth scan in a minute is refused', () => {
  assert.equal(scanRateLimited(4), false)
  assert.equal(scanRateLimited(5), true)
  assert.equal(scanRateLimited(6), true)
})

test('only Prisma unique-constraint failures are classified as signup conflicts', () => {
  assert.equal(isUniqueConstraintError({ code: 'P2002', meta: { target: ['email'] } }), true)
  assert.equal(isUniqueConstraintError({ code: 'P2024' }), false)
  assert.equal(isUniqueConstraintError(new Error('P2002')), false)
  assert.equal(isUniqueConstraintError(null), false)
})

test('checkout classification fails closed on incomplete or unpaid payloads', () => {
  assert.equal(checkoutAction({ id: 'x', metadata: { kind: 'credits', productId: 'scan_pack_25' }, payment_status: 'paid' }), null)
  assert.equal(checkoutAction({ id: 'x', metadata: { userId: 'u', kind: 'credits', productId: 'scan_pack_25' }, payment_status: 'unpaid' }), null)
  assert.equal(checkoutAction({ id: 'x', metadata: { userId: 'u', kind: 'subscription', planId: 'team' } }), null)
  assert.equal(checkoutAction({ id: 'x', metadata: { userId: 'u', kind: 'subscription', planId: 'team' }, subscription: 'sub', customer: 'cus', payment_status: 'unpaid' }), null)
  assert.equal(checkoutAction({ id: 'x', metadata: { userId: 'u', kind: 'subscription', planId: 'team' }, subscription: 'sub', payment_status: 'paid' }), null)
  assert.equal(checkoutAction({ id: 'x', metadata: { userId: 'u', kind: 'unknown' } }), null)
})

test('checkout classification returns one explicit fulfillment action', () => {
  assert.deepEqual(
    checkoutAction({ id: 'c', metadata: { userId: 'u', kind: 'credits', productId: 'scan_pack_25' }, payment_status: 'paid' }),
    { kind: 'credits', userId: 'u', productId: 'scan_pack_25' },
  )
  assert.deepEqual(
    checkoutAction({ id: 's', metadata: { userId: 'u', planId: 'team' }, subscription: { id: 'sub' }, customer: 'cus', payment_status: 'paid' }),
    { kind: 'subscription', userId: 'u', planId: 'team', subscriptionId: 'sub', customerId: 'cus' },
  )
})

test('credit spending retries the next candidate after losing a race', async () => {
  const attempted = []
  const spent = await spendFirstAvailable([{ id: 'oldest' }, { id: 'next' }], async (credit) => {
    attempted.push(credit.id)
    return credit.id === 'next'
  })
  assert.deepEqual(attempted, ['oldest', 'next'])
  assert.deepEqual(spent, { id: 'next' })
})

test('credit spending returns null when every conditional update loses', async () => {
  const spent = await spendFirstAvailable([{ id: 'a' }, { id: 'b' }], async () => false)
  assert.equal(spent, null)
})
