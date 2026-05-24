import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mlDsa } from 'kxco-post-quantum'
import { attest, verify } from '../src/index.js'

// Generate once — keygen is the slow step
const keypair = mlDsa.ml_dsa65.keygen()
const otherKp = mlDsa.ml_dsa65.keygen()

test('attest: returns valid envelope shape', () => {
  const env = attest('hello', keypair)
  assert.equal(env['kxco-attest'], '1')
  assert.ok(typeof env.payload === 'string')
  assert.ok(typeof env.kid === 'string' && env.kid.length === 16)
  assert.ok(typeof env.issuedAt === 'string' && !isNaN(Date.parse(env.issuedAt)))
  assert.ok(typeof env.signature === 'string' && env.signature.length > 0)
})

test('verify: valid envelope returns valid=true and original payload', () => {
  const env = attest('round trip', keypair)
  const result = verify(env, keypair.publicKey)
  assert.equal(result.valid, true)
  assert.equal(Buffer.from(result.payload).toString('utf-8'), 'round trip')
  assert.equal(result.signerKid, env.kid)
  assert.equal(result.issuedAt, env.issuedAt)
})

test('verify: binary payload round-trips correctly', () => {
  const bytes = new Uint8Array([0, 1, 2, 3, 255, 254, 253])
  const env    = attest(bytes, keypair)
  const result = verify(env, keypair.publicKey)
  assert.equal(result.valid, true)
  assert.deepEqual(result.payload, bytes)
})

test('verify: wrong public key returns valid=false', () => {
  const env    = attest('test', keypair)
  const result = verify(env, otherKp.publicKey)
  assert.equal(result.valid, false)
  assert.equal(result.error, 'signature invalid')
})

test('verify: tampered payload returns valid=false', () => {
  const env     = attest('original', keypair)
  const tampered = { ...env, payload: env.payload.slice(0, -4) + 'AAAA' }
  const result  = verify(tampered, keypair.publicKey)
  assert.equal(result.valid, false)
})

test('verify: tampered signature returns valid=false', () => {
  const env     = attest('original', keypair)
  const tampered = { ...env, signature: env.signature.slice(0, -4) + 'AAAA' }
  const result  = verify(tampered, keypair.publicKey)
  assert.equal(result.valid, false)
})

test('verify: tampered issuedAt returns valid=false', () => {
  const env     = attest('original', keypair)
  const tampered = { ...env, issuedAt: '2000-01-01T00:00:00.000Z' }
  const result  = verify(tampered, keypair.publicKey)
  assert.equal(result.valid, false)
})

test('verify: missing signature field returns valid=false', () => {
  const { signature: _, ...noSig } = attest('x', keypair)
  assert.equal(verify(noSig, keypair.publicKey).valid, false)
})

test('verify: unsupported version returns valid=false', () => {
  const env    = { ...attest('x', keypair), 'kxco-attest': '99' }
  const result = verify(env, keypair.publicKey)
  assert.equal(result.valid, false)
  assert.equal(result.error, 'unsupported version')
})
