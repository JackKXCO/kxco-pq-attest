import { mlDsa, fingerprint } from 'kxco-post-quantum'

const VERSION = '1'

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64url')
}

function fromB64url(str) {
  return new Uint8Array(Buffer.from(str, 'base64url'))
}

function signingMsg(payloadB64, kid, issuedAt) {
  const enc = new TextEncoder()
  const parts = [
    enc.encode('kxco-attest-v1\n'),
    enc.encode(payloadB64),
    enc.encode('\n'),
    enc.encode(kid),
    enc.encode('\n'),
    enc.encode(issuedAt),
  ]
  const len = parts.reduce((n, a) => n + a.length, 0)
  const msg = new Uint8Array(len)
  let off = 0
  for (const p of parts) { msg.set(p, off); off += p.length }
  return msg
}

export function attest(payload, keypair) {
  const payloadBytes = typeof payload === 'string'
    ? new TextEncoder().encode(payload)
    : new Uint8Array(payload)

  const payloadB64 = b64url(payloadBytes)
  const kid        = fingerprint(keypair.publicKey)
  const issuedAt   = new Date().toISOString()
  const msg        = signingMsg(payloadB64, kid, issuedAt)
  const sig        = mlDsa.ml_dsa65.sign(new Uint8Array(keypair.secretKey), msg)

  return {
    'kxco-attest': VERSION,
    payload:   payloadB64,
    kid,
    issuedAt,
    signature: b64url(sig),
  }
}

export function verify(envelope, publicKey) {
  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, error: 'malformed envelope' }
  }
  if (envelope['kxco-attest'] !== VERSION) {
    return { valid: false, error: 'unsupported version' }
  }

  const { payload: payloadB64, kid, issuedAt, signature } = envelope
  if (!payloadB64 || !kid || !issuedAt || !signature) {
    return { valid: false, error: 'malformed envelope' }
  }

  const msg = signingMsg(payloadB64, kid, issuedAt)
  let ok
  try {
    ok = mlDsa.ml_dsa65.verify(new Uint8Array(publicKey), msg, fromB64url(signature))
  } catch {
    ok = false
  }

  if (!ok) return { valid: false, error: 'signature invalid' }

  return {
    valid:     true,
    payload:   fromB64url(payloadB64),
    signerKid: kid,
    issuedAt,
  }
}
