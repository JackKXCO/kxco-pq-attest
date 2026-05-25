/// <reference types="node" />

export interface Keypair {
  publicKey: Uint8Array | Buffer
  secretKey: Uint8Array | Buffer
}

export interface AttestationEnvelope {
  'kxco-attest': '1'
  payload:   string   // base64url-encoded payload bytes
  kid:       string   // 16-hex fingerprint of the signing public key
  issuedAt:  string   // ISO 8601 timestamp
  signature: string   // base64url-encoded ML-DSA-65 signature
}

export interface VerifySuccess {
  valid:     true
  payload:   Uint8Array
  signerKid: string
  issuedAt:  string
}

export interface VerifyFailure {
  valid: false
  error: 'malformed envelope' | 'unsupported version' | 'signature invalid'
}

export type VerifyResult = VerifySuccess | VerifyFailure

/**
 * Sign a payload with ML-DSA-65 and return a self-contained attestation
 * envelope any counterparty can verify without contacting any server.
 */
export function attest(
  payload: string | Uint8Array | Buffer,
  keypair: Keypair,
): AttestationEnvelope

/**
 * Verify an attestation envelope.
 * Returns `{ valid: true, payload, signerKid, issuedAt }` on success,
 * or `{ valid: false, error }` on any failure.
 */
export function verify(
  envelope:  unknown,
  publicKey: Uint8Array | Buffer,
): VerifyResult

export class KxcoPqAttestError extends Error {
  name: 'KxcoPqAttestError'
}
