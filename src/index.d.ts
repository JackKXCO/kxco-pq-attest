/// <reference types="node" />

export interface Keypair {
  publicKey: Uint8Array | Buffer
  secretKey: Uint8Array | Buffer
}

export interface AttestationEnvelope {
  'kxco-attest': '1'
  payload:      string   // base64url-encoded payload bytes
  kid:          string   // 16-hex fingerprint of the signing public key
  issuedAt:     string   // ISO 8601 timestamp
  signature:    string   // base64url-encoded ML-DSA-65 signature
  chainAnchor?: { txHash: string; blockNumber: number }
}

/** Minimal chain client interface — accepts kxco-pq-chain KxcoChain instances */
export interface AttestChainClient {
  anchorAttestation(opts: { payloadHash: string; purpose: string }): Promise<{ txHash: string; blockNumber: number }>
}

export interface AttestOptions {
  /** If true, anchors the envelope hash on-chain via `chain`. Requires `chain`. */
  anchor?: boolean
  /** Purpose string for the on-chain anchor (e.g. 'regulatory-report'). Required when anchor=true. */
  purpose?: string
  /** kxco-pq-chain KxcoChain instance. */
  chain?: AttestChainClient
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
 * Pass `{ anchor: true, purpose, chain }` to also anchor the envelope hash on-chain.
 */
export function attest(
  payload: string | Uint8Array | Buffer,
  keypair: Keypair,
  opts?: AttestOptions,
): Promise<AttestationEnvelope>

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
