# kxco-pq-attest

Post-quantum attestations: sign arbitrary payloads with ML-DSA-65 (NIST FIPS 204). Produces a self-contained JSON envelope any counterparty can verify without trust delegation. Works in Node.js ≥ 20 and Cloudflare Workers.

## Install

```
npm install kxco-pq-attest
```

## Quick start

```js
import { attest, verify } from 'kxco-pq-attest'
import { mlDsa } from 'kxco-post-quantum'

const keypair = mlDsa.ml_dsa65.keygen()

// Sign a payload
const envelope = attest('hello world', keypair)
// {
//   "kxco-attest": "1",
//   payload: "<base64url>",
//   kid: "<fingerprint>",
//   issuedAt: "2026-05-24T...",
//   signature: "<base64url>"
// }

// Verify on any machine — no shared state required
const result = verify(envelope, keypair.publicKey)
// { valid: true, payload: Uint8Array, signerKid: '...', issuedAt: '...' }
```

## API

### `attest(payload, keypair)`

Signs `payload` (string or `Uint8Array`) with the ML-DSA-65 `keypair`. Returns a JSON-serialisable envelope object.

### `verify(envelope, publicKey)`

Verifies the envelope against `publicKey`. Returns `{ valid: true, payload, signerKid, issuedAt }` on success or `{ valid: false, error }` on failure.

## Envelope format

```json
{
  "kxco-attest": "1",
  "payload": "<base64url bytes>",
  "kid": "<16-hex SHA-256 prefix of signer public key>",
  "issuedAt": "<ISO 8601>",
  "signature": "<base64url ML-DSA-65 signature>"
}
```

The signing message is `kxco-attest-v1\n<payloadB64>\n<kid>\n<issuedAt>` — no field can be silently reordered or replayed against a different timestamp without breaking the signature.

## CLI

```
kxco-pq attest sign   --secret-key sk.hex --public-key pk.hex --file payload.bin
kxco-pq attest verify --public-key pk.hex --attestation envelope.json
```

Requires [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli).

## Related packages

| Package | Role |
|---|---|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-DSA-65 / ML-KEM-768 primitives |
| [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) | HSM-backed key storage |
| [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) | Tamper-evident operation log |
| [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) | `KxcoIdentity` unified API |

## License

Apache-2.0 © 2026 KXCO by Knightsbridge
