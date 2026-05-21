# @trdnetwork/r2-verify

[![npm version](https://img.shields.io/npm/v/@trdnetwork/r2-verify.svg)](https://www.npmjs.com/package/@trdnetwork/r2-verify)
[![Spec](https://img.shields.io/badge/spec-R%2B2%20v0.1-blue)](https://dcslabs.ai/standard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Reference verifier for the **R+2 Open Provenance Standard** — cryptographically verify AI agent action receipts (Ed25519 + RFC 8785 canonical JSON).

> The full specification is at [https://dcslabs.ai/standard](https://dcslabs.ai/standard).

## Install

```bash
# Global CLI
npm install -g @trdnetwork/r2-verify

# Or use as a library in your project
npm install @trdnetwork/r2-verify
```

Requires Node 18+.

## CLI usage

```bash
# Verify a single receipt with the agent's expected public key
r2-verify --receipt action.json \
          --pubkey u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o
```

Output:

```
✓ Schema
✓ Spec version  r2/v0.1
✓ Pubkey match  u4yK_lH8Z6vJ...
✓ Signature
✓ Chain pointer  first receipt (null)
✓ Timestamp  within ±24h window

Receipt verified.
```

### Pipe from stdin

```bash
curl -s https://api.dcslabs.ai/api/receipts/r2_a83f12cd | jq .receipt \
  | r2-verify --pubkey u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o
```

### Full chain verification

To verify the chain pointer (§9 of the spec), pass the previous receipt:

```bash
r2-verify --receipt action_0002.json \
          --previous action_0001.json \
          --pubkey u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o
```

### Machine-readable output

```bash
r2-verify --receipt action.json --pubkey ... --json
```

```json
{
  "ok": true,
  "checks": [
    { "name": "Schema", "pass": true },
    { "name": "Spec version", "pass": true, "detail": "r2/v0.1" },
    { "name": "Pubkey match", "pass": true, "detail": "u4yK_lH8Z6vJ..." },
    { "name": "Signature", "pass": true },
    { "name": "Chain pointer", "pass": true, "detail": "first receipt (null)" },
    { "name": "Timestamp", "pass": true, "detail": "within ±24h window" }
  ]
}
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Receipt is valid |
| `1` | Receipt is invalid (signature, schema, or chain failure) |
| `2` | CLI usage error (missing args, bad input) |

Use these in CI/CD pipelines or audit scripts.

## Library usage

```js
import { verifyReceipt, computeReceiptCid } from "@trdnetwork/r2-verify";

const receipt = await fetch("https://api.dcslabs.ai/api/receipts/r2_a83f12cd")
                       .then(r => r.json())
                       .then(j => j.receipt);

const expectedPubkey = "u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o";

const result = await verifyReceipt(receipt, expectedPubkey);
if (result.ok) {
  console.log("Receipt verified, safe to trust");
} else {
  console.error("Receipt rejected:", result.error);
}
```

### Options

```js
await verifyReceipt(receipt, expectedPubkey, {
  // Pass the previous receipt to verify §9 chain pointer
  previousReceipt: prevReceipt,

  // Skip the ±24h timestamp sanity check (useful for verifying historical receipts)
  skipTimestampCheck: true,
});
```

### Compute the CID of a signed receipt

If you're building an issuer (writing receipts), you need to compute the CID of receipt N to populate `prev_receipt_cid` in receipt N+1:

```js
import { computeReceiptCid } from "@trdnetwork/r2-verify";

const cid = computeReceiptCid(receiptN);    // "sha256:bafy2bzaceabc..."
const receiptNPlus1 = {
  // ...
  prev_receipt_cid: cid,
  // ...
};
```

## What gets verified

Per [§8 of the R+2 spec](https://dcslabs.ai/standard#verification):

1. **Schema** — all required fields present, correct types and value ranges (per [§4](https://dcslabs.ai/standard#schema))
2. **Spec version** — receipt's `spec_version` equals one the verifier supports
3. **Pubkey match** — receipt's `agent_pubkey` equals the public key obtained from the identity layer
4. **Signature** — Ed25519 verification (RFC 8032) over the canonical JSON form (RFC 8785) of the receipt with `signature` excluded
5. **Chain pointer** — if `prev_receipt_cid` is not null, fetch the previous receipt and check the CID matches (when `--previous` is provided)
6. **Timestamp sanity** — `occurred_at` within ±24h of verification time (warning only, not failure)

## What this verifier does NOT do

- **It does not contact the issuer.** That's the whole point of R+2 — verification is independent of the issuer.
- **It does not fetch the expected public key for you.** You obtain that from your identity layer (DNS, on-chain SBT, DID document) before calling `verifyReceipt`. Common patterns are documented in the [DCS Labs identity guide](https://dcslabs.ai/identity).
- **It does not decrypt the `action_data` content.** R+2 receipts are integrity-protected, not confidentiality-protected. If your receipt contains encrypted action data, decrypt it separately after verification.

## Conformance

This package implements R+2 v0.1 per the published specification at [https://dcslabs.ai/standard](https://dcslabs.ai/standard). It is the **reference implementation**, but any conforming implementation is equally valid. We expect at least three independent verifiers to emerge in 2026.

If you build an alternative implementation and want it cross-tested against this one, open an issue at [github.com/DCS-LabsAI/r2-standard](https://github.com/DCS-LabsAI/r2-standard).

## Security

If you discover a cryptographic or verification flaw, please email **security@dcslabs.ai** privately. We follow [responsible-disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure) practices and credit reporters in our security advisories.

Do **not** open public GitHub issues for security bugs.

## License

MIT. See [LICENSE](./LICENSE).

## Contact

- Editorial: [standards@dcslabs.ai](mailto:standards@dcslabs.ai)
- Security: [security@dcslabs.ai](mailto:security@dcslabs.ai)
- Source: [github.com/DCS-LabsAI/r2-standard](https://github.com/DCS-LabsAI/r2-standard)
- Spec: [https://dcslabs.ai/standard](https://dcslabs.ai/standard)
