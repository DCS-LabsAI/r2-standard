# R+2 Test Vectors

This directory contains canonical test vectors for verifying R+2 conformance. Any implementation claiming R+2 compatibility MUST pass all the "MUST pass" vectors and MUST correctly reject all the "MUST fail" vectors.

## Format

Each test vector is a JSON file with this structure:

```json
{
  "name": "human-readable name",
  "description": "what this vector tests",
  "expected": "pass | fail",
  "expected_failure_reason": "specific reason if fail (null for pass)",
  "inputs": {
    "private_key_hex": "ed25519 32-byte private key in hex (test only)",
    "public_key_hex": "ed25519 32-byte public key in hex",
    "agent_id": "agent identity URI",
    "receipts": [
      { /* receipt 1 */ },
      { /* receipt 2 */ }
    ]
  }
}
```

## Test key

All test vectors use a fixed Ed25519 keypair derived from RFC 8032 §7.1 Test 1:

- **Seed (hex):** `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`
- **Private key (hex):** `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`
- **Public key (hex):** `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`
- **Agent ID:** `did:dcs:test:public-test-agent-001`

DO NOT use this keypair in production. It is published in RFC 8032 itself.

## Vectors

| # | File | Expected | What it tests |
|---|---|---|---|
| 01 | `01-genesis-valid.json` | pass | Valid genesis receipt (action_index 0) |
| 02 | `02-normal-chain.json` | pass | 3-receipt chain, all valid |
| 03 | `03-broken-chain-prev.json` | fail | Second receipt has wrong chain_prev |
| 04 | `04-tampered-payload.json` | fail | Payload hash modified after signing |
| 05 | `05-tampered-signature.json` | fail | Signature byte flipped |
| 06 | `06-monotonic-index-violation.json` | fail | action_index skips a value |
| 07 | `07-timestamp-regression.json` | fail | Timestamp goes backwards |
| 08 | `08-wrong-version-prefix.json` | fail | version field is "r+2" (missing version suffix) |
| 09 | `09-canonicalization-tolerance.json` | pass | Same receipt serialized two ways — must verify identically |
| 10 | `10-unicode-payload.json` | pass | Payload with full Unicode handling |

Vectors are short canonical examples, not full test suites. A complete implementation will additionally test fuzz inputs, performance, and identity-resolution edge cases not covered here.

## Running the vectors

The reference verifier `@trdnetwork/r2-verify` has a built-in test-vector runner:

```bash
npx @trdnetwork/r2-verify --test-vectors ./spec/test-vectors/
```

A third-party verifier can replicate this by:

1. Loading each `.json` file.
2. Running its verify() function against the receipts.
3. Comparing the result against `expected` and `expected_failure_reason`.

A conformant verifier passes all `expected: "pass"` vectors and rejects all `expected: "fail"` vectors with a reason matching `expected_failure_reason`.

## Submitting new vectors

To propose a new vector:

1. Open a PR adding a `.json` file in this directory.
2. Include rationale in the PR description.
3. Include the expected behaviour of `@trdnetwork/r2-verify` against the vector.

Vectors that catch real-world implementation bugs are welcome — these are the most valuable additions.

## Cross-implementation reports

When multiple independent R+2 verifier implementations exist, this directory will be the focal point for cross-implementation conformance reporting. We will publish a simple matrix:

| Implementation | Language | Vectors passed | Vectors failed |
|---|---|---|---|
| @trdnetwork/r2-verify | TypeScript | 10/10 | 0/10 |
| (future) r2-verify-py | Python | — | — |
| (future) r2-verify-rs | Rust | — | — |
| (future) r2-verify-go | Go | — | — |

---

*Test vectors are CC-BY-4.0 licensed. Use freely.*
