# R+2 Conformance Test Vectors

Canonical, fully-materialized test vectors for the **R+2 Open Provenance
Standard, schema `r2/v0.1`**. Any implementation claiming R+2 conformance MUST
verify every `expected: "pass"` vector and MUST reject every
`expected: "fail"` vector at the indicated check.

These vectors carry **real, frozen Ed25519 signatures** — there are no
`COMPUTED_AT_RUNTIME` placeholders. A verifier can replay them with no key
material and no signing step of its own.

## Schema

Vectors target the canonical `r2/v0.1` receipt — the schema the reference
verifier [`@trdnetwork/r2-verify`](https://www.npmjs.com/package/@trdnetwork/r2-verify)
implements. A receipt has exactly these fields:

```
spec_version  agent_pubkey  agent_id  action_id  action_type
action_data   occurred_at   prev_receipt_cid  nonce  extensions  signature
```

> Earlier vectors used an obsolete `r+2/0.1.0` field layout
> (`action_index`, `payload_hash`, `chain_self`, …). They were never runnable
> and have been replaced. If you have an old checkout, regenerate.

## Vector file format

```json
{
  "name": "human-readable name",
  "description": "what this vector tests",
  "expected": "pass | fail",
  "expected_check": "the verifier check that must fail (null when expected=pass)",
  "expected_pubkey": "base64url Ed25519 key the verifier is given",
  "chain": true,
  "receipts": [ { /* signed r2/v0.1 receipt */ } ]
}
```

`chain: true` means the receipts form a sequence — each receipt after the
first is verified with the previous one supplied, so the chain-pointer check
(`prev_receipt_cid`) is exercised.

## Test key

All vectors use a fixed Ed25519 keypair from **RFC 8032 §7.1 Test 1** — a
published value. **Never use it in production.**

- Seed (hex): `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`
- Agent ID: `did:dcs:test:public-test-agent-001`

Vector 06 additionally uses RFC 8032 §7.1 Test 2 as a second, mismatched key.

## Vectors

| # | File | Expected | Fails at | What it tests |
|---|------|----------|----------|---------------|
| 01 | `01-genesis-valid.json` | pass | — | Genesis receipt, `prev_receipt_cid: null` |
| 02 | `02-normal-chain.json` | pass | — | 3-receipt chain, all pointers correct |
| 03 | `03-broken-chain-prev.json` | fail | Chain pointer | Receipt 2's `prev_receipt_cid` does not match receipt 1 |
| 04 | `04-tampered-payload.json` | fail | Signature | `action_data` modified after signing |
| 05 | `05-tampered-signature.json` | fail | Signature | One signature byte flipped |
| 06 | `06-wrong-pubkey.json` | fail | Pubkey match | Receipt self-signed by a different key |
| 07 | `07-wrong-spec-version.json` | fail | Spec version | `spec_version` is `r2/v0.2` |
| 08 | `08-schema-missing-field.json` | fail | Schema | Required `nonce` field removed |
| 09 | `09-canonicalization-tolerance.json` | pass | — | Keys reordered — JCS must normalise to identical bytes |
| 10 | `10-unicode-payload.json` | pass | — | CJK / RTL / emoji / combining chars in payload |

`manifest.json` lists the suite programmatically.

## Running the suite

With the reference verifier:

```bash
npx @trdnetwork/r2-verify --test-vectors ./spec/test-vectors/
# or, from the r2-verify checkout:
npm run conformance
```

Expected output: `10/10 vectors passed`.

A third-party verifier replicates this by, for each vector file: loading it,
running `verify()` on each receipt (supplying the previous receipt when
`chain` is true), and confirming the verdict matches `expected` — and, for
failures, that the first failing check matches `expected_check`.

## Regenerating

The vectors are produced by `scripts/gen-vectors.mjs` in the `@trdnetwork/r2-verify`
package (`npm run gen-vectors`). Regenerate after any schema change so the
frozen signatures stay valid.

## Cross-implementation conformance matrix

| Implementation | Language | Vectors passed |
|---|---|---|
| `@trdnetwork/r2-verify` | JavaScript | 10 / 10 |
| (future) `r2-verify-py` | Python | — |
| (future) `r2-verify-rs` | Rust | — |

---

*Test vectors are CC-BY-4.0 licensed. Use freely.*
