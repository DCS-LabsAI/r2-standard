# R+2 — Open Provenance Standard

[![Spec](https://img.shields.io/badge/spec-r2%2Fv0.1-blue)](https://dcslabs.ai/standard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-public%20draft-orange)](https://dcslabs.ai/standard#governance)
[![npm](https://img.shields.io/npm/v/@trdnetwork/r2-verify.svg?label=r2-verify)](https://www.npmjs.com/package/@trdnetwork/r2-verify)
[![npm](https://img.shields.io/npm/v/@trdnetwork/mcp-server.svg?label=mcp-server)](https://www.npmjs.com/package/@trdnetwork/mcp-server)

> An open, free-to-adopt specification for cryptographically signed AI agent action receipts.
> Ed25519 + RFC 8785 canonical JSON + hash-chained receipts. MIT-licenced.

**🌐 Full spec:** https://dcslabs.ai/standard
**📦 Reference verifier:** [`@trdnetwork/r2-verify`](https://www.npmjs.com/package/@trdnetwork/r2-verify)
**📦 Reference MCP server:** [`@trdnetwork/mcp-server`](https://www.npmjs.com/package/@trdnetwork/mcp-server)
**🔗 On-chain identity layer:** [TRDWorkerSBT on Base mainnet](https://basescan.org/address/0xbDd1f5fC349D9a8EfCEb07Edbd491233b2540f5F)

---

## What is R+2?

AI agents are starting to do real economic work — sign contracts, hold budgets, negotiate with other agents, present audit trails to regulators. But there's no shared open standard for how an agent's actions get signed and made independently verifiable.

R+2 is a small, deliberately minimal specification that defines:

- **The shape of an agent action receipt** — 11 required JSON fields, schema-versioned
- **The signing flow** — Ed25519 (RFC 8032) over RFC 8785 canonical JSON
- **The hash chain** — every receipt links to the previous one by content hash, making tampering immediately detectable
- **The verification flow** — client-side, no need to trust the issuing vendor

Receipts can optionally be pinned to IPFS / Filecoin for permanence beyond the issuer's infrastructure. The standard is chain-agnostic (we use Base mainnet for the reference identity layer, but DNS / DID / any identity source works).

---

## Quick start

### Verify a receipt (5 seconds)

```bash
# No install — npx pulls it on-demand
npx @trdnetwork/r2-verify --receipt receipt.json \
    --pubkey u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o
```

Output:
```
✓ Schema
✓ Spec version  r2/v0.1
✓ Pubkey match
✓ Signature
✓ Chain pointer
✓ Timestamp

Receipt verified.
```

### Produce a receipt (via the reference MCP server)

```bash
npm install @trdnetwork/mcp-server
```

Then mount in your agent and every tool call automatically produces a signed R+2 receipt. Full integration guide at [dcslabs.ai/mcp](https://dcslabs.ai).

---

## Why this is a separate spec rather than another use of W3C VC

We considered Verifiable Credentials (W3C VC) and found that the data-model overhead (issuer, holder, subject, multiple proof formats) added cost without value for high-volume action streams.

R+2 is deliberately lighter:
- One JSON envelope, 11 fields
- One signature primitive (Ed25519)
- One canonicalization scheme (RFC 8785)
- Hash-chained, not Merkle-tree

If you need W3C VC semantics, you can embed an R+2 receipt inside a VC's `credentialSubject`. The two coexist.

---

## Status

This is `r2/v0.1` — a **public draft** open for comment. The standard was published 2026-05-19 and submitted to:

- **Anthropic Standards Program** (private-sector AI standards)
- **MeitY** (Ministry of Electronics and Information Technology, India)
- **ISRO** (Indian Space Research Organisation — for satellite data provenance use case)

The intended trajectory:

| Version | Editorial model | Trigger |
|---|---|---|
| v0.1 (now) | Single-editor draft (DCS AI Technologies) | Public comment open |
| v0.2 | Expanded editorial group (2-3 adopting orgs) | First standards-body acknowledgment |
| v1.0 | Multi-stakeholder ratification | Proposed to W3C-AI WG or equivalent |

DCS Labs will **not** hold a veto over any future version. The spec is MIT-licenced from v0.1 onward and can be forked at any time.

---

## Repository structure

```
r2-standard/
├── spec/
│   ├── r2-v0.1.md           # The canonical specification (Markdown source for dcslabs.ai/standard)
│   ├── profiles/            # Sectoral profiles
│   │   ├── r2-health-v1.md
│   │   ├── r2-gov-v1.md
│   │   └── r2-finance-v1.md
│   └── changelog.md
├── examples/
│   ├── memory-write.json    # Worked example: a Sovereign Memory write receipt
│   ├── a2a-negotiate.json   # Worked example: an agent-to-agent negotiation
│   └── full-chain.json      # 5-receipt chain demonstrating §9
├── contracts/
│   └── TRDWorkerSBT.sol     # Reference on-chain identity contract (deployed on Base mainnet)
├── verifier/                # Reference verifier — also published as @trdnetwork/r2-verify
│   ├── bin/
│   ├── lib/
│   └── test/
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
└── LICENSE
```

The actual production code for the reference implementations lives in separate repos:
- **Verifier:** [DCS-LabsAI/r2-verify](https://github.com/DCS-LabsAI/r2-verify) → published as `@trdnetwork/r2-verify`
- **MCP server:** [TRDnetwork/trd-mcp-server](https://github.com/TRDnetwork/trd-mcp-server) → published as `@trdnetwork/mcp-server`
- **SBT contract:** lives in this repo under `contracts/`, deployed on Base mainnet

---

## How to adopt R+2

### For an AI vendor (issuer-side)

1. Generate an Ed25519 keypair per agent. Store the private key in a secrets manager.
2. Publish the public key to a discoverable identity layer — DNS TXT records, on-chain registry (we use Base mainnet SBTs), DID documents, or a simple HTTPS key endpoint.
3. For every action your agent takes, construct an R+2 receipt and sign it (per [§7 of the spec](https://dcslabs.ai/standard#signing)).
4. Store receipts in a queryable database. Postgres works fine. Index by `agent_id`, `action_id`, `occurred_at`.
5. Expose a public read endpoint for receipt retrieval: `GET /receipts/<action_id>` returning the JSON.
6. Optionally pin receipts to IPFS for durability beyond your servers.

### For a regulator or downstream consumer (verifier-side)

1. Establish a process for obtaining the agent's expected public key (typically via the identity layer in use).
2. Run the verification flow from [§8 of the spec](https://dcslabs.ai/standard#verification) on every receipt before trusting its claims.
3. For sensitive decisions, walk the chain back to a known anchor.
4. Use the reference verifier (`@trdnetwork/r2-verify`) or implement your own — both equally conformant.

---

## How to contribute

We welcome:

- **Spec issues** — open a GitHub Issue with a clear description, citations to relevant RFCs/standards, and your proposed resolution.
- **Reference implementations in new languages** — Python, Go, Rust, Java verifiers are all welcome. Submit a PR with conformance test results against `examples/`.
- **Sectoral profiles** — new profiles (e.g., `r2-edu-v1`, `r2-pharma-v1`) should follow the structure in `spec/profiles/`.
- **Security findings** — see [SECURITY.md](SECURITY.md). Email `security@dcslabs.ai` privately, do not open public issues for security bugs.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full PR workflow.

---

## License

The specification and reference implementations are released under the [MIT License](LICENSE). DCS AI Technologies L.L.C holds no patents covering R+2 and has filed none.

Contributors who submit changes sign a contribution agreement granting an irrevocable royalty-free patent licence. We're not in this to build a patent thicket.

---

## Contact

- **Editorial:** standards@dcslabs.ai
- **Security:** security@dcslabs.ai (PGP key at dcslabs.ai/security/pgp.txt)
- **Source-of-truth spec:** https://dcslabs.ai/standard
- **Status:** [![status](https://img.shields.io/badge/status-public%20draft-orange)](https://dcslabs.ai/standard#governance) — open for public comment as of 2026-05-19

— DCS AI Technologies L.L.C, Dubai
