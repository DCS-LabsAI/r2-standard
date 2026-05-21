#!/usr/bin/env node
/**
 * gen-vectors.mjs — Regenerate the R+2 conformance test-vector suite.
 *
 * Produces fully-materialized, frozen-signature test vectors in the canonical
 * r2/v0.1 schema (the schema the reference verifier @trdnetwork/r2-verify
 * actually implements). Earlier vectors used the obsolete `r+2/0.1.0` field
 * layout and carried `COMPUTED_AT_RUNTIME` placeholders — they were not
 * runnable. These are real, signed, and stable: any verifier can replay them
 * with no key material or signing step of its own.
 *
 * Test key: RFC 8032 §7.1 Test 1 (published — NEVER use in production).
 *   seed = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
 *
 * Run:  node scripts/gen-vectors.mjs
 * Out:  ../r2-standard-repo/spec/test-vectors/*.json
 */
import { ed25519 } from "@noble/curves/ed25519";
import canonicalize from "canonicalize";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { computeReceiptCid } from "../lib/verify.js";

const HERE = dirname(fileURLToPath(import.meta.url));
// This package lives at r2-standard-repo/verifier/ — the spec test-vectors
// are two levels up at ../spec/test-vectors. Fall back to a local dir.
const OUT_CANDIDATES = [
  resolve(HERE, "../../spec/test-vectors"),
  resolve(HERE, "../test-vectors"),
];
const OUT = OUT_CANDIDATES.find(p => existsSync(p)) || OUT_CANDIDATES[1];
mkdirSync(OUT, { recursive: true });

// —— Test keypairs ————————————————————————————————————————————————
// Key 1 — RFC 8032 §7.1 Test 1 (the canonical test key).
const SEED1 = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
// Key 2 — RFC 8032 §7.1 Test 2 (used only for the wrong-pubkey vector).
const SEED2 = Buffer.from("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "hex");

function pubB64(seed) { return Buffer.from(ed25519.getPublicKey(seed)).toString("base64url"); }
const PUB1 = pubB64(SEED1);
const PUB2 = pubB64(SEED2);

// —— Receipt helpers ——————————————————————————————————————————————
const AGENT_ID = "did:dcs:test:public-test-agent-001";
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const nonce = (n) => Buffer.alloc(16, n).toString("base64url"); // deterministic 16-byte nonce
const TS = "2026-05-20T00:00:00.000Z";                          // frozen timestamp

/** Build an unsigned r2/v0.1 receipt body. */
function body({ idx, type, data, prev, pub = PUB1, specVersion = "r2/v0.1" }) {
  return {
    spec_version: specVersion,
    agent_pubkey: pub,
    agent_id: AGENT_ID,
    action_id: uuid(idx),
    action_type: type,
    action_data: data,
    occurred_at: TS,
    prev_receipt_cid: prev,
    nonce: nonce(idx),
    extensions: {},
  };
}

/** Sign an unsigned body with the given seed → returns a signed receipt. */
function sign(unsigned, seed = SEED1) {
  const canonical = canonicalize(unsigned);
  const sig = ed25519.sign(new TextEncoder().encode(canonical), seed);
  return { ...unsigned, signature: Buffer.from(sig).toString("base64url") };
}

/** Write a vector file. */
function emit(file, vector) {
  writeFileSync(resolve(OUT, file), JSON.stringify(vector, null, 2) + "\n");
  console.log(`  wrote ${file}  (${vector.expected})`);
}

console.log(`Regenerating R+2 test vectors → ${OUT}\n`);

// —— 01 · genesis valid (pass) ————————————————————————————————————
const g = sign(body({ idx: 1, type: "agent/init", data: { runtime: "test" }, prev: null }));
emit("01-genesis-valid.json", {
  name: "Valid genesis receipt",
  description: "First receipt in a chain. prev_receipt_cid is null. Signature verifies under the test public key.",
  expected: "pass",
  expected_check: null,
  expected_pubkey: PUB1,
  chain: false,
  receipts: [g],
});

// —— 02 · normal 3-receipt chain (pass) ———————————————————————————
const c1 = sign(body({ idx: 1, type: "agent/init",   data: { runtime: "test" },          prev: null }));
const c2 = sign(body({ idx: 2, type: "memory/write", data: { memory_id: "mem_001" },      prev: computeReceiptCid(c1) }));
const c3 = sign(body({ idx: 3, type: "memory/write", data: { memory_id: "mem_002" },      prev: computeReceiptCid(c2) }));
emit("02-normal-chain.json", {
  name: "Normal 3-receipt chain",
  description: "Three valid receipts. Each prev_receipt_cid equals the canonical CID of the prior receipt.",
  expected: "pass",
  expected_check: null,
  expected_pubkey: PUB1,
  chain: true,
  receipts: [c1, c2, c3],
});

// —— 03 · broken chain pointer (fail · Chain pointer) —————————————
const b1 = sign(body({ idx: 1, type: "agent/init",   data: { runtime: "test" }, prev: null }));
// Receipt 2 is correctly signed, but over a WRONG prev_receipt_cid (all-zero).
const b2 = sign(body({
  idx: 2, type: "memory/write", data: { memory_id: "mem_001" },
  prev: "sha256:" + "0".repeat(64),
}));
emit("03-broken-chain-prev.json", {
  name: "Broken chain pointer",
  description: "Receipt 2 is validly signed but its prev_receipt_cid does not match receipt 1's CID. The verifier must reject it at the chain-pointer check.",
  expected: "fail",
  expected_check: "Chain pointer",
  expected_pubkey: PUB1,
  chain: true,
  receipts: [b1, b2],
});

// —— 04 · tampered payload (fail · Signature) —————————————————————
const t4 = sign(body({ idx: 1, type: "memory/write", data: { memory_id: "mem_001", note: "original" }, prev: null }));
t4.action_data = { ...t4.action_data, note: "TAMPERED" }; // mutate AFTER signing
emit("04-tampered-payload.json", {
  name: "Tampered payload",
  description: "action_data was modified after signing. Canonical bytes no longer match the signature.",
  expected: "fail",
  expected_check: "Signature",
  expected_pubkey: PUB1,
  chain: false,
  receipts: [t4],
});

// —— 05 · tampered signature (fail · Signature) ———————————————————
const t5 = sign(body({ idx: 1, type: "agent/init", data: { runtime: "test" }, prev: null }));
const sigBytes = Buffer.from(t5.signature, "base64url");
sigBytes[0] ^= 0xff;                                   // flip the first byte
t5.signature = sigBytes.toString("base64url");
emit("05-tampered-signature.json", {
  name: "Tampered signature",
  description: "A genuine signature with its first byte flipped. Ed25519 verification must fail.",
  expected: "fail",
  expected_check: "Signature",
  expected_pubkey: PUB1,
  chain: false,
  receipts: [t5],
});

// —— 06 · wrong public key (fail · Pubkey match) ——————————————————
// Receipt is internally consistent — signed by KEY 2, agent_pubkey = KEY 2 —
// but the verifier is given KEY 1 as the expected pubkey from the identity layer.
const w6 = sign(body({ idx: 1, type: "agent/init", data: { runtime: "test" }, prev: null, pub: PUB2 }), SEED2);
emit("06-wrong-pubkey.json", {
  name: "Wrong public key",
  description: "Receipt is validly self-signed by a different key. The verifier is given the expected pubkey from the identity layer; agent_pubkey must match it.",
  expected: "fail",
  expected_check: "Pubkey match",
  expected_pubkey: PUB1,
  chain: false,
  receipts: [w6],
});

// —— 07 · wrong spec version (fail · Spec version) ————————————————
const v7 = sign(body({ idx: 1, type: "agent/init", data: { runtime: "test" }, prev: null, specVersion: "r2/v0.2" }));
emit("07-wrong-spec-version.json", {
  name: "Unsupported spec version",
  description: "spec_version is r2/v0.2. A verifier for r2/v0.1 must reject it rather than guess.",
  expected: "fail",
  expected_check: "Spec version",
  expected_pubkey: PUB1,
  chain: false,
  receipts: [v7],
});

// —— 08 · schema violation — missing field (fail · Schema) ————————
const s8 = sign(body({ idx: 1, type: "agent/init", data: { runtime: "test" }, prev: null }));
delete s8.nonce;                                       // drop a required field
emit("08-schema-missing-field.json", {
  name: "Schema violation — missing required field",
  description: "The required `nonce` field has been removed. The verifier must reject at the schema check.",
  expected: "fail",
  expected_check: "Schema",
  expected_pubkey: PUB1,
  chain: false,
  receipts: [s8],
});

// —— 09 · canonicalization tolerance (pass) ———————————————————————
// Same receipt as 01, but key order is shuffled at every level. After RFC 8785
// JCS canonicalization the bytes are identical, so it must still verify.
const base9 = sign(body({ idx: 1, type: "agent/init", data: { runtime: "test", region: "eu", tier: "free" }, prev: null }));
function shuffleKeys(obj) {
  if (Array.isArray(obj) || obj === null || typeof obj !== "object") return obj;
  const out = {};
  for (const k of Object.keys(obj).reverse()) out[k] = shuffleKeys(obj[k]);
  return out;
}
emit("09-canonicalization-tolerance.json", {
  name: "Canonicalization tolerance",
  description: "Receipt 01 with keys in reverse order at every nesting level. JCS canonicalization must normalise it to identical bytes, so the signature still verifies.",
  expected: "pass",
  expected_check: null,
  expected_pubkey: PUB1,
  chain: false,
  receipts: [shuffleKeys(base9)],
});

// —— 10 · unicode payload (pass) ——————————————————————————————————
const u10 = sign(body({
  idx: 1, type: "memory/write",
  data: {
    note_en: "hello world",
    note_ja: "こんにちは世界",
    note_ar: "مرحبا بالعالم",
    note_emoji: "🛰️🔐✓",
    note_combining: "é", // é as e + combining acute
  },
  prev: null,
}));
emit("10-unicode-payload.json", {
  name: "Unicode payload",
  description: "action_data carrying CJK, RTL, emoji and combining characters. UTF-8 canonicalization must be byte-exact so the signature verifies.",
  expected: "pass",
  expected_check: null,
  expected_pubkey: PUB1,
  chain: false,
  receipts: [u10],
});

// —— manifest ——————————————————————————————————————————————————————
const manifest = {
  suite: "R+2 conformance vectors",
  spec_version: "r2/v0.1",
  generated_by: "@trdnetwork/r2-verify scripts/gen-vectors.mjs",
  test_key_rfc8032: "§7.1 Test 1 — seed 9d61b1…ae7f60 (public; never use in production)",
  count: 10,
  vectors: [
    "01-genesis-valid.json", "02-normal-chain.json", "03-broken-chain-prev.json",
    "04-tampered-payload.json", "05-tampered-signature.json", "06-wrong-pubkey.json",
    "07-wrong-spec-version.json", "08-schema-missing-field.json",
    "09-canonicalization-tolerance.json", "10-unicode-payload.json",
  ],
};
writeFileSync(resolve(OUT, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`  wrote manifest.json\n\nDone — 10 vectors + manifest regenerated to r2/v0.1.`);
