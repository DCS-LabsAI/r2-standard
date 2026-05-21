/**
 * Smoke test for @trdnetwork/r2-verify
 *
 * Tests:
 *  1. Generate a fresh Ed25519 keypair
 *  2. Sign a sample receipt
 *  3. Verify the receipt (should pass)
 *  4. Tamper with action_data (should fail signature check)
 *  5. Tamper with pubkey (should fail pubkey match)
 *  6. Verify the chain pointer between two consecutive signed receipts
 *
 * Run: node test/verify.test.js
 */

import { ed25519 } from "@noble/curves/ed25519";
import canonicalize from "canonicalize";
import { Buffer } from "node:buffer";
import { randomUUID, randomBytes } from "node:crypto";
import { verifyReceipt, computeReceiptCid } from "../lib/verify.js";

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";

let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { console.log(`${PASS} ${name}`); passed++; }
  else      { console.log(`${FAIL} ${name}${detail ? ` — ${detail}` : ""}`); failed++; }
}

// —— Setup: fresh keypair + helper to sign receipts ——
const privateKey = ed25519.utils.randomPrivateKey();
const publicKey  = ed25519.getPublicKey(privateKey);
const pubB64 = Buffer.from(publicKey).toString("base64url");
const nonceB64 = () => Buffer.from(randomBytes(16)).toString("base64url");

function signReceipt(unsigned) {
  const canonical = canonicalize(unsigned);
  const sig = ed25519.sign(new TextEncoder().encode(canonical), privateKey);
  return { ...unsigned, signature: Buffer.from(sig).toString("base64url") };
}

// —— Test 1: A valid receipt should verify ——
const receipt1 = signReceipt({
  spec_version:    "r2/v0.1",
  agent_pubkey:    pubB64,
  agent_id:        "0001",
  action_id:       randomUUID(),
  action_type:     "memory/write",
  action_data:     { memory_id: "mem_test_001", note: "hello world" },
  occurred_at:     new Date().toISOString(),
  prev_receipt_cid: null,
  nonce:           nonceB64(),
  extensions:      {},
});

const r1 = await verifyReceipt(receipt1, pubB64);
check("Valid receipt verifies", r1.ok, r1.error);

// —— Test 2: Tamper with action_data → signature check fails ——
const tampered = { ...receipt1, action_data: { ...receipt1.action_data, note: "TAMPERED" } };
const r2 = await verifyReceipt(tampered, pubB64);
check("Tampered action_data is rejected", !r2.ok && /signature/i.test(r2.error || ""), r2.error || "no error");

// —— Test 3: Wrong pubkey → pubkey match fails ——
const wrongPub = Buffer.from(ed25519.getPublicKey(ed25519.utils.randomPrivateKey())).toString("base64url");
const r3 = await verifyReceipt(receipt1, wrongPub);
check("Wrong expected pubkey is rejected", !r3.ok, r3.error);

// —— Test 4: Chain verification ——
const cid1 = computeReceiptCid(receipt1);
const receipt2 = signReceipt({
  spec_version:    "r2/v0.1",
  agent_pubkey:    pubB64,
  agent_id:        "0001",
  action_id:       randomUUID(),
  action_type:     "memory/search",
  action_data:     { query: "hello", result_count: 1 },
  occurred_at:     new Date().toISOString(),
  prev_receipt_cid: cid1,
  nonce:           nonceB64(),
  extensions:      {},
});
const r4 = await verifyReceipt(receipt2, pubB64, { previousReceipt: receipt1 });
check("Chain pointer matches previous receipt CID", r4.ok, r4.error);

// —— Test 5: Broken chain (wrong prev_receipt_cid) → fails ——
const brokenChain = { ...receipt2, prev_receipt_cid: "sha256:0000000000000000000000000000000000000000000000000000000000000000" };
const brokenSigned = signReceipt({ ...brokenChain, signature: undefined });
delete brokenSigned.signature;
const brokenFull = signReceipt(brokenSigned);
const r5 = await verifyReceipt(brokenFull, pubB64, { previousReceipt: receipt1 });
check("Broken chain pointer is rejected", !r5.ok && /chain/i.test(r5.error || ""), r5.error || "no error");

// —— Test 6: Missing required field → schema fails ——
const noActionData = { ...receipt1 };
delete noActionData.action_data;
const r6 = await verifyReceipt(noActionData, pubB64);
check("Missing required field is rejected", !r6.ok && /schema/i.test(r6.error || ""), r6.error || "no error");

// —— Summary ——
console.log("");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
