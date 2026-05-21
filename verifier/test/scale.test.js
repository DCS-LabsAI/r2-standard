/**
 * R+2 scale test — receipt-chain integrity under volume.
 *
 * The conformance suite proves correctness on small vectors. This proves
 * the property that actually matters operationally: a long chain stays
 * verifiable, and tampering anywhere in it is still caught — at volume.
 *
 * It builds a chain of N signed r2/v0.1 receipts (each linked to the
 * previous by prev_receipt_cid), verifies every one with the full §9
 * chain check, measures throughput, then tampers a receipt deep in the
 * chain and confirms both its signature and the next link break.
 *
 * Run:  node test/scale.test.js            (default N = 10000)
 *       node test/scale.test.js 50000       (custom N)
 *       R2_SCALE_N=2000 node test/scale.test.js
 */
import { ed25519 } from "@noble/curves/ed25519";
import canonicalize from "canonicalize";
import { Buffer } from "node:buffer";
import { randomUUID, randomBytes } from "node:crypto";
import { verifyReceipt, computeReceiptCid } from "../lib/verify.js";

const N = Math.max(2, parseInt(process.argv[2] || process.env.R2_SCALE_N || "10000", 10));

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { console.log(`${PASS} ${name}`); passed++; }
  else { console.log(`${FAIL} ${name}${detail ? ` — ${detail}` : ""}`); failed++; }
}

// —— keypair ——
const privateKey = ed25519.utils.randomPrivateKey();
const publicKey  = ed25519.getPublicKey(privateKey);
const pubB64 = Buffer.from(publicKey).toString("base64url");

function signReceipt(unsigned) {
  const sig = ed25519.sign(new TextEncoder().encode(canonicalize(unsigned)), privateKey);
  return { ...unsigned, signature: Buffer.from(sig).toString("base64url") };
}

console.log(`\nR+2 scale test — ${N.toLocaleString()}-receipt chain\n`);

// —— 1. build the chain ——
let t0 = Date.now();
const chain = [];
let prevCid = null;
for (let i = 0; i < N; i++) {
  const receipt = signReceipt({
    spec_version:     "r2/v0.1",
    agent_pubkey:     pubB64,
    agent_id:         "did:dcs:scale-test-agent",
    action_id:        randomUUID(),
    action_type:      "memory/write",
    action_data:      { seq: i, note: `receipt ${i}` },
    occurred_at:      new Date().toISOString(),
    prev_receipt_cid: prevCid,
    nonce:            Buffer.from(randomBytes(16)).toString("base64url"),
    extensions:       {},
  });
  chain.push(receipt);
  prevCid = computeReceiptCid(receipt);
}
const buildMs = Date.now() - t0;
check(`built a ${N.toLocaleString()}-receipt signed chain`, chain.length === N,
  `${chain.length} receipts`);
console.log(`  build: ${buildMs} ms  ·  ${Math.round(N / (buildMs / 1000)).toLocaleString()} receipts/s\n`);

// —— 2. verify every receipt with the full chain check ——
t0 = Date.now();
let allOk = true, firstBad = -1;
for (let i = 0; i < N; i++) {
  const r = await verifyReceipt(chain[i], pubB64, {
    previousReceipt: i > 0 ? chain[i - 1] : null,
    skipTimestampCheck: true,
  });
  if (!r.ok) { allOk = false; firstBad = i; break; }
}
const verifyMs = Date.now() - t0;
check(`all ${N.toLocaleString()} receipts verify (signature + chain pointer)`, allOk,
  firstBad >= 0 ? `first failure at index ${firstBad}` : "");
console.log(`  verify: ${verifyMs} ms  ·  ${Math.round(N / (verifyMs / 1000)).toLocaleString()} receipts/s`);
console.log(`  per-receipt: ${(verifyMs / N).toFixed(3)} ms\n`);

// —— 3. tamper a receipt deep in the chain ——
const mid = Math.floor(N / 2);
const tampered = { ...chain[mid], action_data: { ...chain[mid].action_data, note: "TAMPERED" } };

const rTampered = await verifyReceipt(tampered, pubB64, {
  previousReceipt: chain[mid - 1], skipTimestampCheck: true,
});
check(`tampering receipt #${mid.toLocaleString()} breaks its signature`,
  !rTampered.ok && /Signature/.test(rTampered.error || ""), rTampered.error);

// the next receipt's prev_receipt_cid was computed over the ORIGINAL
// receipt #mid — so verifying it against the tampered one must fail the
// chain-pointer check (the receipt-omission / substitution attack).
const rNext = await verifyReceipt(chain[mid + 1], pubB64, {
  previousReceipt: tampered, skipTimestampCheck: true,
});
check(`the link into receipt #${(mid + 1).toLocaleString()} breaks (chain pointer)`,
  !rNext.ok && /Chain pointer/.test(rNext.error || ""), rNext.error);

// —— 4. integrity holds — the rest of the chain is unaffected ——
const rUntouched = await verifyReceipt(chain[mid + 1], pubB64, {
  previousReceipt: chain[mid], skipTimestampCheck: true,
});
check(`the untampered chain still verifies around the tamper point`, rUntouched.ok,
  rUntouched.error);

console.log(`\n${passed} passed, ${failed} failed  ·  N=${N.toLocaleString()}`);
process.exit(failed === 0 ? 0 : 1);
