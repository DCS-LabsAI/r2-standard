/**
 * R+2 ADVERSARIAL TEST SUITE — @trdnetwork/r2-verify
 *
 * Complements the canonical conformance vectors (spec/test-vectors/01..10) and
 * the existing smoke/scale tests. Where those vectors are static and pre-baked,
 * this suite *programmatically* mutates a freshly-signed, known-valid receipt
 * and asserts the verifier REJECTS the attack.
 *
 * A test "PASSES" when the attack is correctly REJECTED (or, for the benign
 * canonicalization case, correctly ACCEPTED). A test "FAILS" when the verifier
 * lets an attack through — or when an honest gap is found.
 *
 * Attacks covered:
 *   1. Tampered payload        — flip a byte in action_data
 *   2. Tampered signature      — flip a byte in the signature
 *   3. Wrong public key        — verify under a different pubkey
 *   4. Broken chain pointer    — corrupt prev_receipt_cid in a chained receipt
 *   5. Replayed nonce          — two receipts re-using the same nonce
 *   6. Spec-version mismatch   — spec_version != r2/v0.1
 *   7. Missing required field  — drop a required field
 *   8. Canonicalization attack — benign key reorder still verifies,
 *                                but a real content change is still caught
 *
 * Run: node test/adversarial.test.js
 */

import { ed25519 } from "@noble/curves/ed25519";
import canonicalize from "canonicalize";
import { Buffer } from "node:buffer";
import { randomUUID, randomBytes } from "node:crypto";
import { verifyReceipt, verifyChain, computeReceiptCid } from "../lib/verify.js";

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const WARN = "\x1b[33m⚠\x1b[0m";

let passed = 0, failed = 0;

/** A test passes when `rejected` is true (attack caught). */
function attack(name, rejected, detail) {
  if (rejected) { console.log(`${PASS} ${name}`); passed++; }
  else          { console.log(`${FAIL} ${name}${detail ? ` — ${detail}` : ""}`); failed++; }
}
/** For the benign sub-case: passes when the verifier ACCEPTS. */
function accepts(name, ok, detail) {
  if (ok) { console.log(`${PASS} ${name}`); passed++; }
  else    { console.log(`${FAIL} ${name}${detail ? ` — ${detail}` : ""}`); failed++; }
}

// —— Setup: a fresh keypair + a signing helper (matches verify.test.js style) ——
const privateKey = ed25519.utils.randomPrivateKey();
const publicKey  = ed25519.getPublicKey(privateKey);
const pubB64     = Buffer.from(publicKey).toString("base64url");
const nonceB64   = () => Buffer.from(randomBytes(16)).toString("base64url");

/** Signs an unsigned receipt over its RFC 8785 canonical form. */
function signReceipt(unsigned) {
  const { signature, ...body } = unsigned; // never sign over an existing sig
  const canonical = canonicalize(body);
  const sig = ed25519.sign(new TextEncoder().encode(canonical), privateKey);
  return { ...body, signature: Buffer.from(sig).toString("base64url") };
}

/** Flip the lowest bit of one byte inside a base64url string, re-encoding. */
function flipByteInB64(b64, byteIndex = 0) {
  const buf = Buffer.from(b64, "base64url");
  buf[byteIndex] ^= 0x01;
  return buf.toString("base64url");
}

// A known-valid genesis receipt — the basis for every mutation below.
const validReceipt = signReceipt({
  spec_version:     "r2/v0.1",
  agent_pubkey:     pubB64,
  agent_id:         "did:dcs:test:adversarial-agent",
  action_id:        randomUUID(),
  action_type:      "memory/write",
  action_data:      { memory_id: "mem_adv_001", note: "original content" },
  occurred_at:      new Date().toISOString(),
  prev_receipt_cid: null,
  nonce:            nonceB64(),
  extensions:       {},
});

console.log("\nR+2 adversarial test suite\n");

// —— sanity: the base receipt must verify, or the whole suite is meaningless ——
{
  const r = await verifyReceipt(validReceipt, pubB64);
  accepts("baseline known-valid receipt verifies", r.ok, r.error);
}

// —— Attack 1: Tampered payload — flip a byte in action_data ——
{
  const tampered = {
    ...validReceipt,
    action_data: { ...validReceipt.action_data, note: "originbl content" }, // 'a'->'b'
  };
  const r = await verifyReceipt(tampered, pubB64);
  attack("1. tampered payload (action_data byte flipped) is rejected",
    !r.ok && /signature/i.test(r.error || ""), r.error || "ACCEPTED — attack succeeded");
}

// —— Attack 2: Tampered signature — flip a byte in the signature ——
{
  const tampered = { ...validReceipt, signature: flipByteInB64(validReceipt.signature, 10) };
  const r = await verifyReceipt(tampered, pubB64);
  attack("2. tampered signature (byte flipped) is rejected",
    !r.ok && /signature/i.test(r.error || ""), r.error || "ACCEPTED — attack succeeded");
}

// —— Attack 3: Wrong public key — verify under a different keypair's pubkey ——
{
  const otherPub = Buffer.from(
    ed25519.getPublicKey(ed25519.utils.randomPrivateKey())
  ).toString("base64url");
  const r = await verifyReceipt(validReceipt, otherPub);
  // verifier rejects at "Pubkey match" (agent_pubkey != expected). Either way,
  // a non-matching key MUST be rejected.
  attack("3. verification under a wrong public key is rejected",
    !r.ok, r.error || "ACCEPTED — attack succeeded");
}

// —— Attack 4: Broken chain pointer — corrupt prev_receipt_cid in a chained receipt ——
{
  // Build a legitimate 2-receipt chain first.
  const genesis = validReceipt;
  const cid1 = computeReceiptCid(genesis);
  const child = signReceipt({
    spec_version:     "r2/v0.1",
    agent_pubkey:     pubB64,
    agent_id:         "did:dcs:test:adversarial-agent",
    action_id:        randomUUID(),
    action_type:      "memory/search",
    action_data:      { query: "test" },
    occurred_at:      new Date().toISOString(),
    prev_receipt_cid: cid1,
    nonce:            nonceB64(),
    extensions:       {},
  });
  // Corrupt the pointer, then RE-SIGN so the signature itself is valid —
  // this isolates the chain-pointer check (the attacker controls signing).
  const corruptedCid = "sha256:" + flipByteInB64(
    Buffer.from(cid1.slice(7), "hex").toString("base64url"), 3
  ); // arbitrary wrong hex digest
  const brokenChild = signReceipt({
    ...child,
    prev_receipt_cid: "sha256:" + "0".repeat(64),
  });
  void corruptedCid;
  const r = await verifyReceipt(brokenChild, pubB64, { previousReceipt: genesis });
  attack("4. broken chain pointer (corrupt prev_receipt_cid) is rejected",
    !r.ok && /chain/i.test(r.error || ""), r.error || "ACCEPTED — attack succeeded");
}

// —— Attack 5: Replayed nonce — two receipts re-using the same nonce ——
{
  // Two distinct, individually-valid receipts that share an identical nonce.
  const sharedNonce = nonceB64();
  const first = signReceipt({
    spec_version:     "r2/v0.1",
    agent_pubkey:     pubB64,
    agent_id:         "did:dcs:test:adversarial-agent",
    action_id:        randomUUID(),
    action_type:      "memory/write",
    action_data:      { memory_id: "mem_replay_a" },
    occurred_at:      new Date().toISOString(),
    prev_receipt_cid: null,
    nonce:            sharedNonce,
    extensions:       {},
  });
  const cidFirst = computeReceiptCid(first);
  const replay = signReceipt({
    spec_version:     "r2/v0.1",
    agent_pubkey:     pubB64,
    agent_id:         "did:dcs:test:adversarial-agent",
    action_id:        randomUUID(),
    action_type:      "memory/write",
    action_data:      { memory_id: "mem_replay_b" },
    occurred_at:      new Date().toISOString(),
    prev_receipt_cid: cidFirst,
    nonce:            sharedNonce,            // <-- replayed
    extensions:       {},
  });

  // A single-receipt verifier genuinely cannot see cross-receipt replay, so
  // verifyReceipt() still ACCEPTS each receipt in isolation (correct, by design):
  const r1 = await verifyReceipt(first, pubB64);
  const r2single = await verifyReceipt(replay, pubB64, { previousReceipt: first });

  // The chain/ledger verifier DOES enforce nonce-uniqueness across receipts.
  // Feed both same-nonce receipts to verifyChain() — the replay MUST be rejected.
  const chain = await verifyChain([first, replay], pubB64, { chainLinked: true });
  const nonceReplayCaught =
    !chain.ok && /nonce/i.test(chain.error || "") &&
    chain.collision && chain.collision.nonce === sharedNonce &&
    chain.collision.index === 1 && chain.collision.firstIndex === 0;
  attack("5. replayed nonce is rejected by verifyChain() ledger",
    nonceReplayCaught,
    chain.error
      ? `single-receipt verify still ok by design (r1.ok=${r1.ok}, r2.ok=${r2single.ok}); chain rejected: ${chain.error}`
      : "ACCEPTED — chain verifier failed to detect the nonce replay");
}

// —— Attack 6: Spec-version mismatch — spec_version != r2/v0.1 ——
{
  // Re-sign so the signature is valid over the mutated field: this proves the
  // verifier rejects on the VERSION check, not merely on a broken signature.
  const wrongVersion = signReceipt({ ...validReceipt, spec_version: "r2/v0.2" });
  const r = await verifyReceipt(wrongVersion, pubB64);
  attack('6. spec-version mismatch ("r2/v0.2") is rejected',
    !r.ok && /spec version/i.test(r.error || ""), r.error || "ACCEPTED — attack succeeded");
}

// —— Attack 7: Missing required field — drop a required field ——
{
  const missing = { ...validReceipt };
  delete missing.occurred_at;
  const r = await verifyReceipt(missing, pubB64);
  attack("7. missing required field (occurred_at dropped) is rejected",
    !r.ok && /schema/i.test(r.error || ""), r.error || "ACCEPTED — attack succeeded");
}

// —— Attack 8: Canonicalization attack ——
//   8a. Benign reordering / whitespace MUST still verify (RFC 8785 / JCS
//       normalises key order, so the canonical bytes are identical).
//   8b. A real content change hidden behind a reorder MUST still be caught.
{
  // 8a — round-trip the receipt through JSON with reversed key order + pretty
  // whitespace. canonicalize() inside the verifier must normalise it back.
  function reorderDeep(obj) {
    if (Array.isArray(obj)) return obj.map(reorderDeep);
    if (obj && typeof obj === "object") {
      const out = {};
      for (const k of Object.keys(obj).reverse()) out[k] = reorderDeep(obj[k]);
      return out;
    }
    return obj;
  }
  const reordered = JSON.parse(JSON.stringify(reorderDeep(validReceipt), null, 4));
  const rBenign = await verifyReceipt(reordered, pubB64);
  accepts("8a. benign key reorder + whitespace still verifies (canonicalization tolerant)",
    rBenign.ok, rBenign.error || "REJECTED a benign reorder — canonicalization is broken");

  // 8b — same reorder, but ALSO change content. Must NOT be accepted just
  // because the keys were shuffled.
  const reorderedTampered = reorderDeep({
    ...validReceipt,
    action_data: { ...validReceipt.action_data, note: "smuggled change" },
  });
  const rEvil = await verifyReceipt(reorderedTampered, pubB64);
  attack("8b. content change hidden behind a key reorder is still rejected",
    !rEvil.ok && /signature/i.test(rEvil.error || ""),
    rEvil.error || "ACCEPTED — reorder smuggled a content change past the verifier");
}

// —— Summary ——
console.log("");
console.log(`R+2 ADVERSARIAL: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
