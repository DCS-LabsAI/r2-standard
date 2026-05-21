/**
 * @trdnetwork/r2-verify — Reference verifier for the R+2 Open Provenance Standard
 *
 * Implements the verification flow from §8 of the R+2 spec:
 * https://dcslabs.ai/standard#verification
 *
 * Usage (library):
 *   import { verifyReceipt } from "@trdnetwork/r2-verify";
 *   const result = await verifyReceipt(receipt, expectedPubkey);
 *
 * Usage (CLI):
 *   r2-verify --receipt receipt.json --pubkey <base64url-pubkey>
 */

import { ed25519 } from "@noble/curves/ed25519";
import canonicalize from "canonicalize";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

const SPEC_VERSION = "r2/v0.1";
const PUBKEY_LEN_B64 = 43;   // 32 bytes → 43 chars base64url no-padding
const SIG_LEN_B64    = 86;   // 64 bytes → 86 chars base64url no-padding
const NONCE_LEN_B64  = 22;   // 16 bytes → 22 chars base64url no-padding
const UUID_REGEX     = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RFC3339_REGEX  = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const REQUIRED_FIELDS = [
  "spec_version", "agent_pubkey", "agent_id", "action_id", "action_type",
  "action_data", "occurred_at", "prev_receipt_cid", "nonce", "extensions", "signature"
];

/**
 * Verifies an R+2 receipt against an expected public key.
 *
 * @param {Object} receipt - The R+2 receipt JSON object
 * @param {string} expectedPubkey - The base64url-encoded Ed25519 public key obtained from the identity layer
 * @param {Object} [opts] - Optional verification options
 * @param {boolean} [opts.skipTimestampCheck=false] - Skip the ±24h timestamp sanity check
 * @param {Object} [opts.previousReceipt=null] - The previous receipt in the chain, for §9 verification
 * @returns {Promise<{ok: boolean, checks: Array<{name: string, pass: boolean, detail?: string}>, error?: string}>}
 */
export async function verifyReceipt(receipt, expectedPubkey, opts = {}) {
  const checks = [];
  const fail = (name, detail) => {
    checks.push({ name, pass: false, detail });
    // Include the check name in the error so consumers can pattern-match on it
    return { ok: false, checks, error: `${name}: ${detail}` };
  };
  const ok = (name, detail) => checks.push({ name, pass: true, detail });

  // —— Check 1: Schema ——
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    return fail("Schema", "Receipt is not a JSON object");
  }
  for (const f of REQUIRED_FIELDS) {
    if (!(f in receipt)) {
      return fail("Schema", `Missing required field: ${f}`);
    }
  }
  if (typeof receipt.spec_version !== "string") return fail("Schema", "spec_version must be string");
  if (typeof receipt.agent_pubkey !== "string" || receipt.agent_pubkey.length !== PUBKEY_LEN_B64) {
    return fail("Schema", `agent_pubkey must be ${PUBKEY_LEN_B64}-char base64url string`);
  }
  if (typeof receipt.agent_id !== "string" || !receipt.agent_id) {
    return fail("Schema", "agent_id must be non-empty string");
  }
  if (typeof receipt.action_id !== "string" || !UUID_REGEX.test(receipt.action_id)) {
    return fail("Schema", "action_id must be a UUIDv4");
  }
  if (typeof receipt.action_type !== "string" || !receipt.action_type) {
    return fail("Schema", "action_type must be non-empty string");
  }
  if (!receipt.action_data || typeof receipt.action_data !== "object" || Array.isArray(receipt.action_data)) {
    return fail("Schema", "action_data must be a JSON object");
  }
  if (typeof receipt.occurred_at !== "string" || !RFC3339_REGEX.test(receipt.occurred_at)) {
    return fail("Schema", "occurred_at must be RFC 3339 timestamp");
  }
  if (receipt.prev_receipt_cid !== null && typeof receipt.prev_receipt_cid !== "string") {
    return fail("Schema", "prev_receipt_cid must be string or null");
  }
  if (typeof receipt.nonce !== "string" || receipt.nonce.length !== NONCE_LEN_B64) {
    return fail("Schema", `nonce must be ${NONCE_LEN_B64}-char base64url string (16 bytes)`);
  }
  if (!receipt.extensions || typeof receipt.extensions !== "object" || Array.isArray(receipt.extensions)) {
    return fail("Schema", "extensions must be a JSON object (may be {})");
  }
  if (typeof receipt.signature !== "string" || receipt.signature.length !== SIG_LEN_B64) {
    return fail("Schema", `signature must be ${SIG_LEN_B64}-char base64url string`);
  }
  ok("Schema");

  // —— Check 2: Spec version ——
  if (receipt.spec_version !== SPEC_VERSION) {
    return fail("Spec version", `Got "${receipt.spec_version}", verifier supports "${SPEC_VERSION}"`);
  }
  ok("Spec version", SPEC_VERSION);

  // —— Check 3: Public key match ——
  if (typeof expectedPubkey !== "string" || expectedPubkey.length !== PUBKEY_LEN_B64) {
    return fail("Pubkey match", `expected pubkey must be ${PUBKEY_LEN_B64}-char base64url`);
  }
  if (receipt.agent_pubkey !== expectedPubkey) {
    return fail("Pubkey match",
      `Receipt pubkey ${receipt.agent_pubkey.slice(0,8)}... ≠ expected ${expectedPubkey.slice(0,8)}...`);
  }
  ok("Pubkey match", expectedPubkey.slice(0, 12) + "...");

  // —— Check 4: Signature ——
  const { signature, ...unsigned } = receipt;
  const canonical = canonicalize(unsigned);
  if (canonical === undefined) {
    return fail("Signature", "Receipt failed to canonicalize per RFC 8785");
  }
  const msgBytes = new TextEncoder().encode(canonical);
  let sigBytes, pubBytes;
  try {
    sigBytes = Buffer.from(signature, "base64url");
    pubBytes = Buffer.from(expectedPubkey, "base64url");
  } catch (e) {
    return fail("Signature", `Base64url decode error: ${e.message}`);
  }
  if (sigBytes.length !== 64) return fail("Signature", `decoded sig is ${sigBytes.length} bytes, expected 64`);
  if (pubBytes.length !== 32) return fail("Signature", `decoded pubkey is ${pubBytes.length} bytes, expected 32`);

  let sigValid = false;
  try {
    sigValid = ed25519.verify(sigBytes, msgBytes, pubBytes);
  } catch (e) {
    return fail("Signature", `Ed25519.verify threw: ${e.message}`);
  }
  if (!sigValid) {
    return fail("Signature", "Ed25519 verification failed (signature does not match canonical bytes)");
  }
  ok("Signature");

  // —— Check 5: Chain pointer (optional but recommended) ——
  if (receipt.prev_receipt_cid === null) {
    ok("Chain pointer", "first receipt (null)");
  } else if (opts.previousReceipt) {
    const prevCanonical = canonicalize(stripSig(opts.previousReceipt));
    if (prevCanonical === undefined) {
      return fail("Chain pointer", "Previous receipt failed to canonicalize");
    }
    const computedCid = "sha256:" + sha256Hex(prevCanonical);
    if (receipt.prev_receipt_cid !== computedCid) {
      return fail("Chain pointer",
        `Receipt's prev_receipt_cid ${receipt.prev_receipt_cid.slice(0,24)}... ≠ computed ${computedCid.slice(0,24)}...`);
    }
    ok("Chain pointer", "matches previous receipt CID");
  } else {
    ok("Chain pointer", "skipped (no previous receipt provided)");
  }

  // —— Check 6: Timestamp sanity (warning only, not failure) ——
  if (!opts.skipTimestampCheck) {
    const tsMs = Date.parse(receipt.occurred_at);
    const nowMs = Date.now();
    const windowMs = 24 * 60 * 60 * 1000;
    if (Math.abs(nowMs - tsMs) > windowMs) {
      ok("Timestamp", `outside ±24h window (occurred_at: ${receipt.occurred_at}) — flagged but not rejected`);
    } else {
      ok("Timestamp", "within ±24h window");
    }
  }

  return { ok: true, checks };
}

function stripSig(receipt) {
  const { signature, ...rest } = receipt;
  return rest;
}

function sha256Hex(text) {
  return createHash("sha256").update(text).digest("hex");
}

/**
 * Compute the CID (sha256: prefixed hex) of a signed R+2 receipt.
 * Used to populate `prev_receipt_cid` in the next receipt in the chain.
 */
export function computeReceiptCid(signedReceipt) {
  const canonical = canonicalize(stripSig(signedReceipt));
  if (canonical === undefined) throw new Error("Receipt failed to canonicalize");
  return "sha256:" + sha256Hex(canonical);
}

export const SPEC = {
  version: SPEC_VERSION,
  url: "https://dcslabs.ai/standard",
};
