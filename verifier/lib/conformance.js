/**
 * conformance.js — R+2 conformance-suite runner.
 *
 * Loads the materialized test-vector suite (canonical r2/v0.1 schema) and
 * replays every vector through verifyReceipt(). A vector passes when the
 * verifier's verdict matches the vector's declared expectation:
 *
 *   expected: "pass"  → every receipt must verify.
 *   expected: "fail"  → some receipt must be rejected, and (if the vector
 *                       names expected_check) the FIRST failing check must
 *                       be that check.
 *
 * Vector file shape (see r2-standard-repo/spec/test-vectors/):
 *   { name, description, expected, expected_check, expected_pubkey,
 *     chain, receipts: [ ...signed r2/v0.1 receipts... ] }
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { verifyReceipt } from "./verify.js";

const VECTOR_RE = /^\d{2}-.*\.json$/; // NN-name.json — excludes manifest.json/README

/**
 * Evaluate a single loaded vector object.
 * @returns {{ok: boolean, verdict: string, detail: string}}
 */
export async function evaluateVector(vec) {
  if (!vec || !Array.isArray(vec.receipts) || vec.receipts.length === 0) {
    return { ok: false, verdict: "error", detail: "vector has no receipts" };
  }

  let firstFailCheck = null;
  let firstFailError = null;
  let allVerified = true;

  for (let i = 0; i < vec.receipts.length; i++) {
    const previousReceipt = vec.chain && i > 0 ? vec.receipts[i - 1] : null;
    const res = await verifyReceipt(vec.receipts[i], vec.expected_pubkey, {
      previousReceipt,
      skipTimestampCheck: true, // vectors use a frozen timestamp — keep runs deterministic
    });
    if (!res.ok) {
      allVerified = false;
      const failed = (res.checks || []).find((c) => !c.pass);
      firstFailCheck = failed ? failed.name : "(unknown)";
      firstFailError = res.error || "verification failed";
      break;
    }
  }

  if (vec.expected === "pass") {
    return allVerified
      ? { ok: true, verdict: "pass", detail: `${vec.receipts.length} receipt(s) verified` }
      : { ok: false, verdict: "pass", detail: `expected pass — rejected at "${firstFailCheck}" (${firstFailError})` };
  }

  // expected === "fail"
  if (allVerified) {
    return { ok: false, verdict: "fail", detail: `expected fail at "${vec.expected_check}" — but every receipt verified` };
  }
  if (vec.expected_check && firstFailCheck !== vec.expected_check) {
    return { ok: false, verdict: "fail", detail: `rejected at "${firstFailCheck}", expected "${vec.expected_check}"` };
  }
  return { ok: true, verdict: "fail", detail: `correctly rejected at "${firstFailCheck}"` };
}

/**
 * Run every vector in a directory.
 * @param {string} dir - path to the test-vectors directory
 * @returns {Promise<{total:number, passed:number, failed:number, results:Array}>}
 */
export async function runConformance(dir) {
  let files;
  try {
    files = readdirSync(dir).filter((f) => VECTOR_RE.test(f)).sort();
  } catch (e) {
    throw new Error(`Cannot read test-vector directory "${dir}": ${e.message}`);
  }
  if (files.length === 0) {
    throw new Error(`No test vectors (NN-*.json) found in "${dir}"`);
  }

  const results = [];
  for (const file of files) {
    let vec;
    try {
      vec = JSON.parse(readFileSync(join(dir, file), "utf8"));
    } catch (e) {
      results.push({ file, name: file, ok: false, verdict: "error", detail: `unreadable: ${e.message}` });
      continue;
    }
    const r = await evaluateVector(vec);
    results.push({ file, name: vec.name || file, expected: vec.expected, ...r });
  }

  const passed = results.filter((r) => r.ok).length;
  return { total: results.length, passed, failed: results.length - passed, results };
}
