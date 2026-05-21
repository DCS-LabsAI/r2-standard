#!/usr/bin/env node
/**
 * r2-verify CLI — Verify R+2 Open Provenance Standard receipts from the command line.
 *
 * Usage:
 *   r2-verify --receipt <path>  --pubkey <base64url-pubkey>
 *   r2-verify --help
 *   r2-verify --version
 *
 * Examples:
 *   r2-verify --receipt receipt.json --pubkey u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o
 *   cat receipt.json | r2-verify --pubkey u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o
 *
 * Exit codes:
 *   0  receipt is valid
 *   1  receipt is invalid (signature/schema/chain failure)
 *   2  CLI usage error (missing args, bad input)
 */

import { verifyReceipt, SPEC } from "../lib/verify.js";
import { runConformance } from "../lib/conformance.js";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const VERSION = "0.1.2";
const PROG = "r2-verify";

const args = parseArgs(process.argv.slice(2));

if (args.help || args._.includes("help")) {
  printHelp();
  process.exit(0);
}
if (args.version || args._.includes("version")) {
  console.log(`${PROG} v${VERSION} (R+2 spec ${SPEC.version})`);
  console.log(`spec: ${SPEC.url}`);
  process.exit(0);
}

// —— Conformance mode: replay a test-vector suite ——
if (args["test-vectors"]) {
  (async () => {
    let report;
    try {
      report = await runConformance(resolve(args["test-vectors"]));
    } catch (e) {
      err(e.message);
      process.exit(2);
    }
    if (args.json) {
      console.log(JSON.stringify(report, null, 2));
      process.exit(report.failed === 0 ? 0 : 1);
    }
    console.log(`R+2 conformance suite — ${SPEC.version}\n`);
    for (const r of report.results) {
      const mark = r.ok ? green("✓") : red("✗");
      console.log(`${mark} ${r.file.padEnd(32)} ${dim(r.detail)}`);
    }
    console.log("");
    const line = `${report.passed}/${report.total} vectors passed`;
    console.log(report.failed === 0 ? green(line) : red(line));
    process.exit(report.failed === 0 ? 0 : 1);
  })();
} else if (!args.pubkey) {
  err("Missing required --pubkey <base64url-pubkey>");
  printHelp();
  process.exit(2);
}

// Single-receipt verification mode (skipped entirely in --test-vectors mode).
if (!args["test-vectors"]) (async () => {
  let receiptJson;
  try {
    receiptJson = await loadReceipt(args.receipt);
  } catch (e) {
    err(`Failed to load receipt: ${e.message}`);
    process.exit(2);
  }

  let receipt;
  try {
    receipt = JSON.parse(receiptJson);
  } catch (e) {
    err(`Receipt is not valid JSON: ${e.message}`);
    process.exit(2);
  }

  let prev = null;
  if (args.previous) {
    try {
      const prevJson = readFileSync(resolve(args.previous), "utf8");
      prev = JSON.parse(prevJson);
    } catch (e) {
      err(`Failed to load --previous: ${e.message}`);
      process.exit(2);
    }
  }

  const result = await verifyReceipt(receipt, args.pubkey, {
    previousReceipt: prev,
    skipTimestampCheck: !!args["skip-timestamp"],
  });

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.ok ? 0 : 1);
  }

  // Human-readable output
  for (const c of result.checks) {
    const mark = c.pass ? green("✓") : red("✗");
    const detail = c.detail ? dim(`  ${c.detail}`) : "";
    console.log(`${mark} ${c.name}${detail}`);
  }
  console.log("");
  if (result.ok) {
    console.log(green("Receipt verified."));
    process.exit(0);
  } else {
    console.log(red(`Receipt invalid: ${result.error || "verification failed"}`));
    process.exit(1);
  }
})();

// —— helpers ——

async function loadReceipt(path) {
  if (path) {
    const abs = resolve(path);
    if (!existsSync(abs)) throw new Error(`File not found: ${abs}`);
    return readFileSync(abs, "utf8");
  }
  // No --receipt → read from stdin
  if (process.stdin.isTTY) {
    throw new Error("No --receipt path and stdin is empty (pipe a receipt or use --receipt)");
  }
  return readStdin();
}

function readStdin() {
  return new Promise((resolveP, rejectP) => {
    const chunks = [];
    process.stdin.on("data", (c) => chunks.push(c));
    process.stdin.on("end",  () => resolveP(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", rejectP);
  });
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--version" || a === "-v") out.version = true;
    else if (a === "--json") out.json = true;
    else if (a === "--skip-timestamp") out["skip-timestamp"] = true;
    else if (a === "--receipt") out.receipt = argv[++i];
    else if (a === "--pubkey")  out.pubkey  = argv[++i];
    else if (a === "--previous") out.previous = argv[++i];
    else if (a === "--test-vectors") out["test-vectors"] = argv[++i];
    else if (a.startsWith("--")) { err(`Unknown flag: ${a}`); process.exit(2); }
    else out._.push(a);
  }
  return out;
}

function printHelp() {
  console.log(`
${PROG} v${VERSION} — Verify R+2 Open Provenance Standard receipts

USAGE
  ${PROG} --receipt <path>  --pubkey <base64url>
  ${PROG} --pubkey <base64url>          (read receipt from stdin)
  ${PROG} --test-vectors <dir>          (run the R+2 conformance suite)
  ${PROG} --help | --version

OPTIONS
  --receipt <path>       Path to the receipt JSON file (or omit to read from stdin)
  --pubkey <base64url>   The agent's expected Ed25519 public key (43 chars, no padding)
  --previous <path>      Optional path to the previous receipt — enables full §9 chain check
  --test-vectors <dir>   Replay every conformance vector in a directory and report a matrix
  --skip-timestamp       Skip the ±24h timestamp sanity check
  --json                 Output the result as JSON instead of human-readable
  --version, -v          Print version
  --help, -h             Print this help

EXAMPLES
  # Verify a single receipt with pubkey from the identity layer
  ${PROG} --receipt action_0001.json \\
          --pubkey u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o

  # Pipe from a curl + jq pipeline
  curl -s https://api.dcslabs.ai/api/receipts/r2_a83f12cd | jq .receipt \\
    | ${PROG} --pubkey u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o

  # Verify with full chain check
  ${PROG} --receipt action_0002.json \\
          --previous action_0001.json \\
          --pubkey u4yK_lH8Z6vJ3qZ5tNwQpRz_aBcDeFgH1iJ2kL3mN4o

SPEC
  R+2 Open Provenance Standard ${SPEC.version}
  ${SPEC.url}

EXIT CODES
  0  receipt is valid
  1  receipt is invalid
  2  CLI usage error
`);
}

function err(msg)   { process.stderr.write(red("error: ") + msg + "\n"); }
function green(s)  { return process.stdout.isTTY ? `\x1b[32m${s}\x1b[0m` : s; }
function red(s)    { return process.stderr.isTTY ? `\x1b[31m${s}\x1b[0m` : s; }
function dim(s)    { return process.stdout.isTTY ? `\x1b[2m${s}\x1b[0m` : s; }
