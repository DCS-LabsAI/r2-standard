# Publishing @trdnetwork/r2-verify

Step-by-step to ship the CLI to npm so the `r2-verify` command actually works for journalists, MeitY, ISRO, and Anthropic when they read the standard page.

## Prerequisites

You already have an npm account and 2FA configured (from publishing `@trdnetwork/mcp-server`). If not, run `npm login` and follow the prompts.

## Publish (5 minutes)

```bash
cd "/Users/NEWUSER/Desktop/Project TRDN/r2-verify"

# 1. Install dependencies
npm install

# 2. Make the CLI executable (Linux/Mac)
chmod +x bin/r2-verify.js

# 3. Run the smoke test — must pass before publish
npm test

# Expected output:
# ✓ Valid receipt verifies
# ✓ Tampered action_data is rejected
# ✓ Wrong expected pubkey is rejected
# ✓ Chain pointer matches previous receipt CID
# ✓ Broken chain pointer is rejected
# ✓ Missing required field is rejected
# 6 passed, 0 failed

# 4. Dry-run pack — check what will actually ship
npm pack --dry-run

# Expected files in the tarball:
#   bin/r2-verify.js
#   lib/verify.js
#   README.md
#   LICENSE
#   package.json

# 5. Publish to npm (public scoped package)
npm publish --access public

# Output should end with:
# + @trdnetwork/r2-verify@0.1.0
```

## Verify publication

```bash
# Wait ~10 seconds for npm registry to propagate, then:
npm view @trdnetwork/r2-verify

# Install globally and run the help
npm install -g @trdnetwork/r2-verify
r2-verify --version
# → r2-verify v0.1.0 (R+2 spec r2/v0.1)

r2-verify --help
# Should print the full help text
```

## Sanity-check the CLI against a real receipt

```bash
# Mint a quick test receipt using the smoke-test setup
cd "/Users/NEWUSER/Desktop/Project TRDN/r2-verify"
node -e "
import('./test/gen-sample.js').then(m => m.writeSample('./sample.json'))
" 2>/dev/null || echo "(see test/verify.test.js for sample receipt code)"

# Or just test against any signed receipt you have from the production stack:
curl -s https://api.dcslabs.ai/api/receipts/<some-receipt-id> | jq .receipt > sample.json
r2-verify --receipt sample.json --pubkey <pubkey-from-sbt-contract>
```

## After publish

Update these places to mention the live CLI:

1. **standard.html** — the §12 worked example references `r2-verify` — it now actually exists. No edit needed; it'll just work.
2. **memory.html** — the third curl example pipes to `r2-verify` — same, no edit needed.
3. **Press kit / launch posts** — mention "verifier CLI on npm: `npm install -g @trdnetwork/r2-verify`" in the technical-credibility section of any post that needs it.
4. **Add to dcslabs.ai homepage `install` section** — add a third install line beside `@trdnetwork/mcp-server`.

## Versioning policy

- **v0.1.x** — bug fixes to v0.1 spec compatibility. No spec changes.
- **v0.2.x** — additive spec extensions or new verification options. Backward-compatible.
- **v1.0** — spec ratification milestone. Reserved for when R+2 is adopted by at least one standards body.

Follow semver strictly. Breaking changes go in a new major version.

## Troubleshooting

**"403 You do not have permission"** — Your npm session expired. Run `npm logout && npm login` and retry.

**"Cannot publish over previously published version"** — Bump the `version` field in `package.json` (e.g., `0.1.0` → `0.1.1`) and retry.

**"E2FA required"** — You have 2FA-on-publish enabled. Run `npm publish --access public --otp=<6-digit-code>` with your authenticator code.

**Test failures** — If `npm test` fails after install, check that your Node version is 18+. The package uses ES modules + top-level await.
