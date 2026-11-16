# Grandfuscator 2.1 — Roblox Luau Obfuscator

Grandfuscator 2.1 provides two explicit runtime backends: `compat` remains the stable default, while `v3-experimental` emits a runnable, standalone flat-`vmem` Luau runtime. The v3 backend has broad functional-corpus parity coverage across all three presets; it does not silently fall back to compatibility output. v3 currently rejects Roblox engine and PlaceId/GameId locks, which it does not implement. Client-side obfuscation raises analysis cost; it cannot keep client-executed behavior or runtime plaintext secret from an analyst who controls the client.

## Security status

The red-team report against v2 was valid. A source-level patch can dump the decrypted bytecode buffer and log decoded VM operands before integrity checks. The Studio's `/api/verify-run` now reproduces and reports both attacks. For a test sample on 2.1, the normal hooked/beautifier/tamper probes were blocked, while **the decrypted-buffer dump and VM trace succeeded**. Do not treat anti-tamper as a confidentiality boundary; keep secrets and authoritative checks server-side.

The compatibility emitter's optional anti-tamper checks look for common executor/instrumentation globals such as `hookfunction`, `getgenv`, `getgc`, and `identifyexecutor`, folding hits into its key schedule. This is a best-effort tripwire only: it cannot detect an external logger or a modified script that hides its hooks. The v3 runtime does not claim to prevent client inspection.

## Run locally

```bash
npm install
npm run typecheck
npm test
npm start
```

The Studio listens on `http://localhost:3000` by default. For a custom port use `PORT=3000 npm start`. The Studio includes a runtime selector. API callers may pass `options.runtime: "compat"` (default) or `"v3-experimental"`; the latter returns executable v3 output and backend-specific statistics. The CLI also accepts `--runtime compat|v3-experimental`.

## Deploy publicly with Render

The repo includes a `Dockerfile`, `.dockerignore`, and `render.yaml` Blueprint. To publish it, push this repo to GitHub, then in Render choose **New → Blueprint** and select the repository. Render builds the bundled Luau tools into the Node service and checks `/api/health`; it supplies the public URL after deployment. This app requires a Node/Docker host—GitHub Pages alone cannot serve its API. The deployment has not been created from this workspace because it has no authenticated GitHub or Render access.

### CLI

```bash
npm run cli -- input.luau -o output.obf.luau -p fortress
npm run cli -- input.luau -p nightmare --chains 3 --place-ids 1818,17625359962123
```

## Presets

| Preset | Intended use |
|---|---|
| Swift | Lower overhead for client scripts |
| Fortress | Default balanced protection |
| Nightmare | Higher analysis cost with additional runtime overhead |

The compatibility backend does not use v3 flat-vmem per-handler ciphers, shattered-string lowering, or CFG/graph transforms. The v3 backend uses its own flat runtime and reports its capabilities separately. Roblox engine and PlaceId/GameId locks remain unsupported by v3; requesting one returns an error instead of silently dropping the lock.

## Verification

Validation: `npm run typecheck` passes. `npm test` passes 121 checks, including the full functional fixture corpus across all presets on the v3 runtime, targeted flat-image cases, v3 execution under stripped and production Luau compiler flags, and the existing compatibility, compiler, and security suites. The `/api/verify-run` red-team endpoint reports decrypted-buffer dumps and decoded-instruction traces as unblocked when instrumentation succeeds; a failed instrumentation pattern is not treated as proof that inspection was prevented. Client-side runtime inspection cannot be prevented.
