import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLuau } from './parser.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const COMPILER_TIMEOUT_MS = 4000;
const MAX_SYNC_TIMEOUT_MS = 2_147_483_647;
const VERIFIER_MAX_BUFFER = 4 * 1024 * 1024;

let cachedCompilerBin: string | null | undefined;
let cachedRuntimeBin: string | null | undefined;

/** Create a private, exclusive scratch file and remove partial files on write failure. */
function writePrivateTempScript(filePath: string, code: string): void {
  const fd = fs.openSync(filePath, 'wx', 0o600);
  let complete = false;
  try {
    fs.writeFileSync(fd, code, 'utf8');
    fs.closeSync(fd);
    complete = true;
  } finally {
    if (!complete) {
      try { fs.closeSync(fd); } catch { /* best effort */ }
      try { fs.unlinkSync(filePath); } catch { /* best effort */ }
    }
  }
}

export function findLuauCompiler(): string | null {
  if (cachedCompilerBin !== undefined) return cachedCompilerBin;
  const localCompilerName = process.platform === 'win32' ? 'luau-compile.exe' : 'luau-compile';
  const candidates = [
    path.join(PROJECT_ROOT, 'tools', 'luau', localCompilerName),
    path.join(PROJECT_ROOT, 'tools', 'luau', 'luau-compile'),
    '/tmp/luau-bin/luau-compile',
  ];
  for (const c of candidates) {
    try {
      fs.accessSync(c, fs.constants.X_OK);
      cachedCompilerBin = c;
      return c;
    } catch {
      // keep checking
    }
  }
  cachedCompilerBin = null;
  return null;
}

export function findLuauRuntime(): string | null {
  if (cachedRuntimeBin !== undefined) return cachedRuntimeBin;
  const localRuntimeName = process.platform === 'win32' ? 'luau.exe' : 'luau';
  const candidates = [
    path.join(PROJECT_ROOT, 'tools', 'luau', localRuntimeName),
    path.join(PROJECT_ROOT, 'tools', 'luau', 'luau'),
    '/tmp/luau-bin/luau',
  ];
  for (const c of candidates) {
    try {
      fs.accessSync(c, fs.constants.X_OK);
      cachedRuntimeBin = c;
      return c;
    } catch {
      // keep checking
    }
  }
  cachedRuntimeBin = null;
  return null;
}

export interface VerificationOutcome {
  ok: boolean;
  engine: 'luau-compile' | 'internal-parser';
  error?: string;
}

/**
 * Verify that generated code compiles cleanly as real Roblox Luau bytecode
 * (checks syntax, local-register limits, jump offsets, and bytecode generation).
 */
export function verifyLuauSyntax(code: string): VerificationOutcome {
  const compiler = findLuauCompiler();
  if (compiler) {
    const tmpFile = path.join(os.tmpdir(), `gf_verify_${randomBytes(16).toString('hex')}.luau`);
    let tmpFileCreated = false;
    try {
      // User scripts may contain proprietary source; the helper uses private
      // permissions and exclusive creation without touching any existing path.
      writePrivateTempScript(tmpFile, code);
      tmpFileCreated = true;
      const res = spawnSync(compiler, ['--null', '-O1', tmpFile], {
        timeout: COMPILER_TIMEOUT_MS,
        encoding: 'utf8',
        maxBuffer: VERIFIER_MAX_BUFFER,
      });
      if (res.error) {
        const error = res.error as NodeJS.ErrnoException;
        return {
          ok: false,
          engine: 'luau-compile',
          error: error.code === 'ETIMEDOUT'
            ? `Luau compiler timed out after ${COMPILER_TIMEOUT_MS} ms`
            : error.code === 'ENOBUFS'
              ? `Luau compiler output exceeded the ${VERIFIER_MAX_BUFFER}-byte limit`
              : `Luau compiler process failed: ${error.message}`,
        };
      }
      if (res.status === 0) {
        return { ok: true, engine: 'luau-compile' };
      }
      return {
        ok: false,
        engine: 'luau-compile',
        error: (res.stderr || res.stdout || 'Luau compiler rejected output').trim(),
      };
    } finally {
      if (tmpFileCreated) {
        try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
      }
    }
  }

  // Pure-TypeScript fallback when official binary isn't installed
  try {
    parseLuau(code);
    return { ok: true, engine: 'internal-parser' };
  } catch (err) {
    return {
      ok: false,
      engine: 'internal-parser',
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export interface LuauRunResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  durationMs: number;
  available: boolean;
}

/**
 * Execute a Luau script inside the official Roblox Luau 0.747 runtime with a hard timeout
 * (used by test suite and optional live equivalence check).
 */
export function executeLuau(code: string, timeoutMs = 3000): LuauRunResult {
  const runtime = findLuauRuntime();
  if (!runtime) {
    return { ok: false, stdout: '', stderr: 'Luau runtime binary not installed', durationMs: 0, available: false };
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_SYNC_TIMEOUT_MS) {
    return {
      ok: false,
      stdout: '',
      stderr: `Luau runtime timeout must be an integer from 1 to ${MAX_SYNC_TIMEOUT_MS} ms`,
      durationMs: 0,
      available: true,
    };
  }

  const tmpFile = path.join(os.tmpdir(), `gf_run_${randomBytes(16).toString('hex')}.luau`);
  let tmpFileCreated = false;
  try {
    // Match verifier scratch-file protections for scripts executed by the test/API helper.
    writePrivateTempScript(tmpFile, code);
    tmpFileCreated = true;
    const t0 = performance.now();
    const res = spawnSync(runtime, ['-O2', tmpFile], {
      timeout: timeoutMs,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
    const durationMs = Math.round((performance.now() - t0) * 100) / 100;
    if (res.error) {
      const error = res.error as NodeJS.ErrnoException;
      return {
        ok: false,
        stdout: res.stdout || '',
        stderr: error.code === 'ETIMEDOUT'
          ? `Luau runtime timed out after ${timeoutMs} ms`
          : error.code === 'ENOBUFS'
            ? 'Luau runtime output exceeded the 1 MB limit'
            : error.message,
        durationMs,
        available: true,
      };
    }
    return {
      ok: res.status === 0,
      stdout: res.stdout || '',
      stderr: res.stderr || '',
      durationMs,
      available: true,
    };
  } finally {
    if (tmpFileCreated) {
      try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
    }
  }
}
