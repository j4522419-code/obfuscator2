import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLuau } from './parser.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');

let cachedCompilerBin: string | null | undefined;
let cachedRuntimeBin: string | null | undefined;

export function findLuauCompiler(): string | null {
  if (cachedCompilerBin !== undefined) return cachedCompilerBin;
  const candidates = [
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
  const candidates = [
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
    const tmpFile = path.join(
      os.tmpdir(),
      `gf_verify_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2)}.luau`,
    );
    try {
      fs.writeFileSync(tmpFile, code, 'utf8');
      const res = spawnSync(compiler, ['--null', '-O1', tmpFile], {
        timeout: 4000,
        encoding: 'utf8',
      });
      if (res.status === 0) {
        return { ok: true, engine: 'luau-compile' };
      }
      return {
        ok: false,
        engine: 'luau-compile',
        error: (res.stderr || res.stdout || 'Luau compiler rejected output').trim(),
      };
    } finally {
      try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
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

  const tmpFile = path.join(
    os.tmpdir(),
    `gf_run_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2)}.luau`,
  );
  try {
    fs.writeFileSync(tmpFile, code, 'utf8');
    const t0 = performance.now();
    const res = spawnSync(runtime, ['-O2', tmpFile], {
      timeout: timeoutMs,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
    const durationMs = Math.round((performance.now() - t0) * 100) / 100;
    if (res.error) {
      return {
        ok: false,
        stdout: res.stdout || '',
        stderr: res.error.message,
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
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
  }
}
