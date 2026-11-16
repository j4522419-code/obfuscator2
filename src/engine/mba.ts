import { PRNG, bit32 } from './prng.js';

export interface Bit32Refs {
  bxor: string;
  band: string;
  bor: string;
  bnot: string;
  rrotate?: string;
}

/**
 * Mixed Boolean-Arithmetic (MBA) & Opaque Predicate Engine for Roblox Luau.
 *
 * Uses mathematically exact identities over 32-bit unsigned words (via Luau bit32)
 * and exact IEEE-754 integers (<= 2^50), so values never drift or lose precision:
 *   1. x == (a ^ b)                           where b = a ^ x
 *   2. (a + b) == (a ^ b) + 2 * (a & b)
 *   3. (a + b) == (a | b) + (a & b)
 *   4. (a ^ b) == (a | b) - (a & b)
 *   5. x == ((a | b) - (a & b)) + (x - (a ^ b))
 *   6. ~a == 4294967295 - a                   (in bit32 unsigned 32-bit arithmetic)
 */
export class MBAEngine {
  public count = 0;

  constructor(
    private readonly rng: PRNG,
    private readonly b: Bit32Refs,
    private readonly defaultDepth: number,
  ) {}

  /** Format a non-negative integer as hex or decimal randomly to confuse regex pattern matchers */
  private fmtLit(n: number): string {
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
      return String(n);
    }
    if (this.rng.chance(0.55)) {
      return '0x' + (n >>> 0).toString(16).toUpperCase();
    }
    return String(n >>> 0);
  }

  /**
   * Encode any exact safe integer (including negative and u32 integers up to 2^32 - 1)
   * as a polymorphic Mixed Boolean-Arithmetic Luau expression.
   */
  num(value: number, depthOverride?: number): string {
    const depth = depthOverride ?? this.defaultDepth;
    if (
      depth <= 0 ||
      !Number.isFinite(value) ||
      !Number.isInteger(value) ||
      Math.abs(value) > 0xffffffff ||
      Object.is(value, -0)
    ) {
      return this.formatPlainNumber(value);
    }

    if (value < 0) {
      const pos = -value;
      if (pos <= 0x7fffffff) {
        return `(-${this.encodeU32(pos, depth)})`;
      }
      return this.formatPlainNumber(value);
    }

    return this.encodeU32(value >>> 0, depth);
  }

  private encodeU32(target: number, depth: number): string {
    this.count++;
    if (depth <= 0) {
      return this.fmtLit(target);
    }

    const subDepth = depth - 1;
    const variant = this.rng.int(0, 4);

    switch (variant) {
      case 0: {
        // Identity: target = bxor(a, b) where b = bxor(target, a)
        const mask = target <= 0xffff ? this.rng.int(0x100, 0xffff) : this.rng.nextU32();
        const other = bit32.bxor(target, mask);
        const aExpr = subDepth > 0 && this.rng.chance(0.5) ? this.encodeU32(mask, subDepth) : this.fmtLit(mask);
        const bExpr = subDepth > 0 && this.rng.chance(0.5) ? this.encodeU32(other, subDepth) : this.fmtLit(other);
        return `${this.b.bxor}(${aExpr},${bExpr})`;
      }
      case 1: {
        // MBA Identity: (a | b) - (a & b) == (a ^ b) == target
        const a = target <= 0xffff ? this.rng.int(0x10, 0xffff) : this.rng.nextU32();
        const b = bit32.bxor(target, a);
        // Verify exact equality in JS double
        const check = bit32.bor(a, b) - bit32.band(a, b);
        if (check !== target) return this.fmtLit(target);
        const aS = this.fmtLit(a);
        const bS = this.fmtLit(b);
        return `(${this.b.bor}(${aS},${bS})-${this.b.band}(${aS},${bS}))`;
      }
      case 2: {
        // MBA Identity: target = x + y = (x ^ y) + 2 * (x & y)
        if (target === 0) {
          const k = this.rng.int(0x11, 0x7fff);
          return `${this.b.band}(${this.fmtLit(k)},${this.b.bnot}(${this.fmtLit(k)}))`;
        }
        const x = this.rng.int(0, target);
        const y = target - x;
        const xU = x >>> 0;
        const yU = y >>> 0;
        const check = bit32.bxor(xU, yU) + 2 * bit32.band(xU, yU);
        if (check !== target) return this.fmtLit(target);
        const lhs = subDepth > 0 ? this.encodeU32(bit32.bxor(xU, yU), subDepth) : `${this.b.bxor}(${this.fmtLit(xU)},${this.fmtLit(yU)})`;
        return `(${lhs}+2*${this.b.band}(${this.fmtLit(xU)},${this.fmtLit(yU)}))`;
      }
      case 3: {
        // MBA Identity: target = x + y = (x | y) + (x & y)
        const x = target > 0 ? this.rng.int(0, target) : 0;
        const y = target - x;
        const xU = x >>> 0;
        const yU = y >>> 0;
        const check = bit32.bor(xU, yU) + bit32.band(xU, yU);
        if (check !== target) return this.fmtLit(target);
        const xS = this.fmtLit(xU);
        const yS = this.fmtLit(yU);
        return `(${this.b.bor}(${xS},${yS})+${this.b.band}(${xS},${yS}))`;
      }
      default: {
        // Split delta: target = bxor(a, b) - delta  (for small/medium values)
        const delta = this.rng.int(1, 0x3fff);
        if (target + delta <= 0xffffffff) {
          const sum = (target + delta) >>> 0;
          const a = this.rng.int(0x100, 0xfffff);
          const b = bit32.bxor(sum, a);
          const dExpr = subDepth > 0 ? this.encodeU32(delta, subDepth) : this.fmtLit(delta);
          return `(${this.b.bxor}(${this.fmtLit(a)},${this.fmtLit(b)})-${dExpr})`;
        }
        const a = this.rng.nextU32();
        const b = bit32.bxor(target, a);
        return `${this.b.bxor}(${this.fmtLit(a)},${this.fmtLit(b)})`;
      }
    }
  }

  /**
   * MBA rewrite of runtime `bxor(exprA, exprB)` using `(bor(a,b) - band(a,b))`
   * Note: exprA and exprB must be pure local variable names (no side effects).
   */
  mbaXorVars(varA: string, varB: string): string {
    this.count++;
    if (this.rng.chance(0.5)) {
      return `(${this.b.bor}(${varA},${varB})-${this.b.band}(${varA},${varB}))`;
    }
    return `${this.b.bxor}(${varA},${varB})`;
  }

  /**
   * MBA rewrite of runtime `varA + varB` when both are non-negative 32-bit integers.
   */
  mbaAddU32Vars(varA: string, varB: string): string {
    this.count++;
    const pick = this.rng.int(0, 2);
    if (pick === 0) {
      return `(${this.b.bxor}(${varA},${varB})+2*${this.b.band}(${varA},${varB}))`;
    }
    if (pick === 1) {
      return `(${this.b.bor}(${varA},${varB})+${this.b.band}(${varA},${varB}))`;
    }
    return `(${varA}+${varB})`;
  }

  /**
   * Generate an opaque predicate guaranteed ALWAYS TRUE for any integer local `intVar` (0..2^24).
   */
  alwaysTrue(intVar: string): string {
    this.count++;
    const k = this.rng.int(3, 0x3fff);
    const kind = this.rng.int(0, 3);
    switch (kind) {
      case 0:
        // bor(x, k) >= bxor(x, k) holds for ALL u32 x, k!
        return `(${this.b.bor}(${intVar},${this.fmtLit(k)})>=${this.b.bxor}(${intVar},${this.fmtLit(k)}))`;
      case 1:
        // band(x, k) <= bor(x, k) holds for ALL u32 x, k!
        return `(${this.b.band}(${intVar},${this.fmtLit(k)})<=${this.b.bor}(${intVar},${this.fmtLit(k)}))`;
      case 2:
        // band(x, bnot(x)) == 0 holds for ALL u32 x!
        return `(${this.b.band}(${intVar},${this.b.bnot}(${intVar}))==0)`;
      default:
        // (bor(x, k) - band(x, k)) == bxor(x, k) holds for ALL u32 x, k!
        return `((${this.b.bor}(${intVar},${this.fmtLit(k)})-${this.b.band}(${intVar},${this.fmtLit(k)}))==${this.b.bxor}(${intVar},${this.fmtLit(k)}))`;
    }
  }

  /**
   * Generate an opaque predicate guaranteed ALWAYS FALSE for any integer local `intVar`.
   */
  alwaysFalse(intVar: string): string {
    this.count++;
    const k = this.rng.int(5, 0x3fff);
    const kind = this.rng.int(0, 2);
    switch (kind) {
      case 0:
        return `(${this.b.bor}(${intVar},${this.fmtLit(k)})<${this.b.bxor}(${intVar},${this.fmtLit(k)}))`;
      case 1:
        return `(${this.b.band}(${intVar},${this.b.bnot}(${intVar}))~=0)`;
      default:
        return `(${this.b.band}(${intVar},${this.fmtLit(k)})>${this.b.bor}(${intVar},${this.fmtLit(k)}))`;
    }
  }

  formatPlainNumber(value: number): string {
    if (Object.is(value, -0)) return '(-0)';
    if (value === Infinity) return '(1/0)';
    if (value === -Infinity) return '(-1/0)';
    if (Number.isNaN(value)) return '(0/0)';
    // Guarantee round-trip IEEE-754 representation
    const s = String(value);
    return value < 0 ? `(${s})` : s;
  }
}
