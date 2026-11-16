import crypto from 'node:crypto';

/** Exact 32-bit unsigned bitwise operations mirroring Roblox Luau's `bit32` library */
export const bit32 = {
  u32(x: number): number {
    return x >>> 0;
  },
  bxor(a: number, b: number): number {
    return ((a >>> 0) ^ (b >>> 0)) >>> 0;
  },
  band(a: number, b: number): number {
    return ((a >>> 0) & (b >>> 0)) >>> 0;
  },
  bor(a: number, b: number): number {
    return ((a >>> 0) | (b >>> 0)) >>> 0;
  },
  bnot(a: number): number {
    return (~(a >>> 0)) >>> 0;
  },
  lshift(a: number, disp: number): number {
    if (disp >= 32 || disp <= -32) return 0;
    if (disp < 0) return (a >>> 0) >>> (-disp);
    return ((a >>> 0) << disp) >>> 0;
  },
  rshift(a: number, disp: number): number {
    if (disp >= 32 || disp <= -32) return 0;
    if (disp < 0) return ((a >>> 0) << (-disp)) >>> 0;
    return (a >>> 0) >>> disp;
  },
  rrotate(a: number, disp: number): number {
    const s = ((disp % 32) + 32) % 32;
    const u = a >>> 0;
    if (s === 0) return u;
    return ((u >>> s) | ((u << (32 - s)) >>> 0)) >>> 0;
  },
  lrotate(a: number, disp: number): number {
    const s = ((disp % 32) + 32) % 32;
    const u = a >>> 0;
    if (s === 0) return u;
    return (((u << s) >>> 0) | (u >>> (32 - s))) >>> 0;
  },
  add32(a: number, b: number): number {
    return (((a >>> 0) + (b >>> 0)) % 4294967296) >>> 0;
  },
};

/**
 * Compute a 32-bit hash of a 53-bit Roblox PlaceId/GameId in a way that
 * reproduces identically in Luau using IEEE-754 doubles + bit32 (no 64-bit int needed).
 *
 * Notice all multiplies stay safely below 2^52 (max (2^16)*(2^24) < 2^40) before % 2^32!
 */
export function hashRobloxId53(id: bigint, saltA: number, saltB: number): number {
  const lo = Number(id & 0xffffffffn) >>> 0;
  const hi = Number((id >> 32n) & 0x1fffffn) >>> 0;
  let h = bit32.bxor(lo, saltA >>> 0);
  // Mix low/high 16-bit halves with small primes so double arithmetic in Luau is 100% exact
  const hLo = h & 0xffff;
  const hHi = h >>> 16;
  h = bit32.bxor(bit32.add32((hLo * 40503) >>> 0, ((hHi * 65521) & 0xffff) * 65536), bit32.rrotate(h, 13));
  h = bit32.bxor(h, bit32.add32(hi * 2654435, saltB >>> 0));
  const h2Lo = h & 0xffff;
  const h2Hi = h >>> 16;
  h = bit32.bxor(bit32.add32((h2Lo * 58653) >>> 0, ((h2Hi * 39383) & 0xffff) * 65536), bit32.rrotate(h, 7));
  return h >>> 0;
}

/** xoshiro128** seeded via SHA-256 (either crypto random or user seed) */
export class PRNG {
  private s0: number;
  private s1: number;
  private s2: number;
  private s3: number;
  public readonly buildId: string;

  constructor(seed?: string) {
    const raw = seed !== undefined
      ? crypto.createHash('sha256').update(seed).digest()
      : crypto.randomBytes(32);
    this.s0 = raw.readUInt32LE(0) || 0x9e3779b9;
    this.s1 = raw.readUInt32LE(4) || 0x243f6a88;
    this.s2 = raw.readUInt32LE(8) || 0xb7e15162;
    this.s3 = raw.readUInt32LE(12) || 0xdeadbeef;
    this.buildId = 'GF-' + raw.subarray(16, 20).toString('hex').toUpperCase();
  }

  /** Random unsigned 32-bit integer [0, 2^32 - 1] */
  nextU32(): number {
    const result = Math.imul(bit32.lrotate(Math.imul(this.s1, 5) >>> 0, 7), 9) >>> 0;
    const t = (this.s1 << 9) >>> 0;
    this.s2 = (this.s2 ^ this.s0) >>> 0;
    this.s3 = (this.s3 ^ this.s1) >>> 0;
    this.s1 = (this.s1 ^ this.s2) >>> 0;
    this.s0 = (this.s0 ^ this.s3) >>> 0;
    this.s2 = (this.s2 ^ t) >>> 0;
    this.s3 = bit32.lrotate(this.s3, 11);
    return result;
  }

  /** Random integer in [min, max] inclusive */
  int(min: number, max: number): number {
    if (max <= min) return min;
    const span = max - min + 1;
    return min + (this.nextU32() % span);
  }

  /** Random float in [0, 1) */
  float(): number {
    return this.nextU32() / 4294967296;
  }

  /** Random boolean with probability p */
  chance(p = 0.5): boolean {
    return this.float() < p;
  }

  /** Random odd integer in [min, max] (coprime with powers of 2) */
  oddInt(min: number, max: number): number {
    return this.int(min, max) | 1;
  }

  /** Pick random element from non-empty array */
  pick<T>(arr: readonly T[]): T {
    return arr[this.nextU32() % arr.length];
  }

  /** Return a freshly Fisher-Yates shuffled copy */
  shuffle<T>(arr: readonly T[]): T[] {
    const copy = arr.slice();
    for (let i = copy.length - 1; i > 0; i--) {
      const j = this.nextU32() % (i + 1);
      const tmp = copy[i];
      copy[i] = copy[j];
      copy[j] = tmp;
    }
    return copy;
  }
}
