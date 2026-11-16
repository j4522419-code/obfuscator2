import { PRNG } from './prng.js';
import { NameStyle } from './types.js';

const RESERVED = new Set([
  'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
  'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat',
  'return', 'then', 'true', 'until', 'while',
  // Also avoid Luau contextual keywords, discard `_`, & common globals for maximum cleanliness
  '_', 'continue', 'type', 'export', 'typeof', 'self', '_G', '_VERSION',
]);

const SHORT_FIRST = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';
const SHORT_REST = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
const BARCODE_FIRST = 'Il_';
const BARCODE_REST = 'Il1_';
const SHADOW_FIRST = 'OoQIl_';
const SHADOW_REST = 'O0oQIl1_';
const HEX_CHARS = '0123456789abcdefABCDEF';

export class NameGenerator {
  private used = new Set<string>();
  private counter = 0;
  private shuffledFirst: string;
  private shuffledRest: string;

  constructor(
    private readonly rng: PRNG,
    private readonly style: NameStyle,
  ) {
    this.shuffledFirst = rng.shuffle(SHORT_FIRST.split('')).join('');
    this.shuffledRest = rng.shuffle(SHORT_REST.split('')).join('');
  }

  reserve(name: string): void {
    this.used.add(name);
  }

  next(): string {
    for (let attempt = 0; attempt < 10000; attempt++) {
      let candidate: string;
      switch (this.style) {
        case 'short':
          candidate = this.genShort(this.counter++);
          break;
        case 'barcode':
          candidate = this.genAlphabet(BARCODE_FIRST, BARCODE_REST, this.rng.int(7, 12));
          break;
        case 'shadow':
          candidate = this.genAlphabet(SHADOW_FIRST, SHADOW_REST, this.rng.int(6, 11));
          break;
        case 'hex':
          candidate = '_0x' + this.genPure(HEX_CHARS, this.rng.int(4, 6));
          break;
      }
      if (!RESERVED.has(candidate) && !this.used.has(candidate)) {
        this.used.add(candidate);
        return candidate;
      }
    }
    const fallback = `_g${this.counter++}_${this.rng.nextU32().toString(16)}`;
    this.used.add(fallback);
    return fallback;
  }

  many(count: number): string[] {
    const out: string[] = [];
    for (let i = 0; i < count; i++) out.push(this.next());
    return out;
  }

  private genShort(n: number): string {
    const fLen = this.shuffledFirst.length;
    const rLen = this.shuffledRest.length;
    let out = this.shuffledFirst[n % fLen];
    let rem = Math.floor(n / fLen);
    while (rem > 0) {
      rem -= 1;
      out += this.shuffledRest[rem % rLen];
      rem = Math.floor(rem / rLen);
    }
    return out;
  }

  private genAlphabet(first: string, rest: string, len: number): string {
    let s = first[this.rng.nextU32() % first.length];
    for (let i = 1; i < len; i++) {
      s += rest[this.rng.nextU32() % rest.length];
    }
    return s;
  }

  private genPure(chars: string, len: number): string {
    let s = '';
    for (let i = 0; i < len; i++) {
      s += chars[this.rng.nextU32() % chars.length];
    }
    return s;
  }
}
