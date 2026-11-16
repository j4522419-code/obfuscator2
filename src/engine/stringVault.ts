import { bytesKey, utf8Bytes } from './ast.js';
import { MBAEngine } from './mba.js';
import { NameGenerator } from './names.js';
import { PRNG, bit32 } from './prng.js';
import { buildSafeAlphabet85, encryptAndEncodeBase85 } from './serializer.js';
import { StringEncryptionMode } from './types.js';

interface VaultEntry {
  id: number;     // 1-based slot ID (shuffled, non-sequential)
  offset: number;
  len: number;
  key: number;
}

/**
 * Polymorphic String Vault used for:
 *   1. Encrypting VM bootstrap stdlib identifiers (`bit32`, `buffer`, `string`, `table`, etc.)
 *   2. Encrypting all string literals in AST-obfuscation (Performance) mode and `--@novm` functions.
 *
 * All strings are packed into a single rolling-cipher Base85 Luau `buffer` with individual
 * per-string stream keys — zero plaintext string constants remain in the output.
 */
export class StringVault {
  private entries: VaultEntry[] = [];
  private dedup = new Map<string, VaultEntry>();
  private poolBytes: number[] = [];
  private readonly mult: number;
  private readonly inc: number;
  private readonly idXor: number;
  public readonly fnName: string;

  constructor(
    private readonly rng: PRNG,
    private readonly names: NameGenerator,
    private readonly mode: StringEncryptionMode,
  ) {
    this.mult = rng.oddInt(39, 251);
    this.inc = rng.oddInt(11, 247);
    this.idXor = rng.int(0x100, 0x7fff);
    this.fnName = names.next();
  }

  get count(): number {
    return this.entries.length;
  }

  addBytes(raw: Uint8Array): number {
    const k = bytesKey(raw);
    const existing = this.dedup.get(k);
    if (existing) return existing.id;

    const offset = this.poolBytes.length;
    const len = raw.length;
    const key = this.rng.int(1, 254);
    let s = key;
    for (let i = 0; i < len; i++) {
      const enc = (raw[i] ^ s ^ ((i * 19) & 0xff)) & 0xff;
      this.poolBytes.push(enc);
      s = (s * this.mult + this.inc + enc) & 0xff;
    }
    const id = this.entries.length + 1;
    const entry: VaultEntry = { id, offset, len, key };
    this.entries.push(entry);
    this.dedup.set(k, entry);
    return id;
  }

  addUtf8(str: string): number {
    return this.addBytes(utf8Bytes(str));
  }

  /** Return a Luau call expression decrypting the given string bytes */
  callBytes(raw: Uint8Array, mba: MBAEngine): string {
    const id = this.addBytes(raw);
    const maskedId = bit32.bxor(id, this.idXor);
    return `${this.fnName}(${mba.num(maskedId)})`;
  }

  callUtf8(str: string, mba: MBAEngine): string {
    return this.callBytes(utf8Bytes(str), mba);
  }

  /**
   * Emit standalone Luau code initializing the encrypted buffer and defining `local <fnName>`.
   * Supports mixing an external runtime key local (from line-poison / PlaceId lock) into the cipher!
   */
  emitRuntime(
    mba: MBAEngine,
    refs: {
      bxor: string;
      band: string;
      rrotate: string;
      bufCreate: string;
      bufWriteU32: string;
      bufReadU8: string;
      bufWriteU8: string;
      bufReadStr: string;
      strByte: string;
    },
    runtimeMix?: { varName: string; expectedValue: number },
  ): string {
    if (this.entries.length === 0) {
      return `local function ${this.fnName}()return""end;`;
    }

    const masterKey = this.rng.nextU32() || 0x13579bdf;
    const stepConst = this.rng.oddInt(0x10001, 0x7fffffff);
    const rot1 = this.rng.int(3, 15);
    const rot2 = this.rng.int(17, 29);
    const alphabet = buildSafeAlphabet85(this.rng);

    const raw = new Uint8Array(this.poolBytes.length > 0 ? this.poolBytes : [0]);
    const enc = encryptAndEncodeBase85(raw, { masterKey, stepConst, rot1, rot2, alphabet }, this.rng);

    const preSeed = runtimeMix ? bit32.bxor(masterKey, runtimeMix.expectedValue) : masterKey;

    const [
      vAlpha, vLut, vIdx, vData, vBuf, vState, vWord, vPos, vVal,
      vPow, vDigit, vCipher, vPlain, vMeta, vCache, vArg, vRealId,
      vOff, vLen, vKey, vOut, vJ, vByte, vDec, vRes,
    ] = this.names.many(25);

    const initStateExpr = runtimeMix
      ? `${refs.bxor}(${mba.num(preSeed)},${runtimeMix.varName})`
      : mba.num(preSeed);

    // Flatten metadata triples (offset, len, key) XORed with small masks
    const offMask = this.rng.int(0x10, 0x3fff);
    const lenMask = this.rng.int(0x10, 0x3fff);
    const keyMask = this.rng.int(1, 254);
    const metaNums: number[] = [];
    for (const e of this.entries) {
      metaNums.push(
        bit32.bxor(e.offset, offMask),
        bit32.bxor(e.len, lenMask),
        bit32.bxor(e.key, keyMask),
      );
    }

    const useCache = this.mode !== 'ephemeral';
    const parts: string[] = [];
    parts.push(`local ${vAlpha}="${alphabet}";`);
    parts.push(`local ${vLut}={};for ${vIdx}=1,85 do ${vLut}[${refs.strByte}(${vAlpha},${vIdx})]=${vIdx}-1 end;`);
    parts.push(`local ${vData}="${enc.encoded}";`);
    parts.push(`local ${vBuf}=${refs.bufCreate}(${mba.num(enc.wordCount * 4)});`);
    parts.push(`do local ${vState}=${initStateExpr};local ${vPos}=1;`);
    parts.push(`for ${vWord}=0,${mba.num(enc.wordCount - 1)} do `);
    parts.push(`local ${vVal}=0;local ${vPow}=1;`);
    parts.push(`for ${vDigit}=0,4 do ${vVal}+=${vLut}[${refs.strByte}(${vData},${vPos}+${vDigit})]*${vPow};${vPow}*=85 end;`);
    parts.push(`${vPos}+=5;local ${vCipher}=${vVal};local ${vPlain}=${refs.bxor}(${vCipher},${vState});`);
    parts.push(`${refs.bufWriteU32}(${vBuf},${vWord}*4,${vPlain});`);
    parts.push(`${vState}=${refs.bxor}(${refs.rrotate}(${vState},${rot1}),${vCipher});`);
    parts.push(`${vState}=(${vState}+${mba.num(stepConst)})%4294967296;`);
    parts.push(`${vState}=${refs.bxor}(${vState},${refs.rrotate}(${vCipher},${rot2}));`);
    parts.push(`end end;`);
    parts.push(`local ${vMeta}={${metaNums.join(',')}};`);
    if (useCache) parts.push(`local ${vCache}={};`);
    parts.push(`local function ${this.fnName}(${vArg})`);
    parts.push(`local ${vRealId}=${refs.bxor}(${vArg},${mba.num(this.idXor)});`);
    if (useCache) {
      parts.push(`local ${vRes}=${vCache}[${vRealId}];if ${vRes}~=nil then return ${vRes} end;`);
    }
    parts.push(`local ${vIdx}=(${vRealId}-1)*3;`);
    parts.push(`local ${vOff}=${refs.bxor}(${vMeta}[${vIdx}+1],${mba.num(offMask)});`);
    parts.push(`local ${vLen}=${refs.bxor}(${vMeta}[${vIdx}+2],${mba.num(lenMask)});`);
    parts.push(`if ${vLen}==0 then return""end;`);
    parts.push(`local ${vKey}=${refs.bxor}(${vMeta}[${vIdx}+3],${mba.num(keyMask)});`);
    parts.push(`local ${vOut}=${refs.bufCreate}(${vLen});`);
    parts.push(`for ${vJ}=0,${vLen}-1 do `);
    parts.push(`local ${vByte}=${refs.bufReadU8}(${vBuf},${vOff}+${vJ});`);
    parts.push(`local ${vDec}=${refs.band}(${refs.bxor}(${refs.bxor}(${vByte},${vKey}),(${vJ}*19)%256),255);`);
    parts.push(`${refs.bufWriteU8}(${vOut},${vJ},${vDec});`);
    parts.push(`${vKey}=(${vKey}*${this.mult}+${this.inc}+${vByte})%256;`);
    parts.push(`end;`);
    if (useCache) {
      parts.push(`${vRes}=${refs.bufReadStr}(${vOut},0,${vLen});${vCache}[${vRealId}]=${vRes};return ${vRes};`);
    } else {
      parts.push(`return ${refs.bufReadStr}(${vOut},0,${vLen});`);
    }
    parts.push(`end;`);

    return parts.join('');
  }
}

/**
 * Build a micro XOR-encoded byte string expression for bootstrapping stdlib keys
 * (`"bit32"`, `"buffer"`, `"string"`, `"table"`, etc.) WITHOUT any plaintext global names!
 * Uses only `string.char` and `bit32.bxor` (or simple modular arithmetic BEFORE `bit32` is fetched!).
 */
export function emitBootstrapDecoder(
  rng: PRNG,
  names: NameGenerator,
  words: string[],
): { initCode: string; tableVar: string; indexOf: Map<string, number> } {
  const tableVar = names.next();
  const [vBlob, vChar, vIdx, vLen, vKey, vTmp, vJ, vB] = names.many(8);
  const mult = rng.oddInt(29, 241);
  const inc = rng.oddInt(13, 239);

  // Shuffle order so word indices reveal nothing
  const shuffled = rng.shuffle(words);
  const indexOf = new Map<string, number>();
  const flatNums: number[] = [];

  shuffled.forEach((word, idx) => {
    indexOf.set(word, idx + 1);
    const bytes = utf8Bytes(word);
    const key = rng.int(17, 250);
    flatNums.push(bytes.length, key);
    let s = key;
    for (let i = 0; i < bytes.length; i++) {
      // Modular cipher: enc = (plain + s) % 256  => plain = (enc - s) % 256 (works before bit32 loads!)
      const enc = (bytes[i] + s) & 0xff;
      flatNums.push(enc);
      s = (s * mult + inc + enc) & 0xff;
    }
  });

  // Note: string.char obtained via (""):sub trick! getmetatable("").__index.char — doesn't even spell `string`!
  // Wait: in Roblox Luau, getmetatable("") IS locked ("The metatable is locked")!
  // Good catch!! Use `string.char` directly (single reference), then fetch EVERY other library & method via `env[tableVar[k]]`!
  const initCode =
    `local ${tableVar}={};do local ${vChar}=string.char;` +
    `local ${vBlob}={${flatNums.join(',')}};local ${vIdx}=1;` +
    `while ${vIdx}<=${flatNums.length} do ` +
    `local ${vLen}=${vBlob}[${vIdx}];local ${vKey}=${vBlob}[${vIdx}+1];${vIdx}+=2;` +
    `local ${vTmp}={};for ${vJ}=1,${vLen} do local ${vB}=${vBlob}[${vIdx}];${vIdx}+=1;` +
    `${vTmp}[${vJ}]=${vChar}((${vB}-${vKey})%256);${vKey}=(${vKey}*${mult}+${inc}+${vB})%256 end;` +
    `${tableVar}[#${tableVar}+1]=table.concat(${vTmp}) end end;`;

  return { initCode, tableVar, indexOf };
}
