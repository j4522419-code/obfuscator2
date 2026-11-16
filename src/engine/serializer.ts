import { computeBufferWordsMac32 } from './antiTamper.js';
import {
  CCFICipherSpec,
  createCCFICipherSpec,
  encodeProtoCCFI,
} from './cfgEngine.js';
import {
  RUNTIME_OPS,
  CompiledModule,
  HOT_OPS,
  IRProto,
  Op,
} from './ir.js';
import { PRNG, bit32 } from './prng.js';
import { ResolvedOptions } from './types.js';

/**
 * 85 printable single-byte ASCII characters safe inside a single-line Luau `"..."` literal
 * with zero backslash escapes (excludes `"`, `'`, `\`, `` ` ``, space, `[`, `]`).
 */
export function buildSafeAlphabet85(rng: PRNG): string {
  const chars: string[] = [];
  for (let code = 33; code <= 126; code++) {
    if (
      code === 34 || code === 39 || code === 91 ||
      code === 92 || code === 93 || code === 96
    ) {
      continue;
    }
    chars.push(String.fromCharCode(code));
  }
  return rng.shuffle(chars).slice(0, 85).join('');
}

export interface StreamCipherParams {
  masterKey: number;
  stepConst: number;
  rot1: number;
  rot2: number;
  alphabet: string;
}

export function encryptAndEncodeBase85(
  raw: Uint8Array,
  params: StreamCipherParams,
  rng: PRNG,
): { encoded: string; wordCount: number; rawLength: number; plainWords: Uint32Array } {
  const paddedLen = Math.max(4, Math.ceil(raw.length / 4) * 4);
  const buf = Buffer.alloc(paddedLen);
  buf.set(raw, 0);
  for (let i = raw.length; i < paddedLen; i++) {
    buf[i] = rng.int(0, 255);
  }

  const wordCount = paddedLen / 4;
  const plainWords = new Uint32Array(wordCount);
  let state = params.masterKey >>> 0;
  const alpha = params.alphabet;
  const outChars: string[] = new Array(wordCount * 5);

  for (let w = 0; w < wordCount; w++) {
    const plain = buf.readUInt32LE(w * 4) >>> 0;
    plainWords[w] = plain;
    const cipher = bit32.bxor(plain, state);

    // 32-bit rolling CBC feedback cipher
    state = bit32.bxor(bit32.rrotate(state, params.rot1), cipher);
    state = bit32.add32(state, params.stepConst);
    state = bit32.bxor(state, bit32.rrotate(cipher, params.rot2));

    let rem = cipher;
    const base = w * 5;
    for (let d = 0; d < 5; d++) {
      outChars[base + d] = alpha[rem % 85];
      rem = Math.floor(rem / 85);
    }
  }

  return {
    encoded: outChars.join(''),
    wordCount,
    rawLength: raw.length,
    plainWords,
  };
}

class ByteWriter {
  private buf = Buffer.alloc(8192);
  private pos = 0;

  private ensure(extra: number): void {
    if (this.pos + extra <= this.buf.length) return;
    let next = this.buf.length * 2;
    while (next < this.pos + extra) next *= 2;
    const nb = Buffer.alloc(next);
    this.buf.copy(nb, 0, 0, this.pos);
    this.buf = nb;
  }

  u8(v: number): void {
    this.ensure(1);
    this.buf[this.pos++] = v & 0xff;
  }

  varuint(v: number): void {
    let n = v >>> 0;
    while (n >= 0x80) {
      this.u8((n & 0x7f) | 0x80);
      n >>>= 7;
    }
    this.u8(n & 0x7f);
  }

  i32(v: number): void {
    this.ensure(4);
    this.buf.writeInt32LE(v | 0, this.pos);
    this.pos += 4;
  }

  u32(v: number): void {
    this.ensure(4);
    this.buf.writeUInt32LE(v >>> 0, this.pos);
    this.pos += 4;
  }

  f64(v: number): void {
    this.ensure(8);
    this.buf.writeDoubleLE(v, this.pos);
    this.pos += 8;
  }

  finish(): Uint8Array {
    return new Uint8Array(this.buf.buffer, this.buf.byteOffset, this.pos);
  }
}

export type ProtoSectionId = 'meta' | 'constants' | 'instructions' | 'upvals' | 'protos';

export interface PhysicalOpcodeEntry {
  physId: number;           // unique ID in 0..255
  logicalOp: Op | 'DECOY';
  variantIdx: number;       // structural polymorphism variant 0..2
  decoySeed: number;
}

export interface ConstantTypeTags {
  nil: number;
  boolFalse: number;
  boolTrue: number;
  int32: number;
  float64: number;
  encString: number;
}

export interface PolymorphicVMSpec {
  opAliases: Map<Op, number[]>;
  dispatchTable: PhysicalOpcodeEntry[];
  realPhysicalCount: number;
  decoyCount: number;
  ccfi: CCFICipherSpec;
  sectionOrder: ProtoSectionId[];
  constTags: ConstantTypeTags;
  /** Per-string rolling autokey stream cipher inside encrypted `strBuf` */
  strXorMult: number;
  strXorInc: number;
  strPosPrime: number;
  stringCount: number;
  /** Master stream cipher & payloads */
  masterKey: number;
  strKeyXor: number;
  bytecodeCipher: StreamCipherParams;
  bytecodePayload: string;
  bytecodeWordCount: number;
  rawBytecodeBytes: number;
  strPoolCipher: StreamCipherParams;
  strPoolPayload: string;
  strPoolWordCount: number;
  /** Post-decode full-buffer 32-bit integrity MAC folded into every Proto's CCFI entryKey! */
  postMacSeed: number;
  postMacRot: number;
  postMacStep: number;
  /** XOR fixup: `bxor(computedPostMac, entryKeyFixup) == entryKeySecretMask` */
  entryKeySecretMask: number;
  postMacFixup: number;
}

export function serializePolymorphicVM(
  compiled: CompiledModule,
  opts: ResolvedOptions,
  rng: PRNG,
): PolymorphicVMSpec {
  // 1. Collect all active logical/mutated/superinstruction/CCFI opcodes + sprinkle unused real ops
  const activeOps = new Set<Op>(compiled.allUsedOps);
  const legacyRuntimeOps = RUNTIME_OPS.filter((op) => op <= Op.VM_MBA_NEG || op === Op.GUARD);
  for (const op of legacyRuntimeOps) {
    if (op === Op.JMP) continue; // lowered to JMPX by compatibility preparation
    if (!activeOps.has(op) && rng.chance(opts.preset === 'nightmare' ? 0.35 : 0.18)) {
      activeOps.add(op);
    }
  }

  // 2. Assign randomized & duplicated physical opcode IDs across 0..255
  const idPool = rng.shuffle(Array.from({ length: 256 }, (_, i) => i));
  let cursor = 0;
  const maxRealSlots = Math.max(180, 252 - opts.decoyHandlers);

  const opAliases = new Map<Op, number[]>();
  const dispatchTable: PhysicalOpcodeEntry[] = [];
  const shuffledOps = rng.shuffle(Array.from(activeOps));

  // Guarantee at least 1 slot per op first, then assign 2x/3x split aliases
  for (const op of shuffledOps) {
    const physId = idPool[cursor++];
    opAliases.set(op, [physId]);
    dispatchTable.push({ physId, logicalOp: op, variantIdx: 0, decoySeed: rng.nextU32() });
  }

  if (opts.opcodeDuplication >= 2) {
    for (const op of shuffledOps) {
      if (cursor >= maxRealSlots) break;
      const wantCopies =
        opts.opcodeDuplication >= 3
          ? (HOT_OPS.has(op) ? 3 : 2)
          : (HOT_OPS.has(op) ? 2 : 1);
      const list = opAliases.get(op)!;
      while (list.length < wantCopies && cursor < maxRealSlots) {
        const physId = idPool[cursor++];
        const vIdx = list.length;
        list.push(physId);
        dispatchTable.push({ physId, logicalOp: op, variantIdx: vIdx, decoySeed: rng.nextU32() });
      }
    }
  }

  const realPhysicalCount = dispatchTable.length;

  // 3. Inject interleaved realistic decoy opcode handlers
  const actualDecoys = Math.min(opts.decoyHandlers, 255 - cursor);
  for (let d = 0; d < actualDecoys; d++) {
    const physId = idPool[cursor++];
    dispatchTable.push({
      physId,
      logicalOp: 'DECOY',
      variantIdx: d % 7,
      decoySeed: rng.nextU32(),
    });
  }

  dispatchTable.sort((a, b) => a.physId - b.physId);

  // 4. Create polymorphic CCFI cipher spec & encode EVERY Proto's 12-byte raw buffer instructions!
  const ccfi = createCCFICipherSpec(rng);
  encodeProtoCCFI(compiled.root, opAliases, ccfi, rng);

  // 5. Shuffled Proto section layout & randomized constant type tags
  const sectionOrder = rng.shuffle<ProtoSectionId>([
    'meta',
    'constants',
    'instructions',
    'upvals',
    'protos',
  ]);
  const tagPool = rng.shuffle(Array.from({ length: 250 }, (_, i) => i + 1));
  const constTags: ConstantTypeTags = {
    nil: tagPool[0],
    boolFalse: tagPool[1],
    boolTrue: tagPool[2],
    int32: tagPool[3],
    float64: tagPool[4],
    encString: tagPool[5],
  };

  // 6. Per-string autokey stream cipher into separate encrypted `strBuf`
  const strXorMult = rng.oddInt(37, 251);
  const strXorInc = rng.oddInt(11, 249);
  const strPosPrime = rng.oddInt(13, 61);
  const strWriter = new ByteWriter();
  let strOffset = 0;
  let stringCount = 0;

  const appendEncryptedString = (raw: Uint8Array): { offset: number; len: number; key: number } => {
    stringCount++;
    const offset = strOffset;
    const len = raw.length;
    const key = rng.int(1, 254);
    let s = key;
    for (let i = 0; i < len; i++) {
      const encByte = (raw[i] ^ s ^ ((i * strPosPrime) & 0xff)) & 0xff;
      strWriter.u8(encByte);
      s = (s * strXorMult + strXorInc + encByte) & 0xff;
    }
    strOffset += len;
    return { offset, len, key };
  };

  // Secret mask hiding EVERY Proto's `entryKey` and `entryPC` until post-decode buffer MAC verifies!
  const entryKeySecretMask = rng.nextU32() || 0xd1b54a35;
  const [off0, off1, off2] = ccfi.wordOffsets;

  // Map byte offset (0, 4, 8) -> slot index (0, 1, 2) for raw 12-byte record writing
  const slotWords = new Uint32Array(3);
  const bcWriter = new ByteWriter();

  const writeProto = (proto: IRProto): void => {
    for (const sec of sectionOrder) {
      switch (sec) {
        case 'meta': {
          bcWriter.varuint(proto.numParams);
          bcWriter.u8(proto.isVararg ? 1 : 0);
          // Encrypt both entryPC and entryKey with `entryKeySecretMask` (derived from post-decode MAC!)
          bcWriter.u32(bit32.bxor(proto.entryPC >>> 0, entryKeySecretMask));
          bcWriter.u32(bit32.bxor(proto.entryKey >>> 0, bit32.rrotate(entryKeySecretMask, 13)));
          break;
        }
        case 'constants': {
          bcWriter.varuint(proto.constants.length);
          for (const c of proto.constants) {
            if (c.kind === 'nil') {
              bcWriter.u8(constTags.nil);
            } else if (c.kind === 'bool') {
              bcWriter.u8(c.value ? constTags.boolTrue : constTags.boolFalse);
            } else if (c.kind === 'number') {
              if (
                Number.isInteger(c.value) &&
                !Object.is(c.value, -0) &&
                c.value >= -2147483648 &&
                c.value <= 2147483647
              ) {
                bcWriter.u8(constTags.int32);
                bcWriter.i32(c.value);
              } else {
                bcWriter.u8(constTags.float64);
                bcWriter.f64(c.value);
              }
            } else {
              bcWriter.u8(constTags.encString);
              const d = appendEncryptedString(c.bytes);
              bcWriter.varuint(d.offset);
              bcWriter.varuint(d.len);
              bcWriter.u8(d.key);
            }
          }
          break;
        }
        case 'instructions': {
          // Raw packed 12-byte CCFI-encrypted binary buffer slice (copied directly via buffer.copy!)
          const words = proto.encodedWords!;
          bcWriter.varuint(words.length);
          for (let i = 0; i < words.length; i++) {
            const [c0, c1, c2] = words[i];
            slotWords[off0 >> 2] = c0;
            slotWords[off1 >> 2] = c1;
            slotWords[off2 >> 2] = c2;
            bcWriter.u32(slotWords[0]);
            bcWriter.u32(slotWords[1]);
            bcWriter.u32(slotWords[2]);
          }
          break;
        }
        case 'upvals': {
          bcWriter.varuint(proto.upvals.length);
          for (const u of proto.upvals) {
            bcWriter.u8(u.inStack ? 1 : 0);
            bcWriter.varuint(u.index);
          }
          break;
        }
        case 'protos': {
          bcWriter.varuint(proto.protos.length);
          for (const child of proto.protos) {
            writeProto(child);
          }
          break;
        }
      }
    }
  };

  writeProto(compiled.root);
  const rawBytecode = bcWriter.finish();
  const rawStrPool = strWriter.finish();

  // 7. Encrypt both streams under rolling 32-bit CBC cipher + per-build shuffled Base85 alphabet
  const masterKey = rng.nextU32() || 0xcafef00d;
  const strKeyXor = rng.nextU32() || 0x12345679;
  const alphabet = buildSafeAlphabet85(rng);

  const bytecodeCipher: StreamCipherParams = {
    masterKey,
    stepConst: rng.oddInt(0x1000001, 0x7fffffff),
    rot1: rng.int(3, 15),
    rot2: rng.int(17, 29),
    alphabet,
  };
  const strPoolCipher: StreamCipherParams = {
    masterKey: bit32.bxor(masterKey, strKeyXor),
    stepConst: rng.oddInt(0x1000001, 0x7fffffff),
    rot1: rng.int(3, 15),
    rot2: rng.int(17, 29),
    alphabet,
  };

  const bcEnc = encryptAndEncodeBase85(rawBytecode, bytecodeCipher, rng);
  const spEnc = encryptAndEncodeBase85(
    rawStrPool.length > 0 ? rawStrPool : new Uint8Array([rng.int(1, 254), rng.int(1, 254)]),
    strPoolCipher,
    rng,
  );

  // 8. Compute exact post-decode full-buffer 32-bit integrity MAC over all decrypted u32 words
  const postMacSeed = rng.nextU32() || 0x27d4eb2d;
  const postMacRot = rng.int(5, 25);
  const postMacStep = rng.oddInt(0x10001, 0x3fffffff);
  const exactPostMac = computeBufferWordsMac32(bcEnc.plainWords, postMacSeed, postMacRot, postMacStep);
  const postMacFixup = bit32.bxor(exactPostMac, entryKeySecretMask);

  return {
    opAliases,
    dispatchTable,
    realPhysicalCount,
    decoyCount: actualDecoys,
    ccfi,
    sectionOrder,
    constTags,
    strXorMult,
    strXorInc,
    strPosPrime,
    stringCount,
    masterKey,
    strKeyXor,
    bytecodeCipher,
    bytecodePayload: bcEnc.encoded,
    bytecodeWordCount: bcEnc.wordCount,
    rawBytecodeBytes: rawBytecode.length,
    strPoolCipher,
    strPoolPayload: spEnc.encoded,
    strPoolWordCount: spEnc.wordCount,
    postMacSeed,
    postMacRot,
    postMacStep,
    entryKeySecretMask,
    postMacFixup,
  };
}
