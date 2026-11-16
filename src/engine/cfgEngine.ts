import {
  CFGTransformStats,
  CompiledModule,
  FlatVMemImage,
  Instruction,
  IRProto,
  Op,
} from './ir.js';
import { PRNG, bit32 } from './prng.js';
import { GrandfuscatorError, ResolvedOptions } from './types.js';

/**
 * Grandfuscator v3.0 ("Oblivion") CCFI Cipher Specification.
 *
 *  - Loop head decrypts ONLY `c0` -> (storedPhysId, a16, mac8). `B`/`C` are NEVER
 *    decoded at the loop head — each physical handler decrypts its own operands
 *    with a PRIVATE (rotB, addB, rotC, addC) cipher keyed by a 256-byte nonlinear
 *    S-box:  c1 = rotl(B ^ oldK ^ sboxMask, rotB) + addB,  sboxMask = sbox[op]*0x01010101.
 *  - Every handler applies a PRIVATE exit key transition (hRot, hXor, hAdd) after
 *    the shared post-fetch ratchet, so no single formula models the key stream.
 *  - Key-parity remapping: storedPhysId = handlerId ^ ((oldK & 1) ? keyParityMask : 0).
 */
export interface HandlerCipher {
  rotB: number;
  addB: number;
  rotC: number;
  addC: number;
  hRot: number;
  hXor: number;
  hAdd: number;
}

export interface FlatCipherSpec {
  /** Shuffled byte offsets of logical words (c0, c1, c2) inside each 12-byte slot */
  wordOffsets: [number, number, number];
  ratchetRot: number;
  ratchetStep: number;
  macP1: number;
  macP2: number;
  macPoison: number;
  epochStep: number;
  epochRot1: number;
  epochRot2: number;
  /** XOR mask applied to handlerId when the pre-fetch key is odd (1..255) */
  keyParityMask: number;
  /** 256-byte nonlinear S-box derived from masterKey (shared with vmGenerator) */
  sbox: Uint8Array;
  /** Per-physical-handler private ciphers, indexed by handlerId (0..255) */
  handlers: Array<HandlerCipher | null>;
}

export function createFlatCipherSpec(rng: PRNG, sbox: Uint8Array): FlatCipherSpec {
  const wordOffsets = rng.shuffle([0, 4, 8]) as [number, number, number];
  const handlers: Array<HandlerCipher | null> = new Array(256).fill(null);
  return {
    wordOffsets,
    ratchetRot: rng.int(5, 27),
    ratchetStep: rng.oddInt(0x013579b, 0x3fffffff),
    macP1: rng.oddInt(37, 251),
    macP2: rng.oddInt(53, 249),
    macPoison: rng.oddInt(0x10001, 0x00fffffd),
    epochStep: rng.oddInt(0x0111111, 0x3fffffff),
    epochRot1: rng.int(5, 13),
    epochRot2: rng.int(17, 27),
    keyParityMask: rng.int(1, 255),
    sbox,
    handlers,
  };
}

/** Derive the 256-byte nonlinear S-box from masterKey (bit-exact in TS & Luau) */
export function deriveSBox(masterKey: number): Uint8Array {
  const sbox = new Uint8Array(256);
  const mk = masterKey >>> 0;
  for (let i = 0; i < 256; i++) {
    let x = bit32.bxor(mk, Math.imul(i, 0x9e3779b1) >>> 0);
    x = bit32.bxor(bit32.lrotate(x, 13), bit32.rshift(x, 16));
    x = Math.imul(x, 0x85ebca6b) >>> 0;
    x = bit32.bxor(x, bit32.rshift(x, 13));
    sbox[i] = x & 0xff;
  }
  return sbox;
}

/** Exact 8-bit instruction authentication MAC over ciphertext word c1 (loop-head verifiable!) */
export function computeInstMac8(
  storedPhysId: number,
  a16: number,
  c1: number,
  kBefore: number,
  spec: FlatCipherSpec,
): number {
  const t1 = bit32.bxor(Math.imul(storedPhysId, spec.macP1) >>> 0, Math.imul(a16, spec.macP2) >>> 0);
  const t2 = bit32.bxor(c1 & 0xffff, kBefore >>> 16);
  return bit32.bxor(t1, t2) & 0xff;
}

/** Exact shared post-fetch key ratchet (matches Luau VM bit-for-bit when macDiff === 0) */
export function ratchetKey(kBefore: number, c0: number, spec: FlatCipherSpec): number {
  const mixed = bit32.bxor(bit32.rrotate(kBefore, spec.ratchetRot), c0);
  return bit32.add32(mixed, spec.ratchetStep);
}

/** Exact per-handler exit key transition */
export function exitTransition(k1: number, hc: HandlerCipher): number {
  return bit32.add32(bit32.bxor(bit32.lrotate(k1, hc.hRot), hc.hXor), hc.hAdd);
}

/** Compatibility cipher used while the v3 flat runtime is being completed. */
export interface CCFICipherSpec {
  wordOffsets: [number, number, number];
  rotB: number;
  rotC: number;
  ratchetRot: number;
  ratchetStep: number;
  macP1: number;
  macP2: number;
  macPoison: number;
  epochRot1: number;
  epochRot2: number;
  epochStep: number;
}

export function createCCFICipherSpec(rng: PRNG): CCFICipherSpec {
  return {
    wordOffsets: rng.shuffle([0, 4, 8]) as [number, number, number],
    rotB: rng.int(3, 29),
    rotC: rng.int(3, 29),
    ratchetRot: rng.int(3, 29),
    ratchetStep: rng.oddInt(0x010001, 0x3fffffff),
    macP1: rng.oddInt(37, 251),
    macP2: rng.oddInt(53, 249),
    macPoison: rng.oddInt(0x10001, 0x00fffffd),
    epochRot1: rng.int(5, 13),
    epochRot2: rng.int(17, 27),
    epochStep: rng.oddInt(0x0111111, 0x3fffffff),
  };
}

/**
 * Encode legacy per-proto instruction buffers for the still-active v2 runtime. This
 * adapter is intentionally separate from the v3 `vmem` encoder and is not advertised
 * as v3 flat-memory protection.
 */
export function encodeProtoCCFI(
  root: IRProto,
  aliases: Map<Op, number[]>,
  spec: CCFICipherSpec,
  rng: PRNG,
): void {
  const branches = new Set<Op>([
    Op.JMPF, Op.JMPT, Op.FORPREP, Op.FORLOOP, Op.ITERPREP, Op.TFORLOOP,
    Op.EQJ, Op.NEJ, Op.LTJ, Op.LEJ, Op.STATE_JLE, Op.STATE_JEQ,
    Op.OPQ_NEVER, Op.OPQ_ALWAYS,
  ]);
  const unconditional = new Set<Op>([Op.JMPX, Op.CHAIN_HOP]);
  const noFallthrough = (op: Op): boolean => unconditional.has(op) || op === Op.RETURN;

  const encode = (proto: IRProto): void => {
    const ins = proto.instructions;
    const n = ins.length;
    proto.entryPC = 0;
    proto.entryKey = rng.nextU32() || 0x9e3779b9;
    const key = new Uint32Array(n);
    const after = new Uint32Array(n);
    const ids = new Uint8Array(n);
    const bPlain = new Uint32Array(n);
    const cPlain = new Uint32Array(n);
    const c0s = new Uint32Array(n);
    const c1s = new Uint32Array(n);
    const c2s = new Uint32Array(n);

    for (let pc = 0; pc < n; pc++) {
      const op = ins[pc].op;
      const list = aliases.get(op);
      if (!list?.length) throw new GrandfuscatorError(`No handler alias for ${Op[op]}`, 'vm');
      ids[pc] = rng.pick(list);
      key[pc] = pc === 0 ? proto.entryKey :
        (noFallthrough(ins[pc - 1].op) ? (rng.nextU32() || 0x7f4a7c15) : after[pc - 1]);

      const kb = key[pc];
      let b = ins[pc].b >>> 0;
      if (op === Op.JMPX || op === Op.CHAIN_HOP) b = bit32.bxor(b, kb & 0xfffff);
      bPlain[pc] = b;
      const a = ins[pc].a & 0xffff;
      const mac = bit32.bxor(
        bit32.bxor(Math.imul(ids[pc], spec.macP1) >>> 0, Math.imul(a, spec.macP2) >>> 0),
        bit32.bxor(b & 0xffff, kb >>> 16),
      ) & 0xff;
      const w0 = ((ids[pc] & 0xff) | (a << 8) | (mac << 24)) >>> 0;
      c0s[pc] = bit32.bxor(w0, kb);
      c1s[pc] = bit32.bxor(b, bit32.rrotate(kb, spec.rotB));
      const k1 = bit32.add32(bit32.bxor(bit32.rrotate(kb, spec.ratchetRot), c0s[pc]), spec.ratchetStep);
      after[pc] = k1;
      cPlain[pc] = ins[pc].c >>> 0;
    }

    for (let pc = 0; pc < n; pc++) {
      const op = ins[pc].op;
      const kb = key[pc];
      let cv = cPlain[pc];
      if (op === Op.JMPX) {
        const target = ins[pc].b;
        if (target < 0 || target >= n) throw new GrandfuscatorError(`Bad jump target ${target}`, 'cfg');
        cv = bit32.bxor(after[pc], key[target]);
      } else if (op === Op.CHAIN_HOP) {
        const target = ins[pc].b;
        if (target < 0 || target >= n) throw new GrandfuscatorError(`Bad chain target ${target}`, 'cfg');
        cv = bit32.bxor(bit32.rrotate(after[pc], ins[pc].a & 31), key[target]);
      } else if (branches.has(op)) {
        const target = ins[pc].b;
        if (target < 0 || target >= n) throw new GrandfuscatorError(`Bad branch target ${target}`, 'cfg');
        cv = bit32.bxor(after[pc], key[target]);
      }
      c2s[pc] = bit32.bxor(cv, bit32.rrotate(kb, spec.rotC));
    }

    // Keep logical order here; the serializer applies the randomized byte offsets.
    proto.encodedWords = ins.map((_, pc) => [c0s[pc], c1s[pc], c2s[pc]]);
    for (const child of proto.protos) encode(child);
  };
  encode(root);
}

interface CFGBlock {
  id: number;
  insts: Instruction[];
  loopDepth: number;
  isBogus: boolean;
  isHub: boolean;
}

function isOrigJumpOp(op: Op): boolean {
  return (
    op === Op.JMP ||
    op === Op.JMPF ||
    op === Op.JMPT ||
    op === Op.FORPREP ||
    op === Op.FORLOOP ||
    op === Op.ITERPREP ||
    op === Op.TFORLOOP
  );
}

function isConditionalTerm(op: Op): boolean {
  return (
    op === Op.JMPF ||
    op === Op.JMPT ||
    op === Op.EQJ ||
    op === Op.NEJ ||
    op === Op.LTJ ||
    op === Op.LEJ ||
    op === Op.STATE_JLE ||
    op === Op.STATE_JEQ ||
    op === Op.OPQ_NEVER ||
    op === Op.OPQ_ALWAYS ||
    op === Op.FORPREP ||
    op === Op.FORLOOP ||
    op === Op.TFORLOOP
  );
}

function isUnconditionalJump(op: Op): boolean {
  return op === Op.JMPX || op === Op.CHAIN_HOP || op === Op.ITERPREP;
}

function isTerminator(op: Op): boolean {
  return op === Op.RETURN || isUnconditionalJump(op) || isConditionalTerm(op);
}

/** Strings longer than this are stored as inline SBLK data blocks instead of shattering */
const SBLK_THRESHOLD = 64;

/** A long string collected during lowering, awaiting flat-layout data-slot assignment */
interface SblkPending {
  bytes: Uint8Array;
  key: number;
  /** Flat slot index assigned during layout */
  slot: number;
}

/**
 * Run all compiler optimization & CFG obfuscation passes on every Proto in `mod`:
 *   Pass 1: Basic-Block CFG construction
 *   Pass 2: SSA-verified peephole superinstruction fusion (MOVE2, EQJ, NEJ, LTJ, LEJ)
 *   Pass 3: ZERO constant-pool destruction — strings shattered into SNEW/SADD4/SFIN
 *           (or SBLK data blocks), floats -> LOADF64, ints -> LOADINT/MBA, closures ->
 *           CLOS_UP/CLOS_EXT/CLOS_NEW with encrypted entry operands. Pool is emptied!
 *   Pass 4: Polymorphic operand swapping/reversal + mid-block KEY_MUTATE + live
 *           anti-tamper GUARD & AT_CHECK opcodes
 *   Pass 5: Micro-block splitting + Multi-Hub Graph Control-Flow Flattening (Graph CFF)
 *   Pass 6: Opaque-predicate diamond forks, synthetic bogus CFG blocks & multi-hop
 *           encrypted jump chains
 *   Pass 7: Flat `vmem` layout — chains from ALL protos (plus decoy protos & SBLK
 *           data blocks) are interleaved into ONE unified buffer with random entryPCs
 */
export function runCFGCompilerPasses(
  mod: CompiledModule,
  opts: ResolvedOptions,
  rng: PRNG,
  expectedLine: number,
): void {
  const stats = mod.cfgStats;
  mod.allUsedOps.clear();
  let totalInsts = 0;
  let totalProtos = 0;

  const protoBlocks = new Map<IRProto, CFGBlock[]>();
  const sblkPool: SblkPending[] = [];

  const transformProto = (proto: IRProto, isRoot: boolean): void => {
    totalProtos++;
    for (const sub of proto.protos) {
      transformProto(sub, false);
    }

    // Pass 1: Build explicit Basic-Block CFG
    const blocks = buildBasicBlocks(proto);

    // Pass 2: Safe intra-block superinstruction fusion
    if (opts.superinstructions) {
      stats.fusedSuperinstructions += fuseSuperinstructions(proto, blocks);
    }

    // Pass 3: ZERO constant-pool destruction (strings shattered, floats/ints synthesized,
    // closures lowered to encrypted CLOS_NEW operands) — the pool is 100% eliminated!
    stats.destroyedConstants += lowerConstants(proto, blocks, opts, rng, sblkPool);
    proto.constants = [];

    // Pass 4: Polymorphic operand mutations + KEY_MUTATE + live GUARD/AT_CHECK
    if (opts.opcodeMutation) {
      const mRes = mutateBlockInstructions(blocks, opts, rng, expectedLine, isRoot);
      stats.mutatedInstructions += mRes.mutated;
      stats.guardOpcodes += mRes.guards;
    } else if (opts.antiTamper) {
      blocks[0].insts.unshift({
        op: Op.GUARD,
        a: expectedLine,
        b: rng.oddInt(65537, 16777213),
        c: rng.nextU32(),
      });
      stats.guardOpcodes++;
    }

    // Pass 5 & 6: Micro-block split, Bogus Labyrinth, Multi-Hub Graph CFF, Opaque Forks & Jump Chains
    const baseInstCount = blocks.reduce((acc, b) => acc + b.insts.length, 0);
    const allowHeavy = baseInstCount < 1800;

    if (opts.graphCff && allowHeavy) {
      splitLinearBlocks(blocks, opts, rng);
    }

    const bogusIds: number[] = [];
    if ((opts.graphCff || opts.jumpChainDepth > 0) && allowHeavy) {
      const bogusCount =
        opts.preset === 'nightmare'
          ? rng.int(4, 7)
          : opts.preset === 'fortress'
            ? rng.int(2, 4)
            : rng.int(1, 2);
      const scratchReg = proto.maxStack + 16;
      for (let i = 0; i < bogusCount; i++) {
        bogusIds.push(createBogusBlock(blocks, proto, scratchReg, rng));
      }
      for (const bid of bogusIds) {
        const blk = blocks[bid];
        const other = rng.pick(bogusIds);
        blk.insts.push({ op: Op.JMPX, a: 0, b: 0, c: 0, targetBlock: other });
      }
      stats.bogusBlocks += bogusIds.length;
    }

    if (opts.graphCff && allowHeavy) {
      stats.cffDispatcherNodes += applyMultiHubGraphCFF(blocks, bogusIds, opts, rng);
      if (bogusIds.length > 0) {
        stats.opaqueForks += injectOpaquePredicateForks(blocks, bogusIds, opts, rng);
      }
    }

    if (opts.jumpChainDepth > 0 && allowHeavy) {
      stats.jumpChainHops += injectBytecodeJumpChains(blocks, opts, rng);
    }

    stats.cfgBlocks += blocks.length;
    protoBlocks.set(proto, blocks);
  };

  transformProto(mod.root, true);

  // Pass 7: Interleave every proto's chains (plus decoy protos & SBLK data) into one flat vmem
  layoutFlatVMem(mod, protoBlocks, sblkPool, opts, rng);

  // Refresh used-op census over the final flat instruction stream
  mod.allUsedOps.clear();
  if (mod.vmem) {
    for (const slot of mod.vmem.slots) {
      if (slot !== null) mod.allUsedOps.add(slot.op);
    }
  }
  totalInsts = mod.vmem ? mod.vmem.slots.filter((s) => s !== null).length : 0;
  mod.totalProtos = totalProtos;
  mod.totalInstructions = totalInsts;
}

/** Pass 1: Partition linear 1-based IR into symbolic CFG basic blocks */
function buildBasicBlocks(proto: IRProto): CFGBlock[] {
  const insts = proto.instructions;
  const hints = proto.loopHints ?? insts.map(() => 0);
  const n = insts.length;
  if (n === 0) {
    return [{ id: 0, insts: [{ op: Op.RETURN, a: 0, b: 1, c: 0 }], loopDepth: 0, isBogus: false, isHub: false }];
  }

  const leaderSet = new Set<number>([1]);
  for (let i = 0; i < n; i++) {
    const pc1 = i + 1;
    const ins = insts[i];
    if (isOrigJumpOp(ins.op)) {
      if (ins.b >= 1 && ins.b <= n) leaderSet.add(ins.b);
      if (pc1 + 1 <= n) leaderSet.add(pc1 + 1);
    } else if (ins.op === Op.RETURN) {
      if (pc1 + 1 <= n) leaderSet.add(pc1 + 1);
    }
  }

  const leaders = Array.from(leaderSet).sort((a, b) => a - b);
  const pcToBlock = new Map<number, number>();
  leaders.forEach((lpc, idx) => pcToBlock.set(lpc, idx));

  const blocks: CFGBlock[] = [];
  for (let bi = 0; bi < leaders.length; bi++) {
    const start1 = leaders[bi];
    const end1 = bi + 1 < leaders.length ? leaders[bi + 1] - 1 : n;
    const bInsts: Instruction[] = [];
    let maxLoop = 0;

    for (let pc1 = start1; pc1 <= end1; pc1++) {
      const orig = insts[pc1 - 1];
      if ((hints[pc1 - 1] ?? 0) > maxLoop) maxLoop = hints[pc1 - 1];
      const copy: Instruction = { op: orig.op, a: orig.a, b: orig.b, c: orig.c };

      if (pc1 === end1 && isOrigJumpOp(copy.op)) {
        const tBlk = pcToBlock.get(copy.b);
        if (tBlk === undefined) {
          throw new GrandfuscatorError(`Invalid IR jump target PC ${copy.b}`, 'cfg');
        }
        if (copy.op === Op.JMP) {
          copy.op = Op.JMPX;
          copy.a = 0;
          copy.b = 0;
          copy.c = 0;
          copy.targetBlock = tBlk;
        } else if (copy.op === Op.ITERPREP) {
          copy.b = 0;
          copy.c = 0;
          copy.targetBlock = tBlk;
        } else {
          copy.b = 0;
          copy.c = 0;
          copy.targetBlock = tBlk;
          if (bi + 1 < leaders.length) {
            copy.fallBlock = bi + 1;
          }
        }
      }
      bInsts.push(copy);
    }

    const last = bInsts[bInsts.length - 1];
    if (!isTerminator(last.op)) {
      if (bi + 1 < leaders.length) {
        bInsts.push({ op: Op.JMPX, a: 0, b: 0, c: 0, targetBlock: bi + 1 });
      } else {
        bInsts.push({ op: Op.RETURN, a: 0, b: 1, c: 0 });
      }
    }

    blocks.push({ id: bi, insts: bInsts, loopDepth: maxLoop, isBogus: false, isHub: false });
  }

  return blocks;
}

/**
 * Pass 2: Sound intra-block peephole superinstruction fusion.
 * Computes conservative whole-proto register def/use/capture counts so temporaries
 * are fused ONLY when provably single-def, single-use, and uncaptured.
 */
function fuseSuperinstructions(proto: IRProto, blocks: CFGBlock[]): number {
  const maxR = proto.maxStack + 8;
  const writes = new Int32Array(maxR);
  const reads = new Int32Array(maxR);
  const pinned = new Uint8Array(maxR);

  for (let p = 0; p < proto.numParams; p++) pinned[p] = 1;

  for (const sub of proto.protos) {
    for (const u of sub.upvals) {
      if (u.inStack && u.index < maxR) pinned[u.index] = 1;
    }
  }
  let hasNatClosure = false;

  const markW = (r: number) => { if (r >= 0 && r < maxR) writes[r]++; };
  const markR = (r: number) => { if (r >= 0 && r < maxR) reads[r]++; };
  const pinRange = (lo: number, hi: number) => {
    for (let r = Math.max(0, lo); r <= Math.min(maxR - 1, hi); r++) pinned[r] = 1;
  };

  for (const blk of blocks) {
    for (const ins of blk.insts) {
      switch (ins.op) {
        case Op.MOVE: case Op.UNM: case Op.NOT: case Op.LEN: case Op.TOSTRING:
          markW(ins.a); markR(ins.b); break;
        case Op.LOADK: case Op.LOADBOOL: case Op.GETGLOBAL: case Op.GETUPVAL:
        case Op.NEWTABLE: case Op.CLOSURE:
          markW(ins.a); break;
        case Op.NATCLOSURE:
          hasNatClosure = true; markW(ins.a); break;
        case Op.LOADNIL:
          pinRange(ins.a, ins.b); break;
        case Op.SETGLOBAL: case Op.SETUPVAL:
          markR(ins.a); break;
        case Op.GETTABLE: case Op.ADD: case Op.SUB: case Op.MUL: case Op.DIV:
        case Op.IDIV: case Op.MOD: case Op.POW: case Op.EQ: case Op.NE: case Op.LT: case Op.LE:
          markW(ins.a); markR(ins.b); markR(ins.c); break;
        case Op.GETTABLEK:
          markW(ins.a); markR(ins.b); break;
        case Op.SETTABLE:
          markR(ins.a); markR(ins.b); markR(ins.c); break;
        case Op.SETTABLEK:
          markR(ins.a); markR(ins.c); break;
        case Op.SELF:
          pinRange(ins.a, ins.a + 1); markR(ins.b); break;
        case Op.CONCAT:
          markW(ins.a); pinRange(ins.b, ins.c); break;
        case Op.JMPF: case Op.JMPT:
          markR(ins.a); break;
        case Op.SETLIST:
          pinRange(ins.a, ins.b === 0 ? maxR - 1 : ins.a + ins.b); break;
        case Op.CALL: {
          const hiArg = ins.b === 0 ? maxR - 1 : ins.a + ins.b - 1;
          const hiRet = ins.c === 0 ? maxR - 1 : ins.a + Math.max(0, ins.c - 2);
          pinRange(ins.a, Math.max(hiArg, hiRet));
          break;
        }
        case Op.RETURN:
          if (ins.b !== 1) pinRange(ins.a, ins.b === 0 ? maxR - 1 : ins.a + ins.b - 2);
          break;
        case Op.VARARG:
          pinRange(ins.a, ins.b === 0 ? maxR - 1 : ins.a + ins.b - 2);
          break;
        case Op.FORPREP: case Op.FORLOOP:
          pinRange(ins.a, ins.a + 3); break;
        case Op.ITERPREP:
          pinRange(ins.a, ins.a + 3); break;
        case Op.TFORLOOP: {
          const base = ins.a & 0x3ff;
          const nv = ins.a >>> 10;
          pinRange(base, base + 2 + nv);
          break;
        }
        case Op.CLOSE:
          pinRange(ins.a, maxR - 1); break;
        default:
          break;
      }
    }
  }

  const isSingleUseTemp = (r: number): boolean =>
    !hasNatClosure && r >= 0 && r < maxR && pinned[r] === 0 && writes[r] === 1 && reads[r] === 1;

  let fused = 0;

  for (const blk of blocks) {
    const out: Instruction[] = [];
    const arr = blk.insts;
    let i = 0;
    while (i < arr.length) {
      const a = arr[i];
      const b = i + 1 < arr.length ? arr[i + 1] : null;

      if (b) {
        // 1. Fuse comparison + JMPF -> EQJ / NEJ / LTJ / LEJ
        if (
          (a.op === Op.EQ || a.op === Op.NE || a.op === Op.LT || a.op === Op.LE) &&
          b.op === Op.JMPF &&
          a.a === b.a &&
          a.b < 256 &&
          a.c < 256 &&
          isSingleUseTemp(a.a)
        ) {
          const fusedOp =
            a.op === Op.EQ ? Op.EQJ :
            a.op === Op.NE ? Op.NEJ :
            a.op === Op.LT ? Op.LTJ : Op.LEJ;
          out.push({
            op: fusedOp,
            a: (a.b & 0xff) | ((a.c & 0xff) << 8),
            b: 0,
            c: 0,
            targetBlock: b.targetBlock,
            fallBlock: b.fallBlock,
          });
          fused++;
          i += 2;
          continue;
        }

        // 2. Fuse adjacent MOVE r1, s1 + MOVE r2, s2 -> MOVE2 (when s2 !== r1 and r1 !== r2)
        if (
          a.op === Op.MOVE &&
          b.op === Op.MOVE &&
          a.a < 256 &&
          b.a < 256 &&
          b.b !== a.a &&
          a.a !== b.a
        ) {
          out.push({
            op: Op.MOVE2,
            a: (a.a & 0xff) | ((b.a & 0xff) << 8),
            b: a.b,
            c: b.b,
          });
          fused++;
          i += 2;
          continue;
        }
      }

      out.push(a);
      i++;
    }
    blk.insts = out;
  }

  return fused;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass 3: ZERO constant-pool destruction
// ─────────────────────────────────────────────────────────────────────────────

/** Read a 32-bit little-endian word from a byte array at `off` (zero-padded past end) */
function wordAt(bytes: Uint8Array, off: number): number {
  let w = 0;
  for (let i = 0; i < 4; i++) {
    const byte = off + i < bytes.length ? bytes[off + i] : 0;
    w |= byte << (8 * i);
  }
  return w >>> 0;
}

/**
 * Emit a shattered CCFI string build into register `dst`:
 *   SNEW dst, paddedLen, 0
 *   SADD4_{XOR,ADD,SUB} dst, word, offset|(key<<8)   (shuffled, out-of-order, chaffed)
 *   SFIN dst, leadPad, trueLen
 * The scratch buffer is wiped by SFIN immediately after the string is materialized.
 */
function emitShatteredString(
  out: Instruction[],
  dst: number,
  bytes: Uint8Array,
  rng: PRNG,
): void {
  const trueLen = bytes.length;
  const leadPad = rng.int(0, 12);
  const trailPad = rng.int(4, 12);
  const paddedLen = leadPad + trueLen + trailPad;

  out.push({ op: Op.SNEW, a: dst, b: paddedLen, c: 0 });

  const wordCount = Math.ceil(trueLen / 4);
  const writes: Instruction[] = [];
  for (let w = 0; w < wordCount; w++) {
    const word = wordAt(bytes, w * 4);
    const offset = leadPad + w * 4;
    const key = rng.int(1, 0xffff);
    const variant = rng.int(0, 2);
    let b: number;
    let op: Op;
    if (variant === 0) {
      op = Op.SADD4_XOR;
      b = bit32.bxor(word, bit32.lrotate(key, 5));
    } else if (variant === 1) {
      op = Op.SADD4_ADD;
      b = (word - key + 4294967296) % 4294967296;
    } else {
      op = Op.SADD4_SUB;
      b = (word + key) % 4294967296;
    }
    writes.push({ op, a: dst, b: b >>> 0, c: (offset | (key << 8)) >>> 0 });
  }
  // Chaff writes into leading/trailing padding (excluded by SFIN's read window)
  const chaffCount = rng.int(0, 2);
  for (let i = 0; i < chaffCount; i++) {
    // A chaff word must fit entirely inside padding. When the leading pad is
    // shorter than four bytes, writing there can overwrite the first payload
    // byte (e.g. turning the global name "bit32" into a broken string).
    const inLead = leadPad >= 4 && rng.chance(0.5);
    const offset = inLead ? rng.int(0, leadPad - 4) : leadPad + trueLen + rng.int(0, trailPad - 4);
    const key = rng.int(1, 0xffff);
    writes.push({
      op: Op.SADD4_XOR,
      a: dst,
      b: bit32.bxor(rng.nextU32(), bit32.lrotate(key, 5)),
      c: (offset | (key << 8)) >>> 0,
    });
  }

  // Out-of-order shattered writes — no sequential byte pattern to trace!
  for (const w of rng.shuffle(writes)) out.push(w);

  out.push({ op: Op.SFIN, a: dst, b: leadPad, c: trueLen });
}

/** Emit a long-string SBLK load (data block assigned during flat layout) */
function emitSblkString(
  out: Instruction[],
  dst: number,
  bytes: Uint8Array,
  rng: PRNG,
  sblkPool: SblkPending[],
): void {
  const dataId = sblkPool.length;
  sblkPool.push({ bytes, key: rng.nextU32() || 0x5bd1e995, slot: -1 });
  out.push({ op: Op.SBLK, a: dst, b: 0, c: sblkPool[dataId].key, sblkDataId: dataId });
}

/** Emit `LOADK dst, kIdx` replacement for a number constant (LOADINT / MBA / LOADF64) */
function emitNumberLoad(
  out: Instruction[],
  dst: number,
  value: number,
  blk: CFGBlock,
  opts: ResolvedOptions,
  rng: PRNG,
): void {
  // Non-integers, -0, NaN, infinities and out-of-int32-range values -> bit-exact LOADF64
  const isInt32 = Number.isInteger(value) && !Object.is(value, -0) && value >= -2147483648 && value <= 2147483647;
  if (!isInt32) {
    const tmp = Buffer.alloc(8);
    tmp.writeDoubleLE(value, 0);
    out.push({ op: Op.LOADF64, a: dst, b: tmp.readUInt32LE(0) >>> 0, c: tmp.readUInt32LE(4) >>> 0 });
    return;
  }

  // In tight inner loops on swift preset, prefer single-op LOADINT for max 60 FPS
  if (blk.loopDepth > 0 && opts.preset === 'swift') {
    out.push({ op: Op.LOADINT, a: dst, b: value >>> 0, c: rng.nextU32() });
    return;
  }

  // Keep the signed interpretation explicit: XOR/ADD MBA equations produce the
  // unsigned 32-bit residue, so negative literals use the NEG identity instead.
  if (value < 0) {
    const pos = (-value) >>> 0;
    const m = rng.nextU32();
    const n = bit32.bxor(pos, m);
    out.push({ op: Op.VM_MBA_NEG, a: dst, b: m, c: n });
    return;
  }

  const u = value >>> 0;
  const pick = rng.int(0, 2);
  if (pick === 0) {
    // VM_MBA_XOR: bor(m, n) - band(m, n) == m ^ n == u
    const m = rng.nextU32();
    const n = bit32.bxor(u, m);
    out.push({ op: Op.VM_MBA_XOR, a: dst, b: m, c: n });
  } else if (pick === 1) {
    // VM_MBA_ADD: bxor(x, y) + 2 * band(x, y) == x + y == u
    const x = u > 0 ? rng.int(0, u) >>> 0 : 0;
    const y = (u - x) >>> 0;
    out.push({ op: Op.VM_MBA_ADD, a: dst, b: x, c: y });
  } else {
    out.push({ op: Op.LOADINT, a: dst, b: u, c: rng.nextU32() });
  }
}

/**
 * Pass 3: Eliminate the constant pool completely.
 *  - LOADK string  -> shattered SNEW/SADD4/SFIN (<=64B) or SBLK (>64B)
 *  - LOADK number  -> LOADINT / VM_MBA_* / LOADF64
 *  - GETTABLEK / SETTABLEK / SELF / GETGLOBAL / SETGLOBAL -> shattered string in a
 *    hidden per-proto scratch register + register-based opcode
 *  - CLOSURE -> CLOS_UP* + CLOS_EXT + CLOS_NEW (entryPC/entryKey patched after layout)
 */
function lowerConstants(
  proto: IRProto,
  blocks: CFGBlock[],
  opts: ResolvedOptions,
  rng: PRNG,
  sblkPool: SblkPending[],
): number {
  let destroyed = 0;
  // Hidden per-proto shuffled scratch register for string synthesis (never allocated
  // by the compiler, so it can never clobber a live value)
  const scratch = proto.maxStack + 16 + rng.int(0, 31);

  const emitString = (out: Instruction[], dst: number, bytes: Uint8Array): void => {
    if (bytes.length <= SBLK_THRESHOLD) {
      emitShatteredString(out, dst, bytes, rng);
    } else {
      emitSblkString(out, dst, bytes, rng, sblkPool);
    }
    destroyed++;
  };

  for (const blk of blocks) {
    const out: Instruction[] = [];
    for (const ins of blk.insts) {
      switch (ins.op) {
        case Op.LOADK: {
          const c = proto.constants[ins.b - 1];
          if (!c) throw new GrandfuscatorError(`LOADK references missing constant ${ins.b}`, 'cfg');
          if (c.kind === 'string') {
            emitString(out, ins.a, c.bytes);
          } else if (c.kind === 'number') {
            emitNumberLoad(out, ins.a, c.value, blk, opts, rng);
            destroyed++;
          } else if (c.kind === 'bool') {
            out.push({ op: Op.LOADBOOL, a: ins.a, b: c.value ? 1 : 0, c: 0 });
            destroyed++;
          } else {
            out.push({ op: Op.LOADNIL, a: ins.a, b: ins.a, c: 0 });
            destroyed++;
          }
          break;
        }
        case Op.GETTABLEK: {
          const c = proto.constants[ins.c - 1];
          if (!c || c.kind !== 'string') throw new GrandfuscatorError('GETTABLEK references non-string constant', 'cfg');
          emitString(out, scratch, c.bytes);
          out.push({ op: Op.GETTABLE, a: ins.a, b: ins.b, c: scratch });
          break;
        }
        case Op.SETTABLEK: {
          const c = proto.constants[ins.b - 1];
          if (!c || c.kind !== 'string') throw new GrandfuscatorError('SETTABLEK references non-string constant', 'cfg');
          emitString(out, scratch, c.bytes);
          out.push({ op: Op.SETTABLE, a: ins.a, b: scratch, c: ins.c });
          break;
        }
        case Op.SELF: {
          const c = proto.constants[ins.c - 1];
          if (!c || c.kind !== 'string') throw new GrandfuscatorError('SELF references non-string constant', 'cfg');
          emitString(out, scratch, c.bytes);
          out.push({ op: Op.SELF, a: ins.a, b: ins.b, c: scratch });
          break;
        }
        case Op.GETGLOBAL: {
          const c = proto.constants[ins.b - 1];
          if (!c || c.kind !== 'string') throw new GrandfuscatorError('GETGLOBAL references non-string constant', 'cfg');
          emitString(out, scratch, c.bytes);
          out.push({ op: Op.GETGLOBAL, a: ins.a, b: scratch, c: 0 });
          break;
        }
        case Op.SETGLOBAL: {
          const c = proto.constants[ins.b - 1];
          if (!c || c.kind !== 'string') throw new GrandfuscatorError('SETGLOBAL references non-string constant', 'cfg');
          emitString(out, scratch, c.bytes);
          out.push({ op: Op.SETGLOBAL, a: ins.a, b: scratch, c: 0 });
          break;
        }
        case Op.CLOSURE: {
          const child = proto.protos[ins.b - 1];
          if (!child) throw new GrandfuscatorError(`CLOSURE references missing proto ${ins.b}`, 'cfg');
          for (let ui = 0; ui < child.upvals.length; ui++) {
            const u = child.upvals[ui];
            out.push({ op: Op.CLOS_UP, a: ui, b: u.inStack ? 1 : 0, c: u.index });
          }
          out.push({ op: Op.CLOS_EXT, a: ins.a, b: child.numParams, c: child.isVararg ? 1 : 0 });
          out.push({ op: Op.CLOS_NEW, a: ins.a, b: 0, c: 0, childProtoRef: child });
          destroyed++;
          break;
        }
        default:
          out.push(ins);
          break;
      }
    }
    blk.insts = out;
  }

  // Cold-block decoy string builds + CHAFF_ENV probes (poison inline runtime traces)
  if (opts.chaff) {
    for (const blk of blocks) {
      if (blk.loopDepth > 0 || blk.isBogus || blk.isHub) continue;
      if (!rng.chance(opts.preset === 'nightmare' ? 0.5 : 0.3)) continue;
      const decoy: Instruction[] = [];
      const fakeLen = rng.int(3, 24);
      const fake = new Uint8Array(fakeLen);
      for (let i = 0; i < fakeLen; i++) fake[i] = rng.int(32, 126);
      emitShatteredString(decoy, scratch, fake, rng);
      // Insert before the terminator so the decoy build never affects live state
      const term = blk.insts[blk.insts.length - 1];
      blk.insts.splice(blk.insts.length - 1, 0, ...decoy);
      if (term && rng.chance(0.5)) {
        blk.insts.splice(blk.insts.length - 1, 0, { op: Op.CHAFF_ENV, a: 0, b: scratch, c: 0 });
      }
    }
  }

  return destroyed;
}

/**
 * Pass 4: Mutate operand orders (ADD_SWP, SUB_REV, DIV_REV, IDIV_REV, LT_REV, LE_REV,
 * GETTABLE_SWP, SETTABLE_SWP), insert mid-block dynamic KEY_MUTATE instructions, and
 * insert live anti-tamper GUARD + AT_CHECK opcodes.
 */
function mutateBlockInstructions(
  blocks: CFGBlock[],
  opts: ResolvedOptions,
  rng: PRNG,
  expectedLine: number,
  isRoot: boolean,
): { mutated: number; guards: number } {
  let mutated = 0;
  let guards = 0;

  const swapMap = new Map<Op, Op>([
    [Op.ADD, Op.ADD_SWP],
    [Op.MUL, Op.MUL_SWP],
    [Op.SUB, Op.SUB_REV],
    [Op.DIV, Op.DIV_REV],
    [Op.IDIV, Op.IDIV_REV],
    [Op.LT, Op.LT_REV],
    [Op.LE, Op.LE_REV],
    [Op.GETTABLE, Op.GETTABLE_SWP],
    [Op.SETTABLE, Op.SETTABLE_SWP],
  ]);

  const keyMutateProb =
    opts.preset === 'nightmare' ? 0.35 : opts.preset === 'fortress' ? 0.22 : 0.1;

  for (let bi = 0; bi < blocks.length; bi++) {
    const blk = blocks[bi];
    const out: Instruction[] = [];

    // Inject live anti-tamper GUARD in every function entry block + selected non-loop blocks!
    if (
      opts.antiTamper &&
      (bi === 0 || (blk.loopDepth === 0 && (isRoot || opts.preset === 'nightmare') && rng.chance(0.28)))
    ) {
      out.push({
        op: Op.GUARD,
        a: expectedLine,
        b: rng.oddInt(65537, 16777213),
        c: rng.nextU32(),
      });
      guards++;
    }

    // Inject live AT_CHECK (C-closure identity / vmem length / line lattice) in cold blocks
    if (opts.antiTamper && blk.loopDepth === 0 && rng.chance(0.22)) {
      const checkType = rng.int(0, 3);
      out.push({
        op: Op.AT_CHECK,
        a: checkType,
        b: checkType === 2 ? 0 : expectedLine, // type 2 (vmem len) patched during layout
        c: rng.nextU32(),
      });
      guards++;
    }

    for (let i = 0; i < blk.insts.length; i++) {
      const ins = blk.insts[i];
      const altOp = swapMap.get(ins.op);
      if (altOp !== undefined && rng.chance(0.55)) {
        const tmp = ins.b;
        ins.b = ins.c;
        ins.c = tmp;
        ins.op = altOp;
        mutated++;
      }

      // Inject mid-block rolling opcode-key mutation BEFORE non-terminator ops
      if (
        !isTerminator(ins.op) &&
        (blk.loopDepth === 0 || opts.preset === 'nightmare') &&
        rng.chance(keyMutateProb)
      ) {
        out.push({
          op: Op.KEY_MUTATE,
          a: rng.int(3, 29),
          b: rng.nextU32(),
          c: rng.oddInt(0x1001, 0x3fffffff),
        });
        mutated++;
      }

      out.push(ins);
    }

    blk.insts = out;
  }

  return { mutated, guards };
}

/** Pass 5a: Shatter longer linear basic blocks into smaller CFG micro-blocks */
function splitLinearBlocks(blocks: CFGBlock[], opts: ResolvedOptions, rng: PRNG): void {
  const minLen = opts.preset === 'nightmare' ? 4 : opts.preset === 'fortress' ? 6 : 9;
  const initialCount = blocks.length;

  for (let bi = 0; bi < initialCount; bi++) {
    const blk = blocks[bi];
    if (blk.loopDepth > 0 && opts.preset !== 'nightmare') continue;
    if (blk.insts.length < minLen) continue;

    const splitAt = rng.int(2, blk.insts.length - 2);
    const tail = blk.insts.slice(splitAt);
    const newId = blocks.length;
    blocks.push({
      id: newId,
      insts: tail,
      loopDepth: blk.loopDepth,
      isBogus: false,
      isHub: false,
    });
    blk.insts = [
      ...blk.insts.slice(0, splitAt),
      { op: Op.JMPX, a: 0, b: 0, c: 0, targetBlock: newId },
    ];
  }
}

/** Generate a realistic synthetic bogus basic block (indistinguishable statically, never reached) */
function createBogusBlock(
  blocks: CFGBlock[],
  proto: IRProto,
  scratchBase: number,
  rng: PRNG,
): number {
  const id = blocks.length;
  const r0 = scratchBase;
  const r1 = scratchBase + 1;
  const r2 = scratchBase + 2;
  const ops: Instruction[] = [];
  const count = rng.int(2, 4);

  for (let i = 0; i < count; i++) {
    const kind = rng.int(0, 6);
    switch (kind) {
      case 0:
        ops.push({ op: Op.VM_MBA_XOR, a: r0, b: rng.nextU32(), c: rng.nextU32() });
        break;
      case 1:
        ops.push({ op: Op.VM_MBA_ADD, a: r1, b: rng.int(1, 99999), c: rng.int(1, 99999) });
        break;
      case 2:
        ops.push({ op: Op.ADD_SWP, a: r2, b: r0, c: r1 });
        break;
      case 3:
        ops.push({ op: Op.SUB_REV, a: r0, b: r1, c: r2 });
        break;
      case 4:
        ops.push({ op: Op.KEY_MUTATE, a: rng.int(3, 29), b: rng.nextU32(), c: rng.oddInt(99, 0x1fffffff) });
        break;
      case 5:
        ops.push({ op: Op.LOADINT, a: r1, b: rng.int(1, 65535), c: rng.nextU32() });
        break;
      default: {
        // Decoy shattered string build into scratch (never executed, looks real!)
        const fake = new Uint8Array(rng.int(3, 16));
        for (let j = 0; j < fake.length; j++) fake[j] = rng.int(32, 126);
        emitShatteredString(ops, r1, fake, rng);
        break;
      }
    }
  }

  blocks.push({ id, insts: ops, loopDepth: 0, isBogus: true, isHub: false });
  return id;
}

/**
 * Pass 5b: Multi-Hub Bytecode Control-Flow Graph Flattening (Graph CFF).
 * Routes unconditional CFG edges through 1..3 binary-search bytecode dispatcher hubs
 * mixed with bogus dead state targets and XOR-masked 16-bit state tokens.
 */
function applyMultiHubGraphCFF(
  blocks: CFGBlock[],
  bogusIds: number[],
  opts: ResolvedOptions,
  rng: PRNG,
): number {
  const candidates: CFGBlock[] = [];
  for (const blk of blocks) {
    if (blk.isBogus || blk.isHub) continue;
    if (blk.loopDepth > 0 && opts.preset !== 'nightmare') continue;
    const last = blk.insts[blk.insts.length - 1];
    if (last && last.op === Op.JMPX && last.targetBlock !== undefined) {
      candidates.push(blk);
    }
  }

  if (candidates.length < 2) return 0;

  const maxRouted = opts.preset === 'nightmare' ? 28 : opts.preset === 'fortress' ? 18 : 10;
  const selected = rng.shuffle(candidates).slice(0, maxRouted);

  const hubCount = selected.length >= 10 && opts.preset !== 'swift' ? 2 : 1;
  const usedStates = new Set<number>();
  const allocState16 = (): number => {
    while (true) {
      const s = rng.int(257, 65200);
      if (!usedStates.has(s)) {
        usedStates.add(s);
        return s;
      }
    }
  };

  let hubNodesCreated = 0;
  const fallbackBogus = bogusIds.length > 0 ? bogusIds[0] : selected[0].insts[selected[0].insts.length - 1].targetBlock!;

  for (let h = 0; h < hubCount; h++) {
    const group = selected.filter((_, idx) => idx % hubCount === h);
    if (group.length === 0) continue;

    const targetToState = new Map<number, number>();
    const dispatchEntries: Array<{ state: number; targetBlock: number }> = [];

    for (const src of group) {
      const term = src.insts[src.insts.length - 1];
      const tgt = term.targetBlock!;
      if (!targetToState.has(tgt)) {
        const st = allocState16();
        targetToState.set(tgt, st);
        dispatchEntries.push({ state: st, targetBlock: tgt });
      }
    }

    for (const bid of bogusIds.slice(0, 3)) {
      dispatchEntries.push({ state: allocState16(), targetBlock: bid });
    }

    dispatchEntries.sort((a, b) => a.state - b.state);

    const buildHubTree = (lo: number, hi: number): number => {
      const nodeId = blocks.length;
      hubNodesCreated++;
      const hubBlk: CFGBlock = { id: nodeId, insts: [], loopDepth: 0, isBogus: false, isHub: true };
      blocks.push(hubBlk);

      if (lo === hi) {
        const entry = dispatchEntries[lo];
        const trapId = blocks.length;
        hubNodesCreated++;
        blocks.push({
          id: trapId,
          insts: [{ op: Op.JMPX, a: 0, b: 0, c: 0, targetBlock: fallbackBogus }],
          loopDepth: 0,
          isBogus: true,
          isHub: true,
        });
        hubBlk.insts.push({
          op: Op.STATE_JEQ,
          a: entry.state,
          b: 0,
          c: 0,
          targetBlock: entry.targetBlock,
          fallBlock: trapId,
        });
        return nodeId;
      }

      const mid = (lo + hi) >> 1;
      const leftId = buildHubTree(lo, mid);
      const rightId = buildHubTree(mid + 1, hi);
      hubBlk.insts.push({
        op: Op.STATE_JLE,
        a: dispatchEntries[mid].state,
        b: 0,
        c: 0,
        targetBlock: leftId,
        fallBlock: rightId,
      });
      return nodeId;
    };

    const hubRootId = buildHubTree(0, dispatchEntries.length - 1);

    for (const src of group) {
      const term = src.insts[src.insts.length - 1];
      const st = targetToState.get(term.targetBlock!)!;
      const mask = rng.nextU32();
      const enc = bit32.bxor(st, mask);
      src.insts.pop();
      src.insts.push(
        { op: Op.STATE_SET, a: 0, b: enc, c: mask },
        { op: Op.JMPX, a: 0, b: 0, c: 0, targetBlock: hubRootId },
      );
    }
  }

  return hubNodesCreated;
}

/** Pass 6a: Inject mathematically-invariant bit32 opaque-predicate forks targeting bogus blocks */
function injectOpaquePredicateForks(
  blocks: CFGBlock[],
  bogusIds: number[],
  opts: ResolvedOptions,
  rng: PRNG,
): number {
  let injected = 0;
  const prob = opts.preset === 'nightmare' ? 0.55 : opts.preset === 'fortress' ? 0.35 : 0.2;
  const snapshotLen = blocks.length;

  for (let bi = 0; bi < snapshotLen; bi++) {
    const blk = blocks[bi];
    if (blk.isBogus || blk.isHub) continue;
    if (blk.loopDepth > 0 && opts.preset === 'swift') continue;
    if (!rng.chance(prob)) continue;

    const last = blk.insts[blk.insts.length - 1];
    const bogusTarget = rng.pick(bogusIds);

    if (last.op === Op.JMPX && last.targetBlock !== undefined) {
      if (rng.chance(0.5)) {
        const deadFallId = blocks.length;
        blocks.push({
          id: deadFallId,
          insts: [
            { op: Op.KEY_MUTATE, a: rng.int(3, 27), b: rng.nextU32(), c: rng.oddInt(11, 999999) },
            { op: Op.JMPX, a: 0, b: 0, c: 0, targetBlock: bogusTarget },
          ],
          loopDepth: 0,
          isBogus: true,
          isHub: false,
        });
        last.op = Op.OPQ_ALWAYS;
        last.a = rng.int(17, 65500);
        last.fallBlock = deadFallId;
        injected++;
      } else {
        const contId = blocks.length;
        blocks.push({
          id: contId,
          insts: [last],
          loopDepth: blk.loopDepth,
          isBogus: false,
          isHub: false,
        });
        blk.insts[blk.insts.length - 1] = {
          op: Op.OPQ_NEVER,
          a: rng.int(17, 65500),
          b: 0,
          c: 0,
          targetBlock: bogusTarget,
          fallBlock: contId,
        };
        injected++;
      }
    }
  }

  return injected;
}

/**
 * Pass 6b: Multi-Hop Encrypted Bytecode Jump Chains.
 * Rewrites `JMPX -> dst` into `JMPX -> Hop_1 --(CHAIN_HOP)--> ... --(CHAIN_HOP)--> dst`.
 */
function injectBytecodeJumpChains(
  blocks: CFGBlock[],
  opts: ResolvedOptions,
  rng: PRNG,
): number {
  let hopsCreated = 0;
  const snapshotLen = blocks.length;
  const prob = opts.preset === 'nightmare' ? 0.75 : opts.preset === 'fortress' ? 0.55 : 0.35;
  const maxHopsTotal = opts.preset === 'nightmare' ? 90 : opts.preset === 'fortress' ? 50 : 24;

  for (let bi = 0; bi < snapshotLen; bi++) {
    if (hopsCreated >= maxHopsTotal) break;
    const blk = blocks[bi];
    if (blk.isBogus) continue;
    if (blk.loopDepth > 0 && opts.preset !== 'nightmare') continue;

    const last = blk.insts[blk.insts.length - 1];
    if (!last || last.op !== Op.JMPX || last.targetBlock === undefined) continue;
    if (!rng.chance(prob)) continue;

    const hops = rng.int(1, opts.jumpChainDepth);
    const finalTarget = last.targetBlock;
    let nextTarget = finalTarget;

    for (let h = 0; h < hops; h++) {
      const hopId = blocks.length;
      const rot = rng.int(3, 29);
      blocks.push({
        id: hopId,
        insts: [{ op: Op.CHAIN_HOP, a: rot, b: 0, c: 0, targetBlock: nextTarget }],
        loopDepth: blk.loopDepth,
        isBogus: false,
        isHub: false,
      });
      nextTarget = hopId;
      hopsCreated++;
    }

    last.targetBlock = nextTarget;
  }

  return hopsCreated;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass 7: Flat `vmem` interleaved layout (ZERO proto tree!)
// ─────────────────────────────────────────────────────────────────────────────

/** Extract fallthrough chains from a block list (each chain is a contiguous run) */
function extractChains(blocks: CFGBlock[]): number[][] {
  const claimedFall = new Set<number>();
  const origCount = blocks.length;

  for (let i = 0; i < origCount; i++) {
    const blk = blocks[i];
    const last = blk.insts[blk.insts.length - 1];
    if (last.fallBlock === undefined) continue;
    const fb = last.fallBlock;

    let formsCycle = fb === blk.id;
    if (!formsCycle) {
      let cur: number | undefined = fb;
      const seen = new Set<number>([blk.id]);
      while (cur !== undefined) {
        if (seen.has(cur)) { formsCycle = true; break; }
        seen.add(cur);
        const t: Instruction = blocks[cur].insts[blocks[cur].insts.length - 1];
        cur = t.fallBlock;
      }
    }

    if (claimedFall.has(fb) || formsCycle) {
      const bridgeId = blocks.length;
      blocks.push({
        id: bridgeId,
        insts: [{ op: Op.JMPX, a: 0, b: 0, c: 0, targetBlock: fb }],
        loopDepth: blk.loopDepth,
        isBogus: blk.isBogus,
        isHub: blk.isHub,
      });
      last.fallBlock = bridgeId;
      claimedFall.add(bridgeId);
    } else {
      claimedFall.add(fb);
    }
  }

  const chains: number[][] = [];
  for (const blk of blocks) {
    if (claimedFall.has(blk.id)) continue;
    const chain: number[] = [];
    let cur: number | undefined = blk.id;
    while (cur !== undefined) {
      chain.push(cur);
      const last: Instruction = blocks[cur].insts[blocks[cur].insts.length - 1];
      cur = last.fallBlock;
    }
    chains.push(chain);
  }
  return chains;
}

/** Generate a synthetic decoy proto's blocks (never referenced by any CLOS_NEW) */
function generateDecoyBlocks(rng: PRNG, maxStack: number): CFGBlock[] {
  const r0 = maxStack + 16;
  const r1 = maxStack + 17;
  const r2 = maxStack + 18;
  const blocks: CFGBlock[] = [];
  const blockCount = rng.int(1, 3);
  for (let bi = 0; bi < blockCount; bi++) {
    const insts: Instruction[] = [];
    const count = rng.int(2, 6);
    for (let i = 0; i < count; i++) {
      switch (rng.int(0, 5)) {
        case 0: insts.push({ op: Op.VM_MBA_XOR, a: r0, b: rng.nextU32(), c: rng.nextU32() }); break;
        case 1: insts.push({ op: Op.LOADINT, a: r1, b: rng.nextU32(), c: rng.nextU32() }); break;
        case 2: insts.push({ op: Op.ADD, a: r2, b: r0, c: r1 }); break;
        case 3: insts.push({ op: Op.KEY_MUTATE, a: rng.int(3, 29), b: rng.nextU32(), c: rng.oddInt(99, 0x1fffffff) }); break;
        case 4: insts.push({ op: Op.MOVE, a: r0, b: r1, c: 0 }); break;
        default: insts.push({ op: Op.VM_MBA_ADD, a: r2, b: rng.int(1, 99999), c: rng.int(1, 99999) }); break;
      }
    }
    insts.push({ op: Op.RETURN, a: 0, b: 1, c: 0 });
    blocks.push({ id: bi, insts, loopDepth: 0, isBogus: true, isHub: false });
  }
  return blocks;
}

/**
 * Pass 7: Interleave chains from ALL protos (plus decoy protos and SBLK data blocks)
 * into ONE flat `vmem` slot array. There is NO proto tree, NO per-proto buffer, and
 * NO metadata in the output — only a flat sea of 12-byte slots. Entry PCs are resolved
 * here; entry keys are resolved by the CCFI encoder.
 */
function layoutFlatVMem(
  mod: CompiledModule,
  protoBlocks: Map<IRProto, CFGBlock[]>,
  sblkPool: SblkPending[],
  opts: ResolvedOptions,
  rng: PRNG,
): void {
  // Collect every proto (root + children) in deterministic order
  const allProtos: IRProto[] = [];
  const collect = (p: IRProto): void => {
    allProtos.push(p);
    for (const sub of p.protos) collect(sub);
  };
  collect(mod.root);

  // Build chains per proto
  interface ChainUnit {
    proto: IRProto | null; // null = decoy / data
    blocks: CFGBlock[];
    chain: number[];
  }
  const units: ChainUnit[] = [];
  const blockStartPC = new Map<CFGBlock, number>();

  for (const proto of allProtos) {
    const blocks = protoBlocks.get(proto)!;
    const chains = extractChains(blocks);
    for (const chain of chains) {
      units.push({ proto, blocks, chain });
    }
  }

  // Synthetic decoy protos (1..3) — indistinguishable code regions, never entered
  const decoyCount = opts.preset === 'nightmare' ? rng.int(2, 3) : opts.preset === 'fortress' ? rng.int(1, 2) : 1;
  mod.cfgStats.decoyProtos = decoyCount;
  for (let d = 0; d < decoyCount; d++) {
    const fakeMaxStack = rng.int(8, 64);
    const blocks = generateDecoyBlocks(rng, fakeMaxStack);
    const chains = extractChains(blocks);
    for (const chain of chains) {
      units.push({ proto: null, blocks, chain });
    }
  }

  // Shuffle all chains together — protos, decoys and data interleave into one flat sea
  const shuffledUnits = rng.shuffle(units);

  // Flatten into slots (code = Instruction, data = null placeholder for SBLK words)
  const slots: Array<Instruction | null> = [];
  const slotBlock: Array<CFGBlock | null> = []; // owner block per slot, used for proto-local edge resolution
  const blockOwner = new Map<CFGBlock, IRProto | null>();
  const dataSlotWords = new Map<number, [number, number, number]>(); // slot -> [w0, w1, w2] raw data words

  // First pass: assign slot indices (code slots + SBLK data slots interleaved)
  const sblkUnits: Array<{ dataId: number; wordCount: number }> = sblkPool.map((p, dataId) => ({
    dataId,
    wordCount: 1 + Math.ceil(p.bytes.length / 4),
  }));

  // Interleave SBLK data units at random chain boundaries
  const layoutItems: Array<{ kind: 'chain'; unit: ChainUnit } | { kind: 'sblk'; dataId: number; wordCount: number }> = [];
  for (const unit of shuffledUnits) layoutItems.push({ kind: 'chain', unit });
  for (const su of sblkUnits) {
    const pos = rng.int(0, layoutItems.length);
    layoutItems.splice(pos, 0, { kind: 'sblk', dataId: su.dataId, wordCount: su.wordCount });
  }

  for (const item of layoutItems) {
    if (item.kind === 'chain') {
      for (const bid of item.unit.chain) {
        const blk = item.unit.blocks[bid];
        blockOwner.set(blk, item.unit.proto);
        blockStartPC.set(blk, slots.length);
        for (const ins of blk.insts) {
          slots.push(ins);
          slotBlock.push(blk);
        }
      }
    } else {
      const pending = sblkPool[item.dataId];
      pending.slot = slots.length;
      const key = pending.key;
      const bytes = pending.bytes;
      const len = bytes.length;
      const wordCount = item.wordCount;
      for (let w = 0; w < wordCount; w++) {
        const slotIdx = slots.length;
        let dataWord: number;
        if (w === 0) {
          dataWord = bit32.bxor(len >>> 0, bit32.lrotate(key, 3));
        } else {
          const plain = wordAt(bytes, (w - 1) * 4);
          dataWord = bit32.bxor(plain, bit32.lrotate(key, (w * 7 + 3) % 32));
        }
        dataSlotWords.set(slotIdx, [dataWord >>> 0, rng.nextU32(), rng.nextU32()]);
        slots.push(null);
        slotBlock.push(null);
      }
    }
  }

  // Resolve symbolic block targets to flat PCs; set each proto's entryPC
  for (const proto of allProtos) {
    const blocks = protoBlocks.get(proto)!;
    const entryBlk = blocks[0];
    const entryPC = blockStartPC.get(entryBlk);
    if (entryPC === undefined) throw new GrandfuscatorError('Flat layout error: missing entry block', 'cfg');
    proto.entryPC = entryPC;
  }

  // Resolve block-local edges. Fallthrough is an actual physical next-slot transfer;
  // explicit targets become absolute flat slot indices. IDs are proto-local, so resolve
  // through the owning block rather than searching globally by numeric ID.
  const blockMaps = new Map<IRProto | null, Map<number, CFGBlock>>();
  for (const proto of allProtos) {
    blockMaps.set(proto, new Map(protoBlocks.get(proto)!.map((blk) => [blk.id, blk])));
  }
  for (const unit of shuffledUnits) {
    if (unit.proto === null) {
      blockMaps.set(null, new Map(unit.blocks.map((blk) => [blk.id, blk])));
    }
  }

  for (let pc = 0; pc < slots.length; pc++) {
    const ins = slots[pc];
    if (!ins) continue;
    const owner = slotBlock[pc];
    const ownerProto = owner ? blockOwner.get(owner) ?? null : null;
    if (ins.fallBlock !== undefined) {
      const fallBlk = blockMaps.get(ownerProto)?.get(ins.fallBlock);
      const fallPC = fallBlk ? blockStartPC.get(fallBlk) : undefined;
      if (fallPC !== pc + 1) {
        throw new GrandfuscatorError(`Flat layout error: fallthrough at slot ${pc} is not physically adjacent`, 'cfg');
      }
    }
    if (ins.targetBlock !== undefined) {
      const targetBlk = blockMaps.get(ownerProto)?.get(ins.targetBlock);
      const targetPC = targetBlk ? blockStartPC.get(targetBlk) : undefined;
      if (targetPC === undefined) {
        throw new GrandfuscatorError(`Flat layout error: unresolved target block ${ins.targetBlock}`, 'cfg');
      }
      ins.b = targetPC;
    }
  }

  // Patch SBLK data slot operands + AT_CHECK vmem-length expectations
  const totalBytes = slots.length * 12;
  for (let pc = 0; pc < slots.length; pc++) {
    const ins = slots[pc];
    if (!ins) continue;
    if (ins.op === Op.SBLK && ins.sblkDataId !== undefined) {
      ins.b = sblkPool[ins.sblkDataId].slot;
    }
    if (ins.op === Op.AT_CHECK && ins.a === 2) {
      ins.b = totalBytes;
    }
  }

  // Patch CLOS_NEW entryPC operands (entryKey patched by the CCFI encoder)
  for (let pc = 0; pc < slots.length; pc++) {
    const ins = slots[pc];
    if (!ins || ins.op !== Op.CLOS_NEW || !ins.childProtoRef) continue;
    ins.b = ins.childProtoRef.entryPC;
  }

  mod.vmem = {
    slots,
    totalSlots: slots.length,
    rootEntryPC: mod.root.entryPC,
    rootEntryKey: 0, // patched by the CCFI encoder
    dataSlotWords,
  } as FlatVMemImage;
}

// ─────────────────────────────────────────────────────────────────────────────
// Flat CCFI Encoder (per-handler private ciphers + S-box + key-parity remapping)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 2-Phase Cryptographic Control-Flow Integrity (CCFI) Flat Encoder + Proof Verifier.
 *
 * Assigns every code slot its exact dynamic rolling 32-bit stateKey `K[pc]`, picks a
 * random duplicate physical handler for every instruction, encrypts `(op, a, mac8)` ->
 * `c0`, `B` -> `c1` and `C` -> `c2` under the handler's PRIVATE S-box cipher, patches
 * every CFG edge's exact 32-bit `edgeKeyDelta` into `C`, and mathematically verifies
 * EVERY edge transition before emitting a single byte!
 */
export function encodeFlatVMemCCFI(
  mod: CompiledModule,
  opAliases: Map<Op, number[]>,
  spec: FlatCipherSpec,
  rng: PRNG,
): void {
  const vmem = mod.vmem!;
  const slots = vmem.slots;
  const n = slots.length;

  const kBefore = new Uint32Array(n);
  const kAfter = new Uint32Array(n);
  const c0Arr = new Uint32Array(n);
  const c1Arr = new Uint32Array(n);
  const c2Arr = new Uint32Array(n);
  const rawBArr = new Uint32Array(n);
  const rawCArr = new Uint32Array(n);
  const physArr = new Uint8Array(n);
  const handlerArr = new Uint8Array(n);
  const k2Arr = new Uint32Array(n); // post-exit-transition key (before jump delta)

  const isCode = (i: number): boolean => slots[i] !== null;
  const fallsThrough = (i: number): boolean => {
    if (!isCode(i)) return false;
    const op = slots[i]!.op;
    return !isUnconditionalJump(op) && op !== Op.RETURN;
  };

  // Phase 1: Forward walk — computes exact kBefore[pc], c0[pc], c1[pc], kAfter[pc]!
  for (let pc = 0; pc < n; pc++) {
    if (!isCode(pc)) {
      kBefore[pc] = rng.nextU32() || 0x9e3779b9;
      kAfter[pc] = kBefore[pc];
      continue;
    }
    const ins = slots[pc]!;
    const prevFallsHere = pc > 0 && fallsThrough(pc - 1);
    const kb = prevFallsHere ? kAfter[pc - 1] : (rng.nextU32() || 0x9e3779b9);
    kBefore[pc] = kb;

    const aliases = opAliases.get(ins.op);
    if (!aliases || aliases.length === 0) {
      throw new GrandfuscatorError(`Missing physical opcode alias for Op.${Op[ins.op]}`, 'vm');
    }
    const handlerId = rng.pick(aliases);
    const hc = spec.handlers[handlerId];
    if (!hc) throw new GrandfuscatorError(`Missing handler cipher for handlerId ${handlerId}`, 'vm');
    handlerArr[pc] = handlerId;

    // Key-parity polymorphic remapping: stored ID depends on pre-fetch key parity!
    const storedPhysId = (handlerId ^ ((kb & 1) ? spec.keyParityMask : 0)) & 0xff;
    physArr[pc] = storedPhysId;

    const a16 = ins.a & 0xffff;
    // For JMPX / CHAIN_HOP / ITERPREP / CLOS_NEW, encrypt the target PC with band(kb, 0xFFFFF)!
    let bVal = ins.b >>> 0;
    if (
      ins.op === Op.JMPX ||
      ins.op === Op.CHAIN_HOP ||
      ins.op === Op.ITERPREP ||
      ins.op === Op.CLOS_NEW
    ) {
      bVal = bit32.bxor(bVal, kb & 0xfffff);
    }
    rawBArr[pc] = bVal;

    // Private per-handler S-box operand cipher: c1 = rotl(B ^ kb ^ sboxMask, rotB) + addB
    const sboxMask = (spec.sbox[storedPhysId] * 0x01010101) >>> 0;
    const c1 = bit32.add32(bit32.lrotate(bit32.bxor(bit32.bxor(bVal, kb), sboxMask), hc.rotB), hc.addB);
    c1Arr[pc] = c1;

    const mac8 = computeInstMac8(storedPhysId, a16, c1, kb, spec);
    const plainW0 = ((storedPhysId & 0xff) | ((a16 & 0xffff) << 8) | ((mac8 & 0xff) << 24)) >>> 0;
    const c0 = bit32.bxor(plainW0, kb);
    c0Arr[pc] = c0;

    // Shared post-fetch ratchet, then PRIVATE per-handler exit transition
    const k1 = ratchetKey(kb, c0, spec);
    const k2 = exitTransition(k1, hc);
    k2Arr[pc] = k2;

    // Op-specific K transforms (jumps patch their delta in Phase 2)
    let ka = k2;
    if (ins.op === Op.KEY_MUTATE) {
      const rot = a16 & 31;
      ka = bit32.add32(bit32.bxor(bit32.lrotate(k2, rot), bVal), ins.c >>> 0);
    }
    // GUARD / AT_CHECK: ka = k2 when untampered (handler adds 0)
    kAfter[pc] = ka;
  }

  // Phase 1.5: Patch CLOS_NEW entry keys (child kBefore at its entryPC)
  for (let pc = 0; pc < n; pc++) {
    const ins = slots[pc];
    if (!ins || ins.op !== Op.CLOS_NEW || !ins.childProtoRef) continue;
    ins.c = kBefore[ins.childProtoRef.entryPC] >>> 0;
  }

  // Phase 2: Patch exact 32-bit CCFI `edgeKeyDelta` into operand C for every jump/branch!
  const encoded: Array<[number, number, number] | null> = new Array(n).fill(null);
  for (let pc = 0; pc < n; pc++) {
    if (!isCode(pc)) {
      encoded[pc] = null;
      continue;
    }
    const ins = slots[pc]!;
    const kb = kBefore[pc];
    const k2 = k2Arr[pc];
    const handlerId = handlerArr[pc];
    const hc = spec.handlers[handlerId]!;
    const storedPhysId = physArr[pc];
    const sboxMask = (spec.sbox[storedPhysId] * 0x01010101) >>> 0;
    let cVal = ins.c >>> 0;

    if (ins.op === Op.CHAIN_HOP) {
      const dstPC = ins.b;
      const dstKey = kBefore[dstPC];
      const rotated = bit32.lrotate(k2, ins.a & 31);
      cVal = bit32.bxor(rotated, dstKey);
      if (bit32.bxor(rotated, cVal) !== dstKey || bit32.bxor(rawBArr[pc], kb & 0xfffff) !== dstPC) {
        throw new GrandfuscatorError(`CCFI proof failed on CHAIN_HOP at PC ${pc}`, 'cfg');
      }
    } else if (
      ins.op === Op.JMPX ||
      ins.op === Op.ITERPREP ||
      isConditionalTerm(ins.op)
    ) {
      const dstPC = ins.b;
      const dstKey = kBefore[dstPC];
      cVal = bit32.bxor(k2, dstKey);
      if (bit32.bxor(k2, cVal) !== dstKey) {
        throw new GrandfuscatorError(`CCFI proof failed on branch at PC ${pc}`, 'cfg');
      }
      if (isConditionalTerm(ins.op) && pc + 1 < n && isCode(pc + 1) && kBefore[pc + 1] !== k2) {
        throw new GrandfuscatorError(`CCFI fallthrough proof failed at PC ${pc}`, 'cfg');
      }
    }

    rawCArr[pc] = cVal;
    const c2 = bit32.add32(bit32.lrotate(bit32.bxor(bit32.bxor(cVal, kb), sboxMask), hc.rotC), hc.addC);
    c2Arr[pc] = c2;
    encoded[pc] = [c0Arr[pc], c1Arr[pc], c2];
  }

  // Root entry key = kBefore at the root entry PC (NEVER stored in vmem — header only!)
  vmem.rootEntryKey = kBefore[vmem.rootEntryPC] >>> 0;

  // Materialize final slot words (code slots -> [c0,c1,c2] in word-offset order is
  // applied by the serializer; data slots -> raw words)
  const [off0, off1, off2] = spec.wordOffsets;
  const finalSlots: Array<[number, number, number] | null> = new Array(n);
  for (let pc = 0; pc < n; pc++) {
    if (!isCode(pc)) {
      finalSlots[pc] = null;
      continue;
    }
    const [c0, c1, c2] = encoded[pc]!;
    const words: [number, number, number] = [0, 0, 0];
    words[off0 >> 2] = c0;
    words[off1 >> 2] = c1;
    words[off2 >> 2] = c2;
    finalSlots[pc] = words;
  }
  vmem.encodedSlots = finalSlots;
}
