import { FuncBody } from './ast.js';

/**
 * Grandfuscator v3.0 ("Oblivion") Register ISA — Zero Constant Pool, Zero String Table,
 * Zero Proto Tree, Shattered CCFI String Synthesis, Nonlinear S-Box & Per-Handler Private Ciphers.
 *
 * Pre-lowering instructions (LOADK, GETTABLEK, SETTABLEK, CLOSURE) are 100% eliminated by the
 * CFG compiler before serialization — the emitted Virtual Machine contains ZERO `getK()`,
 * ZERO `decStr()`, ZERO `readProto()`, and ZERO constant/string arrays!
 */
export enum Op {
  // ── Core Register & Environment Ops ──────────────────────────────────────
  MOVE = 0,          // R[a] = R[B]
  LOADK = 1,         // [pre-lowering only — annihilated in Pass 3]
  LOADNIL = 2,       // for i = a, B do R[i] = nil end
  LOADBOOL = 3,      // R[a] = (B ~= 0)
  GETGLOBAL = 4,     // R[a] = env[R[B]]  (lowered: B is register holding shattered string!)
  SETGLOBAL = 5,     // env[R[B]] = R[a]  (lowered: B is register holding shattered string!)
  GETUPVAL = 6,      // R[a] = upvals[B][1][upvals[B][2]]
  SETUPVAL = 7,      // upvals[B][1][upvals[B][2]] = R[a]

  // ── Table & OOP Ops ──────────────────────────────────────────────────────
  NEWTABLE = 8,      // R[a] = {}
  GETTABLE = 9,      // R[a] = R[B][R[C]]
  GETTABLEK = 10,    // [pre-lowering only — lowered to shattered string + GETTABLE/_SWP]
  SETTABLE = 11,     // R[a][R[B]] = R[C]
  SETTABLEK = 12,    // [pre-lowering only — lowered to shattered string + SETTABLE/_SWP]
  SETLIST = 13,      // for i = 1, (B==0 ? top-a : B) do R[a][C+i] = R[a+i] end
  SELF = 14,         // o = R[B]; R[a+1] = o; R[a] = o[R[C]]  (lowered: C is string reg!)

  // ── Arithmetic, String & Unary Ops ───────────────────────────────────────
  ADD = 15,          // R[a] = R[B] + R[C]
  SUB = 16,          // R[a] = R[B] - R[C]
  MUL = 17,          // R[a] = R[B] * R[C]
  DIV = 18,          // R[a] = R[B] / R[C]
  IDIV = 19,         // R[a] = R[B] // R[C]
  MOD = 20,          // R[a] = R[B] % R[C]
  POW = 21,          // R[a] = R[B] ^ R[C]
  UNM = 22,          // R[a] = -R[B]
  NOT = 23,          // R[a] = not R[B]
  LEN = 24,          // R[a] = #R[B]
  CONCAT = 25,       // R[a] = R[B] .. ... .. R[C]
  TOSTRING = 26,     // R[a] = tostring(R[B])

  // ── Relational Comparisons ───────────────────────────────────────────────
  EQ = 27,           // R[a] = (R[B] == R[C])
  NE = 28,           // R[a] = (R[B] ~= R[C])
  LT = 29,           // R[a] = (R[B] < R[C])
  LE = 30,           // R[a] = (R[B] <= R[C])

  // ── Control Flow, Calls, Loops & Closures ────────────────────────────────
  JMP = 31,          // [pre-lowering only -> JMPX / CHAIN_HOP]
  JMPF = 32,         // if not R[a] then pc = B; K = bxor(K, C) end
  JMPT = 33,         // if R[a] then pc = B; K = bxor(K, C) end
  CALL = 34,         // R[a..a+C-2] = R[a](R[a+1..a+B-1])
  RETURN = 35,       // close upvals; return R[a..a+B-2]
  VARARG = 36,       // R[a..a+B-2] = varargs
  FORPREP = 37,      // numeric for setup; else pc = B; K = bxor(K, C)
  FORLOOP = 38,      // numeric for step; if cont then pc = B; K = bxor(K, C)
  ITERPREP = 39,     // Luau generalized iter setup; pc = B; K = bxor(K, C)
  TFORLOOP = 40,     // a = base | (nVars<<10); step iter; if R[base+3]~=nil then pc = B; K = bxor(K, C)
  CLOSURE = 41,      // [pre-lowering only -> CLOS_UP* + CLOS_NEW]
  NATCLOSURE = 42,   // R[a] = nativeEscape[B](boundUpvals)  (--@novm 60-FPS helper)
  CLOSE = 43,        // close open upvalues >= a

  // ── Swapped / Reversed Mutated Opcode Variants ───────────────────────────
  ADD_SWP = 44,      // R[a] = R[C] + R[B]
  SUB_REV = 45,      // R[a] = R[C] - R[B]
  MUL_SWP = 46,      // R[a] = R[C] * R[B]
  DIV_REV = 47,      // R[a] = R[C] / R[B]
  IDIV_REV = 48,     // R[a] = R[C] // R[B]
  LT_REV = 49,       // R[a] = (R[C] < R[B])
  LE_REV = 50,       // R[a] = (R[C] <= R[B])
  GETTABLE_SWP = 51, // R[a] = R[C][R[B]]
  SETTABLE_SWP = 52, // R[a][R[C]] = R[B]

  // ── Fused Multi-Pass Compiler Superinstructions ──────────────────────────
  MOVE2 = 53,        // a = r1 | (r2<<8); R[r1] = R[B]; R[r2] = R[C]
  EQJ = 54,          // a = rL | (rR<<8); if R[rL] ~= R[rR] then pc = B; K = bxor(K, C) end
  NEJ = 55,          // a = rL | (rR<<8); if R[rL] == R[rR] then pc = B; K = bxor(K, C) end
  LTJ = 56,          // a = rL | (rR<<8); if not (R[rL] < R[rR]) then pc = B; K = bxor(K, C) end
  LEJ = 57,          // a = rL | (rR<<8); if not (R[rL] <= R[rR]) then pc = B; K = bxor(K, C) end

  // ── Zero-Constant-Pool Numeric Synthesis (Ints & Full 64-Bit Floats!) ────
  LOADINT = 58,      // R[a] = signed32(B)
  VM_MBA_XOR = 59,   // R[a] = bor(B, C) - band(B, C)
  VM_MBA_ADD = 60,   // R[a] = bxor(B, C) + 2 * band(B, C)
  VM_MBA_NEG = 61,   // R[a] = -(bor(B, C) - band(B, C))
  LOADF64 = 62,      // bufWU32(fScr, 0, B); bufWU32(fScr, 4, C); R[a] = bufRF64(fScr, 0)

  // ── Zero-String-Table Shattered CCFI String Synthesis + Instant Shred ────
  SNEW = 63,         // R[a] = bufCreate(B)  (padded with random leading/trailing chaff!)
  SADD4_XOR = 64,    // bufWU32(R[a], band(C, 255), bxor(B, lrotate(rshift(C, 8), 5)))
  SADD4_ADD = 65,    // bufWU32(R[a], band(C, 255), (B + rshift(C, 8)) % 2^32)
  SADD4_SUB = 66,    // bufWU32(R[a], band(C, 255), (B - rshift(C, 8)) % 2^32)
  SFIN = 67,         // sb=R[a]; R[a]=bufRStr(sb, B_leadOff, C_trueLen); bufFill(sb, 0, band(K,255))
  SBLK = 68,         // Decrypt long string (>96B) from inline vmem[B..B+#-1] under ARX+Sbox key C & shred

  // ── Headerless Interleaved Flat-VM Closure Instantiation ─────────────────
  CLOS_UP = 69,      // Capture upvalue slot `a`: B = inStack (0|1), C = srcReg / parentUpIdx
  CLOS_NEW = 70,     // a = dst|(isVar<<10)|(nParams<<11); B = entryPC; C = entryKey -> makeVmClosure
  CLOS_EXT = 71,     // Optional override when nParams >= 32: pendNParam = B

  // ── CCFI Encrypted Jumps, Jump Chains, Graph CFF, Opaque Forks & Guards ──
  JMPX = 72,         // pc = bxor(B, band(oldK, 0xFFFFF)); K = bxor(K, C)
  CHAIN_HOP = 73,    // K = bxor(rrotate(K, band(a, 31)), C); pc = bxor(B, band(oldK, 0xFFFFF))
  STATE_SET = 74,    // cffState = bor(B, C) - band(B, C)
  STATE_JLE = 75,    // if cffState <= a then pc = B; K = bxor(K, C) end
  STATE_JEQ = 76,    // if cffState == a then pc = B; K = bxor(K, C) end
  OPQ_NEVER = 77,    // if bor(oldK, a) < bxor(oldK, a) then pc = B; K = bxor(K, C) end
  OPQ_ALWAYS = 78,   // if band(oldK, a) <= bor(oldK, a) then pc = B; K = bxor(K, C) end
  KEY_MUTATE = 79,   // K = (bxor(rrotate(K, band(a, 31)), B) + C) % 2^32
  GUARD = 80,        // Live line anchor + vmem byte-len + closure self-identity check folded into K
  AT_CHECK = 81,     // Live C-closure symbol/source/arity + frozen-stdlib re-check folded into K
  CHAFF_ENV = 82,    // Side-effect-free rawget(env, R[B]) + clear R[B] (poisons blind env traces)
}

/** Opcodes that receive extra 2x/3x polymorphic handler copies (each with its own cipher & post-ratchet!) */
export const HOT_OPS: ReadonlySet<Op> = new Set([
  Op.MOVE,
  Op.LOADINT,
  Op.VM_MBA_XOR,
  Op.VM_MBA_ADD,
  Op.LOADF64,
  Op.SNEW,
  Op.SADD4_XOR,
  Op.SADD4_ADD,
  Op.SADD4_SUB,
  Op.SFIN,
  Op.GETGLOBAL,
  Op.GETTABLE,
  Op.GETTABLE_SWP,
  Op.SETTABLE,
  Op.SETTABLE_SWP,
  Op.SELF,
  Op.ADD,
  Op.ADD_SWP,
  Op.SUB,
  Op.SUB_REV,
  Op.MUL,
  Op.CALL,
  Op.RETURN,
  Op.JMPX,
  Op.CHAIN_HOP,
  Op.JMPF,
  Op.EQJ,
  Op.LTJ,
  Op.STATE_SET,
  Op.STATE_JLE,
  Op.KEY_MUTATE,
  Op.GUARD,
  Op.AT_CHECK,
]);

/** Runtime-lowered opcodes eligible for sprinkling into polymorphic dual dispatch engines */
export const RUNTIME_OPS: readonly Op[] = [
  Op.MOVE, Op.LOADNIL, Op.LOADBOOL, Op.GETGLOBAL, Op.SETGLOBAL,
  Op.GETUPVAL, Op.SETUPVAL, Op.NEWTABLE, Op.GETTABLE, Op.SETTABLE,
  Op.SETLIST, Op.SELF, Op.ADD, Op.SUB, Op.MUL, Op.DIV, Op.IDIV,
  Op.MOD, Op.POW, Op.UNM, Op.NOT, Op.LEN, Op.CONCAT, Op.TOSTRING,
  Op.EQ, Op.NE, Op.LT, Op.LE, Op.JMPF, Op.JMPT, Op.CALL, Op.RETURN,
  Op.VARARG, Op.FORPREP, Op.FORLOOP, Op.ITERPREP, Op.TFORLOOP,
  Op.NATCLOSURE, Op.CLOSE, Op.ADD_SWP, Op.SUB_REV, Op.MUL_SWP,
  Op.DIV_REV, Op.IDIV_REV, Op.LT_REV, Op.LE_REV, Op.GETTABLE_SWP,
  Op.SETTABLE_SWP, Op.MOVE2, Op.EQJ, Op.NEJ, Op.LTJ, Op.LEJ,
  Op.LOADINT, Op.VM_MBA_XOR, Op.VM_MBA_ADD, Op.VM_MBA_NEG, Op.LOADF64,
  Op.SNEW, Op.SADD4_XOR, Op.SADD4_ADD, Op.SADD4_SUB, Op.SFIN, Op.SBLK,
  Op.CLOS_UP, Op.CLOS_NEW, Op.CLOS_EXT,
  Op.JMPX, Op.CHAIN_HOP, Op.STATE_SET, Op.STATE_JLE, Op.STATE_JEQ,
  Op.OPQ_NEVER, Op.OPQ_ALWAYS, Op.KEY_MUTATE, Op.GUARD, Op.AT_CHECK,
  Op.CHAFF_ENV,
];

export interface Instruction {
  op: Op;
  a: number;
  b: number;
  c: number;
  /** Symbolic CFG edges used across multi-pass CFG & global interleaving */
  targetBlock?: number;
  fallBlock?: number;
  /** Optional reference to an inline encrypted SBLK data block ID */
  sblkDataId?: number;
  /** Optional reference to a child IRProto during CLOS_NEW lowering */
  childProtoRef?: IRProto;
}

export type IRConstant =
  | { kind: 'nil' }
  | { kind: 'bool'; value: boolean }
  | { kind: 'number'; value: number }
  | { kind: 'string'; bytes: Uint8Array; cacheKey: string };

export interface UpvalDesc {
  inStack: boolean;
  index: number;
  name: string;
}

export interface NativeEscapeProto {
  id: number;
  func: FuncBody;
  upvals: UpvalDesc[];
}

export interface IRProto {
  numParams: number;
  isVararg: boolean;
  maxStack: number;
  /** Final 0-based entry slot inside the single unified interleaved `vmem` buffer */
  entryPC: number;
  /** Initial 32-bit nonlinear CCFI rolling stateKey at `entryPC` */
  entryKey: number;
  instructions: Instruction[];
  /** Legacy flat 12-byte instruction words, populated by the compatibility serializer. */
  encodedWords?: Array<[number, number, number]>;
  constants: IRConstant[];
  upvals: UpvalDesc[];
  protos: IRProto[];
  usedOps: Set<Op>;
  loopHints?: number[];
}

export interface CFGTransformStats {
  fusedSuperinstructions: number;
  mutatedInstructions: number;
  destroyedConstants: number;
  shatteredStrings: number;
  chaffOps: number;
  decoyProtos: number;
  cfgBlocks: number;
  cffDispatcherNodes: number;
  jumpChainHops: number;
  opaqueForks: number;
  bogusBlocks: number;
  guardOpcodes: number;
}

/** Unified flat virtual memory output after cross-function block interleaving & S-box CCFI encoding */
export interface FlatVMemImage {
  /** Every 12-byte slot in physical `vmem` order: code slots hold an Instruction, data slots hold null */
  slots: Array<Instruction | null>;
  /** CCFI-encoded `[c0, c1, c2]` words per code slot (null for data slots); set by the encoder */
  encodedSlots?: Array<[number, number, number] | null>;
  /** Raw `[w0, w1, w2]` words per SBLK data slot (w0 = ciphertext, w1/w2 = random padding) */
  dataSlotWords?: Map<number, [number, number, number]>;
  /** Total 12-byte slots (`vmem` length is `slots.length * 12` bytes) */
  totalSlots: number;
  /** Root chunk entry slot inside `vmem` (NEVER stored in `vmem` — header only!) */
  rootEntryPC: number;
  /** Root chunk entry 32-bit CCFI key (NEVER stored in `vmem` — header only!) */
  rootEntryKey: number;
}

export interface CompiledModule {
  root: IRProto;
  nativeEscapes: NativeEscapeProto[];
  totalProtos: number;
  totalInstructions: number;
  allUsedOps: Set<Op>;
  cfgStats: CFGTransformStats;
  /** Populated by `encodeFlatVMemCCFI` */
  vmem?: FlatVMemImage;
}
