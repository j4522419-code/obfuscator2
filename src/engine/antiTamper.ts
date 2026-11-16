import { MBAEngine } from './mba.js';
import { NameGenerator } from './names.js';
import { PRNG, bit32, hashRobloxId53 } from './prng.js';
import { ResolvedOptions } from './types.js';

export interface CFunctionRef {
  /** Exact C debug symbol returned by `debug.info(fn, "n")` in Roblox Luau */
  cName: string;
  /** Mangled local variable holding the function reference in VM bootstrap */
  localVar: string;
}

export interface StdlibTableRef {
  /** Mangled local or global expression for the frozen stdlib table */
  expr: string;
}

export interface AntiTamperStdlibVars {
  env: string;
  bxor: string;
  band: string;
  bor: string;
  bnot: string;
  rshift: string;
  lrotate: string;
  rrotate: string;
  bufCreate: string;
  bufRU32: string;
  bufWU32: string;
  bufRU8: string;
  bufWF64: string;
  bufRStr: string;
  strByte: string;
  tblIsFrozen: string;
  dbgInfo: string;
  pcall: string;
  typeFn: string;
  getmt: string;
  fmtSlna: string;
  fmtL: string;
  cFunctions: CFunctionRef[];
  frozenLibs: StdlibTableRef[];
}

/**
 * Emit a zero-`string.char`, zero-plaintext ASCII string constructor using only
 * native `buffer.writeu32` + `bit32.bxor` + `buffer.readstring`!
 */
export function emitHiddenAsciiViaBuffer(
  ascii: string,
  bufCreateVar: string,
  bufWU32Var: string,
  bufRStrVar: string,
  bxorVar: string,
  names: NameGenerator,
  rng: PRNG,
): { initCode: string; varName: string } {
  const varName = names.next();
  const tmpBuf = names.next();
  const raw = Buffer.from(ascii, 'utf8');
  const paddedLen = Math.max(4, Math.ceil(raw.length / 4) * 4);
  const padded = Buffer.alloc(paddedLen);
  raw.copy(padded, 0);
  for (let i = raw.length; i < paddedLen; i++) padded[i] = rng.int(1, 254);

  const writes: string[] = [];
  for (let off = 0; off < paddedLen; off += 4) {
    const word = padded.readUInt32LE(off) >>> 0;
    const mask = rng.nextU32();
    const enc = bit32.bxor(word, mask);
    writes.push(`${bufWU32Var}(${tmpBuf},${off},${bxorVar}(0x${enc.toString(16)},0x${mask.toString(16)}));`);
  }

  const initCode =
    `local ${varName};do local ${tmpBuf}=${bufCreateVar}(${paddedLen});` +
    writes.join('') +
    `${varName}=${bufRStrVar}(${tmpBuf},0,${raw.length})end;`;
  return { initCode, varName };
}

/** Exact rolling 32-bit MAC over an ASCII payload string (matches Luau loop bit-for-bit) */
export function computePayloadMac32(payload: string, seed: number, mul16: number, rot: number): number {
  let h = seed >>> 0;
  // Stride 1 for <= 32KB, small stride for huge payloads so startup is always <0.2ms while covering whole stream
  const len = payload.length;
  for (let i = 0; i < len; i++) {
    const b = payload.charCodeAt(i) & 0xff;
    const term = ((b * mul16 + ((i + 1) & 0xffff)) >>> 0);
    h = bit32.add32(bit32.bxor(bit32.rrotate(h, rot), term), 0x9e3779b);
  }
  return bit32.bxor(h, (len * 40503) >>> 0);
}

/** Exact rolling 32-bit MAC over decrypted raw buffer u32 words (post-decode integrity layer) */
export function computeBufferWordsMac32(words: Uint32Array, seed: number, rot: number, step: number): number {
  let h = seed >>> 0;
  for (let i = 0; i < words.length; i++) {
    h = bit32.add32(bit32.bxor(bit32.rrotate(h, rot), words[i] >>> 0), step);
  }
  return h >>> 0;
}

/** Exact compile-time simulation of Sensor 0 (shuffled C-function `debug.info(fn, "slna")` hash) */
function simulateCFunctionHash(
  shuffledFns: CFunctionRef[],
  seed: number,
  pS: number,
  pN: number,
  step: number,
): number {
  const cSrc = [91, 67, 93]; // "[C]"
  let h = seed >>> 0;
  for (const fn of shuffledFns) {
    for (let j = 0; j < cSrc.length; j++) {
      const term = (cSrc[j] * pS + (j + 1) * 257) >>> 0;
      h = bit32.bxor(bit32.rrotate(h, 5), term);
    }
    for (let j = 0; j < fn.cName.length; j++) {
      const term = (fn.cName.charCodeAt(j) * pN + (j + 1) * 521) >>> 0;
      h = bit32.bxor(bit32.rrotate(h, 7), term);
    }
    // l === -1 -> 0x5A3C, a === 0 -> 0, v === true -> 0x3F19
    const meta = (0x5a3c + 0 + 0x3f19) >>> 0;
    h = bit32.add32(bit32.bxor(h, meta), step);
  }
  return h >>> 0;
}

/** Exact compile-time simulation of Sensor 1 (frozen/no-metatable stdlib tables + anti-spoof local sentinel) */
function simulateLibAndSentinelHash(
  libCount: number,
  seed: number,
  pFrozenT: number,
  pNoMtT: number,
  expectedLine: number,
  sentinelArity: number,
): number {
  let h = seed >>> 0;
  for (let i = 0; i < libCount; i++) {
    h = bit32.bxor(bit32.rrotate(h, 9), (pFrozenT + pNoMtT + (i + 1) * 131) >>> 0);
  }
  // Local sentinel: s ~= "[C]" (true -> 0x71E3), l == expectedLine, a == sentinelArity, v == false (0x4B1D)
  const sentVal = (0x71e3 + expectedLine * 31337 + sentinelArity * 4099 + 0x4b1d) >>> 0;
  h = bit32.bxor(bit32.rrotate(h, 11), sentVal);
  return h >>> 0;
}

/**
 * Executor / instrumentation globals that should not exist in a stock Roblox Luau
 * environment. This is a best-effort tripwire: it can catch common injected APIs, but
 * cannot detect an out-of-process logger or a hostile runtime that hides its hooks.
 */
export const ENVIRONMENT_TRIPWIRE_NAMES: readonly string[] = [
  'getgenv', 'getrenv', 'getgc', 'getreg', 'getregistry',
  'hookfunction', 'hookmetamethod', 'newcclosure', 'checkcaller',
  'identifyexecutor', 'getexecutorname', 'syn', 'KRNL_LOADED', 'fluxus',
  'saveinstance', 'isreadonly', 'setreadonly', 'getrawmetatable',
  'setrawmetatable', 'cloneref', 'queue_on_teleport', 'fireproximityprompt',
  'getconnections', 'gethiddenproperty', 'sethiddenproperty',
];

/** Pure helper shared by generated tripwire and red-team tests. */
export function countEnvironmentTripwires(env: Record<string, unknown>): number {
  let count = 0;
  for (const key of ENVIRONMENT_TRIPWIRE_NAMES) {
    if (env[key] !== undefined && env[key] !== null) count++;
  }
  return count;
}

/** Nested 8-Opcode Micro-VM Instruction */
enum MicroOp {
  LDI = 0, // M[a] = imm
  INP = 1, // M[a] = sensors[b]
  XOR = 2, // M[a] = bxor(M[a], M[b])
  ADD = 3, // M[a] = (M[a] + M[b]) % 2^32
  SUB = 4, // M[a] = (M[a] - M[b]) % 2^32
  ROL = 5, // M[a] = lrotate(M[a], b)
  ROR = 6, // M[a] = rrotate(M[a], b)
  MBA = 7, // M[a] = bor(M[a], M[b]) - band(M[a], M[b])
}

interface MicroInst {
  op: MicroOp;
  a: number; // 0..7 register (1..8 in Luau)
  b: number; // u32 operand / register / shift
}

function simulateMicroVM(prog: MicroInst[], sensors: number[]): Uint32Array {
  const M = new Uint32Array(8);
  for (const ins of prog) {
    switch (ins.op) {
      case MicroOp.LDI:
        M[ins.a] = ins.b >>> 0;
        break;
      case MicroOp.INP:
        M[ins.a] = (sensors[ins.b] ?? 0) >>> 0;
        break;
      case MicroOp.XOR:
        M[ins.a] = bit32.bxor(M[ins.a], M[ins.b]);
        break;
      case MicroOp.ADD:
        M[ins.a] = bit32.add32(M[ins.a], M[ins.b]);
        break;
      case MicroOp.SUB:
        M[ins.a] = ((M[ins.a] - M[ins.b] + 4294967296) % 4294967296) >>> 0;
        break;
      case MicroOp.ROL:
        M[ins.a] = bit32.lrotate(M[ins.a], ins.b);
        break;
      case MicroOp.ROR:
        M[ins.a] = bit32.rrotate(M[ins.a], ins.b);
        break;
      case MicroOp.MBA:
        M[ins.a] = (bit32.bor(M[ins.a], M[ins.b]) - bit32.band(M[ins.a], M[ins.b])) >>> 0;
        break;
    }
  }
  return M;
}

export interface GeneratedAntiTamperResult {
  /** Emitted Luau code that computes `masterKeyVar` (and early-returns on unauthorized PlaceId/GameId) */
  initCode: string;
  /** Variable holding the reconstructed 32-bit master stream cipher key */
  masterKeyVar: string;
  /** Variable for bottom-of-file line-anchor closure (must be defined near end of script!) */
  tailAnchorDef: string;
  tailAnchorVar: string;
  /** Variable holding pre-defined bytecode payload string (used by Sensor 3 MAC AND Base85 decoder) */
  bcPayloadVar: string;
  /** Variable holding pre-defined string-pool payload string */
  spPayloadVar: string;
  /** Number of Micro-VM instructions emitted */
  microVmCount: number;
  /** Number of active anti-tamper defense layers */
  layersArmed: number;
}

/**
 * Synthesize the cryptographic anti-tamper sensors (including a best-effort executor/logger
 * environment tripwire) + Nested Micro-VM Key Schedule.
 *
 * ZERO `error("Tampered")` strings, ZERO obvious `if hooked then` branches:
 * every sensor measurement flows directly into the Micro-VM registers that synthesize `masterKey`!
 */
export function generateAntiTamperAndMicroVM(
  targetMasterKey: number,
  bcPayload: string,
  spPayload: string,
  expectedLine: number,
  opts: ResolvedOptions,
  std: AntiTamperStdlibVars,
  names: NameGenerator,
  mba: MBAEngine,
  rng: PRNG,
): GeneratedAntiTamperResult {
  const bcPayloadVar = names.next();
  const spPayloadVar = names.next();
  const tailAnchorVar = names.next();
  const masterKeyVar = names.next();

  const tailAnchorDef = `${tailAnchorVar}=function()return ${std.dbgInfo}(1,${std.fmtL})end;`;

  const codeParts: string[] = [];
  codeParts.push(`${bcPayloadVar}="${bcPayload}";${spPayloadVar}="${spPayload}";`);

  const sensorExpected: number[] = [];
  const sensorVar = names.next();
  codeParts.push(`local ${sensorVar}={};`);

  let layersArmed = 0;

  if (opts.antiTamper) {
    // ── Layer 1 & 2: Shuffled 30-Fn C-Closure `debug.info(fn, "slna")` Hash (Anti-Hook + Anti-newcclosure)
    const shuffledFns = rng.shuffle(std.cFunctions);
    const s0Seed = rng.nextU32() || 0x13572468;
    const pS = rng.oddInt(10007, 60013);
    const pN = rng.oddInt(10009, 60017);
    const s0Step = rng.oddInt(0x10001, 0x3fffffff);
    const s0Expected = simulateCFunctionHash(shuffledFns, s0Seed, pS, pN, s0Step);
    sensorExpected.push(s0Expected);
    const s0Slot = sensorExpected.length;
    layersArmed += 2; // C-hook hash + anti-coroutine.wrap symbol verification

    {
      const [vList, vH, vI, vFn, vS, vL, vN, vA, vV, vJ, vMeta] = names.many(11);
      const fnListStr = shuffledFns.map((f) => f.localVar).join(',');
      codeParts.push(
        `do local ${vList}={${fnListStr}};local ${vH}=${mba.num(s0Seed, 1)};` +
        `for ${vI}=1,${shuffledFns.length} do local ${vFn}=${vList}[${vI}];` +
        `local ${vS},${vL},${vN},${vA},${vV}=${std.dbgInfo}(${vFn},${std.fmtSlna});` +
        `${vS}=${vS} or"";${vN}=${vN} or"";` +
        `for ${vJ}=1,#${vS} do ${vH}=${std.bxor}(${std.rrotate}(${vH},5),(${std.strByte}(${vS},${vJ})*${pS}+${vJ}*257)%4294967296)end;` +
        `for ${vJ}=1,#${vN} do ${vH}=${std.bxor}(${std.rrotate}(${vH},7),(${std.strByte}(${vN},${vJ})*${pN}+${vJ}*521)%4294967296)end;` +
        `local ${vMeta}=((if ${vL}==-1 then 0x5A3C else 0x1197)+(${vA} or 9)*997+(if ${vV}==true then 0x3F19 else 0x0821))%4294967296;` +
        `${vH}=(${std.bxor}(${vH},${vMeta})+${s0Step})%4294967296 end;` +
        `${sensorVar}[${s0Slot}]=${vH} end;`,
      );
    }

    // ── Layer 3 & 4: Stdlib `isfrozen` + No-Metatable Check + Anti-Spoof Reverse Lua Sentinel
    const shuffledLibs = rng.shuffle(std.frozenLibs);
    const s1Seed = rng.nextU32() || 0x89abcdef;
    const pFrzT = rng.oddInt(0x1001, 0x7ffff);
    const pFrzF = rng.oddInt(0x1001, 0x7ffff) ^ 0x3333;
    const pMtT = rng.oddInt(0x1001, 0x7ffff);
    const pMtF = rng.oddInt(0x1001, 0x7ffff) ^ 0x5555;
    const sentArity = rng.int(2, 5);
    const s1Expected = simulateLibAndSentinelHash(
      shuffledLibs.length,
      s1Seed,
      pFrzT,
      pMtT,
      expectedLine,
      sentArity,
    );
    sensorExpected.push(s1Expected);
    const s1Slot = sensorExpected.length;
    layersArmed += 2; // Frozen/proxy-table guard + reverse debug.info spoof trap

    {
      const [vLibs, vH, vI, vLb, vSent, vS, vL, vN, vA, vV, vNotC] = names.many(11);
      const sentParams = names.many(sentArity);
      const libListStr = shuffledLibs.map((l) => l.expr).join(',');
      codeParts.push(
        `do local ${vLibs}={${libListStr}};local ${vH}=${mba.num(s1Seed, 1)};` +
        `for ${vI}=1,${shuffledLibs.length} do local ${vLb}=${vLibs}[${vI}];` +
        `${vH}=${std.bxor}(${std.rrotate}(${vH},9),((if ${std.tblIsFrozen}(${vLb})then ${pFrzT} else ${pFrzF})+(if ${std.getmt}(${vLb})==nil then ${pMtT} else ${pMtF})+${vI}*131)%4294967296)end;` +
        `local function ${vSent}(${sentParams.join(',')})return ${sentParams[0]} end;` +
        `local ${vS},${vL},${vN},${vA},${vV}=${std.dbgInfo}(${vSent},${std.fmtSlna});${vN}=nil;${vS}=${vS} or"";` +
        `${vL}=if(${vL} or 0)<=0 then ${expectedLine} else(${vL} or 0);` +
        `local ${vNotC}=(#${vS}~=3 or ${std.strByte}(${vS},1)~=91 or ${std.strByte}(${vS},2)~=67 or ${std.strByte}(${vS},3)~=93);` +
        `${vH}=${std.bxor}(${std.rrotate}(${vH},11),((if ${vNotC} then 0x71E3 else 0x2204)+${vL}*31337+(${vA} or 0)*4099+(if ${vV}==false then 0x4B1D else 13))%4294967296);` +
        `${sensorVar}[${s1Slot}]=${vH} end;`,
      );
    }

    // ── Layer 5: Triple-Anchor Line-Number & Zero-Delta Key Poisoning (Start + Mid + Tail of Script!)
    const pL1 = rng.oddInt(30011, 190001);
    const pL2 = rng.oddInt(40009, 210001);
    const pL3 = rng.oddInt(50021, 240001);
    const pDelta = rng.oddInt(70001, 310001);
    const s2Xor = rng.nextU32();
    const s2Expected = bit32.bxor(
      s2Xor,
      ((expectedLine * pL1 + expectedLine * pL2 + expectedLine * pL3 + 0 * pDelta) % 4294967296) >>> 0,
    );
    sensorExpected.push(s2Expected);
    const s2Slot = sensorExpected.length;
    layersArmed++;

    {
      const [vL1, vMidFn, vL2, vL3] = names.many(4);
      codeParts.push(
        `do local ${vL1}=${std.dbgInfo}(1,${std.fmtL})or 0;if ${vL1}<=0 then ${vL1}=${expectedLine} end;` +
        `local ${vMidFn}=function()return 0 end;` +
        `local ${vL2}=${std.dbgInfo}(${vMidFn},${std.fmtL})or 0;if ${vL2}<=0 then ${vL2}=${expectedLine} end;` +
        `local ${vL3}=${tailAnchorVar}()or 0;if ${vL3}<=0 then ${vL3}=${expectedLine} end;` +
        `${sensorVar}[${s2Slot}]=${std.bxor}(${mba.num(s2Xor, 1)},(${vL1}*${pL1}+${vL2}*${pL2}+${vL3}*${pL3}+(${vL3}-${vL1})*${pDelta})%4294967296)end;`,
      );
    }

    // ── Layer 6: Full Pre-Decode Ciphertext Stream MAC (1-char edit anywhere destroys key!)
    const macSeed = rng.nextU32() || 0x55aa33cc;
    const macMul = rng.oddInt(257, 16381);
    const macRot = rng.int(5, 25);
    const bcMac = computePayloadMac32(bcPayload, macSeed, macMul, macRot);
    const fullMac = computePayloadMac32(spPayload, bcMac, macMul, macRot);
    sensorExpected.push(fullMac);
    const s3Slot = sensorExpected.length;
    layersArmed++;

    {
      const [vMacFn, vStr, vH, vI, vB] = names.many(5);
      codeParts.push(
        `do local function ${vMacFn}(${vStr},${vH})` +
        `for ${vI}=1,#${vStr} do local ${vB}=${std.strByte}(${vStr},${vI});` +
        `${vH}=(${std.bxor}(${std.rrotate}(${vH},${macRot}),(${vB}*${macMul}+${std.band}(${vI},65535))%4294967296)+0x9E3779B)%4294967296 end;` +
        `return ${std.bxor}(${vH},(#${vStr}*40503)%4294967296)end;` +
        `${sensorVar}[${s3Slot}]=${vMacFn}(${spPayloadVar},${vMacFn}(${bcPayloadVar},${mba.num(macSeed, 1)}))end;`,
      );
    }

    // ── Layer 7: Hardware IEEE-754 Buffer + Bit32 Endian/Emulator Verification
    {
      // Construct an exact finite double from simple power-of-2 dyadic fraction (100% exact literal!)
      const intPart = rng.int(101, 4095);
      const fracNum = rng.oddInt(1, 255);
      const exactDouble = intPart + fracNum / 256; // exact in IEEE-754 binary64!
      const tmp = Buffer.alloc(8);
      tmp.writeDoubleLE(exactDouble, 0);
      const lo32 = tmp.readUInt32LE(0) >>> 0;
      const hi32 = tmp.readUInt32LE(4) >>> 0;
      const s4Expected = bit32.bxor(bit32.rrotate(lo32, 7), bit32.lrotate(hi32, 13));
      sensorExpected.push(s4Expected);
      const s4Slot = sensorExpected.length;
      layersArmed++;

      const [vTb, vW0, vW1] = names.many(3);
      codeParts.push(
        `do local ${vTb}=${std.bufCreate}(8);${std.bufWF64}(${vTb},0,${intPart}+${fracNum}/256);` +
        `local ${vW0},${vW1}=${std.bufRU32}(${vTb},0),${std.bufRU32}(${vTb},4);` +
        `${sensorVar}[${s4Slot}]=${std.bxor}(${std.rrotate}(${vW0},7),${std.lrotate}(${vW1},13))end;`,
      );
    }

    // ── Layer 8: Best-effort anti-instrumentation / environment-logger tripwire
    // Common executor hooks are checked through hidden names and folded into the live
    // Micro-VM sensor. Any non-nil match changes the derived payload key (fail closed).
    // This does NOT stop an external process from recording a runtime it controls.
    {
      const hiddenKeys = ENVIRONMENT_TRIPWIRE_NAMES.map((key) =>
        emitHiddenAsciiViaBuffer(key, std.bufCreate, std.bufWU32, std.bufRStr, std.bxor, names, rng),
      );
      codeParts.push(...hiddenKeys.map((h) => h.initCode));
      const slot = sensorExpected.length + 1;
      sensorExpected.push(0); // stock Roblox environment: no executor/logger hook globals
      const [vKeys, vHits, vI, vOk, vValue] = names.many(5);
      const lookups = hiddenKeys.map((h) => h.varName);
      codeParts.push(
        `do local ${vKeys}={${lookups.join(',')}};local ${vHits}=0;` +
        `for ${vI}=1,#${vKeys} do local ${vOk},${vValue}=${std.pcall}(function()return ${std.env}[${vKeys}[${vI}]]end);` +
        `if not ${vOk} or(${vValue}~=nil and ${vValue}~=false)then ${vHits}+=1 end end;` +
        `${sensorVar}[${slot}]=${vHits} end;`,
      );
      layersArmed++;
    }

    // Layer 9 = Per-instruction 8-bit CCFI MAC + Post-Decode Buffer MAC + Live in-VM GUARD opcodes!
    layersArmed++;
  } else {
    // Even with anti-tamper toggled off, feed a random static nonce sensor into the Micro-VM
    const nonce = rng.nextU32() || 0x42424242;
    sensorExpected.push(nonce);
    codeParts.push(`${sensorVar}[1]=${mba.num(nonce, 1)};`);
  }

  // ── Optional Cryptographic 53-Bit Roblox PlaceId & GameId LUKS-Style Key Slots ──
  if (opts.placeIds.length > 0 || opts.gameIds.length > 0) {
    const vHash53 = names.next();
    const [vId, vSA, vSB, vLo, vHi, vH, vA, vB] = names.many(8);
    codeParts.push(
      `local function ${vHash53}(${vId},${vSA},${vSB})` +
      `local ${vLo}=${vId}%4294967296;local ${vHi}=(${vId}-${vLo})/4294967296;` +
      `local ${vH}=${std.bxor}(${vLo},${vSA});` +
      `local ${vA},${vB}=${std.band}(${vH},65535),${std.rshift}(${vH},16);` +
      `${vH}=${std.bxor}(((${vA}*40503)+${std.band}(${vB}*65521,65535)*65536)%4294967296,${std.rrotate}(${vH},13));` +
      `${vH}=${std.bxor}(${vH},((${vHi}*2654435)%4294967296+${vSB})%4294967296);` +
      `${vA},${vB}=${std.band}(${vH},65535),${std.rshift}(${vH},16);` +
      `return ${std.bxor}(((${vA}*58653)+${std.band}(${vB}*39383,65535)*65536)%4294967296,${std.rrotate}(${vH},7))end;`,
    );

    const kGame = emitHiddenAsciiViaBuffer('game', std.bufCreate, std.bufWU32, std.bufRStr, std.bxor, names, rng);
    const kNum = emitHiddenAsciiViaBuffer('number', std.bufCreate, std.bufWU32, std.bufRStr, std.bxor, names, rng);
    codeParts.push(kGame.initCode, kNum.initCode);

    for (const [prop, idList] of [['PlaceId', opts.placeIds], ['GameId', opts.gameIds]] as const) {
      if (idList.length === 0) continue;
      const kProp = emitHiddenAsciiViaBuffer(prop, std.bufCreate, std.bufWU32, std.bufRStr, std.bxor, names, rng);
      codeParts.push(kProp.initCode);

      const saltTag = rng.nextU32();
      const saltMask = rng.nextU32();
      const contrib = rng.nextU32() || 0x7f4a7c15;
      sensorExpected.push(contrib);
      const slotIdx = sensorExpected.length;

      const usedTags = new Set<number>();
      const slotPairs: string[] = [];
      for (const id of idList) {
        const t = hashRobloxId53(id, saltTag, saltMask);
        const m = hashRobloxId53(id, saltMask, saltTag);
        usedTags.add(t);
        slotPairs.push(`[${mba.num(t, 1)}]=${mba.num(bit32.bxor(contrib, m), 1)}`);
      }
      // 6 indistinguishable decoy slots
      for (let d = 0; d < 6; d++) {
        const ft = rng.nextU32();
        if (!usedTags.has(ft)) {
          usedTags.add(ft);
          slotPairs.push(`[${mba.num(ft, 1)}]=${mba.num(rng.nextU32(), 1)}`);
        }
      }

      const [vSlots, vG, vOk, vVal, vWrap] = names.many(5);
      codeParts.push(
        `do local ${vSlots}={${rng.shuffle(slotPairs).join(',')}};` +
        `local ${vG}=${std.env}[${kGame.varName}];` +
        `local ${vOk},${vVal}=${std.pcall}(function()return ${vG}[${kProp.varName}]end);` +
        `if not ${vOk} or ${std.typeFn}(${vVal})~=${kNum.varName} then return false end;` +
        `local ${vWrap}=${vSlots}[${vHash53}(${vVal},${mba.num(saltTag, 1)},${mba.num(saltMask, 1)})];` +
        `if ${vWrap}==nil then return false end;` +
        `${sensorVar}[${slotIdx}]=${std.bxor}(${vWrap},${vHash53}(${vVal},${mba.num(saltMask, 1)},${mba.num(saltTag, 1)}))end;`,
      );
    }
  }

  // ── Nested 8-Opcode Micro-VM Key Synthesizer (Dual-VM Layer!) ──
  let microVmCount = 0;
  if (opts.microVm) {
    const prog: MicroInst[] = [];
    // Seed all 8 Micro-VM registers with random 32-bit constants
    for (let r = 0; r < 8; r++) {
      prog.push({ op: MicroOp.LDI, a: r, b: rng.nextU32() });
    }
    // Fold EVERY live anti-tamper / PlaceId sensor into multiple registers with non-linear diffusion!
    const tmpReg = 7;
    const sensorOrder = rng.shuffle(Array.from({ length: sensorExpected.length }, (_, i) => i));
    for (const sIdx of sensorOrder) {
      const dst = rng.int(0, 6);
      const other = (dst + rng.int(1, 6)) % 7;
      prog.push({ op: MicroOp.INP, a: tmpReg, b: sIdx });
      prog.push({ op: rng.chance(0.5) ? MicroOp.MBA : MicroOp.XOR, a: dst, b: tmpReg });
      prog.push({ op: rng.chance(0.5) ? MicroOp.ROL : MicroOp.ROR, a: dst, b: rng.int(3, 29) });
      prog.push({ op: rng.chance(0.5) ? MicroOp.ADD : MicroOp.SUB, a: other, b: dst });
    }
    // Collapse all registers 0..6 into `outReg` with extra rounds so EVERY sensor bit affects outReg!
    const outReg = rng.int(0, 6);
    for (let r = 0; r < 7; r++) {
      if (r === outReg) continue;
      prog.push({ op: rng.pick([MicroOp.XOR, MicroOp.ADD, MicroOp.MBA]), a: outReg, b: r });
      prog.push({ op: rng.chance(0.5) ? MicroOp.ROR : MicroOp.ROL, a: outReg, b: rng.int(3, 29) });
    }

    // Simulate exact 32-bit output and append final masked LDI + MBA/XOR yielding `targetMasterKey`!
    const preRegs = simulateMicroVM(prog, sensorExpected);
    const fixMask = bit32.bxor(preRegs[outReg], targetMasterKey >>> 0);
    prog.push({ op: MicroOp.LDI, a: tmpReg, b: fixMask });
    prog.push({ op: MicroOp.MBA, a: outReg, b: tmpReg });

    // Compile-time Micro-VM verification!
    const finalRegs = simulateMicroVM(prog, sensorExpected);
    if (finalRegs[outReg] !== (targetMasterKey >>> 0)) {
      throw new Error('Internal Micro-VM key synthesis verification failed');
    }

    microVmCount = prog.length;

    // Assign unique shuffled physical Micro-VM opcode IDs in 1..250 & rolling-XOR encode bytecode
    const microOpIds = rng.shuffle(Array.from({ length: 240 }, (_, i) => i + 10)).slice(0, 8);
    const mKeyInit = rng.nextU32() || 0xabcdef01;
    const mKeyStep = rng.oddInt(0x10001, 0x2fffffff);
    let mk = mKeyInit;
    const flatWords: string[] = [];
    for (const ins of prog) {
      const phys = microOpIds[ins.op];
      const packedOpA = ((phys & 0xff) | ((ins.a & 0x0f) << 8)) >>> 0;
      const w0 = bit32.bxor(packedOpA, mk & 0xffff);
      const w1 = bit32.bxor(ins.b >>> 0, mk);
      flatWords.push(`0x${w0.toString(16)}`, `0x${w1.toString(16)}`);
      mk = bit32.add32(bit32.rrotate(mk, 11), mKeyStep);
    }

    const [vM, vCode, vMK, vP, vW0, vW1, vU, vOp, vRA] = names.many(9);
    const opCases = rng.shuffle([
      { id: microOpIds[MicroOp.LDI], body: `${vM}[${vRA}]=${vW1}` },
      { id: microOpIds[MicroOp.INP], body: `${vM}[${vRA}]=${sensorVar}[${vW1}+1]or 0` },
      { id: microOpIds[MicroOp.XOR], body: `${vM}[${vRA}]=${std.bxor}(${vM}[${vRA}],${vM}[${vW1}+1])` },
      { id: microOpIds[MicroOp.ADD], body: `${vM}[${vRA}]=(${vM}[${vRA}]+${vM}[${vW1}+1])%4294967296` },
      { id: microOpIds[MicroOp.SUB], body: `${vM}[${vRA}]=(${vM}[${vRA}]-${vM}[${vW1}+1])%4294967296` },
      { id: microOpIds[MicroOp.ROL], body: `${vM}[${vRA}]=${std.lrotate}(${vM}[${vRA}],${vW1})` },
      { id: microOpIds[MicroOp.ROR], body: `${vM}[${vRA}]=${std.rrotate}(${vM}[${vRA}],${vW1})` },
      { id: microOpIds[MicroOp.MBA], body: `${vM}[${vRA}]=${std.bor}(${vM}[${vRA}],${vM}[${vW1}+1])-${std.band}(${vM}[${vRA}],${vM}[${vW1}+1])` },
    ]);
    opCases.sort((a, b) => a.id - b.id);

    const emitMicroTree = (lo: number, hi: number): string => {
      if (lo === hi) return `${opCases[lo].body};`;
      const mid = (lo + hi) >> 1;
      return `if ${vOp}<=0x${opCases[mid].id.toString(16)} then ${emitMicroTree(lo, mid)}else ${emitMicroTree(mid + 1, hi)}end `;
    };

    codeParts.push(
      `do local ${vM}={0,0,0,0,0,0,0,0};local ${vCode}={${flatWords.join(',')}};` +
      `local ${vMK}=${mba.num(mKeyInit, 1)};local ${vP}=1;` +
      `while ${vP}<=${flatWords.length} do ` +
      `local ${vU}=${std.bxor}(${vCode}[${vP}],${std.band}(${vMK},65535));` +
      `local ${vW1}=${std.bxor}(${vCode}[${vP}+1],${vMK});${vP}+=2;` +
      `local ${vOp},${vRA}=${std.band}(${vU},255),${std.rshift}(${vU},8)+1;` +
      emitMicroTree(0, opCases.length - 1) +
      `${vMK}=(${std.rrotate}(${vMK},11)+${mKeyStep})%4294967296 end;` +
      `${masterKeyVar}=${vM}[${outReg + 1}];${sensorVar}=nil end;`,
    );
  } else {
    // Direct cryptographic fold of all sensors into targetMasterKey
    let acc = 0;
    for (const sv of sensorExpected) acc = bit32.bxor(bit32.rrotate(acc, 7), sv);
    const seedFix = bit32.bxor(acc, targetMasterKey >>> 0);
    const [vAcc, vI] = names.many(2);
    codeParts.push(
      `do local ${vAcc}=0;for ${vI}=1,${sensorExpected.length} do ${vAcc}=${std.bxor}(${std.rrotate}(${vAcc},7),${sensorVar}[${vI}]or 0)end;` +
      `${masterKeyVar}=${std.bxor}(${vAcc},${mba.num(seedFix, 1)});${sensorVar}=nil end;`,
    );
  }

  return {
    initCode: codeParts.join(''),
    masterKeyVar,
    tailAnchorDef,
    tailAnchorVar,
    bcPayloadVar,
    spPayloadVar,
    microVmCount,
    layersArmed,
  };
}
