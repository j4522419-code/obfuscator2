import {
  emitHiddenAsciiViaBuffer,
  generateAntiTamperAndMicroVM,
} from './antiTamper.js';
import { emitNativeEscapeTable } from './astObfuscator.js';
import { CFGTransformStats, CompiledModule, Op } from './ir.js';
import { MBAEngine } from './mba.js';
import { NameGenerator } from './names.js';
import { PRNG } from './prng.js';
import {
  PhysicalOpcodeEntry,
  PolymorphicVMSpec,
  serializePolymorphicVM,
} from './serializer.js';
import { GrandfuscatorError, ResolvedOptions } from './types.js';

interface VMVars {
  env: string;
  // bit32 (native fastcall locals)
  bxor: string;
  band: string;
  bor: string;
  bnot: string;
  lshift: string;
  rshift: string;
  lrotate: string;
  rrotate: string;
  // buffer (native fastcall locals)
  bufCreate: string;
  bufCopy: string;
  bufRU32: string;
  bufWU32: string;
  bufRU8: string;
  bufWU8: string;
  bufRI32: string;
  bufRF64: string;
  bufWF64: string;
  bufRStr: string;
  // string / table / coroutine / debug / core
  strByte: string;
  tblPack: string;
  tblUnpack: string;
  tblIsFrozen: string;
  coWrap: string;
  coYield: string;
  dbgInfo: string;
  pcall: string;
  tonum: string;
  tostr: string;
  typeFn: string;
  nextFn: string;
  getmt: string;
  getfenvFn: string;
  // Hidden buffer-built format tags (zero plaintext strings, zero string.char!)
  fmtSlna: string;
  fmtL: string;
  kFunction: string;
  kTable: string;
  // VM runtime helpers
  decStr: string;
  iterWrap: string;
  wrapProto: string;
  natTable: string;
  // Per-frame VM execution registers & CCFI state
  instBuf: string;   // Raw 12-byte/inst encrypted Luau buffer (ZERO instruction tables!)
  mutBuf: string;    // Live self-mutating 4-byte/inst rolling epoch mask buffer!
  R: string;         // VM register file
  top: string;       // Dynamic multi-return/vararg top
  pc: string;        // 0-based instruction pointer
  K: string;         // Live 32-bit rolling CCFI key (post-fetch ratcheted)
  oldK: string;      // Pre-fetch 32-bit CCFI key of current instruction
  cffState: string;  // Dedicated Graph-CFF state register (collision-proof against varargs)
  op: string;        // Dynamically unmasked physical opcode (0..255)
  a: string;         // Unmasked 16-bit operand A
  B: string;         // Unmasked 32-bit operand B
  C: string;         // Unmasked 32-bit operand C
  kCache: string;    // Proto constant cache
  kStr: string;      // Proto encrypted string descriptor map
  getK: string;      // On-demand constant decryptor
  protos: string;    // Child Protos
  upvals: string;    // Frame live upvalue cells
  openUp: string;    // Open upvalue table
  hasOpen: string;   // Fast flag
  closeUp: string;   // Upvalue closer
  vargs: string;
  vcount: string;
  // Sparse shuffled integer keys (1..127) for Proto structs
  pkNumParams: number;
  pkIsVararg: number;
  pkEntryPC: number;
  pkEntryKey: number;
  pkInstBuf: number;
  pkMutBuf: number;
  pkK: number;
  pkKS: number;
  pkUpIn: number;
  pkUpIdx: number;
  pkProtos: number;
}

export interface GeneratedVMOutput {
  code: string;
  spec: PolymorphicVMSpec;
  totalStrings: number;
  mbaCount: number;
  microVmInstructions: number;
  antiTamperLayers: number;
}

function prepareCompatibilityIR(compiled: CompiledModule): void {
  const branches = new Set<Op>([
    Op.JMPF, Op.JMPT, Op.FORPREP, Op.FORLOOP, Op.ITERPREP, Op.TFORLOOP,
  ]);
  let protos = 0;
  let instructionCount = 0;
  compiled.allUsedOps.clear();
  const visit = (proto: CompiledModule['root']): void => {
    protos++;
    proto.entryPC = 0;
    for (const ins of proto.instructions) {
      if (ins.op === Op.JMP) ins.op = Op.JMPX;
      if (ins.op === Op.JMPX || branches.has(ins.op)) ins.b = Math.max(0, ins.b - 1);
      compiled.allUsedOps.add(ins.op);
      instructionCount++;
    }
    for (const child of proto.protos) visit(child);
  };
  visit(compiled.root);
  compiled.totalProtos = protos;
  compiled.totalInstructions = instructionCount;
  compiled.cfgStats = {
    fusedSuperinstructions: 0,
    mutatedInstructions: 0,
    destroyedConstants: 0,
    shatteredStrings: 0,
    chaffOps: 0,
    decoyProtos: 0,
    cfgBlocks: 0,
    cffDispatcherNodes: 0,
    jumpChainHops: 0,
    opaqueForks: 0,
    bogusBlocks: 0,
    guardOpcodes: 0,
  } satisfies CFGTransformStats;
}

/**
 * Synthesize the tested compatibility VM: Micro-VM key schedule, per-proto CCFI buffers,
 * Bootstrap Graph-CFF stages, and anti-tamper sensors. The experimental v3 flat-vmem path
 * is intentionally not wired into this runtime until its serializer/handlers are complete.
 *
 * Strictly 0 `loadstring` calls, 0 `string.char` calls, 0 Lua instruction arrays!
 */
export function generatePolymorphicVM(
  compiled: CompiledModule,
  opts: ResolvedOptions,
  rng: PRNG,
): GeneratedVMOutput {
  const names = new NameGenerator(rng, opts.nameStyle);
  const expectedLine = opts.watermark ? 2 : 1;

  // Prepare the original instruction tree for the legacy execution path. The partial v3
  // CFG pass mutates into flat vmem, while the current VM generator still reads proto buffers;
  // until that runtime is replaced, preserve compiler IR and normalize only PC conventions.
  prepareCompatibilityIR(compiled);

  // Serialize with 2-phase CCFI key scheduler + rolling 32-bit CBC Base85 + post-decode MAC
  const spec = serializePolymorphicVM(compiled, opts, rng);

  const pk = rng.shuffle(Array.from({ length: 127 }, (_, i) => i + 1)).slice(0, 11);
  const n = () => names.next();

  const v: VMVars = {
    env: n(),
    bxor: n(), band: n(), bor: n(), bnot: n(), lshift: n(), rshift: n(), lrotate: n(), rrotate: n(),
    bufCreate: n(), bufCopy: n(), bufRU32: n(), bufWU32: n(), bufRU8: n(), bufWU8: n(),
    bufRI32: n(), bufRF64: n(), bufWF64: n(), bufRStr: n(),
    strByte: n(), tblPack: n(), tblUnpack: n(), tblIsFrozen: n(),
    coWrap: n(), coYield: n(), dbgInfo: n(),
    pcall: n(), tonum: n(), tostr: n(), typeFn: n(), nextFn: n(), getmt: n(), getfenvFn: n(),
    fmtSlna: '', fmtL: '', kFunction: '', kTable: '',
    decStr: n(), iterWrap: n(), wrapProto: n(), natTable: n(),
    instBuf: n(), mutBuf: n(),
    R: n(), top: n(), pc: n(), K: n(), oldK: n(), cffState: n(),
    op: n(), a: n(), B: n(), C: n(),
    kCache: n(), kStr: n(), getK: n(), protos: n(), upvals: n(),
    openUp: n(), hasOpen: n(), closeUp: n(), vargs: n(), vcount: n(),
    pkNumParams: pk[0],
    pkIsVararg: pk[1],
    pkEntryPC: pk[2],
    pkEntryKey: pk[3],
    pkInstBuf: pk[4],
    pkMutBuf: pk[5],
    pkK: pk[6],
    pkKS: pk[7],
    pkUpIn: pk[8],
    pkUpIdx: pk[9],
    pkProtos: pk[10],
  };

  const mba = new MBAEngine(
    rng,
    { bxor: v.bxor, band: v.band, bor: v.bor, bnot: v.bnot, rrotate: v.rrotate },
    opts.mbaDepth,
  );

  // 1. Bind native Roblox Luau C intrinsics (enables 1-cycle Luau FASTCALL + feeds C-hook verifier!)
  const [lBit, lBuf, lStr, lTbl, lCo, lDbg, lMth] = names.many(7);
  const stdBind =
    `local ${lBit},${lBuf},${lStr},${lTbl},${lCo},${lDbg},${lMth}=bit32,buffer,string,table,coroutine,debug,math;` +
    `local ${v.bxor},${v.band},${v.bor},${v.bnot},${v.lshift},${v.rshift},${v.lrotate},${v.rrotate}=` +
    `${lBit}.bxor,${lBit}.band,${lBit}.bor,${lBit}.bnot,${lBit}.lshift,${lBit}.rshift,${lBit}.lrotate,${lBit}.rrotate;` +
    `local ${v.bufCreate},${v.bufCopy},${v.bufRU32},${v.bufWU32},${v.bufRU8},${v.bufWU8},${v.bufRI32},${v.bufRF64},${v.bufWF64},${v.bufRStr}=` +
    `${lBuf}.create,${lBuf}.copy,${lBuf}.readu32,${lBuf}.writeu32,${lBuf}.readu8,${lBuf}.writeu8,${lBuf}.readi32,${lBuf}.readf64,${lBuf}.writef64,${lBuf}.readstring;` +
    `local ${v.strByte},${v.tblPack},${v.tblUnpack},${v.tblIsFrozen},${v.coWrap},${v.coYield},${v.dbgInfo}=` +
    `${lStr}.byte,${lTbl}.pack,${lTbl}.unpack,${lTbl}.isfrozen,${lCo}.wrap,${lCo}.yield,${lDbg}.info;` +
    `local ${v.pcall},${v.tonum},${v.tostr},${v.typeFn},${v.nextFn},${v.getmt},${v.getfenvFn}=` +
    `pcall,tonumber,tostring,type,next,getmetatable,getfenv;` +
    `local ${v.env}=${v.getfenvFn}();`;

  // 2. Construct tiny internal tag strings via XORed buffer.writeu32 (ZERO plaintext, ZERO string.char!)
  const hSlna = emitHiddenAsciiViaBuffer('slna', v.bufCreate, v.bufWU32, v.bufRStr, v.bxor, names, rng);
  const hL = emitHiddenAsciiViaBuffer('l', v.bufCreate, v.bufWU32, v.bufRStr, v.bxor, names, rng);
  v.fmtSlna = hSlna.varName;
  v.fmtL = hL.varName;

  let extraTagsInit = hSlna.initCode + hL.initCode;
  const usesIter = spec.opAliases.has(Op.ITERPREP);
  if (usesIter) {
    const hFn = emitHiddenAsciiViaBuffer('function', v.bufCreate, v.bufWU32, v.bufRStr, v.bxor, names, rng);
    const hTb = emitHiddenAsciiViaBuffer('table', v.bufCreate, v.bufWU32, v.bufRStr, v.bxor, names, rng);
    v.kFunction = hFn.varName;
    v.kTable = hTb.varName;
    extraTagsInit += hFn.initCode + hTb.initCode;
  }

  // 3. Build 8-Layer Anti-Tamper Sensors + Nested 8-Opcode Micro-VM Key Synthesizer!
  const at = generateAntiTamperAndMicroVM(
    spec.masterKey,
    spec.bytecodePayload,
    spec.strPoolPayload,
    expectedLine,
    opts,
    {
      env: v.env,
      bxor: v.bxor, band: v.band, bor: v.bor, bnot: v.bnot,
      rshift: v.rshift, lrotate: v.lrotate, rrotate: v.rrotate,
      bufCreate: v.bufCreate, bufRU32: v.bufRU32, bufWU32: v.bufWU32,
      bufRU8: v.bufRU8, bufWF64: v.bufWF64, bufRStr: v.bufRStr,
      strByte: v.strByte, tblIsFrozen: v.tblIsFrozen,
      dbgInfo: v.dbgInfo, pcall: v.pcall, typeFn: v.typeFn, getmt: v.getmt,
      fmtSlna: v.fmtSlna, fmtL: v.fmtL,
      cFunctions: [
        { cName: 'bxor', localVar: v.bxor },
        { cName: 'band', localVar: v.band },
        { cName: 'bor', localVar: v.bor },
        { cName: 'bnot', localVar: v.bnot },
        { cName: 'lshift', localVar: v.lshift },
        { cName: 'rshift', localVar: v.rshift },
        { cName: 'lrotate', localVar: v.lrotate },
        { cName: 'rrotate', localVar: v.rrotate },
        { cName: 'create', localVar: v.bufCreate },
        { cName: 'copy', localVar: v.bufCopy },
        { cName: 'readu32', localVar: v.bufRU32 },
        { cName: 'writeu32', localVar: v.bufWU32 },
        { cName: 'readu8', localVar: v.bufRU8 },
        { cName: 'writeu8', localVar: v.bufWU8 },
        { cName: 'readi32', localVar: v.bufRI32 },
        { cName: 'readf64', localVar: v.bufRF64 },
        { cName: 'writef64', localVar: v.bufWF64 },
        { cName: 'readstring', localVar: v.bufRStr },
        { cName: 'byte', localVar: v.strByte },
        { cName: 'pack', localVar: v.tblPack },
        { cName: 'unpack', localVar: v.tblUnpack },
        { cName: 'isfrozen', localVar: v.tblIsFrozen },
        { cName: 'wrap', localVar: v.coWrap },
        { cName: 'yield', localVar: v.coYield },
        { cName: 'info', localVar: v.dbgInfo },
        { cName: 'pcall', localVar: v.pcall },
        { cName: 'tonumber', localVar: v.tonum },
        { cName: 'tostring', localVar: v.tostr },
        { cName: 'type', localVar: v.typeFn },
        { cName: 'next', localVar: v.nextFn },
        { cName: 'getmetatable', localVar: v.getmt },
        { cName: 'getfenv', localVar: v.getfenvFn },
      ],
      frozenLibs: [
        { expr: lBit }, { expr: lBuf }, { expr: lStr },
        { expr: lTbl }, { expr: lCo }, { expr: lDbg }, { expr: lMth },
      ],
    },
    names,
    mba,
    rng,
  );

  // 4. Stage: Rolling 32-bit CBC Base85 Stream Decoder + Post-Decode Full-Buffer MAC -> `vEntryMask`
  const vBcBuf = n();
  const vStrBuf = n();
  const vEntryMask = n();
  let streamDecodeStage: string;
  {
    const [
      vAlpha, vLut, vI, vDec, vData, vWords, vState, vStep, vR1, vR2,
      vBuf, vPos, vW, vAcc, vPow, vD, vCiph, vPlain, vMac,
    ] = names.many(19);

    streamDecodeStage =
      `do local ${vAlpha}="${spec.bytecodeCipher.alphabet}";` +
      `local ${vLut}={};for ${vI}=1,85 do ${vLut}[${v.strByte}(${vAlpha},${vI})]=${vI}-1 end;` +
      `local function ${vDec}(${vData},${vWords},${vState},${vStep},${vR1},${vR2})` +
      `local ${vBuf}=${v.bufCreate}(${vWords}*4);local ${vPos}=1;` +
      `for ${vW}=0,${vWords}-1 do ` +
      `local ${vAcc},${vPow}=0,1;` +
      `for ${vD}=0,4 do ${vAcc}+=${vLut}[${v.strByte}(${vData},${vPos}+${vD})]*${vPow};${vPow}*=85 end;` +
      `${vPos}+=5;local ${vCiph}=${vAcc};local ${vPlain}=${mba.mbaXorVars(vCiph, vState)};` +
      `${v.bufWU32}(${vBuf},${vW}*4,${vPlain});` +
      `${vState}=${v.bxor}(${v.rrotate}(${vState},${vR1}),${vCiph});` +
      `${vState}=(${vState}+${vStep})%4294967296;` +
      `${vState}=${v.bxor}(${vState},${v.rrotate}(${vCiph},${vR2}))end;` +
      `return ${vBuf} end;` +
      `${vBcBuf}=${vDec}(${at.bcPayloadVar},${mba.num(spec.bytecodeWordCount, 1)},${at.masterKeyVar},${mba.num(spec.bytecodeCipher.stepConst, 1)},${spec.bytecodeCipher.rot1},${spec.bytecodeCipher.rot2});` +
      `${vStrBuf}=${vDec}(${at.spPayloadVar},${mba.num(spec.strPoolWordCount, 1)},${v.bxor}(${at.masterKeyVar},${mba.num(spec.strKeyXor, 1)}),${mba.num(spec.strPoolCipher.stepConst, 1)},${spec.strPoolCipher.rot1},${spec.strPoolCipher.rot2});` +
      `${at.bcPayloadVar},${at.spPayloadVar},${at.masterKeyVar}=nil,nil,nil;` +
      // Post-decode full-buffer 32-bit MAC: unlocks every Proto's CCFI entryPC & entryKey!
      `local ${vMac}=${mba.num(spec.postMacSeed, 1)};` +
      `for ${vW}=0,${spec.bytecodeWordCount - 1} do ` +
      `${vMac}=(${v.bxor}(${v.rrotate}(${vMac},${spec.postMacRot}),${v.bufRU32}(${vBcBuf},${vW}*4))+${spec.postMacStep})%4294967296 end;` +
      `${vEntryMask}=${v.bxor}(${vMac},${mba.num(spec.postMacFixup, 1)})end;`;
  }

  // 5. Stage: Polymorphic Proto Tree Deserializer (copies raw 12-byte encrypted instruction slices via buffer.copy!)
  const vRootProto = n();
  let deserializeStage: string;
  {
    const [
      vCur, vRU8, vRVar, vRU32F, vRI32F, vRF64F, vReadP, vP,
      vRes, vMul, vByte, vCnt, vI, vTag,
      vPK, vPKS, vOff, vLen, vIBuf, vByteLen, vUIn, vUIdx, vSubs,
    ] = names.many(23);
    const ct = spec.constTags;

    const secCode: Record<string, string> = {
      meta:
        `${vP}[${v.pkNumParams}]=${vRVar}();` +
        `${vP}[${v.pkIsVararg}]=(${vRU8}()~=0);` +
        `${vP}[${v.pkEntryPC}]=${v.bxor}(${vRU32F}(),${vEntryMask});` +
        `${vP}[${v.pkEntryKey}]=${v.bxor}(${vRU32F}(),${v.rrotate}(${vEntryMask},13));`,
      constants:
        `do local ${vCnt}=${vRVar}();local ${vPK},${vPKS}={},{};` +
        `for ${vI}=1,${vCnt} do local ${vTag}=${vRU8}();` +
        `if ${vTag}==${mba.num(ct.encString, 1)} then local ${vOff}=${vRVar}();local ${vLen}=${vRVar}();${vPKS}[${vI}]={${vOff},${vLen},${vRU8}()}` +
        `elseif ${vTag}==${mba.num(ct.int32, 1)} then ${vPK}[${vI}]=${vRI32F}()` +
        `elseif ${vTag}==${mba.num(ct.float64, 1)} then ${vPK}[${vI}]=${vRF64F}()` +
        `elseif ${vTag}==${mba.num(ct.boolTrue, 1)} then ${vPK}[${vI}]=true ` +
        `elseif ${vTag}==${mba.num(ct.boolFalse, 1)} then ${vPK}[${vI}]=false end end;` +
        `${vP}[${v.pkK}]=${vPK};${vP}[${v.pkKS}]=${vPKS} end;`,
      instructions:
        `do local ${vCnt}=${vRVar}();local ${vByteLen}=${vCnt}*12;` +
        `local ${vIBuf}=${v.bufCreate}(${vByteLen});` +
        `${v.bufCopy}(${vIBuf},0,${vBcBuf},${vCur},${vByteLen});${vCur}+=${vByteLen};` +
        `${vP}[${v.pkInstBuf}]=${vIBuf};` +
        (opts.bytecodeMutation ? `${vP}[${v.pkMutBuf}]=${v.bufCreate}(${vCnt}*4);` : '') +
        `end;`,
      upvals:
        `do local ${vCnt}=${vRVar}();local ${vUIn},${vUIdx}={},{};` +
        `for ${vI}=1,${vCnt} do ${vUIn}[${vI}]=${vRU8}();${vUIdx}[${vI}]=${vRVar}()end;` +
        `${vP}[${v.pkUpIn}]=${vUIn};${vP}[${v.pkUpIdx}]=${vUIdx} end;`,
      protos:
        `do local ${vCnt}=${vRVar}();local ${vSubs}={};` +
        `for ${vI}=1,${vCnt} do ${vSubs}[${vI}]=${vReadP}()end;` +
        `${vP}[${v.pkProtos}]=${vSubs} end;`,
    };

    deserializeStage =
      `do local ${vCur}=0;` +
      `local function ${vRU8}()local ${vByte}=${v.bufRU8}(${vBcBuf},${vCur});${vCur}+=1;return ${vByte} end;` +
      `local function ${vRVar}()local ${vRes},${vMul}=0,1;while true do local ${vByte}=${v.bufRU8}(${vBcBuf},${vCur});${vCur}+=1;` +
      `if ${vByte}<128 then return ${vRes}+${vByte}*${vMul} end;${vRes}+=(${vByte}-128)*${vMul};${vMul}*=128 end end;` +
      `local function ${vRU32F}()local ${vRes}=${v.bufRU32}(${vBcBuf},${vCur});${vCur}+=4;return ${vRes} end;` +
      `local function ${vRI32F}()local ${vRes}=${v.bufRI32}(${vBcBuf},${vCur});${vCur}+=4;return ${vRes} end;` +
      `local function ${vRF64F}()local ${vRes}=${v.bufRF64}(${vBcBuf},${vCur});${vCur}+=8;return ${vRes} end;` +
      `local function ${vReadP}()local ${vP}={};${spec.sectionOrder.map((s) => secCode[s]).join('')}return ${vP} end;` +
      `${vRootProto}=${vReadP}();${vBcBuf}=nil;${vEntryMask}=nil end;`;
  }

  // 6. Stage: On-Demand Autokey String Decryptor + Generalized Iteration + Optional `--@novm` Escapes
  let helpersStage = '';
  {
    const [vOff, vLen, vSKey, vOut, vJ, vB, vDec] = names.many(7);
    helpersStage +=
      `${v.decStr}=function(${vOff},${vLen},${vSKey})` +
      `if ${vLen}==0 then return""end;` +
      `local ${vOut}=${v.bufCreate}(${vLen});` +
      `for ${vJ}=0,${vLen}-1 do ` +
      `local ${vB}=${v.bufRU8}(${vStrBuf},${vOff}+${vJ});` +
      `local ${vDec}=${v.band}(${v.bxor}(${v.bxor}(${vB},${vSKey}),(${vJ}*${spec.strPosPrime})%256),255);` +
      `${v.bufWU8}(${vOut},${vJ},${vDec});` +
      `${vSKey}=(${vSKey}*${spec.strXorMult}+${spec.strXorInc}+${vB})%256 end;` +
      `return ${v.bufRStr}(${vOut},0,${vLen})end;`;
  }
  if (usesIter) {
    const [vObj, r1, r2, r3, r4, r5, r6] = names.many(7);
    helpersStage +=
      `${v.iterWrap}=function(${vObj})` +
      `return ${v.coWrap}(function()for ${r1},${r2},${r3},${r4},${r5},${r6} in ${vObj} do ` +
      `${v.coYield}(${r1},${r2},${r3},${r4},${r5},${r6})end end)end;`;
  }

  let natStrings = 0;
  let natDecl = '';
  if (compiled.nativeEscapes.length > 0) {
    const nat = emitNativeEscapeTable(
      compiled.nativeEscapes,
      opts,
      rng,
      names,
      mba,
      v.env,
      v.tostr,
      {
        bxor: v.bxor, band: v.band, rrotate: v.rrotate,
        bufCreate: v.bufCreate, bufWriteU32: v.bufWU32,
        bufReadU8: v.bufRU8, bufWriteU8: v.bufWU8,
        bufReadStr: v.bufRStr, strByte: v.strByte,
      },
    );
    v.natTable = nat.tableVar;
    natStrings = nat.vaultStrings;
    natDecl = nat.code;
  }

  // 7. Synthesize the Self-Mutating Raw-Buffer CCFI Virtual Machine Engine!
  const vmEngineDef = buildCCFIInterpreter(spec, opts, compiled, v, names, rng, mba);

  // 8. Flatten VM Bootstrap Stages into a Shuffled Control-Flow Graph State Machine!
  const vRootFn = n();
  const vAuthorized = n();
  const stageBlocks = [
    // Stage 0: Anti-Tamper Sensors + Nested Micro-VM Key Schedule
    `do local _r=(function()${at.initCode}return true end)();if not _r then ${vAuthorized}=false end end;`,
    // Stage 1: Rolling CBC Base85 Stream Decode + Post-Decode Full-Buffer MAC
    streamDecodeStage,
    // Stage 2: Runtime String Decryptor & Generalized Iter Helpers
    helpersStage,
    // Stage 3: Polymorphic Proto Tree Deserialization into Raw Encrypted Buffers
    deserializeStage,
    // Stage 4: Bind Root VM Closure & Wipe Root Proto Metadata
    `${vRootFn}=${v.wrapProto}(${vRootProto});${vRootProto}=nil;`,
  ];

  // Replace `_r` with a collision-free generated local name!
  const vAuthRes = n();
  stageBlocks[0] = `do local ${vAuthRes}=(function()${at.initCode}return true end)();if not ${vAuthRes} then ${vAuthorized}=false end end;`;

  const bootstrapGraph = emitShuffledStateGraph(stageBlocks, vAuthorized, names, mba, rng);

  // Place `tailAnchorDef` at the VERY END of the script (after the entire 30KB+ VM interpreter!)
  // so adding a newline ANYWHERE in the entire file poisons Sensor 2 in the Micro-VM!
  const singleLine =
    `return(function(...)` +
    stdBind +
    extraTagsInit +
    natDecl +
    `local ${at.bcPayloadVar},${at.spPayloadVar},${at.masterKeyVar},${at.tailAnchorVar},${vBcBuf},${vStrBuf},${vEntryMask},${vRootProto},${vRootFn};` +
    `local ${v.decStr},${v.iterWrap},${v.wrapProto};` +
    `local ${vAuthorized}=true;` +
    vmEngineDef +
    `local function ${vRootFn}Boot(...)` +
    bootstrapGraph +
    `if not ${vAuthorized} then return end;return ${vRootFn}(...)end;` +
    // Put the tail anchor after every generated definition, then run bootstrap. The line
    // check is now sensitive to a newline anywhere in the emitted VM before this point.
    at.tailAnchorDef +
    `return ${vRootFn}Boot(...)end)(...)`;

  // Safety assertions: zero newlines inside VM line, zero `loadstring`, zero `string.char`!
  if (singleLine.includes('\n') || singleLine.includes('\r')) {
    throw new GrandfuscatorError('Internal VM synthesizer emitted unexpected newline', 'vm');
  }
  if (singleLine.includes('loadstring')) {
    throw new GrandfuscatorError('Internal invariant violated: loadstring is forbidden', 'vm');
  }

  const prefix = opts.watermark ? `-- ${opts.watermark}\n` : '';
  return {
    code: prefix + singleLine,
    spec,
    totalStrings: spec.stringCount + natStrings,
    mbaCount: mba.count,
    microVmInstructions: at.microVmCount,
    antiTamperLayers: at.layersArmed,
  };
}

/** Wrap an ordered list of VM lifecycle stages into a physically-shuffled CFF state-machine graph + decoy state */
function emitShuffledStateGraph(
  stages: string[],
  guardFlagVar: string,
  names: NameGenerator,
  mba: MBAEngine,
  rng: PRNG,
): string {
  const used = new Set<number>();
  const allocId = (): number => {
    while (true) {
      const x = rng.int(0x200, 0xfdff);
      if (!used.has(x)) { used.add(x); return x; }
    }
  };

  const ids = stages.map(() => allocId());
  const exitId = allocId();
  const decoyId1 = allocId();
  const decoyId2 = allocId();

  const nodes: Array<{ id: number; body: string; nextExpr: string }> = stages.map((body, idx) => {
    const nextId = idx + 1 < stages.length ? ids[idx + 1] : exitId;
    const nextExpr =
      idx === 0
        ? `(if ${guardFlagVar} then ${mba.num(nextId, 1)} else ${mba.num(exitId, 1)})`
        : mba.num(nextId, 1);
    return { id: ids[idx], body, nextExpr };
  });

  // Add 2 unreachable bogus CFF states to confuse static CFG lifters
  const dTmp = names.next();
  nodes.push(
    { id: decoyId1, body: `local ${dTmp}=${mba.num(rng.int(99, 99999), 1)};${dTmp}=nil;`, nextExpr: mba.num(decoyId2, 1) },
    { id: decoyId2, body: `${guardFlagVar}=false;`, nextExpr: mba.num(exitId, 1) },
  );
  nodes.sort((a, b) => a.id - b.id);

  const vS = names.next();
  const tree = (lo: number, hi: number): string => {
    if (lo === hi) {
      return `${nodes[lo].body}${vS}=${nodes[lo].nextExpr};`;
    }
    const mid = (lo + hi) >> 1;
    if (rng.chance(0.5)) {
      return `if ${vS}<=0x${nodes[mid].id.toString(16)} then ${tree(lo, mid)}else ${tree(mid + 1, hi)}end `;
    }
    return `if ${vS}>0x${nodes[mid].id.toString(16)} then ${tree(mid + 1, hi)}else ${tree(lo, mid)}end `;
  };

  return `do local ${vS}=${mba.num(ids[0], 1)};while ${vS}~=${mba.num(exitId, 1)} do ${tree(0, nodes.length - 1)}end end;`;
}

/**
 * Emit the main Self-Mutating Raw-Buffer CCFI VM Interpreter:
 *  - Fetches 3x32-bit encrypted words from `instBuf` at per-build shuffled offsets
 *  - Re-encrypts `instBuf` IN PLACE on every executed instruction using rolling epoch nonces (`mutBuf`)
 *  - Unmasks `op`, `a`, `B`, `C` against live per-PC CCFI `stateKey`
 *  - Verifies 8-bit per-instruction authentication MAC (silently poisoning `K` if tampered)
 *  - Dispatches across up to 190+ duplicated/mutated/superinstruction/decoy physical opcodes
 */
function buildCCFIInterpreter(
  spec: PolymorphicVMSpec,
  opts: ResolvedOptions,
  compiled: CompiledModule,
  v: VMVars,
  names: NameGenerator,
  rng: PRNG,
  mba: MBAEngine,
): string {
  const ccfi = spec.ccfi;
  const [off0, off1, off2] = ccfi.wordOffsets;

  const [
    vProtoArg, vNParam, vIsVar, vEntryPC, vEntryKey,
    vKIdx, vVal, vDesc, vArgs, vArgN, vI, vMinReg, vReg, vCell,
    vOff, vMOff, vEpoch, vNextEpoch, vC0, vC1, vC2, vU0, vStoredMac, vExpMac, vMacDiff,
  ] = names.many(25);

  // Constant fetcher: 'ephemeral' (Nightmare — ZERO plaintext string caching in RAM!) vs 'lazy' (fast 60-FPS cache)
  const getKCode =
    opts.stringMode === 'ephemeral'
      ? `local function ${v.getK}(${vKIdx})local ${vDesc}=${v.kStr}[${vKIdx}];if ${vDesc} then return ${v.decStr}(${vDesc}[1],${vDesc}[2],${vDesc}[3])end;return ${v.kCache}[${vKIdx}]end;`
      : `local function ${v.getK}(${vKIdx})local ${vVal}=${v.kCache}[${vKIdx}];if ${vVal}~=nil then return ${vVal} end;local ${vDesc}=${v.kStr}[${vKIdx}];if ${vDesc} then ${vVal}=${v.decStr}(${vDesc}[1],${vDesc}[2],${vDesc}[3]);${v.kCache}[${vKIdx}]=${vVal};${v.kStr}[${vKIdx}]=nil;return ${vVal} end;return nil end;`;

  // Fetch + Optional Live In-Place Self-Mutation of `instBuf`!
  const fetchAndMutate = opts.bytecodeMutation
    ? (
        `local ${vOff},${vMOff}=${v.pc}*12,${v.pc}*4;` +
        `local ${vEpoch}=${v.bufRU32}(${v.mutBuf},${vMOff});` +
        `local ${vC0}=${v.bxor}(${v.bufRU32}(${v.instBuf},${vOff}+${off0}),${vEpoch});` +
        `local ${vC1}=${v.bxor}(${v.bufRU32}(${v.instBuf},${vOff}+${off1}),${v.rrotate}(${vEpoch},${ccfi.epochRot1}));` +
        `local ${vC2}=${v.bxor}(${v.bufRU32}(${v.instBuf},${vOff}+${off2}),${v.rrotate}(${vEpoch},${ccfi.epochRot2}));` +
        // Re-encrypt this 12-byte instruction slot in live RAM under a brand-new rolling epoch nonce!
        `local ${vNextEpoch}=(${v.bxor}(${v.rrotate}(${vEpoch},7),${vC0})+${ccfi.epochStep})%4294967296;` +
        `${v.bufWU32}(${v.instBuf},${vOff}+${off0},${v.bxor}(${vC0},${vNextEpoch}));` +
        `${v.bufWU32}(${v.instBuf},${vOff}+${off1},${v.bxor}(${vC1},${v.rrotate}(${vNextEpoch},${ccfi.epochRot1})));` +
        `${v.bufWU32}(${v.instBuf},${vOff}+${off2},${v.bxor}(${vC2},${v.rrotate}(${vNextEpoch},${ccfi.epochRot2})));` +
        `${v.bufWU32}(${v.mutBuf},${vMOff},${vNextEpoch});`
      )
    : (
        `local ${vOff}=${v.pc}*12;` +
        `local ${vC0}=${v.bufRU32}(${v.instBuf},${vOff}+${off0});` +
        `local ${vC1}=${v.bufRU32}(${v.instBuf},${vOff}+${off1});` +
        `local ${vC2}=${v.bufRU32}(${v.instBuf},${vOff}+${off2});`
      );

  // Dynamic per-PC CCFI Opcode & Operand Decode + 8-Bit Instruction MAC Check + State-Key Ratchet!
  const ccfiDecodeAndRatchet =
    `local ${v.oldK}=${v.K};` +
    `local ${vU0}=${v.bxor}(${vC0},${v.oldK});` +
    `local ${v.op},${v.a},${vStoredMac}=${v.band}(${vU0},255),${v.band}(${v.rshift}(${vU0},8),65535),${v.rshift}(${vU0},24);` +
    `local ${v.B}=${v.bxor}(${vC1},${v.rrotate}(${v.oldK},${ccfi.rotB}));` +
    `local ${v.C}=${v.bxor}(${vC2},${v.rrotate}(${v.oldK},${ccfi.rotC}));` +
    `local ${vExpMac}=${v.band}(${v.bxor}(${v.bxor}(${v.op}*${ccfi.macP1},${v.a}*${ccfi.macP2}),${v.bxor}(${v.band}(${v.B},65535),${v.rshift}(${v.oldK},16))),255);` +
    `local ${vMacDiff}=${v.bxor}(${vStoredMac},${vExpMac});` +
    `${v.K}=(${v.bxor}(${v.rrotate}(${v.oldK},${ccfi.ratchetRot}),${vC0})+${ccfi.ratchetStep}+${vMacDiff}*${ccfi.macPoison})%4294967296;` +
    `${v.pc}+=1;`;

  const dispatchTree = emitDispatchDAG(
    spec.dispatchTable,
    0,
    spec.dispatchTable.length - 1,
    v,
    names,
    rng,
    mba,
    compiled,
  );

  return (
    `${v.wrapProto}=function(${vProtoArg},${v.upvals})` +
    `local ${v.instBuf}=${vProtoArg}[${v.pkInstBuf}];` +
    (opts.bytecodeMutation ? `local ${v.mutBuf}=${vProtoArg}[${v.pkMutBuf}];` : '') +
    `local ${v.kCache},${v.kStr},${v.protos}=${vProtoArg}[${v.pkK}],${vProtoArg}[${v.pkKS}],${vProtoArg}[${v.pkProtos}];` +
    `local ${vNParam},${vIsVar}=${vProtoArg}[${v.pkNumParams}],${vProtoArg}[${v.pkIsVararg}];` +
    `local ${vEntryPC},${vEntryKey}=${vProtoArg}[${v.pkEntryPC}],${vProtoArg}[${v.pkEntryKey}];` +
    getKCode +
    `return function(...)` +
    `local ${vArgs}=${v.tblPack}(...);local ${vArgN}=${vArgs}.n;` +
    `local ${v.R}={};` +
    `for ${vI}=1,${vNParam} do ${v.R}[${vI}-1]=${vArgs}[${vI}]end;` +
    `local ${v.vargs},${v.vcount};` +
    `if ${vIsVar} then ${v.vargs}={};${v.vcount}=${vArgN}-${vNParam};` +
    `if ${v.vcount}<0 then ${v.vcount}=0 else for ${vI}=1,${v.vcount} do ${v.vargs}[${vI}]=${vArgs}[${vNParam}+${vI}]end end end;` +
    `${vArgs}=nil;` +
    `local ${v.openUp},${v.hasOpen}={},false;` +
    `local function ${v.closeUp}(${vMinReg})` +
    `local ${vVal}=false;` +
    `for ${vReg},${vCell} in ${v.nextFn},${v.openUp} do ` +
    `if ${vReg}>=${vMinReg} then ${vCell}[0]=${vCell}[1][${vCell}[2]];${vCell}[1]=${vCell};${vCell}[2]=0;${v.openUp}[${vReg}]=nil else ${vVal}=true end end;` +
    `${v.hasOpen}=${vVal} end;` +
    `local ${v.pc},${v.K},${v.top},${v.cffState}=${vEntryPC},${vEntryKey},-1,0;` +
    `while true do ` +
    fetchAndMutate +
    ccfiDecodeAndRatchet +
    dispatchTree +
    `end end end;`
  );
}

/** Recursive O(log N) polymorphic decision tree over all real + split + mutated + decoy opcodes */
function emitDispatchDAG(
  entries: PhysicalOpcodeEntry[],
  lo: number,
  hi: number,
  v: VMVars,
  names: NameGenerator,
  rng: PRNG,
  mba: MBAEngine,
  compiled: CompiledModule,
): string {
  const fmt = (id: number) => (rng.chance(0.6) ? '0x' + id.toString(16).toUpperCase() : String(id));
  if (lo === hi) {
    return emitHandler(entries[lo], v, names, rng, mba, compiled);
  }
  if (hi - lo === 1) {
    const h0 = emitHandler(entries[lo], v, names, rng, mba, compiled);
    const h1 = emitHandler(entries[hi], v, names, rng, mba, compiled);
    const lit = fmt(entries[lo].physId);
    return rng.chance(0.5)
      ? `if ${v.op}==${lit} then ${h0}else ${h1}end `
      : `if ${v.op}~=${lit} then ${h1}else ${h0}end `;
  }
  const mid = (lo + hi) >> 1;
  const lit = fmt(entries[mid].physId);
  const L = emitDispatchDAG(entries, lo, mid, v, names, rng, mba, compiled);
  const R = emitDispatchDAG(entries, mid + 1, hi, v, names, rng, mba, compiled);
  return rng.chance(0.5)
    ? `if ${v.op}<=${lit} then ${L}else ${R}end `
    : `if ${v.op}>${lit} then ${R}else ${L}end `;
}

function emitHandler(
  entry: PhysicalOpcodeEntry,
  v: VMVars,
  names: NameGenerator,
  _rng: PRNG,
  mba: MBAEngine,
  compiled: CompiledModule,
): string {
  const { R, a, B, C, pc, K, oldK, cffState } = v;
  const alt = entry.variantIdx;

  // Indistinguishable decoy VM instruction handlers (7 distinct families!)
  if (entry.logicalOp === 'DECOY') {
    const [t1, t2] = names.many(2);
    switch (entry.variantIdx % 7) {
      case 0:
        return `${R}[${a}]=${v.bor}(${B},${C})-${v.band}(${B},${C});${K}=${v.bxor}(${K},${a});`;
      case 1:
        return `local ${t1}=${R}[${v.band}(${a},255)];if ${t1}~=${R}[${v.rshift}(${a},8)]then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
      case 2:
        return `${pc}=${v.bxor}(${B},${v.band}(${oldK},0xFFFFF));${K}=${v.bxor}(${v.lrotate}(${K},${(entry.decoySeed % 27) + 2}),${C});`;
      case 3:
        return `local ${t1}=${v.getK}(${B});${R}[${a}]=${R}[${C}][${t1}];`;
      case 4:
        return `${cffState}=${v.bxor}(${cffState},${B});if ${cffState}==${a} then ${pc}=${C} end;`;
      case 5:
        return `local ${t1},${t2}=${R}[${C}],${R}[${B}];${R}[${a}]=(${t1}-${t2})%${(entry.decoySeed % 65000) + 17};`;
      default:
        return `for ${t1}=${a},${a}+${v.band}(${B},7)do ${R}[${t1}]=${R}[${t1}+1]end;`;
    }
  }

  switch (entry.logicalOp) {
    // ── Core Data & Superinstructions ──────────────────────────────────────
    case Op.MOVE:
      if (alt === 1) { const t = names.next(); return `local ${t}=${R}[${B}];${R}[${a}]=${t};`; }
      return `${R}[${a}]=${R}[${B}];`;

    case Op.MOVE2:
      return `${R}[${v.band}(${a},255)]=${R}[${B}];${R}[${v.rshift}(${a},8)]=${R}[${C}];`;

    case Op.LOADK:
      return `${R}[${a}]=${v.getK}(${B});`;

    case Op.LOADINT:
      return `${R}[${a}]=if ${B}>=0x80000000 then ${B}-4294967296 else ${B};`;

    case Op.LOADNIL: {
      const i = names.next();
      return `for ${i}=${a},${B} do ${R}[${i}]=nil end;`;
    }

    case Op.LOADBOOL:
      return `${R}[${a}]=(${B}~=0);`;

    case Op.GETGLOBAL:
      return `${R}[${a}]=${v.env}[${v.getK}(${B})];`;

    case Op.SETGLOBAL:
      return `${v.env}[${v.getK}(${B})]=${R}[${a}];`;

    case Op.GETUPVAL: {
      const u = names.next();
      return `local ${u}=${v.upvals}[${B}];${R}[${a}]=${u}[1][${u}[2]];`;
    }

    case Op.SETUPVAL: {
      const u = names.next();
      return `local ${u}=${v.upvals}[${B}];${u}[1][${u}[2]]=${R}[${a}];`;
    }

    // ── Tables, Mutated Swaps & GETGK Superinstruction ─────────────────────
    case Op.NEWTABLE:
      return `${R}[${a}]={};`;

    case Op.GETTABLE:
      return `${R}[${a}]=${R}[${B}][${R}[${C}]];`;

    case Op.GETTABLE_SWP:
      return `${R}[${a}]=${R}[${C}][${R}[${B}]];`;

    case Op.GETTABLEK:
      return `${R}[${a}]=${R}[${B}][${v.getK}(${C})];`;

    case Op.SETTABLE:
      return `${R}[${a}][${R}[${B}]]=${R}[${C}];`;

    case Op.SETTABLE_SWP:
      return `${R}[${a}][${R}[${C}]]=${R}[${B}];`;

    case Op.SETTABLEK:
      return `${R}[${a}][${v.getK}(${B})]=${R}[${C}];`;

    case Op.SETLIST: {
      const [t, n, i] = names.many(3);
      return (
        `local ${t}=${R}[${a}];local ${n}=if ${B}==0 then ${v.top}-${a} else ${B};` +
        `for ${i}=1,${n} do ${t}[${C}+${i}]=${R}[${a}+${i}]end;`
      );
    }

    case Op.SELF: {
      const o = names.next();
      return `local ${o}=${R}[${B}];${R}[${a}+1]=${o};${R}[${a}]=${o}[${v.getK}(${C})];`;
    }

    // ── Arithmetic + Mutated Operand Variants + Fused *K Superinstructions ─
    case Op.ADD:
      return `${R}[${a}]=${R}[${B}]+${R}[${C}];`;
    case Op.ADD_SWP:
      return `${R}[${a}]=${R}[${C}]+${R}[${B}];`;
    case Op.SUB:
      return `${R}[${a}]=${R}[${B}]-${R}[${C}];`;
    case Op.SUB_REV:
      return `${R}[${a}]=${R}[${C}]-${R}[${B}];`;
    case Op.MUL:
      return `${R}[${a}]=${R}[${B}]*${R}[${C}];`;
    case Op.MUL_SWP:
      return `${R}[${a}]=${R}[${C}]*${R}[${B}];`;
    case Op.DIV:
      return `${R}[${a}]=${R}[${B}]/${R}[${C}];`;
    case Op.DIV_REV:
      return `${R}[${a}]=${R}[${C}]/${R}[${B}];`;

    case Op.IDIV:
      return `${R}[${a}]=${R}[${B}]//${R}[${C}];`;
    case Op.IDIV_REV:
      return `${R}[${a}]=${R}[${C}]//${R}[${B}];`;

    case Op.MOD:
      return `${R}[${a}]=${R}[${B}]%${R}[${C}];`;
    case Op.POW:
      return `${R}[${a}]=${R}[${B}]^${R}[${C}];`;
    case Op.UNM:
      return `${R}[${a}]=-${R}[${B}];`;
    case Op.NOT:
      return `${R}[${a}]=not ${R}[${B}];`;
    case Op.LEN:
      return `${R}[${a}]=#${R}[${B}];`;

    case Op.CONCAT: {
      const [acc, i] = names.many(2);
      return `local ${acc}=${R}[${C}];for ${i}=${C}-1,${B},-1 do ${acc}=${R}[${i}]..${acc} end;${R}[${a}]=${acc};`;
    }

    case Op.TOSTRING:
      return `${R}[${a}]=${v.tostr}(${R}[${B}]);`;

    // ── VM-Level MBA Constant Pool Destruction Handlers ────────────────────
    case Op.VM_MBA_XOR:
      if (alt === 1) return `${R}[${a}]=${v.bxor}(${B},${C});`;
      return `${R}[${a}]=${v.bor}(${B},${C})-${v.band}(${B},${C});`;

    case Op.VM_MBA_ADD:
      if (alt === 1) return `${R}[${a}]=${v.bor}(${B},${C})+${v.band}(${B},${C});`;
      return `${R}[${a}]=${v.bxor}(${B},${C})+2*${v.band}(${B},${C});`;

    case Op.VM_MBA_NEG:
      return `${R}[${a}]=-(${v.bor}(${B},${C})-${v.band}(${B},${C}));`;

    // ── Relational Comparisons + Reversed Variants ─────────────────────────
    case Op.EQ:
      return `${R}[${a}]=(${R}[${B}]==${R}[${C}]);`;
    case Op.NE:
      return `${R}[${a}]=(${R}[${B}]~=${R}[${C}]);`;
    case Op.LT:
      return `${R}[${a}]=(${R}[${B}]<${R}[${C}]);`;
    case Op.LT_REV:
      return `${R}[${a}]=(${R}[${C}]<${R}[${B}]);`;
    case Op.LE:
      return `${R}[${a}]=(${R}[${B}]<=${R}[${C}]);`;
    case Op.LE_REV:
      return `${R}[${a}]=(${R}[${C}]<=${R}[${B}]);`;

    // ── CCFI Encrypted Jumps, Multi-Hop Jump Chains & Fused Branches ───────
    case Op.JMP:
    case Op.JMPX:
      return `${pc}=${v.bxor}(${B},${v.band}(${oldK},0xFFFFF));${K}=${v.bxor}(${K},${C});`;

    case Op.CHAIN_HOP:
      return `${K}=${v.bxor}(${v.rrotate}(${K},${v.band}(${a},31)),${C});${pc}=${v.bxor}(${B},${v.band}(${oldK},0xFFFFF));`;

    case Op.JMPF:
      if (alt === 1) return `if ${R}[${a}]then else ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
      return `if not ${R}[${a}]then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    case Op.JMPT:
      return `if ${R}[${a}]then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    case Op.EQJ:
      return `if ${R}[${v.band}(${a},255)]~=${R}[${v.rshift}(${a},8)]then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    case Op.NEJ:
      return `if ${R}[${v.band}(${a},255)]==${R}[${v.rshift}(${a},8)]then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    case Op.LTJ:
      // Use `not (x < y)` rather than `x >= y` so IEEE-754 NaN comparisons stay 100% exact!
      return `if not(${R}[${v.band}(${a},255)]<${R}[${v.rshift}(${a},8)])then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    case Op.LEJ:
      return `if not(${R}[${v.band}(${a},255)]<=${R}[${v.rshift}(${a},8)])then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    // ── Multi-Hub Bytecode Graph CFF Handlers ──────────────────────────────
    case Op.STATE_SET:
      return `${cffState}=${v.bor}(${B},${C})-${v.band}(${B},${C});`;

    case Op.STATE_JLE:
      return `if ${cffState}<=${a} then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    case Op.STATE_JEQ:
      return `if ${cffState}==${a} then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    // ── Opaque-Predicate Forks, Live Key Mutation & Live In-VM Anti-Tamper ─
    case Op.OPQ_NEVER:
      // Mathematically false for ALL u32 (oldK, a), requires bitvector solver to prove!
      return `if ${v.bor}(${oldK},${a})<${v.bxor}(${oldK},${a})then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    case Op.OPQ_ALWAYS:
      // Mathematically true for ALL u32 (oldK, a), routes around inline bogus block!
      return `if ${v.band}(${oldK},${a})<=${v.bor}(${oldK},${a})then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;

    case Op.KEY_MUTATE:
      return `${K}=(${v.bxor}(${v.rrotate}(${K},${v.band}(${a},31)),${B})+${C})%4294967296;`;

    case Op.GUARD: {
      // Live in-VM anti-tamper line probe: adds 0 when untouched (and safe under -g0); obliterates CCFI key if formatted!
      const gl = names.next();
      return `local ${gl}=${v.dbgInfo}(1,${v.fmtL})or 0;if ${gl}>0 then ${K}=(${K}+(${gl}-${a})*${B})%4294967296 end;`;
    }

    // ── Calls, Returns, Varargs, Loops, Closures & Upvalues ────────────────
    case Op.CALL: {
      const [fn, ret, n, i] = names.many(4);
      return (
        `local ${fn}=${R}[${a}];` +
        `if ${C}==1 then ` +
        `if ${B}==1 then ${fn}()elseif ${B}==2 then ${fn}(${R}[${a}+1])elseif ${B}==3 then ${fn}(${R}[${a}+1],${R}[${a}+2])elseif ${B}==4 then ${fn}(${R}[${a}+1],${R}[${a}+2],${R}[${a}+3])elseif ${B}==0 then ${fn}(${v.tblUnpack}(${R},${a}+1,${v.top}))else ${fn}(${v.tblUnpack}(${R},${a}+1,${a}+${B}-1))end ` +
        `elseif ${C}==2 then ` +
        `if ${B}==1 then ${R}[${a}]=${fn}()elseif ${B}==2 then ${R}[${a}]=${fn}(${R}[${a}+1])elseif ${B}==3 then ${R}[${a}]=${fn}(${R}[${a}+1],${R}[${a}+2])elseif ${B}==4 then ${R}[${a}]=${fn}(${R}[${a}+1],${R}[${a}+2],${R}[${a}+3])elseif ${B}==0 then ${R}[${a}]=${fn}(${v.tblUnpack}(${R},${a}+1,${v.top}))else ${R}[${a}]=${fn}(${v.tblUnpack}(${R},${a}+1,${a}+${B}-1))end ` +
        `else local ${ret};` +
        `if ${B}==1 then ${ret}=${v.tblPack}(${fn}())elseif ${B}==2 then ${ret}=${v.tblPack}(${fn}(${R}[${a}+1]))elseif ${B}==0 then ${ret}=${v.tblPack}(${fn}(${v.tblUnpack}(${R},${a}+1,${v.top})))else ${ret}=${v.tblPack}(${fn}(${v.tblUnpack}(${R},${a}+1,${a}+${B}-1)))end;` +
        `if ${C}==0 then local ${n}=${ret}.n;${v.top}=${a}+${n}-1;for ${i}=1,${n} do ${R}[${a}+${i}-1]=${ret}[${i}]end ` +
        `else for ${i}=1,${C}-1 do ${R}[${a}+${i}-1]=${ret}[${i}]end end end;`
      );
    }

    case Op.RETURN:
      return (
        `if ${v.hasOpen} then ${v.closeUp}(0)end;` +
        `if ${B}==1 then return elseif ${B}==2 then return ${R}[${a}]elseif ${B}==3 then return ${R}[${a}],${R}[${a}+1]elseif ${B}==0 then return ${v.tblUnpack}(${R},${a},${v.top})else return ${v.tblUnpack}(${R},${a},${a}+${B}-2)end;`
      );

    case Op.VARARG: {
      const i = names.next();
      return (
        `if ${B}==0 then ${v.top}=${a}+${v.vcount}-1;for ${i}=1,${v.vcount} do ${R}[${a}+${i}-1]=${v.vargs}[${i}]end ` +
        `else for ${i}=1,${B}-1 do ${R}[${a}+${i}-1]=${v.vargs}[${i}]end end;`
      );
    }

    case Op.FORPREP: {
      const [init, lim, step] = names.many(3);
      return (
        `local ${init},${lim},${step}=${v.tonum}(${R}[${a}]),${v.tonum}(${R}[${a}+1]),${v.tonum}(${R}[${a}+2]);` +
        `${R}[${a}],${R}[${a}+1],${R}[${a}+2]=${init},${lim},${step};` +
        `if(${step}>0 and ${init}>${lim})or(${step}<=0 and ${init}<${lim})then ${pc}=${B};${K}=${v.bxor}(${K},${C})else ${R}[${a}+3]=${init} end;`
      );
    }

    case Op.FORLOOP: {
      const [step, nxt, lim] = names.many(3);
      return (
        `local ${step}=${R}[${a}+2];local ${nxt}=${R}[${a}]+${step};local ${lim}=${R}[${a}+1];` +
        `if(${step}>0 and ${nxt}<=${lim})or(${step}<=0 and ${nxt}>=${lim})then ${R}[${a}]=${nxt};${R}[${a}+3]=${nxt};${pc}=${B};${K}=${v.bxor}(${K},${C})end;`
      );
    }

    case Op.ITERPREP: {
      if (!v.kFunction) return `${pc}=${B};${K}=${v.bxor}(${K},${C});`;
      const obj = names.next();
      return (
        `local ${obj}=${R}[${a}];` +
        `if ${v.typeFn}(${obj})~=${v.kFunction} then ` +
        `if ${v.typeFn}(${obj})==${v.kTable} and ${v.getmt}(${obj})==nil then ${R}[${a}]=${v.nextFn};${R}[${a}+1]=${obj};${R}[${a}+2]=nil ` +
        `else ${R}[${a}]=${v.iterWrap}(${obj});${R}[${a}+1]=nil;${R}[${a}+2]=nil end end;` +
        `${pc}=${B};${K}=${v.bxor}(${K},${C});`
      );
    }

    case Op.TFORLOOP: {
      const [base, nv, ret, i, v1, v2] = names.many(6);
      return (
        `local ${base},${nv}=${v.band}(${a},1023),${v.rshift}(${a},10);` +
        `if ${nv}==1 then ${R}[${base}+3]=${R}[${base}](${R}[${base}+1],${R}[${base}+2])` +
        `elseif ${nv}==2 then local ${v1},${v2}=${R}[${base}](${R}[${base}+1],${R}[${base}+2]);${R}[${base}+3],${R}[${base}+4]=${v1},${v2} ` +
        `else local ${ret}=${v.tblPack}(${R}[${base}](${R}[${base}+1],${R}[${base}+2]));for ${i}=1,${nv} do ${R}[${base}+2+${i}]=${ret}[${i}]end end;` +
        `if ${R}[${base}+3]~=nil then ${R}[${base}+2]=${R}[${base}+3];${pc}=${B};${K}=${v.bxor}(${K},${C})end;`
      );
    }

    case Op.CLOSURE: {
      const [sub, uIn, uIdx, nu, childU, i, reg, cell] = names.many(8);
      return (
        `local ${sub}=${v.protos}[${B}];local ${uIn},${uIdx}=${sub}[${v.pkUpIn}],${sub}[${v.pkUpIdx}];` +
        `local ${nu}=#${uIn};local ${childU}=if ${nu}>0 then {} else nil;` +
        `for ${i}=1,${nu} do if ${uIn}[${i}]==1 then local ${reg}=${uIdx}[${i}];local ${cell}=${v.openUp}[${reg}];` +
        `if not ${cell} then ${cell}={${R},${reg}};${v.openUp}[${reg}]=${cell};${v.hasOpen}=true end;${childU}[${i}]=${cell} ` +
        `else ${childU}[${i}]=${v.upvals}[${uIdx}[${i}]]end end;` +
        `${R}[${a}]=${v.wrapProto}(${sub},${childU});`
      );
    }

    case Op.NATCLOSURE: {
      if (compiled.nativeEscapes.length === 0) return `${R}[${a}]=nil;`;
      const [childU, cell] = names.many(2);
      const branches = compiled.nativeEscapes
        .map((esc, idx) => {
          const kw = idx === 0 ? 'if' : 'elseif';
          const binds = esc.upvals
            .map((u, uIdx) => {
              if (u.inStack) {
                return `${cell}=${v.openUp}[${u.index}];if not ${cell} then ${cell}={${R},${u.index}};${v.openUp}[${u.index}]=${cell};${v.hasOpen}=true end;${childU}[${uIdx + 1}]=${cell};`;
              }
              return `${childU}[${uIdx + 1}]=${v.upvals}[${u.index}];`;
            })
            .join('');
          return `${kw} ${B}==${mba.num(esc.id, 1)} then ${binds}${R}[${a}]=${v.natTable}[${esc.id}](${childU})`;
        })
        .join('');
      return `local ${childU}={};local ${cell};${branches} end;`;
    }

    case Op.CLOSE:
      return `if ${v.hasOpen} then ${v.closeUp}(${a})end;`;

    default:
      throw new GrandfuscatorError(`No v3 runtime handler for Op.${Op[entry.logicalOp as Op] ?? entry.logicalOp}`, 'vm');
  }
}
