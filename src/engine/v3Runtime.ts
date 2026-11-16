import { emitNativeEscapeTable } from './astObfuscator.js';
import { FlatV3Image } from './v3Serializer.js';
import { Op } from './ir.js';
import { MBAEngine } from './mba.js';
import { NameGenerator } from './names.js';
import { PRNG, bit32 } from './prng.js';
import { buildSafeAlphabet85, encryptAndEncodeBase85, PhysicalOpcodeEntry, StreamCipherParams } from './serializer.js';
import { ResolvedOptions } from './types.js';

interface V {
  env: string; bxor: string; band: string; bor: string; bnot: string; lshift: string; rshift: string; lrotate: string; rrotate: string;
  bcreate: string; bu32: string; wu32: string; bu8: string; wu8: string; bi32: string; bf64: string; wf64: string; rstr: string; blen: string;
  pack: string; unpack: string; next: string; type: string; tostring: string; tonumber: string; getmt: string; rawget: string;
  vm: string; R: string; pc: string; K: string; oldK: string; top: string; cff: string; opid: string; stored: string; A: string; B: string; C: string;
  c0: string; c1: string; c2: string; u0: string; mac: string; expected: string; macdiff: string; hc: string; sbmask: string; htable: string; sbox: string;
  metas: string; run: string; desc: string; args: string; argn: string; va: string; vcount: string; up: string; open: string; hasopen: string; closeup: string;
  pending: string; fbuf: string; strbuf: string; i: string; j: string; tmp: string; tmp2: string; vals: string; base: string; nv: string; result: string; cell: string;
  iter: string; protoarg: string; alpha: string; lut: string; state: string; wi: string; acc: string; cipherWord: string; decoded: string; payload: string; off: string;
  handlerFn: string; hid: string; fn: string; readCell: string; writeCell: string; nativeTable: string;
}

function makeVars(names: NameGenerator): V {
  const n = () => names.next();
  return {
    env:n(),bxor:n(),band:n(),bor:n(),bnot:n(),lshift:n(),rshift:n(),lrotate:n(),rrotate:n(),
    bcreate:n(),bu32:n(),wu32:n(),bu8:n(),wu8:n(),bi32:n(),bf64:n(),wf64:n(),rstr:n(),blen:n(),
    pack:n(),unpack:n(),next:n(),type:n(),tostring:n(),tonumber:n(),getmt:n(),rawget:n(),
    vm:n(),R:n(),pc:n(),K:n(),oldK:n(),top:n(),cff:n(),opid:n(),stored:n(),A:n(),B:n(),C:n(),
    c0:n(),c1:n(),c2:n(),u0:n(),mac:n(),expected:n(),macdiff:n(),hc:n(),sbmask:n(),htable:n(),sbox:n(),
    metas:n(),run:n(),desc:n(),args:n(),argn:n(),va:n(),vcount:n(),up:n(),open:n(),hasopen:n(),closeup:n(),
    pending:n(),fbuf:n(),strbuf:n(),i:n(),j:n(),tmp:n(),tmp2:n(),vals:n(),base:n(),nv:n(),result:n(),cell:n(),
    iter:n(),protoarg:n(),alpha:n(),lut:n(),state:n(),wi:n(),acc:n(),cipherWord:n(),decoded:n(),payload:n(),off:n(),
    handlerFn:n(),hid:n(),fn:n(),readCell:n(),writeCell:n(),nativeTable:n(),
  };
}

function handler(entry: PhysicalOpcodeEntry, v: V, names: NameGenerator, image: FlatV3Image): string {
  const { R, A, B, C, pc, K, oldK, cff } = { R:v.R,A:v.A,B:v.B,C:v.C,pc:v.pc,K:v.K,oldK:v.oldK,cff:v.cff };
  const N = () => names.next();
  const op = entry.logicalOp;
  if (op === 'DECOY') {
    const t=N();
    switch (entry.variantIdx % 4) {
      case 0: return `${R}[${A}]=${v.bor}(${B},${C})-${v.band}(${B},${C});`;
      case 1: return `${cff}=${v.bxor}(${cff},${B});`;
      case 2: return `if ${R}[${A}]~=nil then ${R}[${A}]=${R}[${A}] end;`;
      default: return `local ${t}=${v.band}(${B},255);${R}[${A}]=${t};`;
    }
  }
  switch (op) {
    case Op.MOVE: return `${R}[${A}]=${R}[${B}];`;
    case Op.MOVE2: return `${R}[${v.band}(${A},255)]=${R}[${B}];${R}[${v.rshift}(${A},8)]=${R}[${C}];`;
    case Op.LOADK: return `error("unlowered LOADK in v3 image")`;
    case Op.LOADINT: return `${R}[${A}]=if ${B}>=2147483648 then ${B}-4294967296 else ${B};`;
    case Op.LOADNIL: { const i=N(); return `for ${i}=${A},${B} do ${R}[${i}]=nil end;`; }
    case Op.LOADBOOL: return `${R}[${A}]=(${B}~=0);`;
    case Op.GETGLOBAL: return `${R}[${A}]=${v.env}[${R}[${B}]];`;
    case Op.SETGLOBAL: return `${v.env}[${R}[${B}]]=${R}[${A}];`;
    case Op.GETUPVAL: return `${R}[${A}]=${v.readCell}(${v.up}[${B}]);`;
    case Op.SETUPVAL: return `${v.writeCell}(${v.up}[${B}],${R}[${A}]);`;
    case Op.NEWTABLE: return `${R}[${A}]={};`;
    case Op.GETTABLE: return `${R}[${A}]=${R}[${B}][${R}[${C}]];`;
    case Op.GETTABLE_SWP: return `${R}[${A}]=${R}[${C}][${R}[${B}]];`;
    case Op.GETTABLEK: return `error("unlowered GETTABLEK in v3 image")`;
    case Op.SETTABLE: return `${R}[${A}][${R}[${B}]]=${R}[${C}];`;
    case Op.SETTABLE_SWP: return `${R}[${A}][${R}[${C}]]=${R}[${B}];`;
    case Op.SETTABLEK: return `error("unlowered SETTABLEK in v3 image")`;
    case Op.SETLIST: { const t=N(),c=N(),i=N(); return `local ${t}=${R}[${A}];local ${c}=if ${B}==0 then ${v.top}-${A} else ${B};for ${i}=1,${c} do ${t}[${C}+${i}]=${R}[${A}+${i}]end;`; }
    case Op.SELF: return `${R}[${A}+1]=${R}[${B}];${R}[${A}]=${R}[${B}][${R}[${C}]];`;
    case Op.ADD: case Op.ADD_SWP: return `${R}[${A}]=${R}[${B}]+${R}[${C}];`;
    case Op.SUB: return `${R}[${A}]=${R}[${B}]-${R}[${C}];`;
    case Op.SUB_REV: return `${R}[${A}]=${R}[${C}]-${R}[${B}];`;
    case Op.MUL: case Op.MUL_SWP: return `${R}[${A}]=${R}[${B}]*${R}[${C}];`;
    case Op.DIV: return `${R}[${A}]=${R}[${B}]/${R}[${C}];`;
    case Op.DIV_REV: return `${R}[${A}]=${R}[${C}]/${R}[${B}];`;
    case Op.IDIV: return `${R}[${A}]=${R}[${B}]//${R}[${C}];`;
    case Op.IDIV_REV: return `${R}[${A}]=${R}[${C}]//${R}[${B}];`;
    case Op.MOD: return `${R}[${A}]=${R}[${B}]%${R}[${C}];`;
    case Op.POW: return `${R}[${A}]=${R}[${B}]^${R}[${C}];`;
    case Op.UNM: return `${R}[${A}]=-${R}[${B}];`;
    case Op.NOT: return `${R}[${A}]=not ${R}[${B}];`;
    case Op.LEN: return `${R}[${A}]=#${R}[${B}];`;
    case Op.CONCAT: { const acc=N(),i=N(); return `local ${acc}=${R}[${C}];for ${i}=${C}-1,${B},-1 do ${acc}=${R}[${i}]..${acc} end;${R}[${A}]=${acc};`; }
    case Op.TOSTRING: return `${R}[${A}]=${v.tostring}(${R}[${B}]);`;
    case Op.VM_MBA_XOR: return `${R}[${A}]=${v.bor}(${B},${C})-${v.band}(${B},${C});`;
    case Op.VM_MBA_ADD: return `${R}[${A}]=${v.bxor}(${B},${C})+2*${v.band}(${B},${C});`;
    case Op.VM_MBA_NEG: return `${R}[${A}]=-(${v.bor}(${B},${C})-${v.band}(${B},${C}));`;
    case Op.LOADF64: return `${v.wu32}(${v.fbuf},0,${B});${v.wu32}(${v.fbuf},4,${C});${R}[${A}]=${v.bf64}(${v.fbuf},0);`;
    case Op.SNEW: return `${R}[${A}]=${v.bcreate}(${B});`;
    case Op.SADD4_XOR: { const o=N(),k=N(); return `local ${o}=${v.band}(${C},255);local ${k}=${v.rshift}(${C},8);${v.wu32}(${R}[${A}],${o},${v.bxor}(${B},${v.lrotate}(${k},5)));`; }
    case Op.SADD4_ADD: { const o=N(),k=N(); return `local ${o}=${v.band}(${C},255);local ${k}=${v.rshift}(${C},8);${v.wu32}(${R}[${A}],${o},(${B}+${k})%4294967296);`; }
    case Op.SADD4_SUB: { const o=N(),k=N(); return `local ${o}=${v.band}(${C},255);local ${k}=${v.rshift}(${C},8);${v.wu32}(${R}[${A}],${o},(${B}-${k})%4294967296);`; }
    case Op.SFIN: { const t=N(),i=N(); return `local ${t}=${R}[${A}];${R}[${A}]=${v.rstr}(${t},${B},${C});for ${i}=0,${v.blen}(${t})-1 do ${v.wu8}(${t},${i},0)end;`; }
    case Op.SBLK: {
      const length=N(), out=N(), i=N(), wi=N(), ew=N(), pw=N();
      return `local ${length}=${v.bxor}(${v.bu32}(${v.vm},${B}*12),${v.lrotate}(${C},3));local ${out}=${v.bcreate}(${length});`+
        `for ${i}=0,${length}-1 do local ${wi}=1+math.floor(${i}/4);local ${ew}=${v.bu32}(${v.vm},(${B}+${wi})*12);local ${pw}=${v.bxor}(${ew},${v.lrotate}(${C},(${wi}*7+3)%32));`+
        `${v.wu8}(${out},${i},${v.band}(${v.rshift}(${pw},(${i}%4)*8),255))end;${R}[${A}]=${v.rstr}(${out},0,${length});for ${i}=0,${length}-1 do ${v.wu8}(${out},${i},0)end;`;
    }
    case Op.EQ: return `${R}[${A}]=(${R}[${B}]==${R}[${C}]);`;
    case Op.NE: return `${R}[${A}]=(${R}[${B}]~=${R}[${C}]);`;
    case Op.LT: return `${R}[${A}]=(${R}[${B}]<${R}[${C}]);`;
    case Op.LT_REV: return `${R}[${A}]=(${R}[${C}]<${R}[${B}]);`;
    case Op.LE: return `${R}[${A}]=(${R}[${B}]<=${R}[${C}]);`;
    case Op.LE_REV: return `${R}[${A}]=(${R}[${C}]<=${R}[${B}]);`;
    case Op.JMP: case Op.JMPX: return `${pc}=${v.bxor}(${B},${v.band}(${oldK},0xFFFFF));${K}=${v.bxor}(${K},${C});`;
    case Op.CHAIN_HOP: return `${K}=${v.bxor}(${v.lrotate}(${K},${v.band}(${A},31)),${C});${pc}=${v.bxor}(${B},${v.band}(${oldK},0xFFFFF));`;
    case Op.JMPF: return `if not ${R}[${A}] then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.JMPT: return `if ${R}[${A}] then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.EQJ: return `if ${R}[${v.band}(${A},255)]~=${R}[${v.rshift}(${A},8)] then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.NEJ: return `if ${R}[${v.band}(${A},255)]==${R}[${v.rshift}(${A},8)] then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.LTJ: return `if not(${R}[${v.band}(${A},255)]<${R}[${v.rshift}(${A},8)]) then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.LEJ: return `if not(${R}[${v.band}(${A},255)]<=${R}[${v.rshift}(${A},8)]) then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.STATE_SET: return `${cff}=${v.bor}(${B},${C})-${v.band}(${B},${C});`;
    case Op.STATE_JLE: return `if ${cff}<=${A} then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.STATE_JEQ: return `if ${cff}==${A} then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.OPQ_NEVER: return `if ${v.bor}(${oldK},${A})<${v.bxor}(${oldK},${A}) then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.OPQ_ALWAYS: return `if ${v.band}(${oldK},${A})<=${v.bor}(${oldK},${A}) then ${pc}=${B};${K}=${v.bxor}(${K},${C})end;`;
    case Op.KEY_MUTATE: return `${K}=(${v.bxor}(${v.lrotate}(${K},${v.band}(${A},31)),${B})+${C})%4294967296;`;
    // Debug line metadata is not stable across Luau -g0 / production optimization.
    // GUARD therefore checks only a structural invariant, never source-line state.
    case Op.GUARD: return `if ${v.blen}(${v.vm})~=${image.vmemBytes.length} then ${K}=(${K}+${B})%4294967296 end;`;
    case Op.AT_CHECK: { const ok=N(); return `if ${A}==2 then local ${ok}=(${v.blen}(${v.vm})==${B});if not ${ok} then ${K}=(${K}+${C})%4294967296 end end;`; }
    case Op.CHAFF_ENV: return `${v.rawget}(${v.env},${R}[${B}]);${R}[${B}]=nil;`;
    case Op.CALL: {
      const fn=N(),endarg=N(),results=N(),i=N();
      return `local ${fn}=${R}[${A}];local ${endarg}=if ${B}==0 then ${v.top} else ${A}+${B}-1;local ${results}=${v.pack}(${fn}(${v.unpack}(${R},${A}+1,${endarg})));`+
        `if ${C}==0 then ${v.top}=${A}+${results}.n-1;for ${i}=1,${results}.n do ${R}[${A}+${i}-1]=${results}[${i}]end `+
        `elseif ${C}>1 then for ${i}=1,${C}-1 do ${R}[${A}+${i}-1]=${results}[${i}]end end;`;
    }
    case Op.RETURN: {
      const end=N();
      return `if ${v.hasopen} then ${v.closeup}(0)end;if ${B}==1 then return elseif ${B}==0 then return ${v.unpack}(${R},${A},${v.top}) else local ${end}=${A}+${B}-2;return ${v.unpack}(${R},${A},${end})end;`;
    }
    case Op.VARARG: { const i=N(); return `if ${B}==0 then ${v.top}=${A}+${v.vcount}-1;for ${i}=1,${v.vcount} do ${R}[${A}+${i}-1]=${v.va}[${i}]end else for ${i}=1,${B}-1 do ${R}[${A}+${i}-1]=${v.va}[${i}]end end;`; }
    case Op.FORPREP: { const init=N(),lim=N(),step=N(); return `local ${init},${lim},${step}=${v.tonumber}(${R}[${A}]),${v.tonumber}(${R}[${A}+1]),${v.tonumber}(${R}[${A}+2]);${R}[${A}],${R}[${A}+1],${R}[${A}+2]=${init},${lim},${step};if(${step}>0 and ${init}>${lim})or(${step}<=0 and ${init}<${lim}) then ${pc}=${B};${K}=${v.bxor}(${K},${C}) else ${R}[${A}+3]=${init} end;`; }
    case Op.FORLOOP: { const step=N(),nxt=N(),lim=N(); return `local ${step}=${R}[${A}+2];local ${nxt}=${R}[${A}]+${step};local ${lim}=${R}[${A}+1];if(${step}>0 and ${nxt}<=${lim})or(${step}<=0 and ${nxt}>=${lim}) then ${R}[${A}]=${nxt};${R}[${A}+3]=${nxt};${pc}=${B};${K}=${v.bxor}(${K},${C})end;`; }
    case Op.ITERPREP: { const obj=N(),mt=N(),fn=N(); return `local ${obj}=${R}[${A}];if ${v.type}(${obj})=="table" and ${v.getmt}(${obj})==nil then ${R}[${A}]=${v.next};${R}[${A}+1]=${obj};${R}[${A}+2]=nil else local ${mt}=${v.getmt}(${obj});local ${fn}=${mt} and ${mt}.__iter;if ${fn} then ${R}[${A}]=${fn}(${obj});${R}[${A}+1]=nil;${R}[${A}+2]=nil end end;${pc}=${v.bxor}(${B},${v.band}(${oldK},0xFFFFF));${K}=${v.bxor}(${K},${C});`; }
    case Op.TFORLOOP: { const base=N(),nv=N(),pack=N(),i=N(); return `local ${base},${nv}=${v.band}(${A},1023),${v.rshift}(${A},10);local ${pack}=${v.pack}(${R}[${base}](${R}[${base}+1],${R}[${base}+2]));for ${i}=1,${nv} do ${R}[${base}+2+${i}]=${pack}[${i}]end;if ${R}[${base}+3]~=nil then ${R}[${base}+2]=${R}[${base}+3];${pc}=${B};${K}=${v.bxor}(${K},${C})end;`; }
    case Op.CLOSURE: return `error("unlowered CLOSURE in v3 image")`;
    case Op.CLOS_UP: { const cell=N(),reg=N(); return `local ${cell};if ${B}~=0 then local ${reg}=${C};${cell}=${v.open}[${reg}];if not ${cell} then ${cell}={${R},${reg}};${v.open}[${reg}]=${cell};${v.hasopen}=true end else ${cell}=${v.up}[${C}]end;${v.pending}[${A}+1]=${cell};`; }
    case Op.CLOS_EXT: return `do end;`;
    case Op.CLOS_NEW: { const dst=N(),entrypc=N(),captures=N(),key=N(); return `local ${dst}=${v.band}(${A},1023);local ${entrypc}=${v.bxor}(${B},${v.band}(${oldK},0xFFFFF));local ${key}=${C};local ${captures}=${v.pending};${v.pending}={};${R}[${dst}]=function(...)return ${v.run}(${entrypc},${key},${v.pack}(...),${captures})end;`; }
    case Op.NATCLOSURE: {
      const caps=N(),cell=N();
      const cases=image.nativeEscapes.map((escape,idx)=>{
        const bind=escape.upvals.map((u,uIdx)=>u.inStack
          ? `local ${cell}=${v.open}[${u.index}];if not ${cell} then ${cell}={${R},${u.index}};${v.open}[${u.index}]=${cell};${v.hasopen}=true end;${caps}[${uIdx+1}]=${cell};`
          : `${caps}[${uIdx+1}]=${v.up}[${u.index}];`).join('');
        return `${idx===0?'if':'elseif'} ${B}==${escape.id} then local ${caps}={};${bind}${R}[${A}]=${v.nativeTable}[${escape.id}](${caps})`;
      }).join('');
      return cases ? `${cases} else error("bad native escape id")end;` : `${R}[${A}]=nil;`;
    }
    case Op.CLOSE: return `if ${v.hasopen} then ${v.closeup}(${A})end;`;
    default: throw new Error(`No v3 runtime handler implemented for Op.${Op[op as Op] ?? String(op)}`);
  }
}

function emitDispatch(entries: PhysicalOpcodeEntry[], v: V, names: NameGenerator, image: FlatV3Image): string {
  return entries.map((entry,idx)=>`${idx===0?'if':'elseif'} ${v.hid}==${entry.physId} then ${handler(entry,v,names,image)}`).join('')+
    `else error("invalid v3 handler id")end;`;
}

function handlerTable(entries: PhysicalOpcodeEntry[], image: FlatV3Image): string {
  const rows = entries.map((entry)=>{
    const h=image.cipher.handlers[entry.physId];
    if (!h) throw new Error(`Missing private cipher for physical handler ${entry.physId}`);
    return `[${entry.physId}]={${h.rotB},${h.addB},${h.rotC},${h.addC},${h.hRot},${h.hXor},${h.hAdd}}`;
  });
  return `{${rows.join(',')}}`;
}

function protoTable(image: FlatV3Image): string {
  return `{${image.protoDescriptors.map((p)=>`[${p.entryPC}]={${p.numParams},${p.isVararg?1:0},${p.maxStack},${p.upvals.length}}`).join(',')}}`;
}

/** Generate a one-line, standalone Luau executor for the encoded flat image. */
export function generateFlatV3Runtime(image: FlatV3Image, opts: ResolvedOptions, rng: PRNG): string {
  const names = new NameGenerator(rng, opts.nameStyle);
  const v = makeVars(names);
  const helperNames = { bxor:v.bxor, band:v.band, bor:v.bor, bnot:v.bnot, rrotate:v.rrotate };
  const mba = new MBAEngine(rng, helperNames, opts.mbaDepth);

  const alphabet=buildSafeAlphabet85(rng);
  const streamParams:StreamCipherParams={
    masterKey:rng.nextU32()||0x7f4a7c15,
    stepConst:rng.oddInt(0x010001,0x3fffffff),
    rot1:rng.int(5,13),
    rot2:rng.int(17,27),
    alphabet,
  };
  const payload=encryptAndEncodeBase85(image.vmemBytes,streamParams,rng);

  const cFuncs = `local ${v.bxor},${v.band},${v.bor},${v.bnot},${v.lshift},${v.rshift},${v.lrotate},${v.rrotate}=bit32.bxor,bit32.band,bit32.bor,bit32.bnot,bit32.lshift,bit32.rshift,bit32.lrotate,bit32.rrotate;`;
  const bufferFuncs = `local ${v.bcreate},${v.bu32},${v.wu32},${v.bu8},${v.wu8},${v.bi32},${v.bf64},${v.wf64},${v.rstr},${v.blen}=buffer.create,buffer.readu32,buffer.writeu32,buffer.readu8,buffer.writeu8,buffer.readi32,buffer.readf64,buffer.writef64,buffer.readstring,buffer.len;`;
  const coreFuncs = `local ${v.pack},${v.unpack},${v.next},${v.type},${v.tostring},${v.tonumber},${v.getmt},${v.rawget}=table.pack,table.unpack,next,type,tostring,tonumber,getmetatable,rawget;local ${v.env}=getfenv();`;

  const dec = names.many(12);
  const [alpha,lut,di,base,d0,d1,d2,d3,d4,cw,plain,state]=dec;
  const pDecode = `local ${v.vm}=${v.bcreate}(${payload.rawLength});local ${alpha}="${alphabet}";local ${lut}={};for ${di}=1,85 do ${lut}[string.byte(${alpha},${di})]=${di}-1 end;local ${state}=${streamParams.masterKey};`+
    `for ${base}=0,${payload.wordCount}-1 do local ${di}=${base}*5+1;local ${d0},${d1},${d2},${d3},${d4}=${lut}[string.byte("${payload.encoded}",${di})],${lut}[string.byte("${payload.encoded}",${di}+1)],${lut}[string.byte("${payload.encoded}",${di}+2)],${lut}[string.byte("${payload.encoded}",${di}+3)],${lut}[string.byte("${payload.encoded}",${di}+4)];`+
    `local ${cw}=${d0}+${d1}*85+${d2}*7225+${d3}*614125+${d4}*52200625;local ${plain}=${v.bxor}(${cw},${state});${v.wu32}(${v.vm},${base}*4,${plain});`+
    `${state}=${v.bxor}(${v.rrotate}(${state},${streamParams.rot1}),${cw});${state}=(${state}+${streamParams.stepConst})%4294967296;${state}=${v.bxor}(${state},${v.rrotate}(${cw},${streamParams.rot2}))end;`;

  const sboxLiteral=`{${Array.from(image.cipher.sbox).join(',')}}`;
  const cipherRows=handlerTable(image.dispatchTable,image);
  const protoRows=protoTable(image);
  const metaLocal=`local ${v.metas}=${protoRows};local ${v.htable}=${cipherRows};local ${v.sbox}=${sboxLiteral};`;

  const cells=`local function ${v.readCell}(${v.cell})if ${v.cell}[1] then return ${v.cell}[1][${v.cell}[2]]end;return ${v.cell}[3]end;local function ${v.writeCell}(${v.cell},${v.tmp})if ${v.cell}[1] then ${v.cell}[1][${v.cell}[2]]=${v.tmp} else ${v.cell}[3]=${v.tmp} end end;`;

  const native=emitNativeEscapeTable(image.nativeEscapes,opts,rng,names,mba,v.env,v.tostring,{
    bxor:v.bxor,band:v.band,rrotate:v.rrotate,bufCreate:v.bcreate,bufWriteU32:v.wu32,bufReadU8:v.bu8,bufWriteU8:v.wu8,bufReadStr:v.rstr,strByte:'string.byte',
  });
  v.nativeTable=native.tableVar;
  const dispatch=emitDispatch(image.dispatchTable,v,names,image);
  const fbuf=`local ${v.fbuf}=${v.bcreate}(8);`;
  const nestedNames=names.many(18);
  const [rdesc,rargs,rargn,rparams,rvar,rup,rR,rTop,rVA,rVC,rOpen,rPending,rPc,rK,rCff,rI,rCloseMin,rKeep]=nestedNames;
  const protoCall=`local ${v.run};${v.run}=function(${v.pc},${v.K},${v.args},${v.up})`+
    `local ${v.desc}=${v.metas}[${v.pc}];if not ${v.desc} then error("invalid flat proto entry")end;`+
    `local ${v.R}={};for ${v.i}=1,${v.desc}[1] do ${v.R}[${v.i}-1]=${v.args}[${v.i}]end;`+
    `local ${v.va},${v.vcount}={},0;if ${v.desc}[2]~=0 then ${v.vcount}=${v.args}.n-${v.desc}[1];if ${v.vcount}<0 then ${v.vcount}=0 else for ${v.i}=1,${v.vcount} do ${v.va}[${v.i}]=${v.args}[${v.desc}[1]+${v.i}]end end end;`+
    `local ${v.top},${v.cff}=-1,0;local ${v.open},${v.hasopen},${v.pending}={},false,{};`+
    `local function ${v.closeup}(${rCloseMin})local ${rKeep}=false;for ${v.i},${v.cell} in ${v.next},${v.open} do if ${v.i}>=${rCloseMin} then ${v.cell}[3]=${v.cell}[1][${v.cell}[2]];${v.cell}[1]=nil;${v.cell}[2]=nil;${v.open}[${v.i}]=nil else ${rKeep}=true end end;${v.hasopen}=${rKeep} end;`+
    `while true do if ${v.pc}<0 or ${v.pc}>=${image.slotCount} then error("flat pc out of range")end;local ${v.oldK}=${v.K};local ${v.off}=${v.pc}*12;`+
    `local ${v.c0}=${v.bu32}(${v.vm},${v.off}+${image.wordOffsets[0]});local ${v.c1}=${v.bu32}(${v.vm},${v.off}+${image.wordOffsets[1]});local ${v.c2}=${v.bu32}(${v.vm},${v.off}+${image.wordOffsets[2]});`+
    `local ${v.u0}=${v.bxor}(${v.c0},${v.oldK});local ${v.stored}=${v.band}(${v.u0},255);local ${v.A}=${v.band}(${v.rshift}(${v.u0},8),65535);local ${v.mac}=${v.rshift}(${v.u0},24);`+
    `local ${v.expected}=${v.band}(${v.bxor}(${v.bxor}(${v.stored}*${image.cipher.macP1},${v.A}*${image.cipher.macP2}),${v.bxor}(${v.band}(${v.c1},65535),${v.rshift}(${v.oldK},16))),255);local ${v.macdiff}=${v.bxor}(${v.mac},${v.expected});`+
    `${v.K}=(${v.bxor}(${v.rrotate}(${v.oldK},${image.cipher.ratchetRot}),${v.c0})+${image.cipher.ratchetStep}+${v.macdiff}*${image.cipher.macPoison})%4294967296;`+
    `local ${v.hid}=${v.bxor}(${v.stored},if ${v.band}(${v.oldK},1)~=0 then ${image.cipher.keyParityMask} else 0);local ${v.hc}=${v.htable}[${v.hid}];if not ${v.hc} then error("invalid physical handler "..${v.tostring}(${v.hid}).."/"..${v.tostring}(${v.stored}))end;`+
    `local ${v.sbmask}=${v.sbox}[${v.stored}+1]*16843009;local ${v.B}=${v.bxor}(${v.bxor}(${v.rrotate}((${v.c1}-${v.hc}[2])%4294967296,${v.hc}[1]),${v.oldK}),${v.sbmask});`+
    `local ${v.C}=${v.bxor}(${v.bxor}(${v.rrotate}((${v.c2}-${v.hc}[4])%4294967296,${v.hc}[3]),${v.oldK}),${v.sbmask});`+
    `${v.K}=(${v.bxor}(${v.lrotate}(${v.K},${v.hc}[5]),${v.hc}[6])+${v.hc}[7])%4294967296;${v.pc}+=1;${dispatch} end end;`;

  const code=`${opts.watermark?`-- ${opts.watermark}\n`:''}${cFuncs}${bufferFuncs}${coreFuncs}${pDecode}${metaLocal}${cells}${fbuf}${native.code}${protoCall} return ${v.run}(${image.rootEntryPC},${image.rootEntryKey},${v.pack}(),{});`;
  return code;
}
