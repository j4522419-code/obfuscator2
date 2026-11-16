import {
  createFlatCipherSpec,
  deriveSBox,
  encodeFlatVMemCCFI,
  FlatCipherSpec,
} from './cfgEngine.js';
import { CompiledModule, FlatVMemImage, IRProto, Op, HOT_OPS } from './ir.js';
import { PhysicalOpcodeEntry } from './serializer.js';
import { PRNG } from './prng.js';
import { ResolvedOptions } from './types.js';

export interface FlatProtoDescriptor {
  entryPC: number;
  numParams: number;
  isVararg: boolean;
  maxStack: number;
  upvals: Array<{ inStack: boolean; index: number }>;
}

/** Serialized v3 payload and its out-of-band execution header. */
export interface FlatV3Image {
  format: 'grandfuscator-flat-vmem-v3';
  vmemBytes: Uint8Array;
  slotCount: number;
  /** 1 = encrypted instruction, 0 = inline data slot. Not embedded in vmem. */
  slotKinds: Uint8Array;
  rootEntryPC: number;
  rootEntryKey: number;
  wordOffsets: [number, number, number];
  masterKey: number;
  cipher: FlatCipherSpec;
  dispatchTable: PhysicalOpcodeEntry[];
  protoDescriptors: FlatProtoDescriptor[];
  nativeEscapes: CompiledModule['nativeEscapes'];
  stats: {
    realHandlers: number;
    decoyHandlers: number;
    codeSlots: number;
    dataSlots: number;
    protoDescriptors: number;
  };
}

function collectProtoDescriptors(root: IRProto): FlatProtoDescriptor[] {
  const out: FlatProtoDescriptor[] = [];
  const visit = (proto: IRProto): void => {
    out.push({
      entryPC: proto.entryPC,
      numParams: proto.numParams,
      isVararg: proto.isVararg,
      maxStack: proto.maxStack,
      upvals: proto.upvals.map(({ inStack, index }) => ({ inStack, index })),
    });
    for (const child of proto.protos) visit(child);
  };
  visit(root);
  out.sort((a, b) => a.entryPC - b.entryPC);
  return out;
}

function makeHandlerMap(
  mod: CompiledModule,
  opts: ResolvedOptions,
  rng: PRNG,
  cipher: FlatCipherSpec,
): { aliases: Map<Op, number[]>; dispatchTable: PhysicalOpcodeEntry[] } {
  const ops = rng.shuffle(Array.from(mod.allUsedOps));
  const ids = rng.shuffle(Array.from({ length: 256 }, (_, id) => id));
  const aliases = new Map<Op, number[]>();
  const dispatchTable: PhysicalOpcodeEntry[] = [];
  let cursor = 0;

  const maxReal = Math.max(ops.length, 252 - opts.decoyHandlers);
  for (const op of ops) {
    const id = ids[cursor++];
    aliases.set(op, [id]);
    dispatchTable.push({ physId: id, logicalOp: op, variantIdx: 0, decoySeed: rng.nextU32() });
  }

  if (opts.opcodeDuplication >= 2) {
    for (const op of ops) {
      const targetCopies = opts.opcodeDuplication >= 3
        ? (HOT_OPS.has(op) ? 3 : 2)
        : (HOT_OPS.has(op) ? 2 : 1);
      const list = aliases.get(op)!;
      while (list.length < targetCopies && cursor < maxReal) {
        const id = ids[cursor++];
        const variantIdx = list.length;
        list.push(id);
        dispatchTable.push({ physId: id, logicalOp: op, variantIdx, decoySeed: rng.nextU32() });
      }
    }
  }

  const realHandlers = dispatchTable.length;
  const decoyCount = Math.min(opts.decoyHandlers, Math.max(0, 255 - cursor));
  for (let d = 0; d < decoyCount; d++) {
    const id = ids[cursor++];
    dispatchTable.push({ physId: id, logicalOp: 'DECOY', variantIdx: d % 7, decoySeed: rng.nextU32() });
  }

  for (const entry of dispatchTable) {
    cipher.handlers[entry.physId] = {
      rotB: rng.int(1, 31),
      addB: rng.nextU32(),
      rotC: rng.int(1, 31),
      addC: rng.nextU32(),
      hRot: rng.int(1, 31),
      hXor: rng.nextU32(),
      hAdd: rng.nextU32(),
    };
  }

  // IDs are unique even after alias duplication; sorting gives the runtime a compact search table.
  dispatchTable.sort((a, b) => a.physId - b.physId);
  return { aliases, dispatchTable };
}

function writeU32LE(dst: Uint8Array, offset: number, value: number): void {
  const n = value >>> 0;
  dst[offset] = n & 0xff;
  dst[offset + 1] = (n >>> 8) & 0xff;
  dst[offset + 2] = (n >>> 16) & 0xff;
  dst[offset + 3] = (n >>> 24) & 0xff;
}

/**
 * Assign per-handler ciphers, run the v3 flat CCFI encoder/proof checks, and serialize
 * the complete flat image as 12-byte little-endian slots plus an out-of-band header.
 */
export function serializeFlatV3Image(
  mod: CompiledModule,
  opts: ResolvedOptions,
  rng: PRNG,
): FlatV3Image {
  const vmem: FlatVMemImage | undefined = mod.vmem;
  if (!vmem) throw new Error('serializeFlatV3Image requires a v3 flat-vmem layout');

  const masterKey = rng.nextU32() || 0x9e3779b9;
  const cipher = createFlatCipherSpec(rng, deriveSBox(masterKey));
  const { aliases, dispatchTable } = makeHandlerMap(mod, opts, rng, cipher);
  encodeFlatVMemCCFI(mod, aliases, cipher, rng);

  const slotKinds = new Uint8Array(vmem.totalSlots);
  const vmemBytes = new Uint8Array(vmem.totalSlots * 12);
  let codeSlots = 0;
  let dataSlots = 0;
  for (let pc = 0; pc < vmem.totalSlots; pc++) {
    const outOff = pc * 12;
    const encoded = vmem.encodedSlots?.[pc];
    if (encoded) {
      slotKinds[pc] = 1;
      codeSlots++;
      writeU32LE(vmemBytes, outOff, encoded[0]);
      writeU32LE(vmemBytes, outOff + 4, encoded[1]);
      writeU32LE(vmemBytes, outOff + 8, encoded[2]);
    } else {
      slotKinds[pc] = 0;
      dataSlots++;
      const words = vmem.dataSlotWords?.get(pc);
      if (!words) throw new Error(`Missing raw data words for flat vmem slot ${pc}`);
      writeU32LE(vmemBytes, outOff, words[0]);
      writeU32LE(vmemBytes, outOff + 4, words[1]);
      writeU32LE(vmemBytes, outOff + 8, words[2]);
    }
  }

  if (vmem.rootEntryPC < 0 || vmem.rootEntryPC >= vmem.totalSlots || slotKinds[vmem.rootEntryPC] !== 1) {
    throw new Error('Flat vmem root entry does not point to an instruction slot');
  }
  const protoDescriptors = collectProtoDescriptors(mod.root);
  if (protoDescriptors.length !== mod.totalProtos) {
    throw new Error(`Flat proto descriptor count mismatch (${protoDescriptors.length} != ${mod.totalProtos})`);
  }

  return {
    format: 'grandfuscator-flat-vmem-v3',
    vmemBytes,
    slotCount: vmem.totalSlots,
    slotKinds,
    rootEntryPC: vmem.rootEntryPC,
    rootEntryKey: vmem.rootEntryKey >>> 0,
    wordOffsets: [...cipher.wordOffsets] as [number, number, number],
    masterKey,
    cipher,
    dispatchTable,
    protoDescriptors,
    nativeEscapes: mod.nativeEscapes,
    stats: {
      realHandlers: dispatchTable.filter((entry) => entry.logicalOp !== 'DECOY').length,
      decoyHandlers: dispatchTable.filter((entry) => entry.logicalOp === 'DECOY').length,
      codeSlots,
      dataSlots,
      protoDescriptors: protoDescriptors.length,
    },
  };
}
