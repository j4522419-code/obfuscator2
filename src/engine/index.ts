import { compileChunk } from './compiler.js';
import { parseLuau } from './parser.js';
import { PRNG } from './prng.js';
import {
  GrandfuscatorError,
  ObfuscationOptions,
  ObfuscationResult,
  ObfuscationStats,
  resolveOptions,
} from './types.js';
import { verifyLuauSyntax } from './verifier.js';
import { generatePolymorphicVM } from './vmGenerator.js';
import { buildFlatV3Image } from './v3Compiler.js';
import { generateFlatV3Runtime } from './v3Runtime.js';

export * from './types.js';
export { verifyLuauSyntax, executeLuau, findLuauCompiler, findLuauRuntime } from './verifier.js';
export { compileFlatV3IR, buildFlatV3Image } from './v3Compiler.js';

const MAX_SOURCE_BYTES = 750_000;
export const ENGINE_VERSION = '2.1.0';

export function obfuscate(source: string, rawOptions: ObfuscationOptions = {}): ObfuscationResult {
  const t0 = performance.now();

  if (typeof source !== 'string') {
    throw new GrandfuscatorError('Input source must be a string', 'options');
  }
  const inputBytes = Buffer.byteLength(source, 'utf8');
  if (inputBytes === 0 || !source.trim()) {
    throw new GrandfuscatorError('Input Luau script is empty', 'options');
  }
  if (inputBytes > MAX_SOURCE_BYTES) {
    throw new GrandfuscatorError(
      `Input script exceeds maximum size (${Math.round(inputBytes / 1024)} KB > ${Math.round(MAX_SOURCE_BYTES / 1024)} KB)`,
      'options',
    );
  }

  const opts = resolveOptions(rawOptions);
  const rng = new PRNG(opts.seed);
  if (opts.runtime === 'v3-experimental') {
    if (opts.robloxLock || opts.placeIds.length > 0 || opts.gameIds.length > 0) {
      throw new GrandfuscatorError(
        'Roblox engine locks and PlaceId/GameId locks are not implemented by the v3 flat runtime.',
        'options',
      );
    }
    const { compiled, image } = buildFlatV3Image(source, opts, rng);
    const code = generateFlatV3Runtime(image, opts, rng);
    let verified = true;
    let verifierEngine: ObfuscationStats['verifierEngine'] = 'skipped';
    if (opts.verify) {
      const verification = verifyLuauSyntax(code);
      verified = verification.ok;
      verifierEngine = verification.engine;
      if (!verification.ok) {
        throw new GrandfuscatorError(
          `Generated v3 flat runtime failed Luau bytecode verification: ${verification.error}`,
          'verifier',
        );
      }
    }

    const outputBytes = Buffer.byteLength(code, 'utf8');
    const cfg = compiled.cfgStats;
    const slotNames = ['C0', 'C1', 'C2'];
    const orderedSlots: string[] = ['', '', ''];
    image.wordOffsets.forEach((byteOff, idx) => {
      orderedSlots[byteOff >> 2] = slotNames[idx];
    });
    const stats: ObfuscationStats = {
      buildId: rng.buildId,
      engineVersion: ENGINE_VERSION,
      architecture: 'Oblivion S-Box Interleaved Flat-VM',
      loadstringUsed: false,
      zeroConstantPool: true,
      zeroStringTable: true,
      preset: opts.preset,
      inputBytes,
      outputBytes,
      bytecodeBytes: image.vmemBytes.length,
      sizeRatio: Math.round((outputBytes / Math.max(1, inputBytes)) * 100) / 100,
      compileTimeMs: Math.round((performance.now() - t0) * 100) / 100,
      vmProtos: image.stats.protoDescriptors,
      decoyProtos: 0,
      vmInstructions: compiled.totalInstructions,
      physicalOpcodes: image.stats.realHandlers,
      decoyOpcodes: image.stats.decoyHandlers,
      perHandlerCiphers: image.dispatchTable.length,
      fusedSuperinstructions: cfg.fusedSuperinstructions,
      mutatedInstructions: cfg.mutatedInstructions,
      destroyedConstants: cfg.destroyedConstants,
      shatteredStrings: cfg.shatteredStrings,
      chaffOps: cfg.chaffOps,
      cfgBlocks: cfg.cfgBlocks,
      cffDispatcherNodes: cfg.cffDispatcherNodes,
      jumpChainHops: cfg.jumpChainHops,
      opaqueForks: cfg.opaqueForks,
      bogusBlocks: cfg.bogusBlocks,
      guardOpcodes: cfg.guardOpcodes,
      payloadShards: 1,
      decoyShards: 0,
      payloadRadix: 85,
      microVmInstructions: 0,
      selfMutatingBuffer: false,
      encryptedStrings: cfg.shatteredStrings,
      noVmFunctions: compiled.nativeEscapes.length,
      mbaExpressions: 0,
      wordPermutation: orderedSlots.join('·'),
      headerPermutation: 'flat-vmem',
      antiTamperLayers: 0,
      cFunctionsVerified: 0,
      antiTamperArmed: false,
      robloxLockArmed: false,
      placeLockCount: 0,
      gameLockCount: 0,
      verified,
      verifierEngine,
      layersApplied: [
        'v3 Flat-VMem Runtime',
        'CCFI-encoded 12-byte instruction slots',
        'Per-handler private instruction ciphers',
        'Base85 payload encoding',
        'Zero constant pool and zero string table',
        ...(cfg.shatteredStrings > 0 ? ['Shattered string synthesis'] : []),
        ...(cfg.guardOpcodes > 0 ? [`CFG integrity guards (${cfg.guardOpcodes})`] : []),
      ],
    };
    return { code, stats };
  }

  // 1. Parse full modern Roblox Luau source into AST (complete type, symbol & comment erasure)
  const ast = parseLuau(source);

  // 2. Compile AST -> Custom Register ISA -> 7-Pass CFG Optimizer/Obfuscator -> Dual-VM Synthesis
  const compiled = compileChunk(ast);
  const vmOut = generatePolymorphicVM(compiled, opts, rng);
  const code = vmOut.code;
  const cfg = compiled.cfgStats;
  const spec = vmOut.spec;

  // 3. Build protection telemetry tags
  const layersApplied: string[] = [
    'Compatibility Runtime 2.1 (v3 flat-vmem pipeline not enabled)',
    '100% Pure Polymorphic VM (0 loadstring)',
    'CCFI Rolling Per-PC Key + 8-Bit Inst MAC',
    'Raw 12B Encrypted Binary Buffer ISA',
  ];
  if (opts.bytecodeMutation) {
    layersApplied.push('Live Self-Mutating Bytecode Buffer');
  }
  if (opts.opcodeMutation) {
    layersApplied.push(`Opcode Mutations (${cfg.mutatedInstructions} ops · ${opts.opcodeDuplication}x Split)`);
  }
  if (opts.graphCff) {
    layersApplied.push(`Multi-Hub Bytecode Graph CFF (${cfg.cffDispatcherNodes} hub nodes · ${cfg.cfgBlocks} blocks)`);
  }
  if (opts.jumpChainDepth > 0 && cfg.jumpChainHops > 0) {
    layersApplied.push(`Encrypted Jump Chains (${opts.jumpChainDepth}-hop · ${cfg.jumpChainHops} hops)`);
  }
  if (opts.superinstructions && cfg.fusedSuperinstructions > 0) {
    layersApplied.push(`Fused Superinstructions (${cfg.fusedSuperinstructions})`);
  }
  if (cfg.destroyedConstants > 0) {
    layersApplied.push(`VM-MBA Constant Pool Destruction (${cfg.destroyedConstants})`);
  }
  if (cfg.opaqueForks > 0 || cfg.bogusBlocks > 0) {
    layersApplied.push(`Opaque Forks (${cfg.opaqueForks}) + Cyclic Bogus Blocks (${cfg.bogusBlocks})`);
  }
  if (spec.decoyCount > 0) {
    layersApplied.push(`Interleaved Decoy Handlers (${spec.decoyCount})`);
  }
  if (opts.microVm) {
    layersApplied.push(`Nested Micro-VM Key Schedule (${vmOut.microVmInstructions} uOps)`);
  }
  if (opts.antiTamper) {
    layersApplied.push(`8-Layer Silent Anti-Tamper (32 C-Hooks + Frozen + Stream/Buf MAC + ${cfg.guardOpcodes} Guards)`);
  }
  layersApplied.push(
    opts.stringMode === 'ephemeral'
      ? 'Zero-Cache Ephemeral Autokey String Vault'
      : 'Lazy Autokey Encrypted String Vault',
  );
  if (opts.placeIds.length > 0) {
    layersApplied.push(`53-Bit PlaceId Cryptographic Key Slots (${opts.placeIds.length})`);
  }
  if (opts.gameIds.length > 0) {
    layersApplied.push(`53-Bit GameId Cryptographic Key Slots (${opts.gameIds.length})`);
  }
  if (compiled.nativeEscapes.length > 0) {
    layersApplied.push(`60-FPS --@novm Fast Paths (${compiled.nativeEscapes.length})`);
  }

  // 4. Verify generated Luau compiles cleanly via Official Roblox Luau 0.747 (`luau-compile`)
  let verified = true;
  let verifierEngine: ObfuscationStats['verifierEngine'] = 'skipped';
  if (opts.verify) {
    const verification = verifyLuauSyntax(code);
    verified = verification.ok;
    verifierEngine = verification.engine;
    if (!verification.ok) {
      throw new GrandfuscatorError(
        `Generated VM failed Luau bytecode verification: ${verification.error}`,
        'verifier',
      );
    }
  }

  const outputBytes = Buffer.byteLength(code, 'utf8');
  const compileTimeMs = Math.round((performance.now() - t0) * 100) / 100;

  const slotNames = ['C0', 'C1', 'C2'];
  const orderedSlots: string[] = ['', '', ''];
  spec.ccfi.wordOffsets.forEach((byteOff, idx) => {
    orderedSlots[byteOff >> 2] = slotNames[idx];
  });
  const wordPermutation = orderedSlots.join('·');
  const headerPermutation = spec.sectionOrder.map((s) => s[0].toUpperCase()).join('·');

  const stats: ObfuscationStats = {
    buildId: rng.buildId,
    engineVersion: ENGINE_VERSION,
    architecture: opts.microVm
      ? 'Dual-VM (Micro-VM + Self-Mutating CCFI VM)'
      : 'Polymorphic CCFI Buffer VM',
    loadstringUsed: false,
    zeroConstantPool: false,
    zeroStringTable: false,
    preset: opts.preset,
    inputBytes,
    outputBytes,
    bytecodeBytes: spec.rawBytecodeBytes,
    sizeRatio: Math.round((outputBytes / Math.max(1, inputBytes)) * 100) / 100,
    compileTimeMs,
    vmProtos: compiled.totalProtos,
    decoyProtos: 0,
    vmInstructions: compiled.totalInstructions,
    physicalOpcodes: spec.realPhysicalCount,
    decoyOpcodes: spec.decoyCount,
    perHandlerCiphers: 0,
    fusedSuperinstructions: cfg.fusedSuperinstructions,
    mutatedInstructions: cfg.mutatedInstructions,
    destroyedConstants: cfg.destroyedConstants,
    shatteredStrings: 0,
    chaffOps: 0,
    cfgBlocks: cfg.cfgBlocks,
    cffDispatcherNodes: cfg.cffDispatcherNodes,
    jumpChainHops: cfg.jumpChainHops,
    opaqueForks: cfg.opaqueForks,
    bogusBlocks: cfg.bogusBlocks,
    guardOpcodes: cfg.guardOpcodes,
    payloadShards: 1,
    decoyShards: 0,
    payloadRadix: 85,
    microVmInstructions: vmOut.microVmInstructions,
    selfMutatingBuffer: opts.bytecodeMutation,
    encryptedStrings: vmOut.totalStrings,
    noVmFunctions: compiled.nativeEscapes.length,
    mbaExpressions: vmOut.mbaCount,
    wordPermutation,
    headerPermutation,
    antiTamperLayers: vmOut.antiTamperLayers,
    cFunctionsVerified: opts.antiTamper ? 32 : 0,
    antiTamperArmed: opts.antiTamper,
    robloxLockArmed: false,
    placeLockCount: opts.placeIds.length,
    gameLockCount: opts.gameIds.length,
    verified,
    verifierEngine,
    layersApplied,
  };

  return { code, stats };
}
