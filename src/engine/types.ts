export type ObfuscationPreset = 'swift' | 'fortress' | 'nightmare';

/** Legacy v1 API preset aliases seamlessly routed into pure 100% VMs */
export type LegacyPresetAlias = 'performance' | 'balanced';

export type NameStyle = 'short' | 'barcode' | 'hex' | 'shadow';

export type StringEncryptionMode = 'lazy' | 'ephemeral';
export type RuntimeTarget = 'compat' | 'v3-experimental';

export interface ObfuscationOptions {
  /** Runtime backend selector. `compat` remains the stable default; `v3-experimental` emits the separately tested flat-vmem runtime. */
  runtime?: RuntimeTarget;
  preset?: ObfuscationPreset | LegacyPresetAlias;
  /** Duplicate hot opcodes into 1x, 2x, or 3x distinct polymorphic handlers (each with its own private cipher & ratchet) */
  opcodeDuplication?: number;
  /** Number of fake decoy opcode handlers interleaved into the dual dispatch engines (0..48) */
  decoyHandlers?: number;
  /** Swapped/reversed operand mutations + per-handler private operand ciphers & post-ratchets */
  opcodeMutation?: boolean;
  /** Live in-place self-mutating unified `vmem` buffer (re-encrypts every 12B instruction on each execution) */
  bytecodeMutation?: boolean;
  /** Multi-hop encrypted bytecode jump chain depth (0 = direct CCFI jump, 1..3 = chained state-mutating hops) */
  jumpChainDepth?: number;
  /** Multi-hub bytecode Control-Flow Graph Flattening + cross-function `vmem` interleaving + cyclic bogus blocks */
  graphCff?: boolean;
  /** Fuse hot instruction pairs into custom superinstructions (speeds up VM & breaks pattern lifters) */
  superinstructions?: boolean;
  /** Nested 8-opcode Micro-VM synthesizing masterKey + 256-byte nonlinear S-box seed + root entry masks */
  microVm?: boolean;
  /** 12-layer silent anti-tamper (68 C-hook hash, anti-newcclosure, 9 frozen libs, live AT_CHECK, 3x MAC, quad anchors) */
  antiTamper?: boolean;
  /**
   * True Roblox C++ Engine & Anti-Executor Cryptographic Lock:
   * Binds `masterKey` and the 256-byte S-box directly to unforgeable Roblox engine invariants
   * (`typeof(game)=="Instance"`, `type(Vector3.zero)=="vector"`, `typeof(CFrame.identity)=="CFrame"`,
   * locked Instance metatable, frozen `[C]` `task`/`Instance`/`Vector3`/`CFrame`/`Color3`/`warn`/`typeof`,
   * and absence of executor hook globals). Scripts with `robloxLock: true` ONLY decrypt inside real Roblox
   * and are 100% undecryptable/unrunnable in standalone CLI Luau or mocked sandboxes!
   */
  robloxLock?: boolean;
  /** Inject realistic decoy shattered strings & harmless env probes to poison inline runtime tracing */
  chaff?: boolean;
  /** Legacy alias for antiTamper */
  antiBeautify?: boolean;
  /** Legacy field accepted & ignored */
  hideStdlib?: boolean;
  /** 'lazy' = loop-safe register hoisting for hot paths + inline cold shatter; 'ephemeral' = inline shatter everywhere outside hot loops + instant wipe */
  stringMode?: StringEncryptionMode;
  /** Mixed Boolean-Arithmetic (MBA) nesting depth (0..3) */
  mbaDepth?: number;
  /** Mangled identifier style for VM internals */
  nameStyle?: NameStyle;
  /** Optional Roblox PlaceId lock list (supports full 53-bit Roblox PlaceIds) */
  placeIds?: Array<string | number | bigint>;
  /** Optional Roblox GameId (UniverseId) lock list */
  gameIds?: Array<string | number | bigint>;
  /** Optional single-line header comment (default "" = zero-banner stealth mode) */
  watermark?: string;
  /** Optional deterministic hex/text seed (default: 256-bit CSPRNG) */
  seed?: string;
  /** Run official Luau bytecode compiler verification on final output */
  verify?: boolean;
}

export interface ResolvedOptions {
  runtime: RuntimeTarget;
  preset: ObfuscationPreset;
  opcodeDuplication: number;
  decoyHandlers: number;
  opcodeMutation: boolean;
  bytecodeMutation: boolean;
  jumpChainDepth: number;
  graphCff: boolean;
  superinstructions: boolean;
  microVm: boolean;
  antiTamper: boolean;
  robloxLock: boolean;
  chaff: boolean;
  stringMode: StringEncryptionMode;
  mbaDepth: number;
  nameStyle: NameStyle;
  placeIds: bigint[];
  gameIds: bigint[];
  watermark: string;
  seed?: string;
  verify: boolean;
}

export interface ObfuscationStats {
  buildId: string;
  engineVersion: string;
  architecture:
    | 'Oblivion Dual-VM (Micro-VM + S-Box Interleaved Flat-VM)'
    | 'Oblivion S-Box Interleaved Flat-VM'
    | 'Dual-VM (Micro-VM + Self-Mutating CCFI VM)'
    | 'Polymorphic CCFI Buffer VM';
  loadstringUsed: false;
  zeroConstantPool: boolean;
  zeroStringTable: boolean;
  preset: ObfuscationPreset;
  inputBytes: number;
  outputBytes: number;
  bytecodeBytes: number;
  sizeRatio: number;
  compileTimeMs: number;
  vmProtos: number;
  decoyProtos: number;
  vmInstructions: number;
  physicalOpcodes: number;
  decoyOpcodes: number;
  perHandlerCiphers: number;
  fusedSuperinstructions: number;
  mutatedInstructions: number;
  destroyedConstants: number;
  shatteredStrings: number;
  chaffOps: number;
  cfgBlocks: number;
  cffDispatcherNodes: number;
  jumpChainHops: number;
  opaqueForks: number;
  bogusBlocks: number;
  guardOpcodes: number;
  payloadShards: number;
  decoyShards: number;
  payloadRadix: number;
  microVmInstructions: number;
  selfMutatingBuffer: boolean;
  encryptedStrings: number;
  noVmFunctions: number;
  mbaExpressions: number;
  wordPermutation: string;
  headerPermutation: string;
  antiTamperLayers: number;
  cFunctionsVerified: number;
  antiTamperArmed: boolean;
  robloxLockArmed: boolean;
  placeLockCount: number;
  gameLockCount: number;
  verified: boolean;
  verifierEngine: 'luau-compile' | 'internal-parser' | 'skipped';
  layersApplied: string[];
}

export interface ObfuscationResult {
  code: string;
  stats: ObfuscationStats;
}

export class GrandfuscatorError extends Error {
  public readonly line?: number;
  public readonly column?: number;
  public readonly phase: 'lexer' | 'parser' | 'compiler' | 'cfg' | 'vm' | 'verifier' | 'options';

  constructor(
    message: string,
    phase: 'lexer' | 'parser' | 'compiler' | 'cfg' | 'vm' | 'verifier' | 'options',
    line?: number,
    column?: number,
  ) {
    const loc = line !== undefined ? ` [line ${line}${column !== undefined ? `:${column}` : ''}]` : '';
    super(`${message}${loc}`);
    this.name = 'GrandfuscatorError';
    this.phase = phase;
    this.line = line;
    this.column = column;
  }
}

export const PRESET_DEFAULTS: Record<ObfuscationPreset, Omit<ResolvedOptions, 'placeIds' | 'gameIds' | 'seed'>> = {
  swift: {
    runtime: 'compat',
    preset: 'swift',
    opcodeDuplication: 1,
    decoyHandlers: 12,
    opcodeMutation: true,
    bytecodeMutation: true,
    jumpChainDepth: 1,
    graphCff: true,
    superinstructions: true,
    microVm: true,
    antiTamper: true,
    robloxLock: false,
    chaff: true,
    stringMode: 'lazy',
    mbaDepth: 1,
    nameStyle: 'short',
    watermark: '',
    verify: true,
  },
  fortress: {
    runtime: 'compat',
    preset: 'fortress',
    opcodeDuplication: 2,
    decoyHandlers: 24,
    opcodeMutation: true,
    bytecodeMutation: true,
    jumpChainDepth: 2,
    graphCff: true,
    superinstructions: true,
    microVm: true,
    antiTamper: true,
    robloxLock: false,
    chaff: true,
    stringMode: 'ephemeral',
    mbaDepth: 2,
    nameStyle: 'barcode',
    watermark: '',
    verify: true,
  },
  nightmare: {
    runtime: 'compat',
    preset: 'nightmare',
    opcodeDuplication: 3,
    decoyHandlers: 38,
    opcodeMutation: true,
    bytecodeMutation: true,
    jumpChainDepth: 3,
    graphCff: true,
    superinstructions: true,
    microVm: true,
    antiTamper: true,
    robloxLock: false,
    chaff: true,
    stringMode: 'ephemeral',
    mbaDepth: 3,
    nameStyle: 'barcode',
    watermark: '',
    verify: true,
  },
};

function parseRobloxIdList(raw: Array<string | number | bigint> | undefined, label: string): bigint[] {
  if (!raw || raw.length === 0) return [];
  const out: bigint[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    const s = String(item).trim();
    if (!s) continue;
    if (!/^\d+$/.test(s)) {
      throw new GrandfuscatorError(`Invalid Roblox ${label} "${s}" — expected a positive integer ID`, 'options');
    }
    const val = BigInt(s);
    if (val <= 0n || val > 9007199254740991n) {
      throw new GrandfuscatorError(`Roblox ${label} "${s}" is out of safe 53-bit integer range`, 'options');
    }
    const key = val.toString();
    if (!seen.has(key)) {
      seen.add(key);
      out.push(val);
    }
  }
  if (out.length > 64) {
    throw new GrandfuscatorError(`Too many ${label} entries (max 64)`, 'options');
  }
  return out;
}

function clampInt(val: number | undefined, fallback: number, min: number, max: number): number {
  if (val === undefined || !Number.isFinite(val)) return fallback;
  return Math.max(min, Math.min(max, Math.round(val)));
}

export function resolveOptions(raw: ObfuscationOptions = {}): ResolvedOptions {
  if (raw.runtime !== undefined && raw.runtime !== 'compat' && raw.runtime !== 'v3-experimental') {
    throw new GrandfuscatorError(`Unknown runtime target "${String(raw.runtime)}"`, 'options');
  }
  const runtime: RuntimeTarget = raw.runtime ?? 'compat';

  let preset: ObfuscationPreset = 'fortress';
  if (raw.preset === 'performance' || raw.preset === 'swift') {
    preset = 'swift';
  } else if (raw.preset === 'balanced' || raw.preset === 'fortress') {
    preset = 'fortress';
  } else if (raw.preset === 'nightmare') {
    preset = 'nightmare';
  }

  const base = PRESET_DEFAULTS[preset];
  const validStyles: NameStyle[] = ['short', 'barcode', 'hex', 'shadow'];
  const nameStyle = raw.nameStyle && validStyles.includes(raw.nameStyle) ? raw.nameStyle : base.nameStyle;
  const stringMode: StringEncryptionMode =
    raw.stringMode === 'lazy' || raw.stringMode === 'ephemeral' ? raw.stringMode : base.stringMode;

  const antiTamper =
    raw.antiTamper !== undefined
      ? Boolean(raw.antiTamper)
      : raw.antiBeautify !== undefined
        ? Boolean(raw.antiBeautify)
        : base.antiTamper;

  let watermark = raw.watermark !== undefined ? String(raw.watermark) : base.watermark;
  watermark = watermark.replace(/[\r\n]+/g, ' ').trim().slice(0, 120);

  const compat = runtime === 'compat';

  return {
    runtime,
    preset,
    opcodeDuplication: clampInt(raw.opcodeDuplication, base.opcodeDuplication, 1, 3),
    decoyHandlers: clampInt(raw.decoyHandlers, base.decoyHandlers, 0, 48),
    // The 2.1 compatibility backend disables transforms not supported by its runtime.
    // The opt-in v3 compiler path retains the preset/raw settings for CFG lowering.
    opcodeMutation: compat ? false : (raw.opcodeMutation !== undefined ? Boolean(raw.opcodeMutation) : base.opcodeMutation),
    bytecodeMutation: raw.bytecodeMutation !== undefined ? Boolean(raw.bytecodeMutation) : base.bytecodeMutation,
    jumpChainDepth: compat ? 0 : clampInt(raw.jumpChainDepth, base.jumpChainDepth, 0, 3),
    graphCff: compat ? false : (raw.graphCff !== undefined ? Boolean(raw.graphCff) : base.graphCff),
    superinstructions: compat ? false : (raw.superinstructions !== undefined ? Boolean(raw.superinstructions) : base.superinstructions),
    microVm: raw.microVm !== undefined ? Boolean(raw.microVm) : base.microVm,
    antiTamper,
    robloxLock: compat ? false : (raw.robloxLock !== undefined ? Boolean(raw.robloxLock) : base.robloxLock),
    chaff: compat ? false : (raw.chaff !== undefined ? Boolean(raw.chaff) : base.chaff),
    stringMode,
    mbaDepth: clampInt(raw.mbaDepth, base.mbaDepth, 0, 3),
    nameStyle,
    placeIds: parseRobloxIdList(raw.placeIds, 'PlaceId'),
    gameIds: parseRobloxIdList(raw.gameIds, 'GameId'),
    watermark,
    seed: raw.seed !== undefined && String(raw.seed).length > 0 ? String(raw.seed) : undefined,
    verify: raw.verify !== undefined ? Boolean(raw.verify) : base.verify,
  };
}
