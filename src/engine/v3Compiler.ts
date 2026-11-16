import { compileChunk } from './compiler.js';
import { runCFGCompilerPasses } from './cfgEngine.js';
import { CompiledModule } from './ir.js';
import { parseLuau } from './parser.js';
import { PRNG } from './prng.js';
import { GrandfuscatorError, ResolvedOptions } from './types.js';
import { FlatV3Image, serializeFlatV3Image } from './v3Serializer.js';

/** Compile source through the isolated v3 CFG/flat-layout pipeline. */
export function compileFlatV3IR(
  source: string,
  opts: ResolvedOptions,
  rng: PRNG,
): CompiledModule {
  if (opts.runtime !== 'v3-experimental') {
    throw new GrandfuscatorError('compileFlatV3IR requires runtime "v3-experimental"', 'options');
  }

  const ast = parseLuau(source);
  const compiled = compileChunk(ast);
  const expectedLine = opts.watermark ? 2 : 1;
  runCFGCompilerPasses(compiled, opts, rng, expectedLine);

  if (!compiled.vmem || compiled.vmem.totalSlots !== compiled.vmem.slots.length) {
    throw new GrandfuscatorError('v3 CFG pipeline did not produce a consistent flat vmem image', 'cfg');
  }
  if (compiled.vmem.rootEntryPC < 0 || compiled.vmem.rootEntryPC >= compiled.vmem.totalSlots) {
    throw new GrandfuscatorError('v3 CFG pipeline produced an invalid root entry PC', 'cfg');
  }
  return compiled;
}

/** Build both compiler IR and the v3 CCFI-encoded flat payload/header artifact. */
export function buildFlatV3Image(
  source: string,
  opts: ResolvedOptions,
  rng: PRNG,
): { compiled: CompiledModule; image: FlatV3Image } {
  const compiled = compileFlatV3IR(source, opts, rng);
  try {
    return { compiled, image: serializeFlatV3Image(compiled, opts, rng) };
  } catch (err) {
    if (err instanceof GrandfuscatorError) throw err;
    throw new GrandfuscatorError(
      `v3 flat-image serialization failed: ${err instanceof Error ? err.message : String(err)}`,
      'cfg',
    );
  }
}
