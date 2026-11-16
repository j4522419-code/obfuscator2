#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { obfuscate, ObfuscationOptions, ObfuscationPreset, NameStyle, RuntimeTarget } from './engine/index.js';

function printHelp(): void {
  console.log(`
Grandfuscator 2.1 — Roblox Luau Obfuscator (0 loadstring)

Usage:
  npm run cli -- <input.luau> [options]

Options:
  --runtime <target>        compat (default) | v3-experimental (executable flat-vmem runtime)
  -o, --output <file>       Output file path (default: <input>.obf.luau)
  -p, --preset <name>       swift | fortress | nightmare (default: fortress)
  --names <style>           short | barcode | shadow | hex
  --chains <0..3>           Encrypted bytecode jump-chain depth
  --no-cff                  Disable multi-hub bytecode Graph CFF
  --no-bc-mutate            Disable live self-mutating bytecode buffer
  --no-op-mutate            Disable swapped/reversed opcode mutations
  --no-antitamper           Disable 8-layer silent anti-tamper
  --no-microvm              Disable nested Micro-VM key synthesizer
  --place-ids <id,id,...>   Cryptographically lock script to Roblox PlaceId(s)
  --game-ids <id,id,...>    Cryptographically lock script to Roblox GameId(s)
  --watermark <text>        Custom header comment (use "" for none)
  --seed <hex>              Deterministic build seed (for testing)
  -h, --help                Show this help message
`);
}

const args = process.argv.slice(2);
if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
  printHelp();
  process.exit(0);
}

let inputPath = '';
let outputPath = '';
const opts: ObfuscationOptions = {};

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--runtime') opts.runtime = args[++i] as RuntimeTarget;
  else if (a === '-o' || a === '--output') outputPath = args[++i] || '';
  else if (a === '-p' || a === '--preset') opts.preset = args[++i] as ObfuscationPreset;
  else if (a === '--names') opts.nameStyle = args[++i] as NameStyle;
  else if (a === '--chains') opts.jumpChainDepth = Number(args[++i] || 0);
  else if (a === '--no-cff') opts.graphCff = false;
  else if (a === '--no-bc-mutate') opts.bytecodeMutation = false;
  else if (a === '--no-op-mutate') opts.opcodeMutation = false;
  else if (a === '--no-antitamper') opts.antiTamper = false;
  else if (a === '--no-microvm') opts.microVm = false;
  else if (a === '--place-ids') opts.placeIds = (args[++i] || '').split(',');
  else if (a === '--game-ids') opts.gameIds = (args[++i] || '').split(',');
  else if (a === '--watermark') opts.watermark = args[++i] ?? '';
  else if (a === '--seed') opts.seed = args[++i] || '';
  else if (!a.startsWith('-') && !inputPath) inputPath = a;
}

if (!inputPath) {
  console.error('Error: missing input .luau file');
  process.exit(1);
}

const source = fs.readFileSync(inputPath, 'utf8');
const result = obfuscate(source, opts);

if (!outputPath) {
  const ext = path.extname(inputPath);
  const base = inputPath.slice(0, inputPath.length - ext.length);
  outputPath = `${base}.obf${ext || '.luau'}`;
}

fs.writeFileSync(outputPath, result.code, 'utf8');
const s = result.stats;
console.log(
  `[${s.buildId}] Grandfuscator v${s.engineVersion} -> ${outputPath}\n` +
  `  Preset: ${s.preset.toUpperCase()} | Size: ${s.inputBytes} B -> ${s.outputBytes} B (${s.sizeRatio}x) | Time: ${s.compileTimeMs} ms\n` +
  `  VM ISA: ${s.vmProtos} protos, ${s.vmInstructions} insts, ${s.physicalOpcodes} phys ops (+${s.decoyOpcodes} decoys), ${s.mutatedInstructions} op-muts, ${s.fusedSuperinstructions} superinsts\n` +
  `  CFG/CCFI: ${s.cfgBlocks} blocks, ${s.cffDispatcherNodes} Graph-CFF nodes, ${s.jumpChainHops} chain hops, ${s.opaqueForks} opaque forks, ${s.bogusBlocks} bogus blocks\n` +
  `  Armor: ${s.antiTamperLayers} anti-tamper layers, ${s.microVmInstructions} Micro-VM uOps, ${s.destroyedConstants} MBA consts, ${s.encryptedStrings} vault strings\n` +
  `  Verified: ${s.verified} (${s.verifierEngine}) | Layout: ${s.wordPermutation} / ${s.headerPermutation}`,
);
