import express, { Request, Response, NextFunction } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  executeLuau,
  findLuauCompiler,
  findLuauRuntime,
  GrandfuscatorError,
  obfuscate,
  ObfuscationOptions,
} from './engine/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

// Serve only frontend static assets — compiler/CFG/CCFI/VM engine remains 100% private on server
app.use(express.static(PUBLIC_DIR, { etag: true, maxAge: 0 }));

app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    ok: true,
    name: 'Grandfuscator',
    version: '2.1.0',
    architecture: 'dual-vm-ccfi',
    zeroLoadstring: true,
    luauCompiler: Boolean(findLuauCompiler()),
    luauRuntime: Boolean(findLuauRuntime()),
  });
});

app.post('/api/obfuscate', (req: Request, res: Response) => {
  try {
    const { source, options } = (req.body ?? {}) as {
      source?: string;
      options?: ObfuscationOptions;
    };
    const result = obfuscate(source ?? '', options ?? {});
    res.json({ ok: true, code: result.code, stats: result.stats });
  } catch (err) {
    if (err instanceof GrandfuscatorError) {
      res.status(400).json({
        ok: false,
        error: err.message,
        phase: err.phase,
        line: err.line ?? null,
        column: err.column ?? null,
      });
      return;
    }
    console.error('[Grandfuscator] Unexpected error:', err);
    res.status(500).json({
      ok: false,
      error: 'Internal obfuscation engine error',
      phase: 'vm',
    });
  }
});

/** Flip a single character inside the encrypted Base85 VM bytecode payload for live MAC tamper testing */
function flipOnePayloadChar(code: string): string {
  let best: RegExpMatchArray | null = null;
  for (const m of code.matchAll(/"([^"\r\n]*)"/g)) {
    if (m[1].length >= 20 && (!best || m[1].length > best[1].length)) {
      best = m;
    }
  }
  if (!best || best.index === undefined) return code + '\n';
  const body = best[1];
  const mid = Math.floor(body.length / 2);
  const origCh = body[mid];
  const replacement = origCh === 'A' ? 'B' : 'A';
  const mutated = body.slice(0, mid) + replacement + body.slice(mid + 1);
  return code.slice(0, best.index) + `"${mutated}"` + code.slice(best.index + best[0].length);
}

/**
 * Red-team source patch: insert a hex dumper immediately after the first encrypted
 * bytecode stream has been decrypted into a Luau buffer, but before the integrity MAC.
 * This models the report's successful in-process buffer extraction, not an external
 * operating-system logger. It intentionally keeps the same line count.
 */
function injectDecryptedPayloadDump(code: string): { code: string; injected: boolean } {
  const re = /(return\s+(\w+)\s+end;)(\w+)=(\w+)\(([^;]*?)\);/;
  const match = re.exec(code);
  let bytecodeBuf: string | undefined;
  let start = -1;
  if (match) {
    bytecodeBuf = match[3];
    start = match.index + match[0].length;
  } else {
    // v3 decodes the flat-vmem payload into a buffer before declaring its local
    // VM helpers. Instrument at that boundary, before any instruction executes.
    const allocation = /local\s+(\w+)=\w+\(\d+\);local\s+\w+="/.exec(code);
    if (allocation) {
      const helperStart = code.indexOf('local function', allocation.index + allocation[0].length);
      if (helperStart >= 0) {
        bytecodeBuf = allocation[1];
        start = helperStart;
      }
    }
  }
  if (!bytecodeBuf || start < 0) return { code, injected: false };
  const dump =
    `do print("GF_PAYLOAD_DUMP_BEGIN");local _i,_s=0,buffer.len(${bytecodeBuf});` +
    `while _i<_s do local _e=math.min(_i+31,_s-1);local _h="";` +
    `for _j=_i,_e do _h..=string.format("%02x",buffer.readu8(${bytecodeBuf},_j))end;print(_h);_i=_e+1 end;` +
    `print("GF_PAYLOAD_DUMP_END")end;`;
  return { code: code.slice(0, start) + dump + code.slice(start), injected: true };
}

/** Inject a trace after the VM's CCFI operand decode, before opcode dispatch. */
function injectDecodedInstructionTrace(code: string): { code: string; injected: boolean } {
  const re = /local\s+(\w+),(\w+),(\w+)=([^;]+);local\s+(\w+)=([^;]+);local\s+(\w+)=([^;]+);/;
  const match = re.exec(code);
  if (match) {
    const [, op, a, , , b, , c] = match;
    const trace = `print("GF_TRACE",${op},${a},${b},${c});`;
    const end = match.index + match[0].length;
    return { code: code.slice(0, end) + trace + code.slice(end), injected: true };
  }
  // v3 stores decoded operands in locals and dispatches by the decoded physical
  // handler id. Trace that id and PC before dispatch; this is still successful
  // instruction inspection, not something the client runtime can prevent.
  const flatDispatch = /(\w+)\+=1;(if\s+(\w+)==\d+\s+then)/;
  const flatMatch = flatDispatch.exec(code);
  if (!flatMatch) return { code, injected: false };
  const [, pc, , handlerId] = flatMatch;
  const trace = `print("GF_TRACE",${pc}-1,${handlerId});`;
  const start = flatMatch.index + `${pc}+=1;`.length;
  return { code: code.slice(0, start) + trace + code.slice(start), injected: true };
}

/**
 * Live Luau 0.747 Verification & Red-Team Anti-Tamper Attack Simulator:
 *  - Executes original + obfuscated scripts under a single-line Roblox Studio shim
 *  - Verifies identical stdout, zero `loadstring`, and zero `string.char`
 *  - Runs anti-tamper probes plus source-level bytecode-buffer dump and decoded-instruction trace
 *    reproductions. Source-level runtime instrumentation is expected to succeed against client code;
 *    the report must not claim otherwise.
 */
app.post('/api/verify-run', (req: Request, res: Response) => {
  if (!findLuauRuntime()) {
    res.status(501).json({ ok: false, error: 'Luau runtime binary is not installed on this host.' });
    return;
  }

  const { originalCode, obfuscatedCode, mockPlaceId, mockGameId, testTamper } = (req.body ?? {}) as {
    originalCode?: string;
    obfuscatedCode?: string;
    mockPlaceId?: string;
    mockGameId?: string;
    testTamper?: boolean;
  };

  if (typeof obfuscatedCode !== 'string' || !obfuscatedCode.trim()) {
    res.status(400).json({ ok: false, error: 'Missing obfuscated code to verify.' });
    return;
  }
  if (obfuscatedCode.length > 950_000) {
    res.status(400).json({ ok: false, error: 'Payload too large for sandbox runner.' });
    return;
  }

  const pid = mockPlaceId && /^\d+$/.test(mockPlaceId.trim()) ? mockPlaceId.trim() : '1818';
  const gid = mockGameId && /^\d+$/.test(mockGameId.trim()) ? mockGameId.trim() : '1001';

  // Single-line Roblox Studio shim — keeps all frozen C stdlibs (`bit32`, `buffer`, `string`, `table`,
  // `coroutine`, `debug`, `math`) 100% untouched and sits on the SAME line so line anchors stay exact!
  const robloxShim =
    `do local _svc={};` +
    `warn=function(...)print("[WARN]",...)end;` +
    `task={wait=function(t)return t or 0.016 end,spawn=function(f,...)return f(...)end,defer=function(f,...)return f(...)end,delay=function(_,f,...)return f(...)end};` +
    `wait=task.wait;spawn=task.spawn;tick=os.clock;` +
    `Vector3={new=function(x,y,z)local v={X=x or 0,Y=y or 0,Z=z or 0};v.Magnitude=math.sqrt(v.X*v.X+v.Y*v.Y+v.Z*v.Z);return v end,zero={X=0,Y=0,Z=0,Magnitude=0}};` +
    `Color3={fromRGB=function(r,g,b)return{R=r/255,G=g/255,B=b/255}end,new=function(r,g,b)return{R=r or 0,G=g or 0,B=b or 0}end};` +
    `Instance={new=function(cls,par)local o={ClassName=cls,Name=cls,Parent=par,_c={}};function o:Destroy()self.Parent=nil end;function o:FindFirstChild(n)return self._c[n]end;function o:WaitForChild(n)return self._c[n]or Instance.new("Folder",self)end;function o:FireServer(...)print("[Remote:FireServer]",self.Name,...)end;function o:FireClient(_,...)print("[Remote:FireClient]",self.Name,...)end;if par and par._c then par._c[cls]=o end;return o end};` +
    `local function _mkSvc(n)local s=Instance.new(n);s.LocalPlayer={Name="LocalDev",UserId=100001,DisplayName="Dev"};s.Heartbeat={Connect=function(_,fn)return{Disconnect=function()end}end};s.RenderStepped=s.Heartbeat;function s:GetPlayers()return{s.LocalPlayer}end;return s end;` +
    `game={PlaceId=${pid},GameId=${gid},JobId="sandbox-job-01",GetService=function(_,n)_svc[n]=_svc[n]or _mkSvc(n);return _svc[n]end};` +
    `workspace=game:GetService("Workspace");script=Instance.new("ModuleScript");end;`;

  const injectSameLine = (src: string, extraPrefix = ''): string => {
    const fullPrefix = robloxShim + extraPrefix;
    if (src.startsWith('--')) {
      const nl = src.indexOf('\n');
      if (nl >= 0) {
        return src.slice(0, nl + 1) + fullPrefix + src.slice(nl + 1);
      }
    }
    return fullPrefix + src;
  };

  const obfRun = executeLuau(injectSameLine(obfuscatedCode), 2200);

  let origRun = null;
  let outputsMatch: boolean | null = null;
  if (typeof originalCode === 'string' && originalCode.trim()) {
    origRun = executeLuau(robloxShim + '\n' + originalCode, 2200);
    if (origRun.ok && obfRun.ok) {
      outputsMatch = origRun.stdout === obfRun.stdout;
    }
  }

  let tamperBlocked: boolean | null = null;
  const tamperSuite: Array<{ attack: string; blocked: boolean; evidence?: string }> = [];

  if (testTamper && obfRun.ok) {
    const wasBlocked = (r: { ok: boolean; stdout: string }): boolean =>
      !r.ok || (obfRun.stdout.length > 0 && r.stdout !== obfRun.stdout);

    // Attack 1: Code Beautifier / Formatter (line-shift)
    const beautified = obfuscatedCode.replace(/;/g, ';\n');
    tamperSuite.push({
      attack: 'Beautifier / Line Shift',
      blocked: wasBlocked(executeLuau(robloxShim + '\n' + beautified, 900)),
    });

    // Attack 2: Constant-Dumper Hook on `buffer.readstring` (unfrozen clone table)
    const hookReadStr =
      `do local _ob=buffer;local _nb={};for k,v in _ob do _nb[k]=v end;` +
      `_nb.readstring=function(b,o,l)return _ob.readstring(b,o,l)end;buffer=_nb end;`;
    tamperSuite.push({
      attack: 'buffer.readstring Dumper Hook',
      blocked: wasBlocked(executeLuau(injectSameLine(obfuscatedCode, hookReadStr), 900)),
    });

    // Attack 3: In-source decrypted-bytecode dump (the report's core technique).
    // A successful dump is reported as NOT blocked even if the script later detects tampering.
    const dumpPatch = injectDecryptedPayloadDump(obfuscatedCode);
    const dumpRun = dumpPatch.injected
      ? executeLuau(injectSameLine(dumpPatch.code), 1400)
      : { ok: false, stdout: '', stderr: 'decoder pattern not found', durationMs: 0 };
    const dumpCaptured = dumpRun.stdout.includes('GF_PAYLOAD_DUMP_BEGIN') &&
      dumpRun.stdout.includes('GF_PAYLOAD_DUMP_END');
    tamperSuite.push({
      attack: 'In-source decrypted bytecode buffer dump',
      blocked: dumpPatch.injected && !dumpCaptured,
      evidence: dumpCaptured ? 'Decrypted payload bytes were printed before integrity verification.' :
        (dumpPatch.injected ? dumpRun.stderr.slice(0, 300) || 'No dump marker observed.' : 'Instrumentation pattern not found; this is not evidence that client inspection was prevented.'),
    });

    // Attack 4: Decoded instruction trace (log CCFI-decoded opcode and operands before dispatch).
    const tracePatch = injectDecodedInstructionTrace(obfuscatedCode);
    const traceRun = tracePatch.injected
      ? executeLuau(injectSameLine(tracePatch.code), 1400)
      : { ok: false, stdout: '', stderr: 'decode pattern not found', durationMs: 0 };
    const traceLines = traceRun.stdout.split('\n').filter((line) => line.includes('GF_TRACE'));
    tamperSuite.push({
      attack: 'Decoded VM instruction trace',
      blocked: tracePatch.injected && traceLines.length === 0,
      evidence: traceLines.length ? `${traceLines.length} decoded instruction(s) observed.` :
        (tracePatch.injected ? traceRun.stderr.slice(0, 300) || 'No trace marker observed.' : 'Instrumentation pattern not found; this is not evidence that client inspection was prevented.'),
    });

    // Attack 5: Fake C-Closure (`coroutine.wrap` / `newcclosure`) Hook on `pcall`
    const fakeCClosure =
      `do local _op=pcall;pcall=coroutine.wrap(function(...)local a={...};while true do a={coroutine.yield(_op(table.unpack(a)))}end end)end;`;
    tamperSuite.push({
      attack: 'Fake [C] Closure (newcclosure)',
      blocked: wasBlocked(executeLuau(injectSameLine(obfuscatedCode, fakeCClosure), 900)),
    });

    // Attack 6: `debug.info` Spoofer Hook (pretends every function is `[C]`)
    const spoofDebug =
      `do local _od=debug;local _nd=table.clone(_od);` +
      `_nd.info=function(f,w)if w=="l"then return _od.info(2,"l")end;return"[C]",-1,"pcall",0,true end;` +
      `table.freeze(_nd);debug=_nd end;`;
    tamperSuite.push({
      attack: 'debug.info Spoofer Hook',
      blocked: wasBlocked(executeLuau(injectSameLine(obfuscatedCode, spoofDebug), 900)),
    });

    // Attack 7: 1-Byte Encrypted VM Bytecode Modification
    tamperSuite.push({
      attack: '1-Byte Bytecode Patch',
      blocked: wasBlocked(executeLuau(injectSameLine(flipOnePayloadChar(obfuscatedCode)), 900)),
    });

    tamperBlocked = tamperSuite.every((t) => t.blocked);
  }

  res.json({
    ok: true,
    zeroLoadstring: !obfuscatedCode.includes('loadstring'),
    zeroStringChar: !obfuscatedCode.includes('string.char'),
    obfuscated: {
      ok: obfRun.ok,
      stdout: obfRun.stdout.slice(0, 8000),
      stderr: obfRun.stderr.slice(0, 2000),
      durationMs: obfRun.durationMs,
    },
    original: origRun
      ? {
          ok: origRun.ok,
          stdout: origRun.stdout.slice(0, 8000),
          stderr: origRun.stderr.slice(0, 2000),
          durationMs: origRun.durationMs,
        }
      : null,
    outputsMatch,
    tamperBlocked,
    tamperSuite,
  });
});

app.use((err: Error & { status?: number }, _req: Request, res: Response, _next: NextFunction) => {
  res.status(err.status || 400).json({ ok: false, error: err.message || 'Bad request' });
});

const PORT = Number(process.env.PORT) || 3000;
const HOST = '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`Grandfuscator v2.1 server running on http://${HOST}:${PORT}`);
});
