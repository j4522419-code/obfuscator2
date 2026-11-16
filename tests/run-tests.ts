import assert from 'node:assert/strict';
import {
  executeLuau,
  NameStyle,
  obfuscate,
  ObfuscationPreset,
  resolveOptions,
  compileFlatV3IR,
  buildFlatV3Image,
  verifyLuauSyntax,
} from '../src/engine/index.js';
import { countEnvironmentTripwires } from '../src/engine/antiTamper.js';
import { PRNG } from '../src/engine/prng.js';
import { Op } from '../src/engine/ir.js';
import { generateFlatV3Runtime } from '../src/engine/v3Runtime.js';

interface TestCase {
  name: string;
  code: string;
  presets?: ObfuscationPreset[];
}

const FUNCTIONAL_TESTS: TestCase[] = [
  {
    name: 'Arithmetic, floor div //, precedence, hex/bin/underscore literals',
    code: `
      local a = 1_000 + 0xFF + 0b1010_0101
      local b = -2 ^ 2
      local c = 2 ^ 3 ^ 2
      local d = 17 // 5
      local e = -17 // 5
      local f = 17 % 5
      local g = (3.5 * 4 - 2) / 3
      -- Self-referential call assignment (must not clobber local before evaluating args!)
      local h = 0x5F3759DF
      h = bit32.bxor(h, 40503)
      h = bit32.bxor(bit32.rrotate(h, 5), h % 65535)
      print(a, b, c, d, e, f, g, h, 0xDEAD_BEEF)
    `,
  },
  {
    name: 'Strings, escapes (\\x, \\u, \\z, \\0, \\ddd), UTF-8 emoji & long brackets',
    code: `
      local s1 = "hello\\nworld\\t\\x41\\066\\u{1F525}"
      local s2 = "trim\\z
           med"
      local s3 = "null\\0inside"
      local s4 = [==[
first line
second [line] "quoted" 'single'
]==]
      local s5 = "日本語テスト⚔️"
      print(#s1, string.byte(s1, 12, 17))
      print(s2, #s3, string.byte(s3, 5), string.byte(s3, 6))
      print(s4)
      print(s5, #s5)
      print("a" .. "b" .. 123 .. "c" .. 45)
    `,
  },
  {
    name: 'Luau string interpolation (nested, tables, escapes, custom __tostring)',
    code: `
      local name = "Grandfuscator"
      local hp, maxHp = 85, 100
      local obj = setmetatable({ tag = "VIP" }, {
        __tostring = function(self) return "<" .. self.tag .. ">" end
      })
      local msg = \`Player {name} {obj}: {hp}/{maxHp} ({math.floor(hp / maxHp * 100)}%) nested={\`[{({ x = 42 }).x}]\`}\`
      local plain = \`no interp \\{literal\\} \\\`tick\\\`\`
      local single = \`{999}\`
      local empty = \`\`
      print(msg)
      print(plain, single, #empty)
    `,
  },
  {
    name: 'Luau compound assignments (+=, -=, *=, /=, //=, %=, ^=, ..=) + single LHS eval',
    code: `
      local x = 10
      x += 5
      x -= 3
      x *= 4
      x /= 2
      x //= 5
      x ^= 3
      x %= 50
      local s = "start"
      s ..= "-"
      s ..= tostring(x)

      local objCalls, keyCalls = 0, 0
      local store = { 100, 200, 300, hp = 50 }
      local function getStore() objCalls += 1; return store end
      local function getKey() keyCalls += 1; return 2 end
      getStore()[getKey()] += 77
      getStore().hp -= 15
      print(x, s, store[2], store.hp, objCalls, keyCalls)
    `,
  },
  {
    name: 'Luau if-then-elseif-else expressions & short-circuit and/or',
    code: `
      local function classify(n)
        return if n < 0 then "neg"
          elseif n == 0 then "zero"
          elseif n < 10 then "small"
          else "big"
      end
      local falsyPick = if true then false else true
      local nilPick = if false then 1 else nil
      local side = 0
      local function bump(v) side += 1; return v end
      local r1 = false and bump(1)
      local r2 = nil and bump(2)
      local r3 = 0 or bump(3)
      local r4 = false or bump(42)
      print(classify(-5), classify(0), classify(7), classify(99))
      print(falsyPick, nilPick, r1, r2, r3, r4, side)
    `,
  },
  {
    name: 'Full strict Roblox Luau type syntax + attributes + contextual keywords',
    code: `
      --!strict
      export type PlayerData = {
        read userId: number,
        coins: number,
        rank: "Bronze" | "Silver" | "Gold",
        tags: { string }?,
        meta: { [string]: any },
      }
      type Callback<T, R = boolean> = (item: T, idx: number) -> R
      type UnionLeading = | "a" | "b" | nil
      type Inter = { a: number } & { b: string }

      @native
      local function transform<T>(list: { T }, fn: Callback<T, string>, ...: number): ({ string }, number)
        local out: { string } = {}
        for i: number, v: T in list do
          out[i] = fn(v, i)
        end
        return out, select("#", ...) :: number
      end

      -- Contextual keywords used as normal identifiers & calls:
      local continue = 10
      continue += 5
      local export = "exported"
      local tName = type(continue)

      local data: PlayerData = {
        userId = 12345,
        coins = 500,
        rank = "Gold",
        tags = { "founder", "beta" },
        meta = { level = 20 },
      }
      local mapped, extraCount = transform(data.tags :: { string }, function(tag: string, i: number): string
        return \`{i}:{tag}\`
      end, 7, 8, 9)
      print(table.concat(mapped, ","), extraCount, continue, export, tName, data.rank)
    `,
  },
  {
    name: 'All loops (numeric for, while, repeat-until inner local scope) + break + continue',
    code: `
      -- Numeric for with continue, break, and loop-var mutation
      local acc = {}
      for i = 1, 10 do
        if i % 2 == 0 then continue end
        if i == 9 then break end
        local copy = i
        i = 999 -- must not corrupt internal loop counter!
        acc[#acc + 1] = copy
      end

      -- Negative step & zero-trip
      local down = {}
      for i = 5, 1, -2 do down[#down + 1] = i end
      local zero = 0
      for i = 10, 1, 1 do zero += 1 end

      -- While with continue & break
      local w, wSum = 0, 0
      while w < 8 do
        w += 1
        if w == 3 or w == 6 then continue end
        if w == 8 then break end
        wSum += w
      end

      -- Repeat..until reading local declared inside body + continue!
      local r, rLog = 0, {}
      repeat
        r += 1
        local done = (r >= 5)
        if r == 2 then continue end
        rLog[#rLog + 1] = r
      until done

      print(table.concat(acc, ","), table.concat(down, ","), zero, wSum, table.concat(rLog, ","))
    `,
  },
  {
    name: 'Luau generalized iteration (raw arrays, dicts, pairs, ipairs, gmatch, custom __iter)',
    code: `
      local arr = { "alpha", "beta", "gamma", "delta" }
      local out1 = {}
      for i, v in arr do
        if i == 2 then continue end
        out1[#out1 + 1] = \`{i}={v}\`
      end

      local dict = { hp = 100, mp = 40, sp = 15 }
      local sum = 0
      for k, v in dict do
        sum += v
      end

      local words = {}
      for w in string.gmatch("Grandfuscator protects Roblox Luau", "%w+") do
        words[#words + 1] = w
      end

      -- Custom __iter metamethod (Luau generalized iteration protocol!)
      local range = setmetatable({ from = 10, to = 13 }, {
        __iter = function(self)
          local cur = self.from - 1
          return function()
            cur += 1
            if cur <= self.to then
              return cur, cur * cur
            end
            return nil
          end
        end
      })
      local sq = {}
      for k, v in range do
        sq[#sq + 1] = \`{k}:{v}\`
      end

      print(table.concat(out1, "|"), sum, table.concat(words, "-"), table.concat(sq, ","))
    `,
  },
  {
    name: 'Closures, mutable shared upvalues, deep nesting, recursion & loop upvalue capture',
    code: `
      local function makeAccount(initial)
        local balance = initial
        local tx = 0
        local function deposit(n)
          balance += n
          tx += 1
          return function()
            return balance, tx
          end
        end
        local function withdraw(n)
          balance -= n
          tx += 1
        end
        return deposit, withdraw, function() return balance, tx end
      end

      local dep, wdr, info = makeAccount(100)
      local snap = dep(50)
      wdr(30)
      local b1, t1 = snap()
      local b2, t2 = info()

      -- Loop closure capture (every iteration MUST have its own closed upvalue!)
      local fns = {}
      for i = 1, 5 do
        local doubled = i * 2
        fns[i] = function(add)
          doubled += add
          return \`{i}:{doubled}\`
        end
      end

      -- Recursive local function
      local function fib(n)
        if n <= 1 then return n end
        return fib(n - 1) + fib(n - 2)
      end

      print(b1, t1, b2, t2, fns[1](1), fns[3](10), fns[5](0), fns[1](1), fib(10))
    `,
  },
  {
    name: 'Varargs, multi-returns, nil holes, table setlist, swaps & LHS eval order',
    code: `
      local function sparse()
        return "first", nil, "third", nil
      end
      local function empty() end
      local function passthrough(head, ...)
        local n = select("#", ...)
        local packed = { head, ... }
        return n, packed[1], packed[2], packed[3], packed[4], ...
      end

      local n, p1, p2, p3, p4, x1, x2, x3 = passthrough("H", sparse())
      local single = (sparse())
      local tbl = { 10, 20, sparse() }
      local tblEmpty = { 10, 20, empty() }

      local a, b, c = 1, 2, 3
      a, b, c = c, a, b

      -- Classic Lua evaluation order: i, arr[i] = i + 1, 99 assigns arr[old_i] = 99
      local i = 1
      local arr = { 0, 0, 0 }
      i, arr[i] = i + 1, 99

      local d, e, f = 7
      print(n, p1, p2, p3, p4, x1, x2, x3)
      print(single, tbl[1], tbl[2], tbl[3], tbl[4], tbl[5], #tblEmpty)
      print(a, b, c, i, arr[1], arr[2], d, e, f)
    `,
  },
  {
    name: 'OOP classes, self methods & metamethods (__index, __add, __call, __eq, __lt)',
    code: `
      local Vec2 = {}
      Vec2.__index = Vec2

      function Vec2.new(x: number, y: number)
        return setmetatable({ x = x, y = y }, Vec2)
      end

      function Vec2:magSq(): number
        return self.x * self.x + self.y * self.y
      end

      function Vec2:scale(k: number)
        self.x *= k
        self.y *= k
        return self
      end

      function Vec2.__add(a, b)
        return Vec2.new(a.x + b.x, a.y + b.y)
      end

      function Vec2.__eq(a, b)
        return a.x == b.x and a.y == b.y
      end

      function Vec2:__tostring()
        return \`({self.x},{self.y})\`
      end

      local v1 = Vec2.new(3, 4)
      local v2 = Vec2.new(1, -2):scale(3)
      local v3 = v1 + v2
      local callable = setmetatable({ base = 100 }, {
        __call = function(self, x, y) return self.base + x * y end
      })
      print(tostring(v3), v1:magSq(), v3 == Vec2.new(6, -2), callable(7, 8))
    `,
  },
  {
    name: 'Coroutines / yielding (Roblox task.wait & InvokeServer simulation) + pcall/xpcall',
    code: `
      local function asyncSequence(mul)
        local a = coroutine.yield("step1")
        local b = coroutine.yield("step2", a * mul)
        return "done", a + b
      end

      local co = coroutine.create(asyncSequence)
      local ok1, s1 = coroutine.resume(co, 5)
      local ok2, s2, prod = coroutine.resume(co, 7)
      local ok3, s3, total = coroutine.resume(co, 13)

      local pOk1, pVal1 = pcall(function(x) return x * 3 end, 14)
      local pOk2, pErr2 = pcall(function()
        error("CUSTOM_ERR_77", 0)
      end)
      local xOk, xRes = xpcall(
        function() error("BOOM", 0) end,
        function(e) return "handled:" .. tostring(e) end
      )

      print(ok1, s1, ok2, s2, prod, ok3, s3, total)
      print(pOk1, pVal1, pOk2, pErr2, xOk, xRes)
    `,
  },
  {
    name: 'Large table constructor (>80 mixed list/record/computed entries)',
    code: `
      local t = {
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
        21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        alpha = "A",
        41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,
        ["be" .. "ta"] = "B",
        61,62,63,64,65,66,67,68,69,70,
      }
      local sum = 0
      for i = 1, 70 do sum += t[i] end
      print(#t, sum, t.alpha, t.beta)
    `,
  },
  {
    name: 'Realistic Roblox Combat & Inventory ModuleScript with --@novm and --@vm pragmas',
    code: `
      --!strict
      type Item = { id: string, power: number, rarity: string }

      -- Mock Roblox Services
      local firedEvents: { string } = {}
      local mockGame = {
        GetService = function(self, serviceName: string)
          if serviceName == "ReplicatedStorage" then
            return {
              WaitForChild = function(_, child: string)
                return {
                  FireServer = function(_, action: string, payload: any)
                    firedEvents[#firedEvents + 1] = \`{serviceName}.{child}:{action}:{payload.dmg}\`
                  end
                }
              end
            }
          end
          return {}
        end
      }

      local ReplicatedStorage = mockGame:GetService("ReplicatedStorage")
      local CombatRemote = ReplicatedStorage:WaitForChild("CombatRemote")

      local comboMultiplier = 1.0
      local totalDamageDealt = 0

      --@novm
      local function stepFramePhysics(dt: number, baseSpeed: number): number
        -- Runs at 100% native Roblox Luau speed while sharing live upvalues with the VM!
        local dist = baseSpeed * dt * comboMultiplier
        totalDamageDealt += math.floor(dist)
        return dist
      end

      --@vm
      local function verifyAndStrike(item: Item, critRoll: number): number
        local bonus = if item.rarity == "Legendary" then 2.5 elseif item.rarity == "Epic" then 1.6 else 1.0
        local isCrit = critRoll >= 0.8
        local raw = math.floor(item.power * bonus * comboMultiplier * (if isCrit then 2 else 1))
        comboMultiplier += 0.25
        totalDamageDealt += raw
        CombatRemote:FireServer("Strike", { id = item.id, dmg = raw })
        return raw
      end

      local sword: Item = { id = "Voidblade", power = 40, rarity = "Legendary" }
      local d1 = verifyAndStrike(sword, 0.5)
      local step1 = stepFramePhysics(0.5, 20)
      local d2 = verifyAndStrike(sword, 0.95)
      print(d1, step1, d2, comboMultiplier, totalDamageDealt, table.concat(firedEvents, " | "))
    `,
  },
];

let passed = 0;
let failed = 0;

function pass(label: string): void {
  passed++;
  console.log(`  \x1b[32m✓\x1b[0m ${label}`);
}

function fail(label: string, detail: string): void {
  failed++;
  console.error(`  \x1b[31m✗\x1b[0m ${label}\n    ${detail}`);
}

console.log('\n=== Grandfuscator 2.1 Runtime & Red-Team Roblox Luau 0.747 Suite ===\n');

// Runtime backend selection: compat remains the default; explicit v3 emits and runs its own backend.
console.log('--- Runtime backend selection ---');
try {
  assert.equal(resolveOptions({}).runtime, 'compat');
  const source = 'print("runtime backend")';
  const stable = obfuscate(source, { seed: 'runtime-scaffold' });
  assert.equal(stable.stats.engineVersion, '2.1.0');
  assert.equal(executeLuau(stable.code).stdout, executeLuau(source).stdout);
  const v3 = obfuscate(source, { runtime: 'v3-experimental', seed: 'runtime-v3' });
  assert.equal(v3.stats.architecture, 'Oblivion S-Box Interleaved Flat-VM');
  assert.equal(v3.stats.zeroConstantPool, true);
  assert.equal(v3.stats.zeroStringTable, true);
  assert.equal(v3.stats.antiTamperArmed, false);
  assert.equal(v3.stats.robloxLockArmed, false);
  assert.equal(v3.stats.selfMutatingBuffer, false);
  assert.equal(executeLuau(v3.code).stdout, executeLuau(source).stdout);
  assert.throws(() => obfuscate(source, { runtime: 'v3-experimental', robloxLock: true }), /not implemented by the v3 flat runtime/);
  pass('compat remains default; explicit v3 emits a verified flat-vmem runtime and rejects unsupported locks');
} catch (err) {
  fail('Runtime backend selection', err instanceof Error ? err.stack || err.message : String(err));
}

// Step 2: exercise CFG transforms and verify the global flat layout on control flow, closures and SBLK data.
console.log('--- v3 CFG + flat-layout compiler pipeline ---');
try {
  const longPayload = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const source = `
    local function make(n)
      local captured = n
      return function(x) captured += x; return captured end
    end
    local f = make(1)
    local blob = "${longPayload}"
    local i = 0
    while i < 3 do
      if i % 2 == 0 then print(f(i), blob) else print(i) end
      i += 1
    end
  `;
  const v3opts = resolveOptions({ runtime: 'v3-experimental', preset: 'fortress' });
  assert.equal(v3opts.graphCff, true);
  assert.equal(v3opts.opcodeMutation, true);
  const flat = compileFlatV3IR(source, v3opts, new PRNG('v3-flat-layout-focused'));
  const image = flat.vmem!;
  const slots = image.slots;
  const codeSlots = slots.flatMap((ins, pc) => ins ? [{ ins, pc }] : []);
  const branchOps = new Set<Op>([
    Op.JMPX, Op.CHAIN_HOP, Op.JMPF, Op.JMPT, Op.EQJ, Op.NEJ, Op.LTJ, Op.LEJ,
    Op.STATE_JLE, Op.STATE_JEQ, Op.OPQ_NEVER, Op.OPQ_ALWAYS,
    Op.FORPREP, Op.FORLOOP, Op.ITERPREP, Op.TFORLOOP,
  ]);
  assert.equal(image.totalSlots, slots.length);
  assert.ok(image.rootEntryPC >= 0 && image.rootEntryPC < slots.length && slots[image.rootEntryPC] !== null);
  assert.ok(codeSlots.length < slots.length, 'expected inline SBLK data slots in flat vmem');
  assert.ok(flat.cfgStats.fusedSuperinstructions > 0);
  assert.ok(flat.cfgStats.cffDispatcherNodes > 0);
  assert.ok(flat.cfgStats.jumpChainHops > 0);
  for (const { ins } of codeSlots) {
    if (branchOps.has(ins.op)) {
      assert.ok(ins.b >= 0 && ins.b < slots.length && slots[ins.b] !== null, `invalid target for ${Op[ins.op]}: ${ins.b}`);
    }
    if (ins.op === Op.CLOS_NEW) {
      assert.ok(ins.b >= 0 && ins.b < slots.length && slots[ins.b] !== null, `invalid closure entry PC: ${ins.b}`);
    }
    if (ins.op === Op.SBLK) {
      assert.ok(ins.b >= 0 && ins.b < slots.length && slots[ins.b] === null, `SBLK target is not a data slot: ${ins.b}`);
    }
  }
  assert.ok(codeSlots.some(({ ins }) => ins.op === Op.SBLK), 'expected long-string SBLK lowering');
  pass(`v3 CFG transforms/layout valid (${slots.length} slots, ${slots.length - codeSlots.length} data slots, ${flat.cfgStats.cfgBlocks} blocks)`);
} catch (err) {
  fail('v3 CFG + flat-layout compiler pipeline', err instanceof Error ? err.stack || err.message : String(err));
}

// Step 3: prove the CCFI encoder and 12-byte flat-image serializer agree on slots and metadata.
console.log('--- v3 CCFI + flat-image serialization ---');
try {
  const payload = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.repeat(2);
  const source = `local function outer(x) local n=x; return function(y) n+=y; return n end end local f=outer(3); local text="${payload}"; if f(2)>4 then print(text) end`;
  const opts = resolveOptions({ runtime: 'v3-experimental', preset: 'fortress' });
  const { image } = buildFlatV3Image(source, opts, new PRNG('v3-serializer-focused'));
  assert.equal(image.format, 'grandfuscator-flat-vmem-v3');
  assert.equal(image.vmemBytes.length, image.slotCount * 12);
  assert.equal(image.slotKinds.length, image.slotCount);
  assert.ok(image.rootEntryPC >= 0 && image.rootEntryPC < image.slotCount);
  assert.equal(image.slotKinds[image.rootEntryPC], 1);
  assert.ok(image.rootEntryKey !== 0);
  assert.ok(image.stats.dataSlots > 0);
  assert.equal(image.stats.codeSlots + image.stats.dataSlots, image.slotCount);
  assert.ok(image.stats.protoDescriptors >= 2);
  assert.ok(image.protoDescriptors.every((p) => image.slotKinds[p.entryPC] === 1));
  const handlerIds = image.dispatchTable.map((entry) => entry.physId);
  assert.equal(new Set(handlerIds).size, handlerIds.length, 'physical handler IDs must be unique');
  assert.ok(image.dispatchTable.some((entry) => entry.logicalOp === 'DECOY'));
  assert.ok(image.dispatchTable.filter((entry) => entry.logicalOp !== 'DECOY').every((entry) => image.cipher.handlers[entry.physId] !== null));
  assert.deepEqual([...image.wordOffsets].sort((a, b) => a - b), [0, 4, 8]);
  pass(`v3 CCFI serialization valid (${image.vmemBytes.length} bytes, ${image.stats.realHandlers} ciphers, ${image.stats.protoDescriptors} closure descriptors)`);
} catch (err) {
  fail('v3 CCFI + flat-image serialization', err instanceof Error ? err.stack || err.message : String(err));
}

// 1. Functional Equivalence Across All 3 Pure-VM Presets (Swift / Fortress / Nightmare)
const presets: ObfuscationPreset[] = ['swift', 'fortress', 'nightmare'];
for (const tc of FUNCTIONAL_TESTS) {
  const baseline = executeLuau(tc.code);
  if (!baseline.ok) {
    fail(`[BASELINE] ${tc.name}`, baseline.stderr);
    continue;
  }

  for (const preset of tc.presets ?? presets) {
    try {
      const obf = obfuscate(tc.code, { preset });
      const run = executeLuau(obf.code);
      if (!run.ok) {
        fail(`[${preset}] ${tc.name}`, `Runtime error: ${run.stderr}`);
      } else if (run.stdout !== baseline.stdout) {
        fail(
          `[${preset}] ${tc.name}`,
          `Output mismatch!\n      Expected: ${JSON.stringify(baseline.stdout)}\n      Actual:   ${JSON.stringify(run.stdout)}`,
        );
      } else {
        pass(`[${preset}] ${tc.name}`);
      }
    } catch (err) {
      fail(`[${preset}] ${tc.name}`, err instanceof Error ? err.stack || err.message : String(err));
    }
  }
}

// v3 runtime smoke parity gate. Broad corpus parity remains an acceptance gate before enabling the backend.
console.log('--- v3 flat-runtime smoke parity ---');
{
  const longText = 'long flat string constant for SBLK data-region smoke verification: ' + 'X'.repeat(24);
  const cases = [
    { label: 'closure/string/table/branch/negative-loop', source: `local function outer(x)local n=x;return function(y)n+=y;return n end end local f=outer(3);local s="hi";local t={a=2};local label=if -2<0 then "neg" else "bad";local rev={};for i=3,1,-1 do rev[#rev+1]=i end;if t.a>1 then print(f(2),s,2+3,label,table.concat(rev,",")) end` },
    { label: 'flat SBLK payload and float load', source: `local long="${longText}";print(#long,3.5)` },
  ];
  for (const preset of presets) {
    for (let c = 0; c < cases.length; c++) {
      const tc = cases[c];
      try {
        const baseline = executeLuau(tc.source);
        const seed = c === 0 ? `step4-smoke-${preset}` : `step4-sblk-${preset}`;
        const rng = new PRNG(seed);
        const opts = resolveOptions({ runtime: 'v3-experimental', preset, seed });
        const { image } = buildFlatV3Image(tc.source, opts, rng);
        const code = generateFlatV3Runtime(image, opts, rng);
        const syntax = verifyLuauSyntax(code);
        const run = executeLuau(code);
        if (!baseline.ok) fail(`[v3 ${preset}] baseline ${tc.label}`, baseline.stderr);
        else if (!syntax.ok) fail(`[v3 ${preset}] syntax ${tc.label}`, syntax.error || 'compile failed');
        else if (!run.ok) fail(`[v3 ${preset}] ${tc.label}`, run.stderr);
        else if (run.stdout !== baseline.stdout) fail(`[v3 ${preset}] ${tc.label}`, `Expected ${JSON.stringify(baseline.stdout)}; got ${JSON.stringify(run.stdout)}`);
        else pass(`[v3 ${preset}] ${tc.label}`);
      } catch (err) {
        fail(`[v3 ${preset}] ${tc.label}`, err instanceof Error ? err.stack || err.message : String(err));
      }
    }
  }
}

// v3 broad functional-parity acceptance gate. Keep behavioral fixtures enabled;
// targeted smoke checks alone are not sufficient to authorize executable output.
console.log('\n--- v3 broad functional parity acceptance gate ---');
for (const preset of presets) {
  for (const tc of FUNCTIONAL_TESTS) {
    try {
      const baseline = executeLuau(tc.code);
      const seed = `v3-parity-${preset}-${tc.name}`;
      const rng = new PRNG(seed);
      const opts = resolveOptions({ runtime: 'v3-experimental', preset, seed });
      const { image } = buildFlatV3Image(tc.code, opts, rng);
      const code = generateFlatV3Runtime(image, opts, rng);
      const syntax = verifyLuauSyntax(code);
      const run = executeLuau(code);
      if (!baseline.ok) fail(`[v3 ${preset}] baseline ${tc.name}`, baseline.stderr);
      else if (!syntax.ok) fail(`[v3 ${preset}] syntax ${tc.name}`, syntax.error || 'compile failed');
      else if (!run.ok) fail(`[v3 ${preset}] ${tc.name}`, run.stderr);
      else if (run.stdout !== baseline.stdout) fail(`[v3 ${preset}] ${tc.name}`, `Expected ${JSON.stringify(baseline.stdout)}; got ${JSON.stringify(run.stdout)}`);
      else pass(`[v3 ${preset}] ${tc.name}`);
    } catch (err) {
      fail(`[v3 ${preset}] ${tc.name}`, err instanceof Error ? err.stack || err.message : String(err));
    }
  }
}

// 2. Compatibility-runtime regression: recursion, NaN, coroutines, and arithmetic
console.log('\n--- Compatibility VM Recursion, NaN, Coroutine & Arithmetic Stress ---');
{
  const tortureSrc = `
    -- Constant folding + VM-MBA positive/negative/edge integers + IEEE-754 NaN relational branches
    local kFold = (120 + 37) * 4 - (2 ^ 5) + (99 // 4)
    local kNeg = -987654
    local kBig = 2147483640
    local kZero = 0
    local nan = 0 / 0
    local nanBranch = "ok"
    if nan < 5 then nanBranch = "bad1" end
    if nan <= 5 then nanBranch = "bad2" end
    if nan > 5 then nanBranch = "bad3" end
    if nan == nan then nanBranch = "bad4" end
    if nan ~= nan then nanBranch = nanBranch .. ":neq" end

    -- Deep multi-branch dispatcher (triggers multi-hub Graph-CFF + 3-hop jump chains + opaque forks)
    local function classify(x: number): string
      local out = ""
      if x < -10 then
        out = "neg_far"
      elseif x < 0 then
        out = "neg_near"
      elseif x == 0 then
        out = "zero"
      elseif x == 1 then
        out = "one"
      elseif x < 10 then
        out = "small:" .. tostring(x * 7 - 3)
      elseif x < 100 then
        local s = 0
        for i = 1, x, 3 do s += (100 - i) // 2 end
        out = "mid:" .. tostring(s)
      else
        out = "large:" .. tostring(1000 / x)
      end
      return out
    end

    -- Mutual & self recursion hitting SAME self-mutating buffer PCs across concurrent live frames!
    local function ack(m: number, n: number): number
      if m == 0 then return n + 1 end
      if n == 0 then return ack(m - 1, 1) end
      return ack(m - 1, ack(m, n - 1))
    end

    -- Coroutine yielding mid-VM while another call mutates the SAME function's bytecode buffer!
    local function gen(seed: number)
      local a = seed + 10
      local b = coroutine.yield(a)
      local c = a * 3 - b
      return coroutine.yield(c) + a + c
    end
    local co1 = coroutine.create(gen)
    local co2 = coroutine.create(gen)
    local _, r1a = coroutine.resume(co1, 5)
    local _, r2a = coroutine.resume(co2, 20)
    local _, r1b = coroutine.resume(co1, 7)
    local _, r2b = coroutine.resume(co2, 11)
    local _, r1c = coroutine.resume(co1, 100)
    local _, r2c = coroutine.resume(co2, 200)

    -- Swapped table get/set + superinstruction GETGK/ADDK/SUBK/MULK
    local tbl = {}
    for i = 1, 8 do
      local key = "k" .. tostring(i)
      tbl[key] = math.abs(i * 13 - 50)
    end

    print(kFold, kNeg, kBig, kZero, nanBranch)
    print(classify(-50), classify(-2), classify(0), classify(1), classify(6), classify(25), classify(250))
    print("ack", ack(2, 4), ack(3, 2))
    print("co", r1a, r2a, r1b, r2b, r1c, r2c)
    print("tbl", tbl.k1, tbl.k4, tbl.k8)
  `;

  const base = executeLuau(tortureSrc);
  assert.equal(base.ok, true, base.stderr);

  for (const preset of presets) {
    const obf = obfuscate(tortureSrc, { preset });
    const run = executeLuau(obf.code);
    const s = obf.stats;
    if (run.ok && run.stdout === base.stdout && s.loadstringUsed === false) {
      pass(
        `[${preset}] Compatibility VM torture (blocks=${s.cfgBlocks}, cff=${s.cffDispatcherNodes}, hops=${s.jumpChainHops}, mut=${s.mutatedInstructions}, mbaK=${s.destroyedConstants}, uVM=${s.microVmInstructions})`,
      );
    } else {
      fail(`[${preset}] Compatibility VM torture`, `err=${run.stderr}\nexp=${base.stdout}\ngot=${run.stdout}`);
    }
  }
}

// 3. ModuleScript Return Value, Top-Level Varargs & All 4 Naming Styles
console.log('\n--- ModuleScript, Varargs & Naming Styles ---');
{
  const moduleCode = `
    local Module = {}
    local secretSalt = 1337
    function Module.compute(a: number, b: number): (number, string)
      return (a + b) * secretSalt, \`ok:{a}:{b}\`
    end
    return Module
  `;
  for (const style of ['short', 'barcode', 'shadow', 'hex'] as NameStyle[]) {
    const obf = obfuscate(moduleCode, { preset: 'nightmare', nameStyle: style, watermark: '' });
    // Single-line harness preserves exact line=1 so ALL 8 anti-tamper layers stay ARMED during require()!
    const harness = `local m=(function(...)${obf.code} end)();local n,t=m.compute(3,4);print(n,t)`;
    const run = executeLuau(harness);
    if (run.ok && run.stdout.trim() === '9359\tok:3:4' && obf.stats.verified) {
      pass(`[nameStyle=${style}] Nightmare ModuleScript return with all 8 anti-tamper layers armed`);
    } else {
      fail(`[nameStyle=${style}] ModuleScript`, run.stderr || run.stdout);
    }
  }
}

// 4. Zero `loadstring`, Zero `string.char` & Zero Plaintext Leakage Verification
console.log('\n--- Zero-loadstring & Zero-Leakage Audit ---');
{
  const secretScript = `
    -- Confidential Developer Comment DO_NOT_LEAK_COMMENT
    export type SecretAdminPayload = { token: string }
    local superSecretApiKey = "GF_LIVE_SECRET_99887766_XYZ"
    local hiddenRemoteName = "UltraSecretAdminRemoteEvent"
    local webhookEndpoint = "https://licensing.example.com/v2/validate"
    local secretPort = 49157
    local function calculateLicenseChecksum(inputKey: string): string
      return inputKey .. ":" .. hiddenRemoteName .. ":" .. webhookEndpoint .. ":" .. tostring(secretPort)
    end
    print(calculateLicenseChecksum(superSecretApiKey))
  `;
  const forbidden = [
    'loadstring',
    'string.char',
    '.char(',
    'setfenv',
    '"slna"',
    'DO_NOT_LEAK_COMMENT',
    'SecretAdminPayload',
    'superSecretApiKey',
    'GF_LIVE_SECRET_99887766_XYZ',
    'hiddenRemoteName',
    'UltraSecretAdminRemoteEvent',
    'webhookEndpoint',
    'licensing.example.com',
    'calculateLicenseChecksum',
    'inputKey',
    '49157',
  ];

  for (const preset of presets) {
    const obf = obfuscate(secretScript, { preset });
    const leaked = forbidden.filter((w) => obf.code.includes(w));
    const run = executeLuau(obf.code);
    if (leaked.length === 0 && run.ok && run.stdout.includes('GF_LIVE_SECRET_99887766_XYZ') && run.stdout.includes('49157')) {
      pass(`[${preset}] Zero loadstring, zero string.char & zero secret/constant leakage (${forbidden.length} checks)`);
    } else {
      fail(`[${preset}] Leakage audit`, `Leaked: ${leaked.join(', ')} | err: ${run.stderr}`);
    }
  }
}

// 5. Per-Build Dual-VM Polymorphism Uniqueness Test
{
  const sample = `local x = 0; for i = 1, 5 do x += i * 3 end; print("sum", x)`;
  const b1 = obfuscate(sample, { preset: 'fortress' });
  const b2 = obfuscate(sample, { preset: 'fortress' });
  assert.notEqual(b1.stats.buildId, b2.stats.buildId);
  assert.notEqual(b1.code, b2.code);
  const r1 = executeLuau(b1.code);
  const r2 = executeLuau(b2.code);
  if (r1.ok && r2.ok && r1.stdout === 'sum\t45\n' && r2.stdout === 'sum\t45\n') {
    pass(
      `Per-build Dual-VM polymorphism (${b1.stats.buildId} [${b1.stats.wordPermutation}/${b1.stats.headerPermutation}] vs ${b2.stats.buildId} [${b2.stats.wordPermutation}/${b2.stats.headerPermutation}])`,
    );
  } else {
    fail('Polymorphism test', `${r1.stderr} / ${r2.stderr}`);
  }
}

// 6. FULL 11-ATTACK RED-TEAM ANTI-TAMPER PENETRATION SUITE!
console.log('\n--- 11-Attack Red-Team Anti-Tamper Penetration Suite ---');
{
  const flipPayloadByte = (code: string, which: 0 | 1): string => {
    const matches = [...code.matchAll(/"([^"\r\n]*)"/g)].filter((m) => m[1].length >= 15);
    const target = matches[Math.min(which, matches.length - 1)];
    assert.ok(target && target.index !== undefined);
    const body = target[1];
    const pos = Math.floor(body.length / 2);
    const rep = body[pos] === 'K' ? 'M' : 'K';
    const next = body.slice(0, pos) + rep + body.slice(pos + 1);
    return code.slice(0, target.index) + `"${next}"` + code.slice(target.index + target[0].length);
  };

  for (const preset of presets) {
    const src = `
      local tag = "VAULT_SECRET_OK_777"
      local sum = 0
      for i = 1, 6 do sum += i * 7 end
      print(tag, sum)
    `;
    const obf = obfuscate(src, { preset, antiTamper: true, watermark: 'Protected by Grandfuscator 2.1' });
    const [hdrLine, vmLine] = obf.code.split('\n');
    const clean = executeLuau(obf.code);
    if (!clean.ok || clean.stdout.trim() !== 'VAULT_SECRET_OK_777\t147') {
      fail(`[${preset}] Clean run before red-team`, clean.stderr || clean.stdout);
      continue;
    }

    const withSameLineHook = (hook: string) => `${hdrLine}\n${hook}${vmLine}`;
    // Insert a single newline mid-VM (between two statements) to test tail anchor + live GUARD opcode
    const midIdx = vmLine.indexOf(';', Math.floor(vmLine.length * 0.55));
    const singleMidNewline = `${hdrLine}\n${vmLine.slice(0, midIdx + 1)}\n${vmLine.slice(midIdx + 1)}`;

    const attacks: Array<{ name: string; payload: string }> = [
      { name: 'Full Beautifier', payload: obf.code.replace(/;/g, ';\n') },
      { name: 'Prepended Spy Line', payload: `local _spy = 1\n` + obf.code },
      { name: 'Single Mid-File Newline', payload: singleMidNewline },
      {
        name: 'buffer.readstring Dumper Hook (Lua)',
        payload: withSameLineHook(
          `do local _o=buffer;local _c=table.clone(_o);_c.readstring=function(b,p,l)return _o.readstring(b,p,l)end;table.freeze(_c);buffer=_c end;`,
        ),
      },
      {
        name: 'bit32.bxor Key-Logger Hook (Lua)',
        payload: withSameLineHook(
          `do local _o=bit32;local _c=table.clone(_o);_c.bxor=function(...)return _o.bxor(...)end;table.freeze(_c);bit32=_c end;`,
        ),
      },
      {
        name: 'Fake [C] newcclosure (coroutine.wrap) on pcall',
        payload: withSameLineHook(
          `do local _p=pcall;pcall=coroutine.wrap(function(...)local a={...};while true do a={coroutine.yield(_p(table.unpack(a)))}end end)end;`,
        ),
      },
      {
        name: 'Fake [C] newcclosure on buffer.readstring',
        payload: withSameLineHook(
          `do local _o=buffer;local _r=_o.readstring;local _c=table.clone(_o);_c.readstring=coroutine.wrap(function(...)local a={...};while true do a={coroutine.yield(_r(table.unpack(a)))}end end);table.freeze(_c);buffer=_c end;`,
        ),
      },
      {
        name: 'Unfrozen Cloned Stdlib Table Spy',
        payload: withSameLineHook(`do math=table.clone(math)end;`),
      },
      {
        name: 'Metatable Proxy on Stdlib Table',
        payload: withSameLineHook(`do math=table.freeze(setmetatable(table.clone(math),{}))end;`),
      },
      {
        name: 'debug.info Spoofer (fakes [C] for all fns)',
        payload: withSameLineHook(
          `do local _d=debug;local _c=table.clone(_d);_c.info=function(f,w)if w=="l"then return _d.info(2,"l")end;return"[C]",-1,"bxor",0,true end;table.freeze(_c);debug=_c end;`,
        ),
      },
      {
        name: 'Genuine [C] Function Swap (lrotate <-> rrotate)',
        payload: withSameLineHook(
          `do local _o=bit32;local _c=table.clone(_o);_c.lrotate,_c.rrotate=_o.rrotate,_o.lrotate;table.freeze(_c);bit32=_c end;`,
        ),
      },
      {
        name: '1-Byte Encrypted Bytecode Payload Flip',
        payload: flipPayloadByte(obf.code, 0),
      },
      {
        name: '1-Byte Encrypted String-Vault Payload Flip',
        payload: flipPayloadByte(obf.code, 1),
      },
    ];

    const leakedAttacks: string[] = [];
    for (const atk of attacks) {
      const res = executeLuau(atk.payload, 1000);
      if (res.stdout.includes('VAULT_SECRET_OK_777')) {
        leakedAttacks.push(atk.name);
      }
    }

    if (leakedAttacks.length === 0) {
      pass(`[${preset}] Defeated ALL ${attacks.length}/${attacks.length} red-team attacks (hooks, newcclosure, debug spoof, proxy, beautify, 1B flip)`);
    } else {
      fail(`[${preset}] Red-team anti-tamper`, `Bypassed by: ${leakedAttacks.join(', ')}`);
    }
  }
}

// 7. Official Roblox Production Compiler Flags Compatibility (`-g0` zero-debug AND `-O2 -g1`)
console.log('\n--- Roblox Production Luau Compiler Flag Compatibility (-g0 & -O2 -g1) ---');
{
  const { spawnSync } = await import('node:child_process');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const { findLuauRuntime } = await import('../src/engine/index.js');
  const luauBin = findLuauRuntime()!;

  const sample = `
    local function fib(n: number): number
      if n <= 1 then return n end
      return fib(n - 1) + fib(n - 2)
    end
    print("prod_ok", fib(10))
  `;
  for (const preset of presets) {
    const obf = obfuscate(sample, { preset });
    const tmp = path.join(os.tmpdir(), `gf_prod_${preset}_${process.pid}.luau`);
    fs.writeFileSync(tmp, obf.code, 'utf8');
    const rG0 = spawnSync(luauBin, ['-g0', tmp], { encoding: 'utf8', timeout: 3000 });
    const rO2 = spawnSync(luauBin, ['-O2', '-g1', tmp], { encoding: 'utf8', timeout: 3000 });
    fs.unlinkSync(tmp);
    if (rG0.stdout.trim() === 'prod_ok\t55' && rO2.stdout.trim() === 'prod_ok\t55') {
      pass(`[${preset}] Exact execution under both Luau -g0 (stripped) and -O2 -g1 (Roblox production)`);
    } else {
      fail(`[${preset}] -g0 / -O2 -g1`, `-g0=${rG0.stdout}/${rG0.stderr} | -O2=${rO2.stdout}/${rO2.stderr}`);
    }
  }
}

// The v3 flat runtime must also survive stripped debug metadata and production optimization.
console.log('\\n--- v3 Luau compiler flags (-g0 & -O2 -g1) ---');
{
  const { spawnSync } = await import('node:child_process');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const { findLuauRuntime } = await import('../src/engine/index.js');
  const luauBin = findLuauRuntime()!;
  const sample = 'local function f(x)return x*x+1 end;print(f(9),"str",bit32.bxor(7,3))';
  for (const preset of presets) {
    const seed = `v3-prod-${preset}`;
    const obf = obfuscate(sample, { runtime: 'v3-experimental', preset, seed });
    const tmp = path.join(os.tmpdir(), `gf_v3_prod_${preset}_${process.pid}.luau`);
    fs.writeFileSync(tmp, obf.code, 'utf8');
    const rG0 = spawnSync(luauBin, ['-g0', tmp], { encoding: 'utf8', timeout: 3000 });
    const rO2 = spawnSync(luauBin, ['-O2', '-g1', tmp], { encoding: 'utf8', timeout: 3000 });
    fs.unlinkSync(tmp);
    if (rG0.stdout.trim() === '82\tstr\t4' && rO2.stdout.trim() === '82\tstr\t4') {
      pass(`[v3 ${preset}] exact execution under both stripped and production Luau flags`);
    } else {
      fail(`[v3 ${preset}] -g0 / -O2 -g1`, `-g0=${rG0.stdout}/${rG0.stderr} | -O2=${rO2.stdout}/${rO2.stderr}`);
    }
  }
}

// 8. Cryptographic 53-Bit Roblox PlaceId & GameId LUKS Key Locks (Zero Plaintext ID Leakage)
console.log('\n--- Cryptographic 53-Bit PlaceId & GameId Locks ---');
for (const preset of presets) {
  const allowedPlace1 = '17625359962123'; // > 2^43 modern 14-digit Roblox PlaceId!
  const allowedPlace2 = '1818';
  const allowedGame = '9944112233';

  const src = `print("AUTHORIZED_IN_PLACE", game.PlaceId)`;
  const obf = obfuscate(src, {
    preset,
    placeIds: [allowedPlace1, allowedPlace2],
    gameIds: [allowedGame],
    watermark: '',
    antiTamper: true,
  });

  const leakedId = obf.code.includes(allowedPlace1) || obf.code.includes(allowedGame);
  const okRun1 = executeLuau(`game={PlaceId=${allowedPlace1},GameId=${allowedGame}};${obf.code}`);
  const okRun2 = executeLuau(`game={PlaceId=${allowedPlace2},GameId=${allowedGame}};${obf.code}`);
  const wrongPlace = executeLuau(`game={PlaceId=123456789,GameId=${allowedGame}};${obf.code}`);
  const wrongGame = executeLuau(`game={PlaceId=${allowedPlace1},GameId=111111};${obf.code}`);
  const noGame = executeLuau(obf.code);

  if (
    !leakedId &&
    okRun1.ok && okRun1.stdout.trim() === `AUTHORIZED_IN_PLACE\t${allowedPlace1}` &&
    okRun2.ok && okRun2.stdout.trim() === `AUTHORIZED_IN_PLACE\t${allowedPlace2}` &&
    wrongPlace.stdout === '' &&
    wrongGame.stdout === '' &&
    noGame.stdout === ''
  ) {
    pass(`[${preset}] 53-bit PlaceId + GameId Micro-VM key lock (authorized runs, stolen returns cleanly, 0 ID leak)`);
  } else {
    fail(
      `[${preset}] PlaceId/GameId lock`,
      `leaked=${leakedId} ok1=${okRun1.stdout}/${okRun1.stderr} ok2=${okRun2.stdout}/${okRun2.stderr} wrongP=${wrongPlace.stdout} wrongG=${wrongGame.stdout}`,
    );
  }
}

// 9. Roblox 60-FPS Frame Budget Benchmark (10,000 tight-loop iterations under `-O2`)
console.log('\n--- Roblox 60-FPS Frame Budget Benchmark (10,000 loop ops) ---');
{
  const benchSrc = `
    local function vmLoop(n: number): number
      local acc = 0
      for i = 1, n do
        acc += (i * 3 - 1) % 97
      end
      return acc
    end

    --@novm
    local function renderSteppedLoop(n: number): number
      local acc = 0
      for i = 1, n do
        acc += (i * 3 - 1) % 97
      end
      return acc
    end

    local t0 = os.clock()
    local r1 = vmLoop(10000)
    local vmMs = (os.clock() - t0) * 1000

    local t1 = os.clock()
    local r2 = renderSteppedLoop(10000)
    local noVmMs = (os.clock() - t1) * 1000

    assert(r1 == r2)
    print(string.format("vm=%.2fms novm=%.3fms sum=%d", vmMs, noVmMs, r1))
  `;

  for (const preset of presets) {
    const obf = obfuscate(benchSrc, { preset });
    const run = executeLuau(obf.code);
    if (run.ok) {
      pass(
        `[${preset}] 10k-op benchmark: ${run.stdout.trim()} | size=${(obf.stats.outputBytes / 1024).toFixed(1)} KB | compile=${obf.stats.compileTimeMs}ms`,
      );
    } else {
      fail(`[${preset}] benchmark`, run.stderr);
    }
  }
}

// Red-team: common environment-logger / executor API tripwires
console.log('\\n--- Anti-environment-logger Tripwire Red-Team ---');
{
  const clean: Record<string, unknown> = { print: () => undefined, game: {} };
  const instrumented: Record<string, unknown> = {
    ...clean,
    hookfunction: () => undefined,
    getgenv: () => ({}),
    identifyexecutor: 'ExampleExecutor',
    syn: {},
  };
  const cleanHits = countEnvironmentTripwires(clean);
  const injectedHits = countEnvironmentTripwires(instrumented);
  if (cleanHits === 0 && injectedHits >= 4) {
    pass(`Environment tripwire detects injected logger/executor markers (${cleanHits} clean, ${injectedHits} injected)`);
  } else {
    fail('Environment tripwire red-team', `clean=${cleanHits}, injected=${injectedHits}`);
  }
}

// 10. 90-Seed Randomized Fuzz Test Across All Presets, Chain Depths, Toggle Combos & Naming Styles
console.log('\n--- 90-Seed Multi-Preset & Feature-Matrix Fuzz Verification ---');
{
  const fuzzSrc = `
    local total = 0
    local function worker(tag: string, mode: number, ...: number): string
      local extra = { ... }
      for i, v in extra do
        if v == 0 then continue end
        if v < 0 then
          total -= (-v) // 2
        elseif mode == 1 then
          total += (v * 3 - 2) // 2
        else
          total += v // 2
        end
      end
      return \`{tag}:{mode}={total}\`
    end
    --@novm
    local function fastBump(k: number) total += k end
    fastBump(5)
    local a = worker("r1", 0, 10, 0, 21, 7, -4)
    local b = worker("r2", 1, 4, 8)
    print(a, b)
  `;
  const expected = executeLuau(fuzzSrc);
  assert.equal(expected.ok, true);

  let fuzzOk = 0;
  let fuzzErr = '';
  const styles: NameStyle[] = ['short', 'barcode', 'shadow', 'hex'];
  for (let i = 0; i < 90; i++) {
    const preset = presets[i % 3];
    const obf = obfuscate(fuzzSrc, {
      preset,
      nameStyle: styles[i % 4],
      jumpChainDepth: i % 4,
      bytecodeMutation: i % 5 !== 0,
      opcodeMutation: i % 7 !== 0,
      graphCff: i % 6 !== 0,
      microVm: i % 8 !== 0,
      antiTamper: i % 9 !== 0,
      seed: `v2_fuzz_${i}`,
    });
    const r = executeLuau(obf.code);
    if (!r.ok || r.stdout !== expected.stdout) {
      fuzzErr = `seed v2_fuzz_${i} (${preset}): ${r.stderr || r.stdout} (expected ${expected.stdout})`;
      break;
    }
    fuzzOk++;
  }
  if (fuzzOk === 90) {
    pass('90/90 randomized Dual-VM builds across every preset, chain depth, Graph-CFF & mutation combo matched 100%');
  } else {
    fail('90-seed polymorphic fuzz', fuzzErr);
  }
}

console.log(`\n=============================================================`);
console.log(`Grandfuscator 2.1 Result: ${passed} passed, ${failed} failed`);
console.log(`=============================================================\n`);

if (failed > 0) process.exit(1);
