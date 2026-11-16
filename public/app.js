const SAMPLES = {
  combat: {
    filename: 'CombatClient.luau',
    placeIds: '',
    code: `--!strict
-- Roblox Combat Controller (Protected inside Grandfuscator's Polymorphic VM)
type WeaponSpec = {
  read name: string,
  baseDamage: number,
  critChance: number,
  tier: "Common" | "Epic" | "Mythic",
}

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local CombatRemote = ReplicatedStorage:WaitForChild("CombatRemote")

local SECRET_HANDSHAKE = "GF_COMBAT_SIG_9481"
local comboStack = 0
local stamina = 100

-- Tag any heavy 60-FPS loop with --@novm so it runs at native Roblox speed
-- while still sharing live variables with the VM!
--@novm
local function onRenderStepped(dt: number, sprintFactor: number): number
  local drain = dt * 12 * sprintFactor
  stamina = math.max(0, stamina - drain)
  return stamina
end

local function executeStrike(weapon: WeaponSpec, roll: number): number
  comboStack += 1
  local tierMult = if weapon.tier == "Mythic" then 2.25
    elseif weapon.tier == "Epic" then 1.5
    else 1.0
  local isCrit = roll <= weapon.critChance
  local finalDmg = math.floor(weapon.baseDamage * tierMult * (1 + comboStack * 0.1))
  if isCrit then
    finalDmg *= 2
  end

  local token = \`{SECRET_HANDSHAKE}:{weapon.name}:{finalDmg}\`
  CombatRemote:FireServer("Slash", finalDmg, token)
  return finalDmg
end

local katana: WeaponSpec = {
  name = "Eclipse Katana",
  baseDamage = 48,
  critChance = 0.35,
  tier = "Mythic",
}

local hit1 = executeStrike(katana, 0.60)
local hit2 = executeStrike(katana, 0.15)
local remStamina = onRenderStepped(0.5, 1.5)
print(\`Combo x{comboStack} | Hits: {hit1}, {hit2} | Stamina: {remStamina}\`)
`,
  },

  module: {
    filename: 'LicenseVault.luau',
    placeIds: '',
    code: `--!strict
-- Licensed Roblox ModuleScript (safe to distribute to buyers)
export type VaultConfig = {
  productId: string,
  maxSeats: number,
  features: { string },
}

local LicenseVault = {}
LicenseVault.__index = LicenseVault

local MASTER_SALT = 0x5F37_59DF

local function computeSignature(productId: string, seats: number): string
  local hash = MASTER_SALT
  for i = 1, #productId do
    local b = string.byte(productId, i)
    hash = bit32.bxor(bit32.rrotate(hash, 5), (b * 16777619) % 4294967296)
  end
  hash = bit32.bxor(hash, seats * 40503)
  return string.format("SIG-%08X", hash)
end

function LicenseVault.new(config: VaultConfig)
  local self = setmetatable({
    productId = config.productId,
    signature = computeSignature(config.productId, config.maxSeats),
    enabled = {} :: { [string]: boolean },
  }, LicenseVault)

  for _, feat in config.features do
    self.enabled[feat] = true
  end
  return self
end

function LicenseVault:hasFeature(name: string): boolean
  return self.enabled[name] == true
end

function LicenseVault:summary(): string
  local list = {}
  for _, name in { "AntiExploit", "AdminPanel", "LiveAnalytics", "CloudBan" } do
    if self:hasFeature(name) then
      list[#list + 1] = name
    end
  end
  return \`[{self.productId}] {self.signature} -> {table.concat(list, ", ")}\`
end

local vault = LicenseVault.new({
  productId = "PRO-ADMIN-SUITE",
  maxSeats = 50,
  features = { "AntiExploit", "AdminPanel", "CloudBan" },
})
print(vault:summary())
return LicenseVault
`,
  },

  placelock: {
    filename: 'PlaceLockedLoader.luau',
    placeIds: '1818, 17625359962',
    code: `-- PlaceId-Locked Game Script
-- The allowed PlaceIds on the left are hashed straight into the VM cipher key.
-- Even if someone steals this script, it mathematically cannot decrypt in their game!

local Players = game:GetService("Players")
local localPlayer = Players.LocalPlayer

local unlockedPerks = { "DoubleXP", "FounderAura", "VaultAccess" }
local active = {}

for idx, perk in unlockedPerks do
  if perk == "" then continue end
  active[#active + 1] = \`#{idx} {perk}\`
end

print(\`Verified PlaceId {game.PlaceId} for {localPlayer.Name}: {table.concat(active, " | ")}\`)
`,
  },

  closures: {
    filename: 'StateMachine.luau',
    placeIds: '',
    code: `-- Closures, Mutable Upvalues & Coroutine Yielding (task.wait compatible)
local function createQuestTracker(playerName: string)
  local xp = 0
  local completed: { string } = {}

  local function finishQuest(title: string, reward: number, ...: number)
    local bonus = 0
    for _, extra in { ... } do
      bonus += extra // 2
    end
    xp += reward + bonus
    completed[#completed + 1] = title
    return xp, #completed
  end

  local function report(): string
    return \`{playerName} -> {xp} XP ({table.concat(completed, ", ")})\`
  end

  return finishQuest, report
end

local finish, report = createQuestTracker("AetherKnight")

local co = coroutine.create(function()
  finish("Dragon Peak", 250, 40, 20)
  coroutine.yield("checkpoint")
  finish("Obsidian Citadel", 600, 100)
  return report()
end)

local _, stage = coroutine.resume(co)
local _, summary = coroutine.resume(co)
print("Stage:", stage, "| Final:", summary)
`,
  },
};

const PRESET_UI_DEFAULTS = {
  swift: {
    bytecodeMutation: false,
    opcodeMutation: true,
    graphCff: true,
    antiTamper: true,
    jumpChainDepth: '1',
    opcodeDuplication: '1',
    microVm: true,
    superinstructions: true,
    stringMode: 'lazy',
    nameStyle: 'short',
    mbaDepth: '1',
    decoyHandlers: '10',
  },
  fortress: {
    bytecodeMutation: true,
    opcodeMutation: true,
    graphCff: true,
    antiTamper: true,
    jumpChainDepth: '2',
    opcodeDuplication: '2',
    microVm: true,
    superinstructions: true,
    stringMode: 'lazy',
    nameStyle: 'barcode',
    mbaDepth: '2',
    decoyHandlers: '20',
  },
  nightmare: {
    bytecodeMutation: true,
    opcodeMutation: true,
    graphCff: true,
    antiTamper: true,
    jumpChainDepth: '3',
    opcodeDuplication: '3',
    microVm: true,
    superinstructions: true,
    stringMode: 'ephemeral',
    nameStyle: 'barcode',
    mbaDepth: '3',
    decoyHandlers: '36',
  },
};

// DOM references
const $ = (id) => document.getElementById(id);

const sourceEditor = $('sourceEditor');
const lineNumbers = $('lineNumbers');
const inputMeta = $('inputMeta');
const filenameInput = $('filenameInput');
const outputEditor = $('outputEditor');
const emptyState = $('emptyState');
const outputDot = $('outputDot');
const buildBadge = $('buildBadge');
const verifyBadge = $('verifyBadge');
const errorBanner = $('errorBanner');
const errorText = $('errorText');
const obfuscateBtn = $('obfuscateBtn');
const obfuscateLabel = $('obfuscateLabel');
const copyBtn = $('copyBtn');
const copyLabel = $('copyLabel');
const downloadBtn = $('downloadBtn');
const wrapToggleBtn = $('wrapToggleBtn');
const testRunBtn = $('testRunBtn');
const clearBtn = $('clearBtn');
const uploadBtn = $('uploadBtn');
const fileInput = $('fileInput');
const sampleSelect = $('sampleSelect');
const inputPane = $('inputPane');
const dropOverlay = $('dropOverlay');

const bytecodeMutationCheck = $('bytecodeMutationCheck');
const runtimeSelect = $('runtimeSelect');
const opcodeMutationSub = $('opcodeMutationSub');
const graphCffSub = $('graphCffSub');
const bytecodeMutationSub = $('bytecodeMutationSub');
const antiTamperSub = $('antiTamperSub');
const microVmSub = $('microVmSub');
const superinstSub = $('superinstSub');
const opcodeMutationCheck = $('opcodeMutationCheck');
const graphCffCheck = $('graphCffCheck');
const antiTamperCheck = $('antiTamperCheck');
const jumpChainSelect = $('jumpChainSelect');
const opcodeDupSelect = $('opcodeDupSelect');

const placeIdsInput = $('placeIdsInput');
const gameIdsInput = $('gameIdsInput');
const advancedToggle = $('advancedToggle');
const advancedPanel = $('advancedPanel');
const microVmCheck = $('microVmCheck');
const superinstCheck = $('superinstCheck');
const stringModeSelect = $('stringModeSelect');
const nameStyleSelect = $('nameStyleSelect');
const mbaDepthSelect = $('mbaDepthSelect');
const decoyRange = $('decoyRange');
const decoyValue = $('decoyValue');
const watermarkInput = $('watermarkInput');

const statsBar = $('statsBar');
const statSize = $('statSize');
const statOpcodes = $('statOpcodes');
const statCff = $('statCff');
const statChains = $('statChains');
const statArmor = $('statArmor');
const statLayout = $('statLayout');
const statTime = $('statTime');
const layerPills = $('layerPills');

const sandboxDrawer = $('sandboxDrawer');
const sandboxBadges = $('sandboxBadges');
const attackGrid = $('attackGrid');
const sandboxOutput = $('sandboxOutput');
const closeSandboxBtn = $('closeSandboxBtn');
const toast = $('toast');

let currentPreset = 'fortress';
let lastOutputCode = '';
let lastSourceCode = '';
let hasLuauRuntime = false;
let toastTimer = null;

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function showToast(msg) {
  toast.textContent = msg;
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.hidden = true;
  }, 2400);
}

function syncRuntimeControls(resetToPreset = false) {
  const isV3 = runtimeSelect.value === 'v3-experimental';
  const d = PRESET_UI_DEFAULTS[currentPreset];
  bytecodeMutationCheck.disabled = isV3;
  opcodeMutationCheck.disabled = !isV3;
  graphCffCheck.disabled = !isV3;
  antiTamperCheck.disabled = isV3;
  microVmCheck.disabled = isV3;
  superinstCheck.disabled = !isV3;
  stringModeSelect.disabled = isV3;
  if (resetToPreset) {
    bytecodeMutationCheck.checked = !isV3 && d.bytecodeMutation;
    opcodeMutationCheck.checked = isV3 && d.opcodeMutation;
    graphCffCheck.checked = isV3 && d.graphCff;
    antiTamperCheck.checked = !isV3 && d.antiTamper;
    microVmCheck.checked = !isV3 && d.microVm;
    superinstCheck.checked = isV3 && d.superinstructions;
    stringModeSelect.value = d.stringMode;
  }
  bytecodeMutationSub.textContent = isV3
    ? 'Not implemented by the v3 flat runtime'
    : 'Re-encrypts raw 12B buffer per instruction';
  opcodeMutationSub.textContent = isV3
    ? 'Operand swaps and mutation are active in v3'
    : 'Unavailable in the compatibility runtime';
  graphCffSub.textContent = isV3
    ? 'Multi-hub control-flow flattening in v3'
    : 'Unavailable in the compatibility runtime';
  antiTamperSub.textContent = isV3
    ? 'No inspection barrier; client buffer dumps and traces can succeed'
    : 'Compatibility-only heuristic checks; not a confidentiality boundary';
  microVmSub.textContent = isV3
    ? 'Not implemented by the v3 flat runtime'
    : 'Compatibility-only key generation';
  superinstSub.textContent = isV3
    ? 'Instruction fusion is active in v3'
    : 'Unavailable in the compatibility runtime';
}

function updateEditorGutter() {
  const val = sourceEditor.value;
  const lines = val ? val.split('\n').length : 1;
  const bytes = new TextEncoder().encode(val).length;
  inputMeta.textContent = `${lines} ${lines === 1 ? 'line' : 'lines'} · ${formatBytes(bytes)}`;

  // Build line-number gutter string efficiently
  let nums = '';
  const cap = Math.min(lines, 8000);
  for (let i = 1; i <= cap; i++) {
    nums += i + '\n';
  }
  lineNumbers.textContent = nums;
}

sourceEditor.addEventListener('input', () => {
  errorBanner.hidden = true;
  updateEditorGutter();
});

sourceEditor.addEventListener('scroll', () => {
  lineNumbers.scrollTop = sourceEditor.scrollTop;
});

// Support clean 2-space Tab indentation & Ctrl/Cmd+Enter shortcut
sourceEditor.addEventListener('keydown', (e) => {
  if (e.key === 'Tab') {
    e.preventDefault();
    const start = sourceEditor.selectionStart;
    const end = sourceEditor.selectionEnd;
    sourceEditor.value = sourceEditor.value.slice(0, start) + '  ' + sourceEditor.value.slice(end);
    sourceEditor.selectionStart = sourceEditor.selectionEnd = start + 2;
    updateEditorGutter();
  }
});

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    runObfuscation();
  }
});

// Preset cards
document.querySelectorAll('.preset-card').forEach((card) => {
  card.addEventListener('click', () => {
    const preset = card.dataset.preset;
    currentPreset = preset;
    document.querySelectorAll('.preset-card').forEach((c) => {
      const active = c === card;
      c.classList.toggle('active', active);
      c.setAttribute('aria-checked', String(active));
    });
    const d = PRESET_UI_DEFAULTS[preset];
    bytecodeMutationCheck.checked = d.bytecodeMutation;
    opcodeMutationCheck.checked = d.opcodeMutation;
    graphCffCheck.checked = d.graphCff;
    antiTamperCheck.checked = d.antiTamper;
    jumpChainSelect.value = d.jumpChainDepth;
    opcodeDupSelect.value = d.opcodeDuplication;
    microVmCheck.checked = d.microVm;
    superinstCheck.checked = d.superinstructions;
    stringModeSelect.value = d.stringMode;
    nameStyleSelect.value = d.nameStyle;
    mbaDepthSelect.value = d.mbaDepth;
    decoyRange.value = d.decoyHandlers;
    decoyValue.textContent = d.decoyHandlers;
    syncRuntimeControls();
  });
});

runtimeSelect.addEventListener('change', () => syncRuntimeControls(true));
syncRuntimeControls(true);

decoyRange.addEventListener('input', () => {
  decoyValue.textContent = decoyRange.value;
});

advancedToggle.addEventListener('click', () => {
  const expanded = advancedToggle.getAttribute('aria-expanded') === 'true';
  advancedToggle.setAttribute('aria-expanded', String(!expanded));
  advancedPanel.hidden = expanded;
});

// Example selector
sampleSelect.addEventListener('change', () => {
  const key = sampleSelect.value;
  if (!key || !SAMPLES[key]) return;
  const s = SAMPLES[key];
  sourceEditor.value = s.code;
  filenameInput.value = s.filename;
  placeIdsInput.value = s.placeIds;
  errorBanner.hidden = true;
  sandboxDrawer.hidden = true;
  updateEditorGutter();
  sampleSelect.value = '';
  showToast(`Loaded ${s.filename}`);
});

// Clear button
clearBtn.addEventListener('click', () => {
  sourceEditor.value = '';
  errorBanner.hidden = true;
  updateEditorGutter();
  sourceEditor.focus();
});

// File upload & drag-and-drop
function loadFile(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    sourceEditor.value = String(reader.result || '');
    filenameInput.value = file.name || 'script.luau';
    errorBanner.hidden = true;
    updateEditorGutter();
    showToast(`Imported ${file.name}`);
  };
  reader.readAsText(file);
}

uploadBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files && fileInput.files[0]) {
    loadFile(fileInput.files[0]);
    fileInput.value = '';
  }
});

let dragCounter = 0;
inputPane.addEventListener('dragenter', (e) => {
  e.preventDefault();
  dragCounter++;
  dropOverlay.hidden = false;
});
inputPane.addEventListener('dragover', (e) => e.preventDefault());
inputPane.addEventListener('dragleave', () => {
  dragCounter = Math.max(0, dragCounter - 1);
  if (dragCounter === 0) dropOverlay.hidden = true;
});
inputPane.addEventListener('drop', (e) => {
  e.preventDefault();
  dragCounter = 0;
  dropOverlay.hidden = true;
  if (e.dataTransfer?.files?.[0]) {
    loadFile(e.dataTransfer.files[0]);
  }
});

// Visual line wrap toggle (never mutates `lastOutputCode`!)
wrapToggleBtn.addEventListener('click', () => {
  const wrapped = outputEditor.classList.toggle('wrapped');
  wrapToggleBtn.classList.toggle('active', wrapped);
});

function parseIdCSV(str) {
  return str
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

async function runObfuscation() {
  const source = sourceEditor.value;
  if (!source.trim()) {
    errorText.textContent = 'Paste a Roblox Luau script or load an example first.';
    errorBanner.hidden = false;
    sourceEditor.focus();
    return;
  }

  errorBanner.hidden = true;
  sandboxDrawer.hidden = true;
  obfuscateBtn.classList.add('loading');
  obfuscateLabel.textContent = 'Synthesizing VM…';

  const options = {
    runtime: runtimeSelect.value,
    preset: currentPreset,
    bytecodeMutation: bytecodeMutationCheck.checked,
    opcodeMutation: opcodeMutationCheck.checked,
    graphCff: graphCffCheck.checked,
    antiTamper: antiTamperCheck.checked,
    jumpChainDepth: Number(jumpChainSelect.value),
    opcodeDuplication: Number(opcodeDupSelect.value),
    microVm: microVmCheck.checked,
    superinstructions: superinstCheck.checked,
    stringMode: stringModeSelect.value,
    nameStyle: nameStyleSelect.value,
    decoyHandlers: Number(decoyRange.value),
    mbaDepth: Number(mbaDepthSelect.value),
    placeIds: parseIdCSV(placeIdsInput.value),
    gameIds: parseIdCSV(gameIdsInput.value),
    watermark: watermarkInput.value,
  };

  try {
    const res = await fetch('/api/obfuscate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source, options }),
    });
    const data = await res.json();

    if (!res.ok || !data.ok) {
      errorText.textContent = data.error || 'Obfuscation failed.';
      errorBanner.hidden = false;
      return;
    }

    lastOutputCode = data.code;
    lastSourceCode = source;

    emptyState.hidden = true;
    outputEditor.hidden = false;
    outputEditor.value = data.code;
    outputEditor.scrollTop = 0;

    outputDot.classList.add('ready');
    copyBtn.disabled = false;
    downloadBtn.disabled = false;
    testRunBtn.disabled = !hasLuauRuntime;

    const s = data.stats;
    buildBadge.textContent = `${s.buildId} · ${s.preset.toUpperCase()} VM`;
    buildBadge.hidden = false;
    verifyBadge.hidden = !s.verified;

    statSize.textContent = `${formatBytes(s.outputBytes)} (${s.vmInstructions} insts)`;
    statOpcodes.textContent = `${s.physicalOpcodes} + ${s.decoyOpcodes} decoy`;
    statCff.textContent = `${s.cfgBlocks} blk · ${s.cffDispatcherNodes} hub · ${s.bogusBlocks} bogus`;
    statChains.textContent = `${s.jumpChainHops} hops · ${s.mutatedInstructions} mut · ${s.destroyedConstants} MBA-K`;
    statArmor.textContent = `${s.microVmInstructions} uOps · ${s.antiTamperLayers}L AT${s.selfMutatingBuffer ? ' · LiveMut' : ''}`;
    statLayout.textContent = `${s.wordPermutation} / ${s.headerPermutation}`;
    statTime.textContent = `${s.compileTimeMs} ms`;

    layerPills.innerHTML = '';
    for (const layer of s.layersApplied) {
      const span = document.createElement('span');
      span.className = 'layer-pill';
      span.textContent = layer;
      layerPills.appendChild(span);
    }
    statsBar.hidden = false;
    showToast(`Synthesized ${s.preset.toUpperCase()} Dual-VM ${s.buildId} (${formatBytes(s.outputBytes)})`);
  } catch (err) {
    errorText.textContent = `Network error: ${err.message || err}`;
    errorBanner.hidden = false;
  } finally {
    obfuscateBtn.classList.remove('loading');
    obfuscateLabel.textContent = 'Obfuscate';
  }
}

obfuscateBtn.addEventListener('click', runObfuscation);

// Copy exact unformatted output to clipboard
copyBtn.addEventListener('click', async () => {
  if (!lastOutputCode) return;
  try {
    await navigator.clipboard.writeText(lastOutputCode);
  } catch {
    outputEditor.focus();
    outputEditor.select();
    document.execCommand('copy');
  }
  copyBtn.classList.add('copied');
  copyLabel.textContent = 'Copied!';
  showToast('Copied protected Luau to clipboard');
  setTimeout(() => {
    copyBtn.classList.remove('copied');
    copyLabel.textContent = 'Copy';
  }, 1600);
});

// Download .obf.luau file
downloadBtn.addEventListener('click', () => {
  if (!lastOutputCode) return;
  const rawName = (filenameInput.value || 'script.luau').trim();
  const m = rawName.match(/^(.+?)(\.(luau|lua|txt))?$/i);
  const base = m ? m[1] : 'script';
  const ext = m && m[2] ? m[2] : '.luau';
  const outName = `${base}.obf${ext}`;

  const blob = new Blob([lastOutputCode], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = outName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast(`Downloaded ${outName}`);
});

// Live Luau 0.747 Execution & 5-Attack Red-Team Anti-Tamper Simulator
testRunBtn.addEventListener('click', async () => {
  if (!lastOutputCode) return;
  testRunBtn.disabled = true;
  sandboxDrawer.hidden = false;
  attackGrid.hidden = true;
  attackGrid.innerHTML = '';
  sandboxBadges.innerHTML = '<span class="status-pill neutral">Running Luau 0.747 + 5 Red-Team Attacks…</span>';
  sandboxOutput.textContent = '';

  const firstPlace = parseIdCSV(placeIdsInput.value)[0] || '1818';
  const firstGame = parseIdCSV(gameIdsInput.value)[0] || '1001';

  try {
    const res = await fetch('/api/verify-run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        originalCode: lastSourceCode,
        obfuscatedCode: lastOutputCode,
        mockPlaceId: firstPlace,
        mockGameId: firstGame,
        testTamper: antiTamperCheck.checked,
      }),
    });
    const data = await res.json();
    sandboxBadges.innerHTML = '';

    const addBadge = (text, cls) => {
      const el = document.createElement('span');
      el.className = `status-pill ${cls}`;
      el.textContent = text;
      sandboxBadges.appendChild(el);
    };

    if (!data.ok) {
      addBadge('Error', 'bad');
      sandboxOutput.textContent = data.error || 'Sandbox failed';
      return;
    }

    if (data.obfuscated.ok) {
      addBadge(`VM OK (${data.obfuscated.durationMs} ms)`, 'ok');
    } else {
      addBadge('Runtime Error', 'bad');
    }

    if (data.zeroLoadstring && data.zeroStringChar) {
      addBadge('0 loadstring / 0 string.char', 'ok');
    }

    if (data.outputsMatch === true) {
      addBadge('100% Output Match', 'ok');
    } else if (data.outputsMatch === false) {
      addBadge('Output Differs', 'bad');
    }

    if (Array.isArray(data.tamperSuite) && data.tamperSuite.length > 0) {
      const blockedCount = data.tamperSuite.filter((t) => t.blocked).length;
      const total = data.tamperSuite.length;
      addBadge(
        `${blockedCount}/${total} Attacks Defeated`,
        blockedCount === total ? 'ok' : 'bad',
      );
      for (const item of data.tamperSuite) {
        const chip = document.createElement('span');
        chip.className = `attack-chip ${item.blocked ? 'blocked' : 'failed'}`;
        chip.textContent = `${item.blocked ? '✓' : '✗'} ${item.attack}: ${item.blocked ? 'BLOCKED' : 'SUCCEEDED'}`;
        if (item.evidence) chip.title = item.evidence;
        attackGrid.appendChild(chip);
      }
      attackGrid.hidden = false;
    }

    if (data.obfuscated.ok) {
      sandboxOutput.textContent =
        data.obfuscated.stdout.trim() || '(Script completed cleanly with no print output)';
    } else {
      sandboxOutput.textContent =
        data.obfuscated.stderr.trim() ||
        'Runtime error (note: scripts using full Roblox Instances should be tested in Roblox Studio).';
    }
  } catch (err) {
    sandboxOutput.textContent = `Request failed: ${err.message || err}`;
  } finally {
    testRunBtn.disabled = false;
  }
});

closeSandboxBtn.addEventListener('click', () => {
  sandboxDrawer.hidden = true;
});

// Initialize with the flagship Roblox Combat example so the studio feels alive immediately
sourceEditor.value = SAMPLES.combat.code;
filenameInput.value = SAMPLES.combat.filename;
updateEditorGutter();

// Check backend engine & Luau runtime capability
fetch('/api/health')
  .then((r) => r.json())
  .then((h) => {
    hasLuauRuntime = Boolean(h.luauRuntime);
    if (!hasLuauRuntime) {
      testRunBtn.hidden = true;
    }
  })
  .catch(() => {});
