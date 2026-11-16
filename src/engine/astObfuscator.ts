import {
  Block,
  Expression,
  FuncBody,
  Statement,
} from './ast.js';
import { collectFreeVars } from './compiler.js';
import { NativeEscapeProto, UpvalDesc } from './ir.js';
import { MBAEngine } from './mba.js';
import { NameGenerator } from './names.js';
import { PRNG } from './prng.js';
import { StringVault } from './stringVault.js';
import { ResolvedOptions } from './types.js';

/**
 * Check if joining two Luau tokens without a space would fuse them lexically
 * (e.g. `local` + `a` -> `locala`, `1` + `..` -> `1..`, `-` + `-` -> comment `--`!).
 */
function isWordChar(c: number): boolean {
  return (
    (c >= 48 && c <= 57) ||
    (c >= 65 && c <= 90) ||
    (c >= 97 && c <= 122) ||
    c === 95
  );
}

export class MinifiedEmitter {
  private chunks: string[] = [];
  private lastChar = -1;

  emit(token: string): void {
    if (!token) return;
    const first = token.charCodeAt(0);
    if (this.lastChar >= 0 && this.needsSpace(this.lastChar, first)) {
      this.chunks.push(' ');
    }
    this.chunks.push(token);
    this.lastChar = token.charCodeAt(token.length - 1);
  }

  private needsSpace(a: number, b: number): boolean {
    if (isWordChar(a) && isWordChar(b)) return true;
    // Prevent `-` + `-` becoming a comment `--`!
    if (a === 45 && b === 45) return true;
    // Prevent number/dot fusion like `0` + `.` or `.` + `.`
    if (a === 46 && (b === 46 || (b >= 48 && b <= 57))) return true;
    if ((a >= 48 && a <= 57) && b === 46) return true;
    // Prevent `[` + `[` becoming long string `[[`
    if (a === 91 && (b === 91 || b === 61)) return true;
    // Prevent `=`/`~`/`<`/`>`/`/`/`+`/`*`/`%`/`^` + `=` fusion
    if (b === 61 && (a === 61 || a === 126 || a === 60 || a === 62 || a === 47 || a === 43 || a === 45 || a === 42 || a === 37 || a === 94)) {
      return true;
    }
    // Prevent `/` + `/` becoming `//`
    if (a === 47 && b === 47) return true;
    // Prevent `:` + `:` becoming `::`
    if (a === 58 && b === 58) return true;
    return false;
  }

  toString(): string {
    return this.chunks.join('');
  }
}

interface ScopeMap {
  parent: ScopeMap | null;
  /** Original Luau local name -> mangled name (or shared VM upval cell expression) */
  vars: Map<string, { kind: 'local'; mangled: string } | { kind: 'upvalCell'; cellExpr: string }>;
}

function lookupScope(
  scope: ScopeMap,
  name: string,
): { kind: 'local'; mangled: string } | { kind: 'upvalCell'; cellExpr: string } | null {
  let s: ScopeMap | null = scope;
  while (s) {
    const hit = s.vars.get(name);
    if (hit) return hit;
    s = s.parent;
  }
  return null;
}

function childScope(parent: ScopeMap): ScopeMap {
  return { parent, vars: new Map() };
}

export interface EmbeddedVmCallback {
  (func: FuncBody, freeVarNames: string[]): { helperInitCode: string; factoryCallExpr: string };
}

export interface AstEmitContext {
  rng: PRNG;
  names: NameGenerator;
  mba: MBAEngine;
  vault: StringVault;
  opts: ResolvedOptions;
  tostringVar: string;
  envVar: string;
  opaqueSeedVar: string;
  /** Keep hot `--@novm` functions free of CFF state machines so 60 FPS loops run at full native Luau speed */
  isNoVmFastPath: boolean;
  /** Local names captured by embedded `--@vm` functions — boxed into live shared cells for bidirectional mutation! */
  vmCapturedLocals: Set<string>;
  embedVm?: EmbeddedVmCallback;
  embeddedVmCount: { value: number };
}

/** Find all variable names captured by any `--@vm` function inside `block` */
function collectVmCapturedNames(block: Block): Set<string> {
  const out = new Set<string>();
  const scanFunc = (fb: FuncBody) => {
    if (fb.pragma === 'vm') {
      for (const n of collectFreeVars(fb)) out.add(n);
      return;
    }
    scanBlock(fb.body);
  };
  const scanExpr = (e: Expression) => {
    switch (e.kind) {
      case 'FuncExpr': scanFunc(e.func); break;
      case 'TableExpr':
        for (const f of e.fields) {
          if (f.kind === 'IndexField') scanExpr(f.key);
          scanExpr(f.value);
        }
        break;
      case 'BinaryExpr': scanExpr(e.left); scanExpr(e.right); break;
      case 'UnaryExpr': scanExpr(e.argument); break;
      case 'IndexExpr': scanExpr(e.object); scanExpr(e.index); break;
      case 'MemberExpr': scanExpr(e.object); break;
      case 'CallExpr': scanExpr(e.callee); e.args.forEach(scanExpr); break;
      case 'MethodCallExpr': scanExpr(e.object); e.args.forEach(scanExpr); break;
      case 'IfExpr': e.branches.forEach((b) => { scanExpr(b.condition); scanExpr(b.value); }); scanExpr(e.elseValue); break;
      case 'InterpStringExpr': e.expressions.forEach(scanExpr); break;
      case 'ParenExpr': scanExpr(e.expression); break;
      default: break;
    }
  };
  const scanBlock = (b: Block) => {
    for (const s of b.statements) {
      switch (s.kind) {
        case 'LocalStmt': s.values.forEach(scanExpr); break;
        case 'LocalFuncStmt': scanFunc(s.func); break;
        case 'FuncStmt': scanFunc(s.func); break;
        case 'AssignStmt': s.targets.forEach(scanExpr); s.values.forEach(scanExpr); break;
        case 'CompoundAssignStmt': scanExpr(s.target); scanExpr(s.value); break;
        case 'CallStmt': scanExpr(s.expr); break;
        case 'DoStmt': scanBlock(s.body); break;
        case 'WhileStmt': scanExpr(s.condition); scanBlock(s.body); break;
        case 'RepeatStmt': scanBlock(s.body); scanExpr(s.condition); break;
        case 'IfStmt': s.branches.forEach((br) => { scanExpr(br.condition); scanBlock(br.body); }); if (s.elseBody) scanBlock(s.elseBody); break;
        case 'NumericForStmt': scanExpr(s.start); scanExpr(s.limit); if (s.step) scanExpr(s.step); scanBlock(s.body); break;
        case 'GenericForStmt': s.iterators.forEach(scanExpr); scanBlock(s.body); break;
        default: break;
      }
    }
    if (b.returnStmt) b.returnStmt.values.forEach(scanExpr);
  };
  scanBlock(block);
  return out;
}

/**
 * Emit an obfuscated Luau Block (scope-aware variable mangling, encrypted string vault,
 * MBA integer encoding, optional control-flow flattening, and opaque predicates).
 */
function emitBlock(out: MinifiedEmitter, block: Block, scope: ScopeMap, ctx: AstEmitContext, allowCff: boolean): void {
  const bScope = childScope(scope);

  // Control-flow flattening on straight-line non-local-declaring runs (keeps lexical scoping 100% sound!)
  const canFlatten =
    allowCff &&
    ctx.opts.graphCff &&
    !ctx.isNoVmFastPath &&
    block.statements.length >= 3 &&
    block.statements.length <= 18 &&
    block.statements.every(
      (s) =>
        s.kind !== 'LocalStmt' &&
        s.kind !== 'LocalFuncStmt' &&
        s.kind !== 'BreakStmt' &&
        s.kind !== 'ContinueStmt' &&
        s.kind !== 'TypeAliasStmt',
    );

  if (canFlatten) {
    emitFlattenedStatements(out, block.statements, bScope, ctx);
  } else {
    for (const s of block.statements) {
      if (s.kind === 'TypeAliasStmt') continue;

      // Occasional lightweight opaque-predicate dead branch in AST mode
      if (
        ctx.opts.graphCff &&
        !ctx.isNoVmFastPath &&
        s.kind !== 'BreakStmt' &&
        s.kind !== 'ContinueStmt' &&
        ctx.rng.chance(0.18)
      ) {
        const tmp = ctx.names.next();
        out.emit('if');
        out.emit(ctx.mba.alwaysFalse(ctx.opaqueSeedVar));
        out.emit('then');
        out.emit('local');
        out.emit(tmp);
        out.emit('=');
        out.emit(ctx.mba.num(ctx.rng.int(10, 9999), 1));
        out.emit(ctx.opaqueSeedVar);
        out.emit('=');
        out.emit(tmp);
        out.emit('end');
      }

      emitStatement(out, s, bScope, ctx);
    }
  }

  if (block.returnStmt) {
    out.emit('return');
    emitExprList(out, block.returnStmt.values, bScope, ctx);
  }
}

/** Flatten a sequence of statements into an MBA-keyed state-machine loop with a decoy state */
function emitFlattenedStatements(
  out: MinifiedEmitter,
  stmts: Statement[],
  scope: ScopeMap,
  ctx: AstEmitContext,
): void {
  const n = stmts.length;
  const usedIds = new Set<number>();
  const allocState = (): number => {
    while (true) {
      const id = ctx.rng.int(101, 65000);
      if (!usedIds.has(id)) {
        usedIds.add(id);
        return id;
      }
    }
  };

  const stateIds = stmts.map(() => allocState());
  const exitId = allocState();
  const decoyId = allocState();

  const items: Array<{ id: number; stmt: Statement | null; nextId: number }> = stmts.map((st, i) => ({
    id: stateIds[i],
    stmt: st,
    nextId: i + 1 < n ? stateIds[i + 1] : exitId,
  }));
  items.push({ id: decoyId, stmt: null, nextId: exitId });
  items.sort((a, b) => a.id - b.id);

  const stateVar = ctx.names.next();
  out.emit('local');
  out.emit(stateVar);
  out.emit('=');
  out.emit(ctx.mba.num(stateIds[0], 1));
  out.emit('while');
  out.emit(stateVar);
  out.emit('~=');
  out.emit(ctx.mba.num(exitId, 1));
  out.emit('do');

  const emitTree = (lo: number, hi: number): void => {
    if (lo === hi) {
      const item = items[lo];
      if (item.stmt) {
        emitStatement(out, item.stmt, scope, ctx);
      } else {
        // Unreachable decoy state
        const fake = ctx.names.next();
        out.emit('local');
        out.emit(fake);
        out.emit('=');
        out.emit(ctx.mba.num(ctx.rng.int(1, 5000), 1));
        out.emit(ctx.opaqueSeedVar);
        out.emit('=');
        out.emit(fake);
      }
      out.emit(stateVar);
      out.emit('=');
      out.emit(ctx.mba.num(item.nextId, 1));
      return;
    }
    const mid = (lo + hi) >> 1;
    out.emit('if');
    out.emit(stateVar);
    out.emit('<=');
    out.emit(String(items[mid].id));
    out.emit('then');
    emitTree(lo, mid);
    out.emit('else');
    emitTree(mid + 1, hi);
    out.emit('end');
  };

  emitTree(0, items.length - 1);
  out.emit('end');
}

function emitStatement(out: MinifiedEmitter, s: Statement, scope: ScopeMap, ctx: AstEmitContext): void {
  switch (s.kind) {
    case 'TypeAliasStmt':
      return;

    case 'LocalStmt': {
      // Emit RHS using pre-declaration scope, then register mangled names!
      const mangled = s.names.map(() => ctx.names.next());
      out.emit('local');
      out.emit(mangled.join(','));
      if (s.values.length > 0) {
        out.emit('=');
        emitExprList(out, s.values, scope, ctx);
      }
      out.emit(';');
      for (let i = 0; i < s.names.length; i++) {
        const origName = s.names[i];
        if (ctx.embedVm && ctx.vmCapturedLocals.has(origName)) {
          // Box into a live VM-compatible upvalue cell `{ [0] = val, [1] = self, [2] = 0 }`
          const cellVar = ctx.names.next();
          out.emit(`local ${cellVar}={[0]=${mangled[i]}};${cellVar}[1]=${cellVar};${cellVar}[2]=0;`);
          scope.vars.set(origName, { kind: 'upvalCell', cellExpr: cellVar });
        } else {
          scope.vars.set(origName, { kind: 'local', mangled: mangled[i] });
        }
      }
      return;
    }

    case 'LocalFuncStmt': {
      const mangled = ctx.names.next();
      if (ctx.embedVm && ctx.vmCapturedLocals.has(s.name)) {
        const cellVar = ctx.names.next();
        out.emit(`local ${cellVar}={};${cellVar}[1]=${cellVar};${cellVar}[2]=0;`);
        scope.vars.set(s.name, { kind: 'upvalCell', cellExpr: cellVar });
        if (s.func.pragma === 'vm') {
          out.emit(`${cellVar}[0]=`);
          emitEmbeddedVmFunc(out, s.func, scope, ctx);
          out.emit(';');
        } else {
          out.emit(`local function ${mangled}`);
          emitFuncBody(out, s.func, scope, ctx);
          out.emit(`${cellVar}[0]=${mangled};`);
        }
        return;
      }
      scope.vars.set(s.name, { kind: 'local', mangled });
      if (s.func.pragma === 'vm' && ctx.embedVm) {
        out.emit('local');
        out.emit(mangled);
        out.emit(';');
        out.emit(mangled);
        out.emit('=');
        emitEmbeddedVmFunc(out, s.func, scope, ctx);
        out.emit(';');
        return;
      }
      out.emit('local');
      out.emit('function');
      out.emit(mangled);
      emitFuncBody(out, s.func, scope, ctx);
      return;
    }

    case 'FuncStmt': {
      const { name, func } = s;
      const effectiveFunc: FuncBody = name.method
        ? { ...func, params: ['self', ...func.params] }
        : func;
      // Emit as `target = function(...) ... end` so property names are encrypted via vault!
      if (name.fields.length === 0 && !name.method) {
        emitAssignIdent(out, name.base, scope, ctx);
      } else {
        emitIdentRef(out, name.base, scope, ctx);
        const all = name.method ? [...name.fields, name.method] : name.fields;
        for (const f of all) {
          out.emit('[');
          out.emit(ctx.vault.callUtf8(f, ctx.mba));
          out.emit(']');
        }
      }
      out.emit('=');
      if (effectiveFunc.pragma === 'vm' && ctx.embedVm) {
        emitEmbeddedVmFunc(out, effectiveFunc, scope, ctx);
      } else {
        out.emit('function');
        emitFuncBody(out, effectiveFunc, scope, ctx);
      }
      out.emit(';');
      return;
    }

    case 'AssignStmt': {
      for (let i = 0; i < s.targets.length; i++) {
        if (i > 0) out.emit(',');
        const t = s.targets[i];
        if (t.kind === 'IdentExpr') {
          emitAssignIdent(out, t.name, scope, ctx);
        } else if (t.kind === 'MemberExpr') {
          emitIndexableObject(out, t.object, scope, ctx);
          out.emit('[');
          out.emit(ctx.vault.callUtf8(t.property, ctx.mba));
          out.emit(']');
        } else {
          emitIndexableObject(out, t.object, scope, ctx);
          out.emit('[');
          emitExpr(out, t.index, scope, ctx);
          out.emit(']');
        }
      }
      out.emit('=');
      emitExprList(out, s.values, scope, ctx);
      out.emit(';');
      return;
    }

    case 'CompoundAssignStmt': {
      const t = s.target;
      if (t.kind === 'IdentExpr') {
        emitAssignIdent(out, t.name, scope, ctx);
      } else if (t.kind === 'MemberExpr') {
        emitIndexableObject(out, t.object, scope, ctx);
        if (ctx.isNoVmFastPath) {
          out.emit('.');
          out.emit(t.property);
        } else {
          out.emit('[');
          out.emit(ctx.vault.callUtf8(t.property, ctx.mba));
          out.emit(']');
        }
      } else {
        emitIndexableObject(out, t.object, scope, ctx);
        out.emit('[');
        emitExpr(out, t.index, scope, ctx);
        out.emit(']');
      }
      out.emit(s.op);
      emitExpr(out, s.value, scope, ctx);
      out.emit(';');
      return;
    }

    case 'CallStmt':
      emitExpr(out, s.expr, scope, ctx);
      out.emit(';');
      return;

    case 'DoStmt':
      out.emit('do');
      emitBlock(out, s.body, scope, ctx, true);
      out.emit('end');
      return;

    case 'WhileStmt':
      out.emit('while');
      emitExpr(out, s.condition, scope, ctx);
      out.emit('do');
      // Avoid flattening tight loop bodies to preserve 60 FPS!
      emitBlock(out, s.body, scope, ctx, false);
      out.emit('end');
      return;

    case 'RepeatStmt': {
      out.emit('repeat');
      const rScope = childScope(scope);
      for (const st of s.body.statements) emitStatement(out, st, rScope, ctx);
      if (s.body.returnStmt) {
        out.emit('return');
        emitExprList(out, s.body.returnStmt.values, rScope, ctx);
      }
      out.emit('until');
      emitExpr(out, s.condition, rScope, ctx);
      out.emit(';');
      return;
    }

    case 'IfStmt': {
      for (let i = 0; i < s.branches.length; i++) {
        out.emit(i === 0 ? 'if' : 'elseif');
        emitExpr(out, s.branches[i].condition, scope, ctx);
        out.emit('then');
        emitBlock(out, s.branches[i].body, scope, ctx, true);
      }
      if (s.elseBody) {
        out.emit('else');
        emitBlock(out, s.elseBody, scope, ctx, true);
      }
      out.emit('end');
      return;
    }

    case 'NumericForStmt': {
      const mVar = ctx.names.next();
      out.emit('for');
      out.emit(mVar);
      out.emit('=');
      emitExpr(out, s.start, scope, ctx);
      out.emit(',');
      emitExpr(out, s.limit, scope, ctx);
      if (s.step) {
        out.emit(',');
        emitExpr(out, s.step, scope, ctx);
      }
      out.emit('do');
      const fScope = childScope(scope);
      fScope.vars.set(s.varName, { kind: 'local', mangled: mVar });
      emitBlock(out, s.body, fScope, ctx, false);
      out.emit('end');
      return;
    }

    case 'GenericForStmt': {
      const mVars = s.names.map(() => ctx.names.next());
      out.emit('for');
      out.emit(mVars.join(','));
      out.emit('in');
      emitExprList(out, s.iterators, scope, ctx);
      out.emit('do');
      const fScope = childScope(scope);
      for (let i = 0; i < s.names.length; i++) {
        fScope.vars.set(s.names[i], { kind: 'local', mangled: mVars[i] });
      }
      emitBlock(out, s.body, fScope, ctx, false);
      out.emit('end');
      return;
    }

    case 'BreakStmt':
      out.emit('break');
      out.emit(';');
      return;

    case 'ContinueStmt':
      out.emit('continue');
      out.emit(';');
      return;
  }
}

function emitFuncBody(out: MinifiedEmitter, func: FuncBody, parentScope: ScopeMap, ctx: AstEmitContext): void {
  const fScope = childScope(parentScope);
  const mParams = func.params.map((p) => {
    const m = ctx.names.next();
    fScope.vars.set(p, { kind: 'local', mangled: m });
    return m;
  });
  if (func.isVararg) mParams.push('...');
  out.emit('(');
  out.emit(mParams.join(','));
  out.emit(')');
  const prevFast = ctx.isNoVmFastPath;
  if (func.pragma === 'novm') ctx.isNoVmFastPath = true;
  emitBlock(out, func.body, fScope, ctx, !ctx.isNoVmFastPath);
  ctx.isNoVmFastPath = prevFast;
  out.emit('end');
}

function emitEmbeddedVmFunc(
  out: MinifiedEmitter,
  func: FuncBody,
  scope: ScopeMap,
  ctx: AstEmitContext,
): void {
  const freeAll = collectFreeVars(func);
  // Capture locals visible in scope as value-cells passed into the VM closure
  const capturedNames: string[] = [];
  const cellExprs: string[] = [];
  for (const name of freeAll) {
    const hit = lookupScope(scope, name);
    if (hit) {
      capturedNames.push(name);
      if (hit.kind === 'upvalCell') {
        cellExprs.push(hit.cellExpr);
      } else {
        // Read-through cell referencing current local value `{ [0] = loc, [1] = self, [2] = 0 }`
        const c = ctx.names.next();
        cellExprs.push(`(function()local ${c}={[0]=${hit.mangled}};${c}[1]=${c};${c}[2]=0;return ${c} end)()`);
      }
    }
  }
  const built = ctx.embedVm!(func, capturedNames);
  ctx.embeddedVmCount.value++;
  out.emit(`${built.factoryCallExpr}({${cellExprs.join(',')}})`);
}

function emitAssignIdent(out: MinifiedEmitter, name: string, scope: ScopeMap, ctx: AstEmitContext): void {
  const hit = lookupScope(scope, name);
  if (hit) {
    if (hit.kind === 'local') {
      out.emit(hit.mangled);
    } else {
      // Live shared VM upvalue cell: `u[1][u[2]]`!
      out.emit(`${hit.cellExpr}[1][${hit.cellExpr}[2]]`);
    }
    return;
  }
  // Global via encrypted env key
  out.emit(ctx.envVar);
  out.emit('[');
  out.emit(ctx.vault.callUtf8(name, ctx.mba));
  out.emit(']');
}

function emitIdentRef(out: MinifiedEmitter, name: string, scope: ScopeMap, ctx: AstEmitContext): void {
  emitAssignIdent(out, name, scope, ctx);
}

function emitIndexableObject(out: MinifiedEmitter, obj: Expression, scope: ScopeMap, ctx: AstEmitContext): void {
  const safeSuffix =
    obj.kind === 'IdentExpr' ||
    obj.kind === 'IndexExpr' ||
    obj.kind === 'MemberExpr' ||
    obj.kind === 'CallExpr' ||
    obj.kind === 'MethodCallExpr' ||
    obj.kind === 'ParenExpr';
  if (!safeSuffix) out.emit('(');
  emitExpr(out, obj, scope, ctx);
  if (!safeSuffix) out.emit(')');
}

function emitExprList(out: MinifiedEmitter, list: Expression[], scope: ScopeMap, ctx: AstEmitContext): void {
  for (let i = 0; i < list.length; i++) {
    if (i > 0) out.emit(',');
    emitExpr(out, list[i], scope, ctx);
  }
}

function emitExpr(out: MinifiedEmitter, e: Expression, scope: ScopeMap, ctx: AstEmitContext): void {
  switch (e.kind) {
    case 'NilLiteral':
      out.emit('nil');
      return;

    case 'BoolLiteral':
      if (ctx.opts.graphCff && !ctx.isNoVmFastPath && ctx.rng.chance(0.4)) {
        out.emit(e.value ? ctx.mba.alwaysTrue(ctx.opaqueSeedVar) : ctx.mba.alwaysFalse(ctx.opaqueSeedVar));
      } else {
        out.emit(e.value ? 'true' : 'false');
      }
      return;

    case 'NumberLiteral':
      if (ctx.isNoVmFastPath) {
        out.emit(ctx.mba.formatPlainNumber(e.value));
      } else {
        out.emit(ctx.mba.num(e.value));
      }
      return;

    case 'StringLiteral':
      out.emit(ctx.vault.callBytes(e.bytes, ctx.mba));
      return;

    case 'VarargExpr':
      out.emit('...');
      return;

    case 'ParenExpr':
      out.emit('(');
      emitExpr(out, e.expression, scope, ctx);
      out.emit(')');
      return;

    case 'IdentExpr':
      emitIdentRef(out, e.name, scope, ctx);
      return;

    case 'FuncExpr':
      if (e.func.pragma === 'vm' && ctx.embedVm) {
        emitEmbeddedVmFunc(out, e.func, scope, ctx);
        return;
      }
      out.emit('function');
      emitFuncBody(out, e.func, scope, ctx);
      return;

    case 'TableExpr': {
      out.emit('{');
      for (let i = 0; i < e.fields.length; i++) {
        if (i > 0) out.emit(',');
        const f = e.fields[i];
        if (f.kind === 'ListField') {
          emitExpr(out, f.value, scope, ctx);
        } else if (f.kind === 'RecordField') {
          out.emit('[');
          out.emit(ctx.vault.callUtf8(f.key, ctx.mba));
          out.emit(']');
          out.emit('=');
          emitExpr(out, f.value, scope, ctx);
        } else {
          out.emit('[');
          emitExpr(out, f.key, scope, ctx);
          out.emit(']');
          out.emit('=');
          emitExpr(out, f.value, scope, ctx);
        }
      }
      out.emit('}');
      return;
    }

    case 'MemberExpr':
      emitIndexableObject(out, e.object, scope, ctx);
      if (ctx.isNoVmFastPath) {
        // Keep hot loop field reads fast (cache-friendly Luau GETIMPORT/GETTABLEKS!)
        out.emit('.');
        out.emit(e.property);
      } else {
        out.emit('[');
        out.emit(ctx.vault.callUtf8(e.property, ctx.mba));
        out.emit(']');
      }
      return;

    case 'IndexExpr':
      emitIndexableObject(out, e.object, scope, ctx);
      out.emit('[');
      emitExpr(out, e.index, scope, ctx);
      out.emit(']');
      return;

    case 'UnaryExpr':
      out.emit('(');
      out.emit(e.op);
      out.emit('(');
      emitExpr(out, e.argument, scope, ctx);
      out.emit('))');
      return;

    case 'BinaryExpr':
      out.emit('(');
      emitExpr(out, e.left, scope, ctx);
      out.emit(e.op);
      emitExpr(out, e.right, scope, ctx);
      out.emit(')');
      return;

    case 'CallExpr':
      emitIndexableObject(out, e.callee, scope, ctx);
      out.emit('(');
      emitExprList(out, e.args, scope, ctx);
      out.emit(')');
      return;

    case 'MethodCallExpr': {
      if (ctx.isNoVmFastPath) {
        // Native Luau NAMECALL fast path inside --@novm functions!
        emitIndexableObject(out, e.object, scope, ctx);
        out.emit(':');
        out.emit(e.method);
        out.emit('(');
        emitExprList(out, e.args, scope, ctx);
        out.emit(')');
        return;
      }
      // Preserve single evaluation of `object` AND encrypt the method name!
      const isSimpleLocal = e.object.kind === 'IdentExpr' && lookupScope(scope, e.object.name)?.kind === 'local';
      if (isSimpleLocal) {
        emitExpr(out, e.object, scope, ctx);
        out.emit('[');
        out.emit(ctx.vault.callUtf8(e.method, ctx.mba));
        out.emit(']');
        out.emit('(');
        emitExpr(out, e.object, scope, ctx);
        if (e.args.length > 0) {
          out.emit(',');
          emitExprList(out, e.args, scope, ctx);
        }
        out.emit(')');
      } else {
        // Use native `:` when object may yield or return multi-values so coroutines stay 100% yieldable!
        emitIndexableObject(out, e.object, scope, ctx);
        out.emit(':');
        out.emit(e.method);
        out.emit('(');
        emitExprList(out, e.args, scope, ctx);
        out.emit(')');
      }
      return;
    }

    case 'IfExpr': {
      out.emit('(if');
      for (let i = 0; i < e.branches.length; i++) {
        if (i > 0) out.emit('elseif');
        emitExpr(out, e.branches[i].condition, scope, ctx);
        out.emit('then');
        emitExpr(out, e.branches[i].value, scope, ctx);
      }
      out.emit('else');
      emitExpr(out, e.elseValue, scope, ctx);
      out.emit(')');
      return;
    }

    case 'InterpStringExpr': {
      const pieces: string[] = [];
      for (let i = 0; i < e.segments.length; i++) {
        if (e.segments[i].length > 0) {
          pieces.push(ctx.vault.callBytes(e.segments[i], ctx.mba));
        }
        if (i < e.expressions.length) {
          const sub = new MinifiedEmitter();
          emitExpr(sub, e.expressions[i], scope, ctx);
          pieces.push(`${ctx.tostringVar}(${sub.toString()})`);
        }
      }
      if (pieces.length === 0) {
        out.emit('""');
      } else {
        out.emit('(' + pieces.join('..') + ')');
      }
      return;
    }
  }
}

/**
 * Emit native AST-obfuscated `--@novm` helper factories to be embedded inside a VM script.
 * Each factory receives `(upvalsTable)` and runs at 100% native Roblox Luau 60-FPS speed
 * while sharing live mutable upvalues (`u[1][u[2]]`) with the surrounding VM!
 */
export function emitNativeEscapeTable(
  escapes: NativeEscapeProto[],
  opts: ResolvedOptions,
  rng: PRNG,
  names: NameGenerator,
  mba: MBAEngine,
  envVar: string,
  tostringVar: string,
  stdlibRefs: {
    bxor: string;
    band: string;
    rrotate: string;
    bufCreate: string;
    bufWriteU32: string;
    bufReadU8: string;
    bufWriteU8: string;
    bufReadStr: string;
    strByte: string;
  },
): { code: string; tableVar: string; vaultStrings: number } {
  const tableVar = names.next();
  if (escapes.length === 0) {
    return { code: `local ${tableVar}={};`, tableVar, vaultStrings: 0 };
  }

  // Always use 'lazy' caching for --@novm string vault so 60-FPS loops never re-decrypt strings!
  const vault = new StringVault(rng, names, 'lazy');
  const opaqueSeedVar = names.next();

  const ctx: AstEmitContext = {
    rng,
    names,
    mba,
    vault,
    opts,
    tostringVar,
    envVar,
    opaqueSeedVar,
    isNoVmFastPath: true,
    vmCapturedLocals: new Set(),
    embeddedVmCount: { value: 0 },
  };

  const factoryExprs: string[] = [];
  for (const esc of escapes) {
    const upArg = names.next();
    const out = new MinifiedEmitter();
    out.emit('function(');
    out.emit(upArg);
    out.emit(')');

    // Bind each captured upvalue cell to a fast local `u_k = upArg[k]`
    const rootScope: ScopeMap = { parent: null, vars: new Map() };
    esc.upvals.forEach((u: UpvalDesc, idx: number) => {
      const cellLocal = names.next();
      out.emit('local');
      out.emit(cellLocal);
      out.emit(`=${upArg}[${idx + 1}];`);
      rootScope.vars.set(u.name, { kind: 'upvalCell', cellExpr: cellLocal });
    });

    out.emit('return function');
    emitFuncBody(out, esc.func, rootScope, ctx);
    out.emit('end');
    factoryExprs.push(out.toString());
  }

  const vaultCode = vault.count > 0 ? vault.emitRuntime(mba, stdlibRefs) : '';
  const code =
    vaultCode +
    `local ${opaqueSeedVar}=${mba.num(rng.int(17, 4095), 1)};` +
    `local ${tableVar}={${factoryExprs.join(',')}};`;

  return { code, tableVar, vaultStrings: vault.count };
}

