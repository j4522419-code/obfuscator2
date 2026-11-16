import {
  AssignStmt,
  BinaryExpr,
  BinaryOp,
  Block,
  CallExpr,
  Chunk,
  CompoundAssignStmt,
  CompoundOp,
  Expression,
  FuncBody,
  FuncStmt,
  GenericForStmt,
  IfExpr,
  IfStmt,
  InterpStringExpr,
  LValue,
  MethodCallExpr,
  NumericForStmt,
  RepeatStmt,
  Statement,
  TableExpr,
  UnaryExpr,
  VarargExpr,
  WhileStmt,
  bytesKey,
  utf8Bytes,
} from './ast.js';
import {
  CFGTransformStats,
  CompiledModule,
  IRConstant,
  IRProto,
  Instruction,
  NativeEscapeProto,
  Op,
  UpvalDesc,
} from './ir.js';
import { GrandfuscatorError } from './types.js';

interface LocalVar {
  name: string;
  reg: number;
  scopeDepth: number;
  captured: boolean;
}

interface ScopeInfo {
  depth: number;
  firstLocalIdx: number;
  baseReg: number;
}

interface LoopContext {
  breakJumps: number[];
  continueJumps: number[];
  /** Scope depth inside the loop; break/continue closes captured locals with depth >= loopBodyDepth */
  breakMinLocalIdx: number;
  continueMinLocalIdx: number;
}

function isMultiReturnExpr(expr: Expression): expr is CallExpr | MethodCallExpr | VarargExpr {
  return expr.kind === 'CallExpr' || expr.kind === 'MethodCallExpr' || expr.kind === 'VarargExpr';
}

function compoundToBinary(op: CompoundOp): BinaryOp {
  switch (op) {
    case '+=': return '+';
    case '-=': return '-';
    case '*=': return '*';
    case '/=': return '/';
    case '//=': return '//';
    case '%=': return '%';
    case '^=': return '^';
    case '..=': return '..';
  }
}

/**
 * Optimizing Compiler Pass: Safe constant-folding over pure Luau sub-expressions.
 * Erases source arithmetic formulas (which are then split into polymorphic VM-MBA ops in cfgEngine).
 */
function foldExpr(expr: Expression): Expression {
  if (expr.kind === 'ParenExpr') {
    const inner = foldExpr(expr.expression);
    if (inner.kind === 'NumberLiteral' || inner.kind === 'BoolLiteral' || inner.kind === 'NilLiteral') {
      return inner;
    }
    return { ...expr, expression: inner };
  }
  if (expr.kind === 'UnaryExpr') {
    const arg = foldExpr(expr.argument);
    if (expr.op === '-' && arg.kind === 'NumberLiteral') {
      return { kind: 'NumberLiteral', value: -arg.value, line: expr.line };
    }
    if (expr.op === 'not') {
      if (arg.kind === 'BoolLiteral') return { kind: 'BoolLiteral', value: !arg.value, line: expr.line };
      if (arg.kind === 'NilLiteral') return { kind: 'BoolLiteral', value: true, line: expr.line };
      if (arg.kind === 'NumberLiteral' || arg.kind === 'StringLiteral') {
        return { kind: 'BoolLiteral', value: false, line: expr.line };
      }
    }
    if (expr.op === '#' && arg.kind === 'StringLiteral') {
      return { kind: 'NumberLiteral', value: arg.bytes.length, line: expr.line };
    }
    return { ...expr, argument: arg };
  }
  if (expr.kind === 'BinaryExpr') {
    const L = foldExpr(expr.left);
    const R = foldExpr(expr.right);
    if (L.kind === 'NumberLiteral' && R.kind === 'NumberLiteral') {
      const a = L.value;
      const b = R.value;
      let res: number | null = null;
      switch (expr.op) {
        case '+': res = a + b; break;
        case '-': res = a - b; break;
        case '*': res = a * b; break;
        case '/': if (b !== 0) res = a / b; break;
        case '//': if (b !== 0) res = Math.floor(a / b); break;
        case '%':
          // Exact Lua/Luau floored modulo: a - floor(a / b) * b
          if (b !== 0) res = a - Math.floor(a / b) * b;
          break;
        case '^': res = Math.pow(a, b); break;
        case '==': return { kind: 'BoolLiteral', value: a === b, line: expr.line };
        case '~=': return { kind: 'BoolLiteral', value: a !== b, line: expr.line };
        case '<':  return { kind: 'BoolLiteral', value: a < b, line: expr.line };
        case '<=': return { kind: 'BoolLiteral', value: a <= b, line: expr.line };
        case '>':  return { kind: 'BoolLiteral', value: a > b, line: expr.line };
        case '>=': return { kind: 'BoolLiteral', value: a >= b, line: expr.line };
      }
      if (res !== null && Number.isFinite(res)) {
        return { kind: 'NumberLiteral', value: res, line: expr.line };
      }
    }
    return { ...expr, left: L, right: R };
  }
  return expr;
}

class FuncCompiler {
  public readonly instructions: Instruction[] = [];
  public readonly loopHints: number[] = [];
  public readonly constants: IRConstant[] = [];
  public readonly upvals: UpvalDesc[] = [];
  public readonly protos: IRProto[] = [];
  public readonly usedOps = new Set<Op>();

  private constMap = new Map<string, number>(); // key -> 1-based index
  private locals: LocalVar[] = [];
  private scopes: ScopeInfo[] = [];
  private loops: LoopContext[] = [];
  private nextReg = 0;
  public maxStack = 1;

  constructor(
    public readonly parent: FuncCompiler | null,
    public readonly numParams: number,
    public readonly isVararg: boolean,
    private readonly nativeEscapes: NativeEscapeProto[],
  ) {}

  // ---------------------------------------------------------------------------
  // Register & Scope Management
  // ---------------------------------------------------------------------------

  allocReg(): number {
    const r = this.nextReg++;
    if (this.nextReg > this.maxStack) this.maxStack = this.nextReg;
    return r;
  }

  allocRegs(count: number): number {
    const base = this.nextReg;
    this.nextReg += count;
    if (this.nextReg > this.maxStack) this.maxStack = this.nextReg;
    return base;
  }

  setTopReg(reg: number): void {
    this.nextReg = reg;
    if (this.nextReg > this.maxStack) this.maxStack = this.nextReg;
  }

  getTopReg(): number {
    return this.nextReg;
  }

  enterScope(): ScopeInfo {
    const info: ScopeInfo = {
      depth: this.scopes.length,
      firstLocalIdx: this.locals.length,
      baseReg: this.nextReg,
    };
    this.scopes.push(info);
    return info;
  }

  leaveScope(emitClose = true): void {
    const info = this.scopes.pop()!;
    let lowestCapturedReg = -1;
    for (let i = info.firstLocalIdx; i < this.locals.length; i++) {
      if (this.locals[i].captured) {
        lowestCapturedReg = this.locals[i].reg;
        break;
      }
    }
    if (emitClose && lowestCapturedReg >= 0) {
      this.emit(Op.CLOSE, lowestCapturedReg, 0, 0);
    }
    this.locals.length = info.firstLocalIdx;
    this.nextReg = info.baseReg;
  }

  private emitCloseFromLocalIdx(minLocalIdx: number): void {
    for (let i = minLocalIdx; i < this.locals.length; i++) {
      if (this.locals[i].captured) {
        this.emit(Op.CLOSE, this.locals[i].reg, 0, 0);
        return;
      }
    }
  }

  declareLocal(name: string, existingReg?: number): number {
    const reg = existingReg !== undefined ? existingReg : this.allocReg();
    if (reg >= this.nextReg) {
      this.setTopReg(reg + 1);
    }
    const depth = this.scopes.length > 0 ? this.scopes[this.scopes.length - 1].depth : 0;
    this.locals.push({ name, reg, scopeDepth: depth, captured: false });
    return reg;
  }

  resolveLocal(name: string): LocalVar | null {
    for (let i = this.locals.length - 1; i >= 0; i--) {
      if (this.locals[i].name === name) {
        return this.locals[i];
      }
    }
    return null;
  }

  /** Returns 1-based upvalue index, or null if global */
  resolveUpvalue(name: string): number | null {
    if (!this.parent) return null;

    const parentLocal = this.parent.resolveLocal(name);
    if (parentLocal) {
      parentLocal.captured = true;
      return this.addUpvalue(true, parentLocal.reg, name);
    }

    const parentUp = this.parent.resolveUpvalue(name);
    if (parentUp !== null) {
      return this.addUpvalue(false, parentUp, name);
    }

    return null;
  }

  private addUpvalue(inStack: boolean, index: number, name: string): number {
    for (let i = 0; i < this.upvals.length; i++) {
      const u = this.upvals[i];
      if (u.inStack === inStack && u.index === index) {
        return i + 1; // 1-based
      }
    }
    this.upvals.push({ inStack, index, name });
    return this.upvals.length;
  }

  /** Capture free variables referenced by a `--@novm` native child function */
  captureForNativeEscape(freeNames: Set<string>): UpvalDesc[] {
    const descs: UpvalDesc[] = [];
    for (const name of freeNames) {
      const loc = this.resolveLocal(name);
      if (loc) {
        loc.captured = true;
        descs.push({ inStack: true, index: loc.reg, name });
        continue;
      }
      const up = this.resolveUpvalue(name);
      if (up !== null) {
        descs.push({ inStack: false, index: up, name });
      }
    }
    return descs;
  }

  // ---------------------------------------------------------------------------
  // Constants & Emission (1-based PC and 1-based K index)
  // ---------------------------------------------------------------------------

  addStringConst(bytes: Uint8Array): number {
    const key = 'S:' + bytesKey(bytes);
    const existing = this.constMap.get(key);
    if (existing !== undefined) return existing;
    this.constants.push({ kind: 'string', bytes, cacheKey: key });
    const idx = this.constants.length;
    this.constMap.set(key, idx);
    return idx;
  }

  addIdentConst(name: string): number {
    return this.addStringConst(utf8Bytes(name));
  }

  addNumberConst(value: number): number {
    const key = Object.is(value, -0)
      ? 'N:-0'
      : Number.isNaN(value)
        ? 'N:NaN'
        : `N:${value}`;
    const existing = this.constMap.get(key);
    if (existing !== undefined) return existing;
    this.constants.push({ kind: 'number', value });
    const idx = this.constants.length;
    this.constMap.set(key, idx);
    return idx;
  }

  emit(op: Op, a: number, b: number, c: number): number {
    this.usedOps.add(op);
    this.instructions.push({ op, a, b, c });
    this.loopHints.push(this.loops.length);
    return this.instructions.length; // 1-based PC of emitted instruction
  }

  nextPC(): number {
    return this.instructions.length + 1; // 1-based PC of next instruction
  }

  patchB(pc1Based: number, targetPC1Based: number): void {
    this.instructions[pc1Based - 1].b = targetPC1Based;
  }

  // ---------------------------------------------------------------------------
  // Statements
  // ---------------------------------------------------------------------------

  compileBlock(block: Block, ownScope = true): void {
    if (ownScope) this.enterScope();
    for (const stmt of block.statements) {
      this.compileStatement(stmt);
    }
    if (block.returnStmt) {
      this.compileReturn(block.returnStmt.values);
    }
    if (ownScope) this.leaveScope(true);
  }

  compileStatement(stmt: Statement): void {
    const savedTop = this.getTopReg();
    switch (stmt.kind) {
      case 'TypeAliasStmt':
        // Pure compile-time Luau type; completely erased!
        break;

      case 'LocalStmt': {
        const nVars = stmt.names.length;
        const base = this.allocRegs(nVars);
        if (stmt.values.length === 0) {
          this.emit(Op.LOADNIL, base, base + nVars - 1, 0);
        } else {
          this.compileExprListFixed(stmt.values, base, nVars);
        }
        // Declare locals AFTER evaluating RHS (so `local x = x + 1` reads outer `x`!)
        for (let i = 0; i < nVars; i++) {
          this.declareLocal(stmt.names[i], base + i);
        }
        return; // Keep local registers alive!
      }

      case 'LocalFuncStmt': {
        // Declare local BEFORE compiling body so recursive calls capture it!
        const reg = this.declareLocal(stmt.name);
        this.compileClosureInto(stmt.func, reg);
        return; // Keep local register alive!
      }

      case 'FuncStmt':
        this.compileFuncStmt(stmt);
        break;

      case 'AssignStmt':
        this.compileAssign(stmt);
        break;

      case 'CompoundAssignStmt':
        this.compileCompoundAssign(stmt);
        break;

      case 'CallStmt': {
        const r = this.allocReg();
        this.compileCallInto(stmt.expr, r, 0); // 0 results kept
        break;
      }

      case 'DoStmt':
        this.compileBlock(stmt.body, true);
        break;

      case 'IfStmt':
        this.compileIfStmt(stmt);
        break;

      case 'WhileStmt':
        this.compileWhileStmt(stmt);
        break;

      case 'RepeatStmt':
        this.compileRepeatStmt(stmt);
        break;

      case 'NumericForStmt':
        this.compileNumericFor(stmt);
        break;

      case 'GenericForStmt':
        this.compileGenericFor(stmt);
        break;

      case 'BreakStmt': {
        if (this.loops.length === 0) {
          throw new GrandfuscatorError('`break` outside of loop', 'compiler', stmt.line);
        }
        const loop = this.loops[this.loops.length - 1];
        this.emitCloseFromLocalIdx(loop.breakMinLocalIdx);
        loop.breakJumps.push(this.emit(Op.JMP, 0, 0, 0));
        break;
      }

      case 'ContinueStmt': {
        if (this.loops.length === 0) {
          throw new GrandfuscatorError('`continue` outside of loop', 'compiler', stmt.line);
        }
        const loop = this.loops[this.loops.length - 1];
        this.emitCloseFromLocalIdx(loop.continueMinLocalIdx);
        loop.continueJumps.push(this.emit(Op.JMP, 0, 0, 0));
        break;
      }
    }
    // Reclaim any temporary registers allocated during the statement
    if (this.getTopReg() > savedTop) {
      this.setTopReg(savedTop);
    }
  }

  private compileFuncStmt(stmt: FuncStmt): void {
    const { name, func } = stmt;
    const effectiveFunc: FuncBody = name.method
      ? {
          params: ['self', ...func.params],
          isVararg: func.isVararg,
          body: func.body,
          pragma: func.pragma,
          line: func.line,
        }
      : func;

    if (name.fields.length === 0 && name.method === null) {
      // `function foo() ... end`
      const fnReg = this.allocReg();
      this.compileClosureInto(effectiveFunc, fnReg);
      this.storeIdent(name.base, fnReg);
      return;
    }

    // `function a.b.c() ... end` or `function a.b:c() ... end`
    const objReg = this.allocReg();
    this.loadIdent(name.base, objReg);
    const allFields = name.method ? [...name.fields, name.method] : name.fields;
    for (let i = 0; i < allFields.length - 1; i++) {
      const k = this.addIdentConst(allFields[i]);
      this.emit(Op.GETTABLEK, objReg, objReg, k);
    }
    const lastKey = this.addIdentConst(allFields[allFields.length - 1]);
    const fnReg = this.allocReg();
    this.compileClosureInto(effectiveFunc, fnReg);
    this.emit(Op.SETTABLEK, objReg, lastKey, fnReg);
  }

  private compileAssign(stmt: AssignStmt): void {
    const nTargets = stmt.targets.length;

    // Pre-evaluate table & index expressions left-to-right BEFORE evaluating RHS
    // (Exact Lua/Luau order so `i, a[i] = i + 1, 20` uses original `i` for `a[i]`!)
    type PreparedTarget =
      | { kind: 'local'; reg: number }
      | { kind: 'upval'; idx: number }
      | { kind: 'global'; kIdx: number }
      | { kind: 'tablek'; objReg: number; kIdx: number }
      | { kind: 'table'; objReg: number; keyReg: number };

    const prepared: PreparedTarget[] = [];
    for (const target of stmt.targets) {
      if (target.kind === 'IdentExpr') {
        const loc = this.resolveLocal(target.name);
        if (loc) {
          prepared.push({ kind: 'local', reg: loc.reg });
        } else {
          const up = this.resolveUpvalue(target.name);
          if (up !== null) prepared.push({ kind: 'upval', idx: up });
          else prepared.push({ kind: 'global', kIdx: this.addIdentConst(target.name) });
        }
      } else if (target.kind === 'MemberExpr') {
        const objReg = this.allocReg();
        this.compileExprInto(target.object, objReg);
        prepared.push({ kind: 'tablek', objReg, kIdx: this.addIdentConst(target.property) });
      } else {
        const objReg = this.allocReg();
        this.compileExprInto(target.object, objReg);
        const keyReg = this.allocReg();
        this.compileExprInto(target.index, keyReg);
        prepared.push({ kind: 'table', objReg, keyReg });
      }
    }

    // Fast path for single local assignment `x = expr`
    if (nTargets === 1 && prepared[0].kind === 'local' && stmt.values.length === 1) {
      this.compileExprInto(stmt.values[0], prepared[0].reg);
      return;
    }

    // Evaluate RHS list into fresh temporary registers (handles swaps like `a, b = b, a`!)
    const valBase = this.allocRegs(nTargets);
    this.compileExprListFixed(stmt.values, valBase, nTargets);

    // Assign right-to-left (exact Lua 5.1 / Luau semantics for duplicate targets `x, x = 1, 2`)
    for (let i = nTargets - 1; i >= 0; i--) {
      const t = prepared[i];
      const vReg = valBase + i;
      switch (t.kind) {
        case 'local':
          this.emit(Op.MOVE, t.reg, vReg, 0);
          break;
        case 'upval':
          this.emit(Op.SETUPVAL, vReg, t.idx, 0);
          break;
        case 'global':
          this.emit(Op.SETGLOBAL, vReg, t.kIdx, 0);
          break;
        case 'tablek':
          this.emit(Op.SETTABLEK, t.objReg, t.kIdx, vReg);
          break;
        case 'table':
          this.emit(Op.SETTABLE, t.objReg, t.keyReg, vReg);
          break;
      }
    }
  }

  /** Luau compound assignment `target op= value` — evaluates LHS base & key strictly ONCE! */
  private compileCompoundAssign(stmt: CompoundAssignStmt): void {
    const binOp = compoundToBinary(stmt.op);
    const target: LValue = stmt.target;

    if (target.kind === 'IdentExpr') {
      const loc = this.resolveLocal(target.name);
      if (loc) {
        const rhsReg = this.allocReg();
        this.compileExprInto(stmt.value, rhsReg);
        this.emitBinaryArithOrConcat(binOp, loc.reg, loc.reg, rhsReg);
        return;
      }
      const curReg = this.allocReg();
      const up = this.resolveUpvalue(target.name);
      const kIdx = up === null ? this.addIdentConst(target.name) : 0;
      if (up !== null) this.emit(Op.GETUPVAL, curReg, up, 0);
      else this.emit(Op.GETGLOBAL, curReg, kIdx, 0);

      const rhsReg = this.allocReg();
      this.compileExprInto(stmt.value, rhsReg);
      this.emitBinaryArithOrConcat(binOp, curReg, curReg, rhsReg);

      if (up !== null) this.emit(Op.SETUPVAL, curReg, up, 0);
      else this.emit(Op.SETGLOBAL, curReg, kIdx, 0);
      return;
    }

    if (target.kind === 'MemberExpr') {
      const objReg = this.allocReg();
      this.compileExprInto(target.object, objReg);
      const kIdx = this.addIdentConst(target.property);
      const curReg = this.allocReg();
      this.emit(Op.GETTABLEK, curReg, objReg, kIdx);
      const rhsReg = this.allocReg();
      this.compileExprInto(stmt.value, rhsReg);
      this.emitBinaryArithOrConcat(binOp, curReg, curReg, rhsReg);
      this.emit(Op.SETTABLEK, objReg, kIdx, curReg);
      return;
    }

    // IndexExpr: evaluate object & index ONCE
    const objReg = this.allocReg();
    this.compileExprInto(target.object, objReg);
    const keyReg = this.allocReg();
    this.compileExprInto(target.index, keyReg);
    const curReg = this.allocReg();
    this.emit(Op.GETTABLE, curReg, objReg, keyReg);
    const rhsReg = this.allocReg();
    this.compileExprInto(stmt.value, rhsReg);
    this.emitBinaryArithOrConcat(binOp, curReg, curReg, rhsReg);
    this.emit(Op.SETTABLE, objReg, keyReg, curReg);
  }

  private emitBinaryArithOrConcat(op: BinaryOp, dst: number, lhs: number, rhs: number): void {
    if (op === '..') {
      // CONCAT requires contiguous registers B..C
      const pair = this.allocRegs(2);
      this.emit(Op.MOVE, pair, lhs, 0);
      this.emit(Op.MOVE, pair + 1, rhs, 0);
      this.emit(Op.CONCAT, dst, pair, pair + 1);
      return;
    }
    this.emitSimpleBinaryOp(op, dst, lhs, rhs);
  }

  private compileIfStmt(stmt: IfStmt): void {
    const endJumps: number[] = [];

    for (let i = 0; i < stmt.branches.length; i++) {
      const br = stmt.branches[i];
      const saved = this.getTopReg();
      const condReg = this.allocReg();
      this.compileExprInto(br.condition, condReg);
      const falseJmp = this.emit(Op.JMPF, condReg, 0, 0);
      this.setTopReg(saved);

      this.compileBlock(br.body, true);

      if (i < stmt.branches.length - 1 || stmt.elseBody) {
        endJumps.push(this.emit(Op.JMP, 0, 0, 0));
      }
      this.patchB(falseJmp, this.nextPC());
    }

    if (stmt.elseBody) {
      this.compileBlock(stmt.elseBody, true);
    }

    const endPC = this.nextPC();
    for (const j of endJumps) this.patchB(j, endPC);
  }

  private compileWhileStmt(stmt: WhileStmt): void {
    const condPC = this.nextPC();
    const saved = this.getTopReg();
    const condReg = this.allocReg();
    this.compileExprInto(stmt.condition, condReg);
    const exitJmp = this.emit(Op.JMPF, condReg, 0, 0);
    this.setTopReg(saved);

    const bodyScope = this.enterScope();
    const loopCtx: LoopContext = {
      breakJumps: [exitJmp],
      continueJumps: [],
      breakMinLocalIdx: bodyScope.firstLocalIdx,
      continueMinLocalIdx: bodyScope.firstLocalIdx,
    };
    this.loops.push(loopCtx);

    this.compileBlock(stmt.body, false);
    this.leaveScope(true);
    this.loops.pop();

    this.emit(Op.JMP, 0, condPC, 0);

    const afterPC = this.nextPC();
    for (const j of loopCtx.continueJumps) this.patchB(j, condPC);
    for (const j of loopCtx.breakJumps) this.patchB(j, afterPC);
  }

  private compileRepeatStmt(stmt: RepeatStmt): void {
    // CRITICAL LUAU RULE:
    // 1. Locals declared in `repeat` body are IN SCOPE inside `until <cond>`!
    // 2. `continue` jumps to `<cond>` (keeping body locals live for `<cond>`, then closed)!
    // 3. `break` closes body locals and jumps past `until <cond>`!
    const startPC = this.nextPC();
    const bodyScope = this.enterScope();
    const loopCtx: LoopContext = {
      breakJumps: [],
      continueJumps: [],
      breakMinLocalIdx: bodyScope.firstLocalIdx,
      continueMinLocalIdx: this.locals.length + 999999, // patched below per continue? No: inner nested blocks inside body still must close!
    };
    this.loops.push(loopCtx);

    // Compile body statements directly in bodyScope; note `continue` inside nested block closes
    // any captured locals; closing even body locals read in `until` is SAFE in Luau because closed
    // upvalues retain their exact value in `u[0]` and locals themselves stay in `R[reg]` until overwritten!
    loopCtx.continueMinLocalIdx = bodyScope.firstLocalIdx;
    this.compileBlock(stmt.body, false);
    this.loops.pop();

    const condPC = this.nextPC();
    for (const j of loopCtx.continueJumps) this.patchB(j, condPC);

    const condReg = this.allocReg();
    this.compileExprInto(stmt.condition, condReg);

    // Check if any local in bodyScope was captured — must close on EVERY iteration!
    let hasCaptured = false;
    let firstCapturedReg = 0;
    for (let i = bodyScope.firstLocalIdx; i < this.locals.length; i++) {
      if (this.locals[i].captured) {
        hasCaptured = true;
        firstCapturedReg = this.locals[i].reg;
        break;
      }
    }

    if (hasCaptured) {
      // Save condition result or close before branching (CLOSE doesn't alter stack registers!)
      this.emit(Op.CLOSE, firstCapturedReg, 0, 0);
    }
    this.emit(Op.JMPF, condReg, startPC, 0);

    // Already emitted CLOSE above, so leaveScope(false)
    this.leaveScope(false);

    const afterPC = this.nextPC();
    for (const j of loopCtx.breakJumps) this.patchB(j, afterPC);
  }

  private compileNumericFor(stmt: NumericForStmt): void {
    const outerScope = this.enterScope();
    // Hidden control slots: base+0 = index, base+1 = limit, base+2 = step; base+3 = user loop var
    const base = this.allocRegs(4);
    this.compileExprInto(stmt.start, base);
    this.compileExprInto(stmt.limit, base + 1);
    if (stmt.step) {
      this.compileExprInto(stmt.step, base + 2);
    } else {
      const k1 = this.addNumberConst(1);
      this.emit(Op.LOADK, base + 2, k1, 0);
    }

    const prepPC = this.emit(Op.FORPREP, base, 0, 0);
    const bodyPC = this.nextPC();

    const innerScope = this.enterScope();
    this.declareLocal(stmt.varName, base + 3);

    const loopCtx: LoopContext = {
      breakJumps: [],
      continueJumps: [],
      breakMinLocalIdx: outerScope.firstLocalIdx,
      continueMinLocalIdx: innerScope.firstLocalIdx,
    };
    this.loops.push(loopCtx);

    this.compileBlock(stmt.body, false);
    this.leaveScope(true); // emits CLOSE base+3 if loop var or body local was captured!
    this.loops.pop();

    const stepPC = this.nextPC();
    for (const j of loopCtx.continueJumps) this.patchB(j, stepPC);

    this.emit(Op.FORLOOP, base, bodyPC, 0);

    const afterPC = this.nextPC();
    this.patchB(prepPC, afterPC);
    for (const j of loopCtx.breakJumps) this.patchB(j, afterPC);

    this.leaveScope(false);
  }

  private compileGenericFor(stmt: GenericForStmt): void {
    const outerScope = this.enterScope();
    const nVars = stmt.names.length;
    // base+0 = iter fn, base+1 = state, base+2 = control var, base+3..base+2+nVars = user loop vars
    const base = this.allocRegs(3 + nVars);
    this.compileExprListFixed(stmt.iterators, base, 3);

    // ITERPREP supports full Luau generalized iteration (`for k, v in tbl do` + `__iter` + `pairs`/`ipairs`)
    const prepPC = this.emit(Op.ITERPREP, base, 0, 0);
    const bodyPC = this.nextPC();

    const innerScope = this.enterScope();
    for (let i = 0; i < nVars; i++) {
      this.declareLocal(stmt.names[i], base + 3 + i);
    }

    const loopCtx: LoopContext = {
      breakJumps: [],
      continueJumps: [],
      breakMinLocalIdx: outerScope.firstLocalIdx,
      continueMinLocalIdx: innerScope.firstLocalIdx,
    };
    this.loops.push(loopCtx);

    this.compileBlock(stmt.body, false);
    this.leaveScope(true); // closes captured loop vars each iteration!
    this.loops.pop();

    const loopTestPC = this.nextPC();
    this.patchB(prepPC, loopTestPC);
    for (const j of loopCtx.continueJumps) this.patchB(j, loopTestPC);

    this.emit(Op.TFORLOOP, base | (nVars << 10), bodyPC, 0);

    const afterPC = this.nextPC();
    for (const j of loopCtx.breakJumps) this.patchB(j, afterPC);

    this.leaveScope(false);
  }

  private compileReturn(values: Expression[]): void {
    if (values.length === 0) {
      this.emit(Op.RETURN, 0, 1, 0);
      return;
    }

    if (values.length === 1 && !isMultiReturnExpr(values[0])) {
      const r = this.allocReg();
      this.compileExprInto(values[0], r);
      this.emit(Op.RETURN, r, 2, 0);
      return;
    }

    const last = values[values.length - 1];
    if (isMultiReturnExpr(last)) {
      const fixedCount = values.length - 1;
      const base = this.allocRegs(fixedCount + 1);
      for (let i = 0; i < fixedCount; i++) {
        this.compileExprInto(values[i], base + i);
      }
      this.compileMultiExpr(last, base + fixedCount);
      this.emit(Op.RETURN, base, 0, 0); // B=0 -> return R[base..top]
      return;
    }

    const base = this.allocRegs(values.length);
    for (let i = 0; i < values.length; i++) {
      this.compileExprInto(values[i], base + i);
    }
    this.emit(Op.RETURN, base, values.length + 1, 0);
  }

  // ---------------------------------------------------------------------------
  // Expressions
  // ---------------------------------------------------------------------------

  compileExprListFixed(exprs: Expression[], baseReg: number, needed: number): void {
    if (needed === 0) {
      for (const e of exprs) {
        const tmp = this.allocReg();
        this.compileExprInto(e, tmp);
      }
      return;
    }

    const nExprs = exprs.length;
    if (nExprs === 0) {
      this.emit(Op.LOADNIL, baseReg, baseReg + needed - 1, 0);
      return;
    }

    // Evaluate all expressions except the last to 1 value each
    for (let i = 0; i < nExprs - 1; i++) {
      if (i < needed) {
        this.compileExprInto(exprs[i], baseReg + i);
      } else {
        // Extra expression — evaluate for side effects and discard!
        const tmp = this.allocReg();
        this.compileExprInto(exprs[i], tmp);
      }
    }

    const lastIdx = nExprs - 1;
    const last = exprs[lastIdx];

    if (lastIdx >= needed) {
      const tmp = this.allocReg();
      this.compileExprInto(last, tmp);
      return;
    }

    const remaining = needed - lastIdx; // >= 1
    if (isMultiReturnExpr(last) && remaining > 1) {
      if (last.kind === 'VarargExpr') {
        this.emit(Op.VARARG, baseReg + lastIdx, remaining + 1, 0);
      } else {
        this.compileCallInto(last, baseReg + lastIdx, remaining);
      }
      return;
    }

    this.compileExprInto(last, baseReg + lastIdx);
    if (remaining > 1) {
      this.emit(Op.LOADNIL, baseReg + lastIdx + 1, baseReg + needed - 1, 0);
    }
  }

  /** Compile a trailing multi-return expression setting VM `top` dynamically */
  private compileMultiExpr(expr: Expression, dstReg: number): void {
    // Ensure dstReg is at/near the top of active registers so variable results don't clobber live locals!
    if (this.nextReg <= dstReg) this.setTopReg(dstReg + 1);
    if (expr.kind === 'VarargExpr') {
      this.emit(Op.VARARG, dstReg, 0, 0);
    } else if (expr.kind === 'CallExpr' || expr.kind === 'MethodCallExpr') {
      this.compileCallInto(expr, dstReg, -1); // -1 => variable results (C = 0)
    } else {
      this.compileExprInto(expr, dstReg);
    }
  }

  compileExprInto(rawExpr: Expression, dst: number): void {
    const expr = foldExpr(rawExpr);
    const saved = Math.max(this.getTopReg(), dst + 1);
    this.setTopReg(saved);

    switch (expr.kind) {
      case 'NilLiteral':
        this.emit(Op.LOADNIL, dst, dst, 0);
        break;

      case 'BoolLiteral':
        this.emit(Op.LOADBOOL, dst, expr.value ? 1 : 0, 0);
        break;

      case 'NumberLiteral': {
        const k = this.addNumberConst(expr.value);
        this.emit(Op.LOADK, dst, k, 0);
        break;
      }

      case 'StringLiteral': {
        const k = this.addStringConst(expr.bytes);
        this.emit(Op.LOADK, dst, k, 0);
        break;
      }

      case 'VarargExpr':
        if (!this.isVararg) {
          throw new GrandfuscatorError('Cannot use `...` outside a vararg function', 'compiler', expr.line);
        }
        this.emit(Op.VARARG, dst, 2, 0); // 1 result
        break;

      case 'ParenExpr':
        // Explicitly produces strictly 1 value (already true of compileExprInto)
        this.compileExprInto(expr.expression, dst);
        break;

      case 'IdentExpr':
        this.loadIdent(expr.name, dst);
        break;

      case 'FuncExpr':
        this.compileClosureInto(expr.func, dst);
        break;

      case 'TableExpr':
        this.compileTableInto(expr, dst);
        break;

      case 'MemberExpr': {
        const objReg = this.allocReg();
        this.compileExprInto(expr.object, objReg);
        const k = this.addIdentConst(expr.property);
        this.emit(Op.GETTABLEK, dst, objReg, k);
        break;
      }

      case 'IndexExpr': {
        const objReg = this.allocReg();
        this.compileExprInto(expr.object, objReg);
        const keyReg = this.allocReg();
        this.compileExprInto(expr.index, keyReg);
        this.emit(Op.GETTABLE, dst, objReg, keyReg);
        break;
      }

      case 'UnaryExpr':
        this.compileUnaryInto(expr, dst);
        break;

      case 'BinaryExpr':
        this.compileBinaryInto(expr, dst);
        break;

      case 'CallExpr':
      case 'MethodCallExpr':
        this.compileCallInto(expr, dst, 1); // 1 result
        break;

      case 'IfExpr':
        this.compileIfExprInto(expr, dst);
        break;

      case 'InterpStringExpr':
        this.compileInterpStringInto(expr, dst);
        break;
    }

    this.setTopReg(saved);
  }

  private loadIdent(name: string, dst: number): void {
    const loc = this.resolveLocal(name);
    if (loc) {
      if (loc.reg !== dst) this.emit(Op.MOVE, dst, loc.reg, 0);
      return;
    }
    const up = this.resolveUpvalue(name);
    if (up !== null) {
      this.emit(Op.GETUPVAL, dst, up, 0);
      return;
    }
    const k = this.addIdentConst(name);
    this.emit(Op.GETGLOBAL, dst, k, 0);
  }

  private storeIdent(name: string, src: number): void {
    const loc = this.resolveLocal(name);
    if (loc) {
      if (loc.reg !== src) this.emit(Op.MOVE, loc.reg, src, 0);
      return;
    }
    const up = this.resolveUpvalue(name);
    if (up !== null) {
      this.emit(Op.SETUPVAL, src, up, 0);
      return;
    }
    const k = this.addIdentConst(name);
    this.emit(Op.SETGLOBAL, src, k, 0);
  }

  private compileUnaryInto(expr: UnaryExpr, dst: number): void {
    const r = this.allocReg();
    this.compileExprInto(expr.argument, r);
    switch (expr.op) {
      case '-': this.emit(Op.UNM, dst, r, 0); break;
      case 'not': this.emit(Op.NOT, dst, r, 0); break;
      case '#': this.emit(Op.LEN, dst, r, 0); break;
    }
  }

  private compileBinaryInto(expr: BinaryExpr, dst: number): void {
    // Short-circuit `and`: returns left if falsy, else evaluates & returns right
    if (expr.op === 'and') {
      this.compileExprInto(expr.left, dst);
      const skipJmp = this.emit(Op.JMPF, dst, 0, 0);
      this.compileExprInto(expr.right, dst);
      this.patchB(skipJmp, this.nextPC());
      return;
    }

    // Short-circuit `or`: returns left if truthy, else evaluates & returns right
    if (expr.op === 'or') {
      this.compileExprInto(expr.left, dst);
      const skipJmp = this.emit(Op.JMPT, dst, 0, 0);
      this.compileExprInto(expr.right, dst);
      this.patchB(skipJmp, this.nextPC());
      return;
    }

    // Flatten chained string concatenations `a .. b .. c .. d` into a single CONCAT instruction!
    if (expr.op === '..') {
      const parts: Expression[] = [];
      let cur: Expression = expr;
      while (cur.kind === 'BinaryExpr' && cur.op === '..') {
        parts.push(cur.left);
        cur = cur.right;
      }
      parts.push(cur);
      const base = this.allocRegs(parts.length);
      for (let i = 0; i < parts.length; i++) {
        this.compileExprInto(parts[i], base + i);
      }
      this.emit(Op.CONCAT, dst, base, base + parts.length - 1);
      return;
    }

    // Evaluate left then right (preserving side-effect order!)
    const lhsReg = this.allocReg();
    this.compileExprInto(expr.left, lhsReg);
    const rhsReg = this.allocReg();
    this.compileExprInto(expr.right, rhsReg);
    this.emitSimpleBinaryOp(expr.op, dst, lhsReg, rhsReg);
  }

  private emitSimpleBinaryOp(op: BinaryOp, dst: number, lhs: number, rhs: number): void {
    switch (op) {
      case '+':  this.emit(Op.ADD, dst, lhs, rhs); break;
      case '-':  this.emit(Op.SUB, dst, lhs, rhs); break;
      case '*':  this.emit(Op.MUL, dst, lhs, rhs); break;
      case '/':  this.emit(Op.DIV, dst, lhs, rhs); break;
      case '//': this.emit(Op.IDIV, dst, lhs, rhs); break;
      case '%':  this.emit(Op.MOD, dst, lhs, rhs); break;
      case '^':  this.emit(Op.POW, dst, lhs, rhs); break;
      case '==': this.emit(Op.EQ, dst, lhs, rhs); break;
      case '~=': this.emit(Op.NE, dst, lhs, rhs); break;
      case '<':  this.emit(Op.LT, dst, lhs, rhs); break;
      case '<=': this.emit(Op.LE, dst, lhs, rhs); break;
      case '>':  this.emit(Op.LT, dst, rhs, lhs); break; // a > b  <=> b < a
      case '>=': this.emit(Op.LE, dst, rhs, lhs); break; // a >= b <=> b <= a
      default:
        throw new GrandfuscatorError(`Unhandled binary operator ${op}`, 'compiler');
    }
  }

  /**
   * Compile function or method call.
   * `numResults`: -1 = all results (sets VM `top`), 0 = none, 1 = single into `dst`, k = `dst..dst+k-1`.
   *
   * CRITICAL REGISTER SAFETY:
   * CALL uses a contiguous frame `callBase, callBase+1, ...` at the TOP of the register file
   * so arguments and variable returns NEVER clobber any live local variable below `nextReg`!
   */
  private compileCallInto(expr: CallExpr | MethodCallExpr, dst: number, numResults: number): void {
    // Only call in-place for variable multi-return (`numResults === -1`), where the caller always
    // passes a brand-new unaliased top register. Otherwise allocate a fresh frame so assignments
    // like `x = fn(x, y)` or `x = obj:method(x)` never clobber `x` before evaluating arguments!
    const canCallInPlace = numResults === -1 && dst + 1 === this.nextReg;

    const frame = canCallInPlace ? dst : this.allocReg();
    let argStart: number;
    let implicitSelfCount = 0;

    if (expr.kind === 'MethodCallExpr') {
      // Reserve frame (fn) and frame+1 (self)
      if (this.nextReg < frame + 2) this.setTopReg(frame + 2);
      const objTmp = this.allocReg();
      this.compileExprInto(expr.object, objTmp);
      const methodK = this.addIdentConst(expr.method);
      this.emit(Op.SELF, frame, objTmp, methodK);
      this.setTopReg(frame + 2);
      argStart = frame + 2;
      implicitSelfCount = 1;
    } else {
      if (this.nextReg < frame + 1) this.setTopReg(frame + 1);
      this.compileExprInto(expr.callee, frame);
      this.setTopReg(frame + 1);
      argStart = frame + 1;
    }

    const args = expr.args;
    let bField: number;

    if (args.length === 0) {
      bField = 1 + implicitSelfCount;
    } else {
      const lastArg = args[args.length - 1];
      if (isMultiReturnExpr(lastArg)) {
        const fixed = args.length - 1;
        this.setTopReg(argStart + fixed + 1);
        for (let i = 0; i < fixed; i++) {
          this.compileExprInto(args[i], argStart + i);
        }
        this.setTopReg(argStart + fixed + 1);
        this.compileMultiExpr(lastArg, argStart + fixed);
        bField = 0; // variable args frame+1..top
      } else {
        this.setTopReg(argStart + args.length);
        for (let i = 0; i < args.length; i++) {
          this.compileExprInto(args[i], argStart + i);
        }
        bField = 1 + implicitSelfCount + args.length;
      }
    }

    const cField = numResults < 0 ? 0 : numResults + 1;
    this.emit(Op.CALL, frame, bField, cField);

    if (!canCallInPlace && numResults > 0) {
      for (let i = 0; i < numResults; i++) {
        this.emit(Op.MOVE, dst + i, frame + i, 0);
      }
    }
  }

  private compileTableInto(expr: TableExpr, dst: number): void {
    // Allocate table in a fresh top slot if dst could alias something, then build fields cleanly
    const tblReg = this.allocReg();
    this.emit(Op.NEWTABLE, tblReg, 0, 0);

    const BATCH = 32;
    let listOffset = 0;
    let pendingList = 0;
    const batchBase = tblReg; // SETLIST copies batchBase+1 .. batchBase+B into tbl[offset+1..]

    const flushBatch = () => {
      if (pendingList > 0) {
        this.emit(Op.SETLIST, batchBase, pendingList, listOffset);
        listOffset += pendingList;
        pendingList = 0;
        this.setTopReg(batchBase + 1);
      }
    };

    for (let i = 0; i < expr.fields.length; i++) {
      const f = expr.fields[i];
      const isLast = i === expr.fields.length - 1;

      if (f.kind === 'ListField') {
        if (isLast && isMultiReturnExpr(f.value)) {
          const slot = batchBase + 1 + pendingList;
          this.setTopReg(slot + 1);
          this.compileMultiExpr(f.value, slot);
          // B = 0 copies batchBase+1 .. top into tbl[listOffset+1 ..]
          this.emit(Op.SETLIST, batchBase, 0, listOffset);
          pendingList = 0;
          this.setTopReg(batchBase + 1);
        } else {
          pendingList++;
          const slot = batchBase + pendingList;
          this.setTopReg(slot + 1);
          this.compileExprInto(f.value, slot);
          if (pendingList >= BATCH) flushBatch();
        }
      } else if (f.kind === 'RecordField') {
        // Keep pending list slots intact above batchBase while evaluating record field above them!
        const valReg = this.allocReg();
        this.compileExprInto(f.value, valReg);
        const k = this.addIdentConst(f.key);
        this.emit(Op.SETTABLEK, batchBase, k, valReg);
        this.setTopReg(batchBase + 1 + pendingList);
      } else {
        const keyReg = this.allocReg();
        this.compileExprInto(f.key, keyReg);
        const valReg = this.allocReg();
        this.compileExprInto(f.value, valReg);
        this.emit(Op.SETTABLE, batchBase, keyReg, valReg);
        this.setTopReg(batchBase + 1 + pendingList);
      }
    }

    flushBatch();
    if (tblReg !== dst) {
      this.emit(Op.MOVE, dst, tblReg, 0);
    }
  }

  private compileIfExprInto(expr: IfExpr, dst: number): void {
    const endJumps: number[] = [];
    for (const br of expr.branches) {
      const cReg = this.allocReg();
      this.compileExprInto(br.condition, cReg);
      const falseJmp = this.emit(Op.JMPF, cReg, 0, 0);
      this.compileExprInto(br.value, dst);
      endJumps.push(this.emit(Op.JMP, 0, 0, 0));
      this.patchB(falseJmp, this.nextPC());
    }
    this.compileExprInto(expr.elseValue, dst);
    const endPC = this.nextPC();
    for (const j of endJumps) this.patchB(j, endPC);
  }

  private compileInterpStringInto(expr: InterpStringExpr, dst: number): void {
    // Collect non-empty segments & tostring(expr) pieces in exact evaluation order
    // First evaluate ALL expressions in order (preserving side effects even around empty segments)
    const parts: { kind: 'seg'; bytes: Uint8Array }[] | { kind: 'expr'; reg: number }[] = [];
    const items: Array<{ kind: 'seg'; bytes: Uint8Array } | { kind: 'expr'; expr: Expression }> = [];

    for (let i = 0; i < expr.segments.length; i++) {
      if (expr.segments[i].length > 0) {
        items.push({ kind: 'seg', bytes: expr.segments[i] });
      }
      if (i < expr.expressions.length) {
        items.push({ kind: 'expr', expr: expr.expressions[i] });
      }
    }
    void parts;

    if (items.length === 0) {
      const k = this.addStringConst(new Uint8Array(0));
      this.emit(Op.LOADK, dst, k, 0);
      return;
    }

    if (items.length === 1) {
      const only = items[0];
      if (only.kind === 'seg') {
        const k = this.addStringConst(only.bytes);
        this.emit(Op.LOADK, dst, k, 0);
      } else {
        const tmp = this.allocReg();
        this.compileExprInto(only.expr, tmp);
        this.emit(Op.TOSTRING, dst, tmp, 0);
      }
      return;
    }

    const base = this.allocRegs(items.length);
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (it.kind === 'seg') {
        const k = this.addStringConst(it.bytes);
        this.emit(Op.LOADK, base + i, k, 0);
      } else {
        this.compileExprInto(it.expr, base + i);
        this.emit(Op.TOSTRING, base + i, base + i, 0);
      }
    }
    this.emit(Op.CONCAT, dst, base, base + items.length - 1);
  }

  private compileClosureInto(func: FuncBody, dst: number): void {
    // `--@novm` escape hatch: emit native AST-obfuscated function sharing live VM upvalues!
    if (func.pragma === 'novm') {
      const free = collectFreeVars(func);
      const upvals = this.captureForNativeEscape(free);
      const id = this.nativeEscapes.length + 1; // 1-based
      this.nativeEscapes.push({ id, func, upvals });
      this.emit(Op.NATCLOSURE, dst, id, 0);
      return;
    }

    const child = new FuncCompiler(this, func.params.length, func.isVararg, this.nativeEscapes);
    child.enterScope();
    for (const p of func.params) {
      child.declareLocal(p);
    }
    child.compileBlock(func.body, false);
    child.leaveScope(true);
    // Implicit trailing `return`
    child.emit(Op.RETURN, 0, 1, 0);

    const proto = child.toProto();
    this.protos.push(proto);
    this.emit(Op.CLOSURE, dst, this.protos.length, 0); // 1-based proto index
  }

  toProto(): IRProto {
    return {
      numParams: this.numParams,
      isVararg: this.isVararg,
      maxStack: Math.max(2, this.maxStack),
      entryPC: 0,
      entryKey: 0,
      instructions: this.instructions,
      constants: this.constants,
      upvals: this.upvals,
      protos: this.protos,
      usedOps: this.usedOps,
      loopHints: this.loopHints,
    };
  }
}

/** Collect all identifier names referenced inside `func` that aren't declared locally inside it */
export function collectFreeVars(func: FuncBody): Set<string> {
  const free = new Set<string>();

  function visitFunc(fb: FuncBody, outerBound: Set<string>): void {
    const bound = new Set(outerBound);
    for (const p of fb.params) bound.add(p);
    visitBlock(fb.body, bound);
  }

  function visitBlock(block: Block, parentBound: Set<string>): void {
    const bound = new Set(parentBound);
    for (const s of block.statements) visitStmt(s, bound);
    if (block.returnStmt) {
      for (const v of block.returnStmt.values) visitExpr(v, bound);
    }
  }

  function visitStmt(s: Statement, bound: Set<string>): void {
    switch (s.kind) {
      case 'LocalStmt':
        for (const v of s.values) visitExpr(v, bound);
        for (const n of s.names) bound.add(n);
        break;
      case 'LocalFuncStmt':
        bound.add(s.name);
        visitFunc(s.func, bound);
        break;
      case 'FuncStmt': {
        if (!bound.has(s.name.base)) free.add(s.name.base);
        const fb = s.name.method
          ? { ...s.func, params: ['self', ...s.func.params] }
          : s.func;
        visitFunc(fb, bound);
        break;
      }
      case 'AssignStmt':
        for (const t of s.targets) visitExpr(t, bound);
        for (const v of s.values) visitExpr(v, bound);
        break;
      case 'CompoundAssignStmt':
        visitExpr(s.target, bound);
        visitExpr(s.value, bound);
        break;
      case 'CallStmt':
        visitExpr(s.expr, bound);
        break;
      case 'DoStmt':
        visitBlock(s.body, bound);
        break;
      case 'WhileStmt':
        visitExpr(s.condition, bound);
        visitBlock(s.body, bound);
        break;
      case 'RepeatStmt': {
        const inner = new Set(bound);
        for (const st of s.body.statements) visitStmt(st, inner);
        if (s.body.returnStmt) for (const v of s.body.returnStmt.values) visitExpr(v, inner);
        visitExpr(s.condition, inner);
        break;
      }
      case 'IfStmt':
        for (const b of s.branches) {
          visitExpr(b.condition, bound);
          visitBlock(b.body, bound);
        }
        if (s.elseBody) visitBlock(s.elseBody, bound);
        break;
      case 'NumericForStmt': {
        visitExpr(s.start, bound);
        visitExpr(s.limit, bound);
        if (s.step) visitExpr(s.step, bound);
        const inner = new Set(bound);
        inner.add(s.varName);
        visitBlock(s.body, inner);
        break;
      }
      case 'GenericForStmt': {
        for (const it of s.iterators) visitExpr(it, bound);
        const inner = new Set(bound);
        for (const n of s.names) inner.add(n);
        visitBlock(s.body, inner);
        break;
      }
      case 'BreakStmt':
      case 'ContinueStmt':
      case 'TypeAliasStmt':
        break;
    }
  }

  function visitExpr(e: Expression, bound: Set<string>): void {
    switch (e.kind) {
      case 'IdentExpr':
        if (!bound.has(e.name)) free.add(e.name);
        break;
      case 'FuncExpr':
        visitFunc(e.func, bound);
        break;
      case 'TableExpr':
        for (const f of e.fields) {
          if (f.kind === 'IndexField') visitExpr(f.key, bound);
          visitExpr(f.value, bound);
        }
        break;
      case 'BinaryExpr':
        visitExpr(e.left, bound);
        visitExpr(e.right, bound);
        break;
      case 'UnaryExpr':
        visitExpr(e.argument, bound);
        break;
      case 'IndexExpr':
        visitExpr(e.object, bound);
        visitExpr(e.index, bound);
        break;
      case 'MemberExpr':
        visitExpr(e.object, bound);
        break;
      case 'CallExpr':
        visitExpr(e.callee, bound);
        for (const a of e.args) visitExpr(a, bound);
        break;
      case 'MethodCallExpr':
        visitExpr(e.object, bound);
        for (const a of e.args) visitExpr(a, bound);
        break;
      case 'IfExpr':
        for (const b of e.branches) {
          visitExpr(b.condition, bound);
          visitExpr(b.value, bound);
        }
        visitExpr(e.elseValue, bound);
        break;
      case 'InterpStringExpr':
        for (const ex of e.expressions) visitExpr(ex, bound);
        break;
      case 'ParenExpr':
        visitExpr(e.expression, bound);
        break;
      case 'NilLiteral':
      case 'BoolLiteral':
      case 'NumberLiteral':
      case 'StringLiteral':
      case 'VarargExpr':
        break;
    }
  }

  visitFunc(func, new Set());
  return free;
}

function gatherStats(proto: IRProto, allOps: Set<Op>): { protos: number; insts: number } {
  for (const op of proto.usedOps) allOps.add(op);
  let protos = 1;
  let insts = proto.instructions.length;
  for (const child of proto.protos) {
    const sub = gatherStats(child, allOps);
    protos += sub.protos;
    insts += sub.insts;
  }
  return { protos, insts };
}

function emptyCfgStats(): CFGTransformStats {
  return {
    fusedSuperinstructions: 0,
    mutatedInstructions: 0,
    destroyedConstants: 0,
    shatteredStrings: 0,
    chaffOps: 0,
    decoyProtos: 0,
    cfgBlocks: 0,
    cffDispatcherNodes: 0,
    jumpChainHops: 0,
    opaqueForks: 0,
    bogusBlocks: 0,
    guardOpcodes: 0,
  };
}

export function compileChunk(chunk: Chunk): CompiledModule {
  const nativeEscapes: NativeEscapeProto[] = [];
  // Top-level Luau chunk is always a vararg function (`local args = {...}`)
  const rootCompiler = new FuncCompiler(null, 0, true, nativeEscapes);
  rootCompiler.compileBlock(chunk.body, true);
  rootCompiler.emit(Op.RETURN, 0, 1, 0);

  const root = rootCompiler.toProto();
  const allUsedOps = new Set<Op>();
  const stats = gatherStats(root, allUsedOps);

  return {
    root,
    nativeEscapes,
    totalProtos: stats.protos,
    totalInstructions: stats.insts,
    allUsedOps,
    cfgStats: emptyCfgStats(),
  };
}

export function compileSingleFunction(func: FuncBody, freeVarUpvals: string[]): CompiledModule {
  const nativeEscapes: NativeEscapeProto[] = [];
  const fakeParent = freeVarUpvals.length > 0 ? new FuncCompiler(null, 0, false, nativeEscapes) : null;
  if (fakeParent) {
    fakeParent.enterScope();
    for (let i = 0; i < freeVarUpvals.length; i++) {
      fakeParent.declareLocal(freeVarUpvals[i], i);
    }
  }
  const fnCompiler = new FuncCompiler(fakeParent, func.params.length, func.isVararg, nativeEscapes);
  for (const name of freeVarUpvals) {
    fnCompiler.resolveUpvalue(name);
  }
  fnCompiler.enterScope();
  for (const p of func.params) {
    fnCompiler.declareLocal(p);
  }
  fnCompiler.compileBlock(func.body, false);
  fnCompiler.leaveScope(true);
  fnCompiler.emit(Op.RETURN, 0, 1, 0);

  const root = fnCompiler.toProto();
  const allUsedOps = new Set<Op>();
  const stats = gatherStats(root, allUsedOps);
  return {
    root,
    nativeEscapes,
    totalProtos: stats.protos,
    totalInstructions: stats.insts,
    allUsedOps,
    cfgStats: emptyCfgStats(),
  };
}
