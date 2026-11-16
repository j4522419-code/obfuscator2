import {
  AssignStmt,
  BinaryOp,
  Block,
  CallExpr,
  Chunk,
  CompoundOp,
  Expression,
  FuncBody,
  FuncName,
  IfBranch,
  InterpStringExpr,
  LValue,
  MethodCallExpr,
  ReturnStmt,
  Statement,
  TableExpr,
  TableField,
  UnaryOp,
  VmPragma,
} from './ast.js';
import { Token, tokenize } from './lexer.js';
import { GrandfuscatorError } from './types.js';

const COMPOUND_OPS = new Set<string>(['+=', '-=', '*=', '/=', '//=', '%=', '^=', '..=']);

const BLOCK_TERMINATORS = new Set(['end', 'else', 'elseif', 'until']);

function getBinaryPrecedence(tok: Token): [number, number] | null {
  const v = tok.value;
  if (tok.kind === 'Keyword') {
    if (v === 'or') return [1, 1];
    if (v === 'and') return [2, 2];
    return null;
  }
  if (tok.kind === 'Symbol') {
    switch (v) {
      case '<': case '>': case '<=': case '>=': case '~=': case '==':
        return [3, 3];
      case '..':
        return [5, 4]; // right-associative
      case '+': case '-':
        return [6, 6];
      case '*': case '/': case '//': case '%':
        return [7, 7];
      case '^':
        return [10, 9]; // right-associative, binds tighter than unary (8)
    }
  }
  return null;
}

const UNARY_PREC = 8;

export function parseLuau(source: string): Chunk {
  const tokens = tokenize(source);
  let idx = 0;

  function cur(): Token {
    return tokens[idx] ?? tokens[tokens.length - 1];
  }

  function peek(offset = 1): Token {
    return tokens[idx + offset] ?? tokens[tokens.length - 1];
  }

  function next(): Token {
    const t = cur();
    if (t.kind !== 'EOF') idx++;
    return t;
  }

  function fail(msg: string, tok = cur()): never {
    throw new GrandfuscatorError(msg, 'parser', tok.line, tok.column);
  }

  function isKw(kw: string, t = cur()): boolean {
    return t.kind === 'Keyword' && t.value === kw;
  }

  function isSym(sym: string, t = cur()): boolean {
    return t.kind === 'Symbol' && t.value === sym;
  }

  function isIdentVal(val: string, t = cur()): boolean {
    return t.kind === 'Ident' && t.value === val;
  }

  function matchKw(kw: string): boolean {
    if (isKw(kw)) { next(); return true; }
    return false;
  }

  function matchSym(sym: string): boolean {
    if (isSym(sym)) { next(); return true; }
    return false;
  }

  function expectKw(kw: string): Token {
    const t = cur();
    if (!isKw(kw, t)) fail(`Expected keyword \`${kw}\`, got \`${t.value || t.kind}\``, t);
    return next();
  }

  function expectSym(sym: string): Token {
    const t = cur();
    if (!isSym(sym, t)) fail(`Expected \`${sym}\`, got \`${t.value || t.kind}\``, t);
    return next();
  }

  function expectIdent(): Token {
    const t = cur();
    if (t.kind !== 'Ident') fail(`Expected identifier, got \`${t.value || t.kind}\``, t);
    return next();
  }

  // ---------------------------------------------------------------------------
  // Full Roblox Luau Type Annotation Grammar (parsed & stripped at AST level)
  // ---------------------------------------------------------------------------

  function skipGenericTypeParamDecl(): void {
    if (!matchSym('<')) return;
    let first = true;
    while (!isSym('>') && cur().kind !== 'EOF') {
      if (!first) expectSym(',');
      first = false;
      expectIdent();
      matchSym('...'); // type pack T...
      if (matchSym('=')) {
        // default type or type pack
        if (isSym('...')) { next(); skipType(); }
        else if (isSym('(')) { skipTypePackOrParenType(); }
        else skipType();
      }
    }
    expectSym('>');
  }

  function skipType(): void {
    // Luau allows optional leading `|` or `&`
    matchSym('|');
    matchSym('&');
    skipIntersectionOrUnionAtom();
    while (isSym('|') || isSym('&')) {
      next();
      skipIntersectionOrUnionAtom();
    }
  }

  function skipIntersectionOrUnionAtom(): void {
    skipSimpleType();
    while (matchSym('?')) {
      // nullable T?
    }
  }

  function skipSimpleType(): void {
    const t = cur();

    // Generic function type: `<T, U...>(...) -> Ret`
    if (isSym('<', t)) {
      skipGenericTypeParamDecl();
      skipParenTypeList();
      expectSym('->');
      skipReturnType();
      return;
    }

    // Parenthesized type OR function type `(a: T, b: U) -> R`
    if (isSym('(', t)) {
      skipTypePackOrParenType();
      if (matchSym('->')) {
        skipReturnType();
      }
      return;
    }

    // Table type `{ [K]: V, read prop: T, T }`
    if (isSym('{', t)) {
      next();
      while (!isSym('}') && cur().kind !== 'EOF') {
        // Optional Luau `read` / `write` access modifier before prop or indexer
        if (
          (isIdentVal('read') || isIdentVal('write')) &&
          (isSym('[', peek()) || (peek().kind === 'Ident' && isSym(':', peek(2))))
        ) {
          next();
        }
        if (matchSym('[')) {
          skipType();
          expectSym(']');
          expectSym(':');
          skipType();
        } else if (cur().kind === 'Ident' && isSym(':', peek())) {
          next();
          next();
          skipType();
        } else {
          skipType();
        }
        if (!matchSym(',') && !matchSym(';')) break;
      }
      expectSym('}');
      return;
    }

    // Singleton literal types: "foo", 'bar', true, false, nil
    if (t.kind === 'String') { next(); return; }
    if (isKw('nil', t) || isKw('true', t) || isKw('false', t)) { next(); return; }

    // typeof(expr)
    if (isIdentVal('typeof', t) && isSym('(', peek())) {
      next();
      expectSym('(');
      parseExpression();
      expectSym(')');
      return;
    }

    // Named type: Foo, Module.Foo, Foo<A, B, C...>
    if (t.kind === 'Ident') {
      next();
      while (matchSym('.')) {
        expectIdent();
      }
      if (matchSym('<')) {
        let first = true;
        while (!isSym('>') && cur().kind !== 'EOF') {
          if (!first) expectSym(',');
          first = false;
          if (matchSym('...')) {
            skipType();
          } else if (cur().kind === 'Ident' && isSym('...', peek())) {
            next();
            next();
          } else {
            skipType();
            matchSym('...');
          }
        }
        expectSym('>');
      }
      return;
    }

    fail(`Expected type annotation, got \`${t.value || t.kind}\``, t);
  }

  function skipParenTypeList(): void {
    expectSym('(');
    skipTypePackItems();
    expectSym(')');
  }

  function skipTypePackOrParenType(): void {
    expectSym('(');
    skipTypePackItems();
    expectSym(')');
  }

  function skipTypePackItems(): void {
    let first = true;
    while (!isSym(')') && cur().kind !== 'EOF') {
      if (!first) expectSym(',');
      first = false;
      if (matchSym('...')) {
        skipType();
        break;
      }
      // Named function type param `x: T`
      if (cur().kind === 'Ident' && isSym(':', peek())) {
        next();
        next();
        skipType();
      } else if (cur().kind === 'Ident' && isSym('...', peek())) {
        next();
        next();
        break;
      } else {
        skipType();
        if (matchSym('...')) break;
      }
    }
  }

  function skipReturnType(): void {
    if (matchSym('...')) {
      skipType();
      return;
    }
    if (cur().kind === 'Ident' && isSym('...', peek())) {
      next();
      next();
      return;
    }
    skipType();
  }

  // ---------------------------------------------------------------------------
  // Blocks & Statements
  // ---------------------------------------------------------------------------

  function isBlockEnd(): boolean {
    const t = cur();
    if (t.kind === 'EOF') return true;
    if (t.kind === 'Keyword' && BLOCK_TERMINATORS.has(t.value)) return true;
    return false;
  }

  function parseBlock(): Block {
    const statements: Statement[] = [];
    let returnStmt: ReturnStmt | null = null;

    while (!isBlockEnd()) {
      while (matchSym(';')) { /* empty semicolons */ }
      if (isBlockEnd()) break;

      if (isKw('return')) {
        const rTok = next();
        const values: Expression[] = [];
        if (!isBlockEnd() && !isSym(';')) {
          values.push(...parseExprList());
        }
        matchSym(';');
        returnStmt = { kind: 'ReturnStmt', values, line: rTok.line };
        break;
      }

      if (isKw('break')) {
        const bTok = next();
        matchSym(';');
        statements.push({ kind: 'BreakStmt', line: bTok.line });
        // Luau requires break/continue to be the last statement in a block
        break;
      }

      if (isContinueStatement()) {
        const cTok = next();
        matchSym(';');
        statements.push({ kind: 'ContinueStmt', line: cTok.line });
        break;
      }

      const stmt = parseStatement();
      if (stmt) statements.push(stmt);
      matchSym(';');
    }

    return { kind: 'Block', statements, returnStmt };
  }

  /** Luau contextual `continue`: statement UNLESS followed by assignment, call, or member suffix */
  function isContinueStatement(): boolean {
    if (!isIdentVal('continue')) return false;
    const p = peek();
    if (p.kind === 'String' || p.kind === 'InterpSimple' || p.kind === 'InterpBegin') return false;
    if (p.kind === 'Symbol') {
      if (
        p.value === '=' || p.value === ',' || p.value === '(' || p.value === '{' ||
        p.value === '.' || p.value === ':' || p.value === '[' || COMPOUND_OPS.has(p.value)
      ) {
        return false;
      }
    }
    return true;
  }

  /** Luau contextual `type Foo = ...` or `export type Foo = ...` */
  function isTypeAliasStart(): boolean {
    if (isIdentVal('type')) {
      const p1 = peek(1);
      const p2 = peek(2);
      if (p1.kind === 'Ident' && (isSym('=', p2) || isSym('<', p2))) return true;
      // `type function Foo(...)` (Luau type functions) - skip if simple
    }
    if (isIdentVal('export') && isIdentVal('type', peek(1)) && peek(2).kind === 'Ident') {
      const p3 = peek(3);
      if (isSym('=', p3) || isSym('<', p3)) return true;
    }
    return false;
  }

  function parseTypeAlias(): Statement {
    const startLine = cur().line;
    let exported = false;
    if (isIdentVal('export')) {
      exported = true;
      next();
    }
    next(); // 'type'
    const name = expectIdent().value;
    skipGenericTypeParamDecl();
    expectSym('=');
    skipType();
    return { kind: 'TypeAliasStmt', exported, name, line: startLine };
  }

  function consumeAttributes(): VmPragma {
    let pragma: VmPragma = null;
    while (cur().kind === 'Attribute') {
      const a = next();
      if (a.pragma) pragma = a.pragma;
    }
    return pragma;
  }

  function parseStatement(): Statement | null {
    // Handle Luau attributes `@native`, `@checked`, `@deprecated` before functions
    let attrPragma: VmPragma = null;
    if (cur().kind === 'Attribute') {
      attrPragma = consumeAttributes();
    }

    const t = cur();
    const attachedPragma: VmPragma = t.pragma ?? attrPragma;

    if (isTypeAliasStart()) {
      return parseTypeAlias();
    }

    if (isKw('local', t)) {
      const lTok = next();
      let fnPragma: VmPragma = attachedPragma;
      if (cur().kind === 'Attribute') {
        const p2 = consumeAttributes();
        if (p2) fnPragma = p2;
      }
      if (isKw('function')) {
        const fTok = next();
        if (fTok.pragma) fnPragma = fTok.pragma;
        const name = expectIdent().value;
        const func = parseFuncBody(fnPragma, lTok.line);
        return { kind: 'LocalFuncStmt', name, func, line: lTok.line };
      }
      const names: string[] = [];
      do {
        names.push(expectIdent().value);
        if (matchSym(':')) skipType();
      } while (matchSym(','));
      const values = matchSym('=') ? parseExprList() : [];
      return { kind: 'LocalStmt', names, values, line: lTok.line };
    }

    if (isKw('function', t)) {
      const fTok = next();
      const name = parseFuncName();
      const func = parseFuncBody(attachedPragma, fTok.line);
      return { kind: 'FuncStmt', name, func, line: fTok.line };
    }

    if (isKw('if', t)) {
      return parseIfStmt();
    }

    if (isKw('while', t)) {
      const wTok = next();
      const condition = parseExpression();
      expectKw('do');
      const body = parseBlock();
      expectKw('end');
      return { kind: 'WhileStmt', condition, body, line: wTok.line };
    }

    if (isKw('repeat', t)) {
      const rTok = next();
      const body = parseBlock();
      expectKw('until');
      const condition = parseExpression();
      return { kind: 'RepeatStmt', body, condition, line: rTok.line };
    }

    if (isKw('do', t)) {
      const dTok = next();
      const body = parseBlock();
      expectKw('end');
      return { kind: 'DoStmt', body, line: dTok.line };
    }

    if (isKw('for', t)) {
      return parseForStmt();
    }

    // Expression statement: Assignment, Compound Assignment, or Function Call
    const first = parseSuffixedExpr();

    // Compound assignment: `lvalue += expr`
    if (cur().kind === 'Symbol' && COMPOUND_OPS.has(cur().value)) {
      const opTok = next();
      assertLValue(first, opTok);
      const value = parseExpression();
      return {
        kind: 'CompoundAssignStmt',
        op: opTok.value as CompoundOp,
        target: first,
        value,
        line: first.line,
      };
    }

    // Regular assignment: `v1, v2 = e1, e2`
    if (isSym('=') || isSym(',')) {
      assertLValue(first, cur());
      const targets: LValue[] = [first];
      while (matchSym(',')) {
        const lv = parseSuffixedExpr();
        assertLValue(lv, cur());
        targets.push(lv);
      }
      expectSym('=');
      const values = parseExprList();
      const stmt: AssignStmt = { kind: 'AssignStmt', targets, values, line: first.line };
      return stmt;
    }

    // Function / method call statement
    if (first.kind === 'CallExpr' || first.kind === 'MethodCallExpr') {
      return { kind: 'CallStmt', expr: first, line: first.line };
    }

    fail('Expected assignment or function call statement', t);
  }

  function assertLValue(expr: Expression, tok: Token): asserts expr is LValue {
    if (expr.kind !== 'IdentExpr' && expr.kind !== 'IndexExpr' && expr.kind !== 'MemberExpr') {
      fail('Invalid assignment target (expected variable or table field)', tok);
    }
  }

  function parseFuncName(): FuncName {
    const base = expectIdent().value;
    const fields: string[] = [];
    while (matchSym('.')) {
      fields.push(expectIdent().value);
    }
    let method: string | null = null;
    if (matchSym(':')) {
      method = expectIdent().value;
    }
    return { base, fields, method };
  }

  function parseFuncBody(pragma: VmPragma, line: number): FuncBody {
    skipGenericTypeParamDecl();
    expectSym('(');
    const params: string[] = [];
    let isVararg = false;

    if (!isSym(')')) {
      while (true) {
        if (matchSym('...')) {
          isVararg = true;
          if (matchSym(':')) {
            // Variadic type `...: number` or `...: T...`
            if (cur().kind === 'Ident' && isSym('...', peek())) {
              next();
              next();
            } else {
              skipType();
            }
          }
          break;
        }
        params.push(expectIdent().value);
        if (matchSym(':')) skipType();
        if (!matchSym(',')) break;
        if (isSym(')')) break;
      }
    }
    expectSym(')');

    // Optional return type annotation `: RetType` or `: (A, B, ...C)`
    if (matchSym(':')) {
      skipReturnType();
    }

    const body = parseBlock();
    expectKw('end');
    return { params, isVararg, body, pragma, line };
  }

  function parseIfStmt(): Statement {
    const iTok = expectKw('if');
    const branches: IfBranch[] = [];
    const firstCond = parseExpression();
    expectKw('then');
    const firstBody = parseBlock();
    branches.push({ condition: firstCond, body: firstBody, line: iTok.line });

    while (isKw('elseif')) {
      const eiTok = next();
      const cond = parseExpression();
      expectKw('then');
      const body = parseBlock();
      branches.push({ condition: cond, body, line: eiTok.line });
    }

    let elseBody: Block | null = null;
    if (matchKw('else')) {
      elseBody = parseBlock();
    }
    expectKw('end');
    return { kind: 'IfStmt', branches, elseBody, line: iTok.line };
  }

  function parseForStmt(): Statement {
    const fTok = expectKw('for');
    const firstVar = expectIdent().value;
    if (matchSym(':')) skipType();

    // Numeric for: `for i = start, limit [, step] do`
    if (matchSym('=')) {
      const start = parseExpression();
      expectSym(',');
      const limit = parseExpression();
      const step = matchSym(',') ? parseExpression() : null;
      expectKw('do');
      const body = parseBlock();
      expectKw('end');
      return { kind: 'NumericForStmt', varName: firstVar, start, limit, step, body, line: fTok.line };
    }

    // Generic / Generalized for: `for k, v in exprlist do`
    const names: string[] = [firstVar];
    while (matchSym(',')) {
      names.push(expectIdent().value);
      if (matchSym(':')) skipType();
    }
    expectKw('in');
    const iterators = parseExprList();
    expectKw('do');
    const body = parseBlock();
    expectKw('end');
    return { kind: 'GenericForStmt', names, iterators, body, line: fTok.line };
  }

  // ---------------------------------------------------------------------------
  // Expressions
  // ---------------------------------------------------------------------------

  function parseExprList(): Expression[] {
    const list: Expression[] = [parseExpression()];
    while (matchSym(',')) {
      list.push(parseExpression());
    }
    return list;
  }

  function parseExpression(minPrec = 1): Expression {
    let left = parseUnaryExpr();

    while (true) {
      const prec = getBinaryPrecedence(cur());
      if (!prec || prec[0] < minPrec) break;
      const opTok = next();
      const right = parseExpression(prec[1] + 1);
      left = {
        kind: 'BinaryExpr',
        op: opTok.value as BinaryOp,
        left,
        right,
        line: opTok.line,
      };
    }

    return left;
  }

  function parseUnaryExpr(): Expression {
    const t = cur();
    if (isKw('not', t) || isSym('-', t) || isSym('#', t)) {
      next();
      const argument = parseExpression(UNARY_PREC);
      return { kind: 'UnaryExpr', op: t.value as UnaryOp, argument, line: t.line };
    }
    return parseSimpleExpr();
  }

  function parseSimpleExpr(): Expression {
    // Allow attributes on anonymous function expressions: `@native function(x) ... end`
    let attrPragma: VmPragma = null;
    if (cur().kind === 'Attribute') {
      attrPragma = consumeAttributes();
    }

    const t = cur();
    let expr: Expression;

    if (isKw('nil', t)) {
      next();
      expr = { kind: 'NilLiteral', line: t.line };
    } else if (isKw('true', t)) {
      next();
      expr = { kind: 'BoolLiteral', value: true, line: t.line };
    } else if (isKw('false', t)) {
      next();
      expr = { kind: 'BoolLiteral', value: false, line: t.line };
    } else if (t.kind === 'Number') {
      next();
      expr = { kind: 'NumberLiteral', value: t.numValue!, line: t.line };
    } else if (t.kind === 'String') {
      next();
      expr = { kind: 'StringLiteral', bytes: t.bytes!, line: t.line };
    } else if (t.kind === 'InterpSimple') {
      next();
      expr = { kind: 'StringLiteral', bytes: t.bytes!, line: t.line };
    } else if (t.kind === 'InterpBegin') {
      expr = parseInterpString();
    } else if (isSym('...', t)) {
      next();
      expr = { kind: 'VarargExpr', line: t.line };
    } else if (isKw('function', t)) {
      next();
      const func = parseFuncBody(t.pragma ?? attrPragma, t.line);
      expr = { kind: 'FuncExpr', func, line: t.line };
    } else if (isSym('{', t)) {
      expr = parseTableConstructor();
    } else if (isKw('if', t)) {
      expr = parseIfExpr();
    } else {
      expr = parseSuffixedExpr();
    }

    // Luau type assertion `expr :: Type` (repeatable: `x :: any :: number`)
    while (matchSym('::')) {
      skipType();
    }

    return expr;
  }

  function parsePrimaryExpr(): Expression {
    const t = cur();
    if (t.kind === 'Ident') {
      next();
      return { kind: 'IdentExpr', name: t.value, line: t.line };
    }
    if (isSym('(', t)) {
      next();
      const inner = parseExpression();
      expectSym(')');
      return { kind: 'ParenExpr', expression: inner, line: t.line };
    }
    fail(`Unexpected token \`${t.value || t.kind}\` in expression`, t);
  }

  function parseSuffixedExpr(): Expression {
    let expr = parsePrimaryExpr();

    while (true) {
      const t = cur();
      if (matchSym('.')) {
        const prop = expectIdent();
        expr = { kind: 'MemberExpr', object: expr, property: prop.value, line: prop.line };
      } else if (matchSym('[')) {
        const index = parseExpression();
        expectSym(']');
        expr = { kind: 'IndexExpr', object: expr, index, line: t.line };
      } else if (matchSym(':')) {
        const method = expectIdent();
        const args = parseCallArgs();
        const mc: MethodCallExpr = {
          kind: 'MethodCallExpr',
          object: expr,
          method: method.value,
          args,
          line: method.line,
        };
        expr = mc;
      } else if (
        isSym('(', t) ||
        isSym('{', t) ||
        t.kind === 'String' ||
        t.kind === 'InterpSimple' ||
        t.kind === 'InterpBegin'
      ) {
        const args = parseCallArgs();
        const call: CallExpr = { kind: 'CallExpr', callee: expr, args, line: t.line };
        expr = call;
      } else {
        break;
      }
    }

    return expr;
  }

  function parseCallArgs(): Expression[] {
    const t = cur();
    if (matchSym('(')) {
      if (matchSym(')')) return [];
      const args = parseExprList();
      expectSym(')');
      return args;
    }
    if (isSym('{', t)) {
      return [parseTableConstructor()];
    }
    if (t.kind === 'String' || t.kind === 'InterpSimple') {
      next();
      return [{ kind: 'StringLiteral', bytes: t.bytes!, line: t.line }];
    }
    if (t.kind === 'InterpBegin') {
      return [parseInterpString()];
    }
    fail('Expected function call arguments', t);
  }

  function parseTableConstructor(): TableExpr {
    const open = expectSym('{');
    const fields: TableField[] = [];

    while (!isSym('}') && cur().kind !== 'EOF') {
      if (matchSym('[')) {
        const key = parseExpression();
        expectSym(']');
        expectSym('=');
        const value = parseExpression();
        fields.push({ kind: 'IndexField', key, value });
      } else if (cur().kind === 'Ident' && isSym('=', peek())) {
        const key = expectIdent().value;
        expectSym('=');
        const value = parseExpression();
        fields.push({ kind: 'RecordField', key, value });
      } else {
        const value = parseExpression();
        fields.push({ kind: 'ListField', value });
      }
      if (!matchSym(',') && !matchSym(';')) break;
    }

    expectSym('}');
    return { kind: 'TableExpr', fields, line: open.line };
  }

  function parseIfExpr(): Expression {
    const iTok = expectKw('if');
    const branches: { condition: Expression; value: Expression }[] = [];
    const c0 = parseExpression();
    expectKw('then');
    const v0 = parseExpression();
    branches.push({ condition: c0, value: v0 });

    while (matchKw('elseif')) {
      const ci = parseExpression();
      expectKw('then');
      const vi = parseExpression();
      branches.push({ condition: ci, value: vi });
    }

    expectKw('else');
    const elseValue = parseExpression();
    return { kind: 'IfExpr', branches, elseValue, line: iTok.line };
  }

  function parseInterpString(): InterpStringExpr {
    const begin = next(); // InterpBegin
    const segments: Uint8Array[] = [begin.bytes!];
    const expressions: Expression[] = [];

    while (true) {
      expressions.push(parseExpression());
      const t = cur();
      if (t.kind === 'InterpMid') {
        next();
        segments.push(t.bytes!);
      } else if (t.kind === 'InterpEnd') {
        next();
        segments.push(t.bytes!);
        break;
      } else {
        fail('Expected `}` inside interpolated string', t);
      }
    }

    return { kind: 'InterpStringExpr', segments, expressions, line: begin.line };
  }

  // Parse root chunk
  const body = parseBlock();
  if (cur().kind !== 'EOF') {
    fail(`Unexpected token \`${cur().value || cur().kind}\``, cur());
  }
  return { kind: 'Chunk', body };
}
