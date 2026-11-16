export type VmPragma = 'vm' | 'novm' | null;

export type CompoundOp = '+=' | '-=' | '*=' | '/=' | '//=' | '%=' | '^=' | '..=';

export type BinaryOp =
  | '+' | '-' | '*' | '/' | '//' | '%' | '^' | '..'
  | '==' | '~=' | '<' | '<=' | '>' | '>='
  | 'and' | 'or';

export type UnaryOp = '-' | 'not' | '#';

export interface Chunk {
  kind: 'Chunk';
  body: Block;
}

export interface Block {
  kind: 'Block';
  statements: Statement[];
  returnStmt: ReturnStmt | null;
}

export type Statement =
  | LocalStmt
  | LocalFuncStmt
  | FuncStmt
  | AssignStmt
  | CompoundAssignStmt
  | CallStmt
  | DoStmt
  | WhileStmt
  | RepeatStmt
  | IfStmt
  | NumericForStmt
  | GenericForStmt
  | BreakStmt
  | ContinueStmt
  | TypeAliasStmt;

export interface ReturnStmt {
  kind: 'ReturnStmt';
  values: Expression[];
  line: number;
}

export interface LocalStmt {
  kind: 'LocalStmt';
  names: string[];
  values: Expression[];
  line: number;
}

export interface LocalFuncStmt {
  kind: 'LocalFuncStmt';
  name: string;
  func: FuncBody;
  line: number;
}

export interface FuncName {
  base: string;
  fields: string[];
  method: string | null;
}

export interface FuncStmt {
  kind: 'FuncStmt';
  name: FuncName;
  func: FuncBody;
  line: number;
}

export interface FuncBody {
  params: string[];
  isVararg: boolean;
  body: Block;
  pragma: VmPragma;
  line: number;
}

export type LValue = IdentExpr | IndexExpr | MemberExpr;

export interface AssignStmt {
  kind: 'AssignStmt';
  targets: LValue[];
  values: Expression[];
  line: number;
}

export interface CompoundAssignStmt {
  kind: 'CompoundAssignStmt';
  op: CompoundOp;
  target: LValue;
  value: Expression;
  line: number;
}

export interface CallStmt {
  kind: 'CallStmt';
  expr: CallExpr | MethodCallExpr;
  line: number;
}

export interface DoStmt {
  kind: 'DoStmt';
  body: Block;
  line: number;
}

export interface WhileStmt {
  kind: 'WhileStmt';
  condition: Expression;
  body: Block;
  line: number;
}

export interface RepeatStmt {
  kind: 'RepeatStmt';
  body: Block;
  condition: Expression;
  line: number;
}

export interface IfBranch {
  condition: Expression;
  body: Block;
  line: number;
}

export interface IfStmt {
  kind: 'IfStmt';
  branches: IfBranch[];
  elseBody: Block | null;
  line: number;
}

export interface NumericForStmt {
  kind: 'NumericForStmt';
  varName: string;
  start: Expression;
  limit: Expression;
  step: Expression | null;
  body: Block;
  line: number;
}

export interface GenericForStmt {
  kind: 'GenericForStmt';
  names: string[];
  iterators: Expression[];
  body: Block;
  line: number;
}

export interface BreakStmt {
  kind: 'BreakStmt';
  line: number;
}

export interface ContinueStmt {
  kind: 'ContinueStmt';
  line: number;
}

export interface TypeAliasStmt {
  kind: 'TypeAliasStmt';
  exported: boolean;
  name: string;
  line: number;
}

export type Expression =
  | NilLiteral
  | BoolLiteral
  | NumberLiteral
  | StringLiteral
  | VarargExpr
  | IdentExpr
  | FuncExpr
  | TableExpr
  | BinaryExpr
  | UnaryExpr
  | IndexExpr
  | MemberExpr
  | CallExpr
  | MethodCallExpr
  | IfExpr
  | InterpStringExpr
  | ParenExpr;

export interface NilLiteral {
  kind: 'NilLiteral';
  line: number;
}

export interface BoolLiteral {
  kind: 'BoolLiteral';
  value: boolean;
  line: number;
}

export interface NumberLiteral {
  kind: 'NumberLiteral';
  value: number;
  line: number;
}

/** `bytes` holds exact raw Luau string bytes (0..255 per element, UTF-8 preserved) */
export interface StringLiteral {
  kind: 'StringLiteral';
  bytes: Uint8Array;
  line: number;
}

export interface VarargExpr {
  kind: 'VarargExpr';
  line: number;
}

export interface IdentExpr {
  kind: 'IdentExpr';
  name: string;
  line: number;
}

export interface FuncExpr {
  kind: 'FuncExpr';
  func: FuncBody;
  line: number;
}

export type TableField =
  | { kind: 'ListField'; value: Expression }
  | { kind: 'RecordField'; key: string; value: Expression }
  | { kind: 'IndexField'; key: Expression; value: Expression };

export interface TableExpr {
  kind: 'TableExpr';
  fields: TableField[];
  line: number;
}

export interface BinaryExpr {
  kind: 'BinaryExpr';
  op: BinaryOp;
  left: Expression;
  right: Expression;
  line: number;
}

export interface UnaryExpr {
  kind: 'UnaryExpr';
  op: UnaryOp;
  argument: Expression;
  line: number;
}

export interface IndexExpr {
  kind: 'IndexExpr';
  object: Expression;
  index: Expression;
  line: number;
}

export interface MemberExpr {
  kind: 'MemberExpr';
  object: Expression;
  property: string;
  line: number;
}

export interface CallExpr {
  kind: 'CallExpr';
  callee: Expression;
  args: Expression[];
  line: number;
}

export interface MethodCallExpr {
  kind: 'MethodCallExpr';
  object: Expression;
  method: string;
  args: Expression[];
  line: number;
}

export interface IfExpr {
  kind: 'IfExpr';
  branches: { condition: Expression; value: Expression }[];
  elseValue: Expression;
  line: number;
}

/** `segments.length === expressions.length + 1` */
export interface InterpStringExpr {
  kind: 'InterpStringExpr';
  segments: Uint8Array[];
  expressions: Expression[];
  line: number;
}

/** Explicit `(expr)` — important in Lua/Luau because `(multiReturn())` truncates to 1 value! */
export interface ParenExpr {
  kind: 'ParenExpr';
  expression: Expression;
  line: number;
}

const utf8Encoder = new TextEncoder();

export function utf8Bytes(str: string): Uint8Array {
  return utf8Encoder.encode(str);
}

export function bytesKey(bytes: Uint8Array): string {
  // Exact byte-identity map key using Latin-1 code points
  let out = '';
  const chunk = 4096;
  for (let i = 0; i < bytes.length; i += chunk) {
    const slice = bytes.subarray(i, Math.min(i + chunk, bytes.length));
    out += String.fromCharCode(...slice);
  }
  return out;
}
