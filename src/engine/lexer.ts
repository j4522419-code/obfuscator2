import { GrandfuscatorError } from './types.js';
import { VmPragma } from './ast.js';

export type TokenKind =
  | 'Ident'
  | 'Keyword'
  | 'Number'
  | 'String'
  | 'InterpSimple'
  | 'InterpBegin'
  | 'InterpMid'
  | 'InterpEnd'
  | 'Symbol'
  | 'Attribute'
  | 'EOF';

export interface Token {
  kind: TokenKind;
  value: string;
  numValue?: number;
  bytes?: Uint8Array;
  line: number;
  column: number;
  /** Attached pragma from an immediately preceding --@vm or --@novm comment */
  pragma?: VmPragma;
}

const KEYWORDS = new Set([
  'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
  'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat',
  'return', 'then', 'true', 'until', 'while',
]);

function isAlpha(c: number): boolean {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
}

function isDigit(c: number): boolean {
  return c >= 48 && c <= 57;
}

function isHexDigit(c: number): boolean {
  return isDigit(c) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
}

function hexVal(c: number): number {
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 65 && c <= 70) return c - 55;
  return c - 87;
}

function isAlnum(c: number): boolean {
  return isAlpha(c) || isDigit(c);
}

function pushCodePointUtf8(out: number[], cp: number): void {
  if (cp <= 0x7f) {
    out.push(cp);
  } else if (cp <= 0x7ff) {
    out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
  } else if (cp <= 0xffff) {
    out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  } else {
    out.push(
      0xf0 | (cp >> 18),
      0x80 | ((cp >> 12) & 0x3f),
      0x80 | ((cp >> 6) & 0x3f),
      0x80 | (cp & 0x3f),
    );
  }
}

export function tokenize(source: string): Token[] {
  // Normalize optional UTF-8 BOM & leading shebang
  let pos = 0;
  let line = 1;
  let col = 1;
  const len = source.length;
  const tokens: Token[] = [];
  let pendingPragma: VmPragma = null;

  // Stack for nested interpolated strings: each entry tracks open `{` count inside `{ expr }`
  const interpBraceStack: number[] = [];

  if (source.charCodeAt(0) === 0xfeff) {
    pos = 1;
  }
  if (source.startsWith('#!', pos)) {
    while (pos < len && source.charCodeAt(pos) !== 10) pos++;
  }

  function peek(offset = 0): number {
    const idx = pos + offset;
    return idx < len ? source.charCodeAt(idx) : -1;
  }

  function advance(): number {
    const c = source.charCodeAt(pos++);
    if (c === 10) {
      line++;
      col = 1;
    } else {
      col++;
    }
    return c;
  }

  function advanceNewline(): void {
    const c = peek();
    if (c === 13 && peek(1) === 10) {
      pos += 2;
      line++;
      col = 1;
    } else if (c === 10 || c === 13) {
      pos += 1;
      line++;
      col = 1;
    }
  }

  function fail(msg: string, errLine = line, errCol = col): never {
    throw new GrandfuscatorError(msg, 'lexer', errLine, errCol);
  }

  function emit(tok: Token): void {
    if (pendingPragma) {
      tok.pragma = pendingPragma;
      // Only clear once consumed by `function`, `local`, or non-attribute token
      if (tok.kind !== 'Attribute') {
        pendingPragma = null;
      }
    }
    tokens.push(tok);
  }

  /** Check if pos sits at `[=*[`; returns number of `=` or -1 */
  function checkLongBracket(): number {
    if (peek() !== 91) return -1; // '['
    let i = 1;
    while (peek(i) === 61) i++; // '='
    if (peek(i) === 91) return i - 1;
    return -1;
  }

  function readLongString(eqCount: number, startLine: number, startCol: number, isComment: boolean): Uint8Array {
    // Skip `[=*[`
    pos += eqCount + 2;
    col += eqCount + 2;

    // Lua/Luau skips an immediate leading newline after opening long bracket
    if (peek() === 10 || peek() === 13) {
      advanceNewline();
    }

    const bytes: number[] = [];
    while (pos < len) {
      const c = peek();
      if (c === 93) { // ']'
        let j = 1;
        while (j <= eqCount && peek(j) === 61) j++;
        if (j === eqCount + 1 && peek(j) === 93) {
          pos += eqCount + 2;
          col += eqCount + 2;
          return new Uint8Array(bytes);
        }
      }
      if (c === 10 || c === 13) {
        advanceNewline();
        if (!isComment) bytes.push(10);
      } else {
        // Handle full Unicode code point (including surrogate pairs) as UTF-8
        const cp = source.codePointAt(pos)!;
        if (cp > 0xffff) {
          pos += 2;
          col += 2;
        } else {
          pos += 1;
          col += 1;
        }
        if (!isComment) pushCodePointUtf8(bytes, cp);
      }
    }
    fail(`Unfinished long ${isComment ? 'comment' : 'string'}`, startLine, startCol);
  }

  function readEscapeInto(bytes: number[], isInterp: boolean, startLine: number, startCol: number): void {
    advance(); // consume '\'
    if (pos >= len) fail('Unfinished escape sequence', startLine, startCol);
    const esc = peek();
    switch (esc) {
      case 97: advance(); bytes.push(7); break;   // \a
      case 98: advance(); bytes.push(8); break;   // \b
      case 102: advance(); bytes.push(12); break; // \f
      case 110: advance(); bytes.push(10); break; // \n
      case 114: advance(); bytes.push(13); break; // \r
      case 116: advance(); bytes.push(9); break;  // \t
      case 118: advance(); bytes.push(11); break; // \v
      case 92: advance(); bytes.push(92); break;  // \\
      case 34: advance(); bytes.push(34); break;  // \"
      case 39: advance(); bytes.push(39); break;  // \'
      case 96: advance(); bytes.push(96); break;  // \`
      case 123: // \{ (allowed in interpolated strings)
        if (isInterp) { advance(); bytes.push(123); break; }
        advance(); bytes.push(123); break;
      case 125:
        advance(); bytes.push(125); break;
      case 10:
      case 13:
        advanceNewline();
        bytes.push(10);
        break;
      case 122: // \z skip following whitespace including newlines
        advance();
        while (pos < len) {
          const w = peek();
          if (w === 10 || w === 13) advanceNewline();
          else if (w === 32 || w === 9 || w === 11 || w === 12) advance();
          else break;
        }
        break;
      case 120: { // \xHH
        advance();
        const h1 = peek();
        const h2 = peek(1);
        if (!isHexDigit(h1) || !isHexDigit(h2)) {
          fail('Invalid hexadecimal escape sequence (expected \\xHH)', line, col);
        }
        advance();
        advance();
        bytes.push((hexVal(h1) << 4) | hexVal(h2));
        break;
      }
      case 117: { // \u{H...}
        advance();
        if (peek() !== 123) fail('Missing `{` in \\u{...} unicode escape', line, col);
        advance();
        let cp = 0;
        let digits = 0;
        while (isHexDigit(peek())) {
          cp = cp * 16 + hexVal(advance());
          digits++;
          if (cp > 0x10ffff) fail('Unicode escape code point out of range', line, col);
        }
        if (digits === 0 || peek() !== 125) {
          fail('Invalid \\u{...} unicode escape', line, col);
        }
        advance(); // '}'
        pushCodePointUtf8(bytes, cp);
        break;
      }
      default: {
        if (isDigit(esc)) {
          let val = advance() - 48;
          if (isDigit(peek())) {
            val = val * 10 + (advance() - 48);
            if (isDigit(peek())) {
              val = val * 10 + (advance() - 48);
            }
          }
          if (val > 255) fail(`Decimal escape \\${val} too large (max 255)`, line, col);
          bytes.push(val);
        } else {
          // Tolerate benign unknown escapes as literal character
          const cp = source.codePointAt(pos)!;
          pos += cp > 0xffff ? 2 : 1;
          col += cp > 0xffff ? 2 : 1;
          pushCodePointUtf8(bytes, cp);
        }
      }
    }
  }

  function readQuotedString(quote: number, startLine: number, startCol: number): Uint8Array {
    advance(); // opening quote
    const bytes: number[] = [];
    while (pos < len) {
      const c = peek();
      if (c === quote) {
        advance();
        return new Uint8Array(bytes);
      }
      if (c === 10 || c === 13) {
        fail('Unfinished string literal', startLine, startCol);
      }
      if (c === 92) {
        readEscapeInto(bytes, false, startLine, startCol);
      } else {
        const cp = source.codePointAt(pos)!;
        pos += cp > 0xffff ? 2 : 1;
        col += cp > 0xffff ? 2 : 1;
        pushCodePointUtf8(bytes, cp);
      }
    }
    fail('Unfinished string literal', startLine, startCol);
  }

  function readInterpSegment(isStart: boolean, startLine: number, startCol: number): void {
    advance(); // consume opening '`' or resuming '}'
    const bytes: number[] = [];
    while (pos < len) {
      const c = peek();
      if (c === 96) { // closing '`'
        advance();
        emit({
          kind: isStart ? 'InterpSimple' : 'InterpEnd',
          value: '',
          bytes: new Uint8Array(bytes),
          line: startLine,
          column: startCol,
        });
        return;
      }
      if (c === 123) { // '{' interpolation start
        advance();
        if (peek() === 123) {
          fail('Double brace `{{` is invalid in Luau interpolated strings; escape with `\\{`', line, col);
        }
        interpBraceStack.push(0);
        emit({
          kind: isStart ? 'InterpBegin' : 'InterpMid',
          value: '',
          bytes: new Uint8Array(bytes),
          line: startLine,
          column: startCol,
        });
        return;
      }
      if (c === 10 || c === 13) {
        fail('Unfinished interpolated string', startLine, startCol);
      }
      if (c === 92) {
        readEscapeInto(bytes, true, startLine, startCol);
      } else {
        const cp = source.codePointAt(pos)!;
        pos += cp > 0xffff ? 2 : 1;
        col += cp > 0xffff ? 2 : 1;
        pushCodePointUtf8(bytes, cp);
      }
    }
    fail('Unfinished interpolated string', startLine, startCol);
  }

  function readNumber(startLine: number, startCol: number): number {
    let raw = '';
    const c0 = peek();
    const c1 = peek(1);

    // Binary: 0b / 0B
    if (c0 === 48 && (c1 === 98 || c1 === 66)) {
      advance(); advance();
      let digits = '';
      while (pos < len) {
        const c = peek();
        if (c === 48 || c === 49) digits += String.fromCharCode(advance());
        else if (c === 95) advance();
        else break;
      }
      if (!digits.length) fail('Malformed binary number literal', startLine, startCol);
      // Parse arbitrarily wide binary into IEEE-754 double like Luau
      let val = 0;
      for (let i = 0; i < digits.length; i++) {
        val = val * 2 + (digits.charCodeAt(i) - 48);
      }
      return val;
    }

    // Hex: 0x / 0X (supports hex integers and hex floats 0x1.fp+3)
    if (c0 === 48 && (c1 === 120 || c1 === 88)) {
      advance(); advance();
      let intHex = '';
      let fracHex = '';
      let hasDot = false;
      while (pos < len) {
        const c = peek();
        if (isHexDigit(c)) {
          const ch = String.fromCharCode(advance());
          if (hasDot) fracHex += ch;
          else intHex += ch;
        } else if (c === 95) {
          advance();
        } else if (c === 46 && !hasDot && peek(1) !== 46) {
          hasDot = true;
          advance();
        } else {
          break;
        }
      }
      if (!intHex.length && !fracHex.length) {
        fail('Malformed hexadecimal number literal', startLine, startCol);
      }
      let exp = 0;
      if (peek() === 112 || peek() === 80) { // p / P binary exponent
        advance();
        let sign = 1;
        if (peek() === 43) advance();
        else if (peek() === 45) { sign = -1; advance(); }
        let expDigits = '';
        while (isDigit(peek()) || peek() === 95) {
          const c = advance();
          if (c !== 95) expDigits += String.fromCharCode(c);
        }
        if (!expDigits.length) fail('Malformed hex float exponent', startLine, startCol);
        exp = sign * Number(expDigits);
      }
      let val = 0;
      for (let i = 0; i < intHex.length; i++) {
        val = val * 16 + hexVal(intHex.charCodeAt(i));
      }
      if (fracHex.length) {
        let scale = 1 / 16;
        for (let i = 0; i < fracHex.length; i++) {
          val += hexVal(fracHex.charCodeAt(i)) * scale;
          scale /= 16;
        }
      }
      if (exp !== 0) {
        val *= Math.pow(2, exp);
      }
      return val;
    }

    // Decimal integer / float
    let hasDot = false;
    while (pos < len) {
      const c = peek();
      if (isDigit(c)) {
        raw += String.fromCharCode(advance());
      } else if (c === 95) {
        advance();
      } else if (c === 46 && !hasDot && peek(1) !== 46) {
        hasDot = true;
        raw += String.fromCharCode(advance());
      } else {
        break;
      }
    }
    if (peek() === 101 || peek() === 69) {
      raw += String.fromCharCode(advance());
      if (peek() === 43 || peek() === 45) {
        raw += String.fromCharCode(advance());
      }
      let expDigits = 0;
      while (isDigit(peek()) || peek() === 95) {
        const c = advance();
        if (c !== 95) {
          raw += String.fromCharCode(c);
          expDigits++;
        }
      }
      if (expDigits === 0) fail('Malformed exponent in number literal', startLine, startCol);
    }
    const parsed = Number(raw);
    if (Number.isNaN(parsed)) {
      fail(`Malformed number literal "${raw}"`, startLine, startCol);
    }
    return parsed;
  }

  while (pos < len) {
    const c = peek();

    // Whitespace
    if (c === 32 || c === 9 || c === 11 || c === 12) {
      advance();
      continue;
    }
    if (c === 10 || c === 13) {
      advanceNewline();
      continue;
    }

    // Comment: `--`
    if (c === 45 && peek(1) === 45) {
      const cLine = line;
      const cCol = col;
      advance(); advance();
      const eq = checkLongBracket();
      if (eq >= 0) {
        // Peek inside short pragma block comments like --[[@novm]]
        const startComment = pos;
        readLongString(eq, cLine, cCol, true);
        const body = source.slice(startComment + eq + 2, pos - (eq + 2)).trim().toLowerCase();
        if (body === '@novm') pendingPragma = 'novm';
        else if (body === '@vm') pendingPragma = 'vm';
      } else {
        const commentStart = pos;
        while (pos < len && peek() !== 10 && peek() !== 13) {
          pos++;
          col++;
        }
        const commentText = source.slice(commentStart, pos).trim();
        if (/^@novm\b/i.test(commentText)) {
          pendingPragma = 'novm';
        } else if (/^@vm\b/i.test(commentText)) {
          pendingPragma = 'vm';
        }
      }
      continue;
    }

    const startLine = line;
    const startCol = col;

    // Identifier or Keyword
    if (isAlpha(c)) {
      const start = pos;
      while (pos < len && isAlnum(peek())) advance();
      const word = source.slice(start, pos);
      emit({
        kind: KEYWORDS.has(word) ? 'Keyword' : 'Ident',
        value: word,
        line: startLine,
        column: startCol,
      });
      continue;
    }

    // Luau Attribute: @native, @checked, @deprecated
    if (c === 64) { // '@'
      advance();
      if (peek() === 91) {
        // Luau parameterized attribute list @[attr(...)]
        advance();
        let depth = 1;
        while (pos < len && depth > 0) {
          const ch = advance();
          if (ch === 91) depth++;
          else if (ch === 93) depth--;
        }
        emit({ kind: 'Attribute', value: 'attrlist', line: startLine, column: startCol });
        continue;
      }
      const start = pos;
      while (pos < len && isAlnum(peek())) advance();
      const attrName = source.slice(start, pos);
      if (!attrName) fail('Expected attribute name after `@`', startLine, startCol);
      emit({ kind: 'Attribute', value: attrName, line: startLine, column: startCol });
      continue;
    }

    // Number literal
    if (isDigit(c) || (c === 46 && isDigit(peek(1)))) {
      const numVal = readNumber(startLine, startCol);
      emit({ kind: 'Number', value: String(numVal), numValue: numVal, line: startLine, column: startCol });
      continue;
    }

    // Quoted strings
    if (c === 34 || c === 39) {
      const bytes = readQuotedString(c, startLine, startCol);
      emit({ kind: 'String', value: '', bytes, line: startLine, column: startCol });
      continue;
    }

    // Long string `[=*[ ... ]=*]`
    if (c === 91) {
      const eq = checkLongBracket();
      if (eq >= 0) {
        const bytes = readLongString(eq, startLine, startCol, false);
        emit({ kind: 'String', value: '', bytes, line: startLine, column: startCol });
        continue;
      }
      advance();
      emit({ kind: 'Symbol', value: '[', line: startLine, column: startCol });
      continue;
    }

    // Luau interpolated string `` `...` ``
    if (c === 96) {
      readInterpSegment(true, startLine, startCol);
      continue;
    }

    // Braces (track interpolated string nesting!)
    if (c === 123) { // '{'
      advance();
      if (interpBraceStack.length > 0) {
        interpBraceStack[interpBraceStack.length - 1]++;
      }
      emit({ kind: 'Symbol', value: '{', line: startLine, column: startCol });
      continue;
    }
    if (c === 125) { // '}'
      if (interpBraceStack.length > 0 && interpBraceStack[interpBraceStack.length - 1] === 0) {
        interpBraceStack.pop();
        readInterpSegment(false, startLine, startCol);
        continue;
      }
      advance();
      if (interpBraceStack.length > 0) {
        interpBraceStack[interpBraceStack.length - 1]--;
      }
      emit({ kind: 'Symbol', value: '}', line: startLine, column: startCol });
      continue;
    }

    // Multi-char operators & symbols (including Luau compound ops, //, ::, ->, ...)
    const c2 = peek(1);
    const c3 = peek(2);

    // 3-char symbols: `...`, `..=`, `//=`
    if (c === 46 && c2 === 46 && c3 === 46) {
      pos += 3; col += 3;
      emit({ kind: 'Symbol', value: '...', line: startLine, column: startCol });
      continue;
    }
    if (c === 46 && c2 === 46 && c3 === 61) {
      pos += 3; col += 3;
      emit({ kind: 'Symbol', value: '..=', line: startLine, column: startCol });
      continue;
    }
    if (c === 47 && c2 === 47 && c3 === 61) {
      pos += 3; col += 3;
      emit({ kind: 'Symbol', value: '//=', line: startLine, column: startCol });
      continue;
    }

    // 2-char symbols
    const two = c2 >= 0 ? String.fromCharCode(c, c2) : '';
    if (
      two === '==' || two === '~=' || two === '<=' || two === '>=' ||
      two === '..' || two === '//' || two === '::' || two === '->' ||
      two === '+=' || two === '-=' || two === '*=' || two === '/=' ||
      two === '%=' || two === '^='
    ) {
      pos += 2; col += 2;
      emit({ kind: 'Symbol', value: two, line: startLine, column: startCol });
      continue;
    }

    // 1-char symbols
    const one = String.fromCharCode(c);
    if ('+-*/%^#<>=();:,.[].?|&'.includes(one)) {
      advance();
      emit({ kind: 'Symbol', value: one, line: startLine, column: startCol });
      continue;
    }

    fail(`Unexpected character "${one}" (0x${c.toString(16)})`, startLine, startCol);
  }

  tokens.push({ kind: 'EOF', value: '', line, column: col });
  return tokens;
}
