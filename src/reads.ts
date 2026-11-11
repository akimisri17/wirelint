import type { EnvRead, ReadKind } from './types.js';

/**
 * Blank out comments while keeping string contents and line numbers, so that a
 * variable mentioned in a comment is not counted as a read.
 */
export function stripComments(src: string): string {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i]!;
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && d === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') out += '\n';
        i++;
      }
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      out += c;
      i++;
      while (i < n && src[i] !== c) {
        if (src[i] === '\\' && i + 1 < n) {
          out += src[i]! + src[i + 1]!;
          i += 2;
          continue;
        }
        if (src[i] === '\n' && c !== '`') break;
        out += src[i];
        i++;
      }
      if (i < n && src[i] === c) {
        out += c;
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

const NAME = '[A-Za-z_][A-Za-z0-9_]*';
const ENV_OBJ = '(?:process\\.env|import\\.meta\\.env|Bun\\.env)';

const DOT_RE = new RegExp(`\\b${ENV_OBJ}\\??\\.(${NAME})`, 'g');
const BRACKET_RE = new RegExp(`\\b${ENV_OBJ}(?:\\?\\.)?\\[\\s*(['"\`])([^'"\`\\]]*)\\1\\s*\\]`, 'g');
const DYNAMIC_RE = new RegExp(`\\b${ENV_OBJ}(?:\\?\\.)?\\[\\s*(?!['"\`])`, 'g');
const DESTRUCTURE_RE = new RegExp(`\\{([^{}]*)\\}\\s*=\\s*${ENV_OBJ}(?![\\w.\\[])`, 'g');
const CONFIG_GET_RE =
  /\b([A-Za-z_$][\w$]*)\s*\??\.\s*(get|getOrThrow)\s*(?:<[^()]*?>)?\s*\(\s*(['"`])([A-Z][A-Z0-9_]*)\3\s*([,)])/g;
const SCHEMA_KEY_RE =
  /(?:^|[\s{,])['"]?([A-Z][A-Z0-9_]+)['"]?\s*:\s*(?:(z)\s*\.\s*(?:string|number|boolean|enum|coerce|literal|union|preprocess|nativeEnum|any|unknown|array|object|optional|bigint|date)\b|(Joi|joi|yup)\s*\.\s*\w+|(str|num|bool|url|port|host|email|json)\s*\()/g;
const NEXT_KEY_RE = /[,}]\s*['"]?[A-Z][A-Z0-9_]+['"]?\s*:/;
const CLASS_PROP_RE = /^[ \t]*(?:@\w+\([^\n]*\)\s*)*(?:public\s+|readonly\s+)*([A-Z][A-Z0-9_]{2,})\s*([!?])?\s*:\s*[\w<>\[\]| ]+;?\s*$/gm;

const LOCAL_LITERAL = /localhost|127\.0\.0\.1|0\.0\.0\.0/;
const CHAIN_OP_TAIL = /^\s*(\|\||\?\?)\s*/;
const ASSIGNED_RE = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*(?:await\s+)?\(?\s*(?:this\s*\.\s*)?$/;

/** `|| 'literal'` or `?? 'literal'`: a default, and a dangerous one when it is localhost. */
function literalDefault(tail: string): ReadKind | null {
  const op = CHAIN_OP_TAIL.exec(tail);
  if (!op) return null;
  const lit = /^(['"`])([^'"`]*)\1/.exec(tail.slice(op[0].length));
  return lit && LOCAL_LITERAL.test(lit[2]!) ? 'localdefault' : 'default';
}

/**
 * Classify one read from the code around it. `start`/`end` delimit the read
 * expression itself. Anything that shows the code copes with an unset value
 * makes the read optional; only an explicit guard makes it required.
 */
function kindFromContext(text: string, start: number, end: number): ReadKind {
  const tail = text.slice(end, end + 700);
  const head = text.slice(Math.max(0, start - 90), start);
  const chained = /(\|\||\?\?)\s*(?:this\s*\.\s*)?$/.test(head);

  if (/^\s*!(?!=)/.test(tail)) return 'required';
  const dflt = literalDefault(tail);
  if (dflt) return chained ? 'default' : dflt;
  if (chained) return 'default';
  if (/^\s*\?\./.test(tail)) return 'flag';
  if (/^\s*(===?|!==?)/.test(tail) || /^\s*\?(?![.?])/.test(tail) || /^\s*&&/.test(tail)) return 'flag';
  if (/\b(Number|parseInt|parseFloat|Boolean|String)\(\s*(?:this\s*\.\s*)?$/.test(head)) return 'default';
  if (/!\s*\(?\s*(?:this\s*\.\s*)?$/.test(head)) return /^[^;{]*\)\s*\{?\s*throw\b/.test(tail) ? 'required' : 'flag';
  if (/(===?|!==?|&&)\s*(?:this\s*\.\s*)?$/.test(head) || /\bif\s*\(\s*(?:this\s*\.\s*)?$/.test(head)) return 'flag';

  const assigned = ASSIGNED_RE.exec(head);
  if (assigned) {
    const v = assigned[1]!.replace(/\$/g, '\\$');
    if (new RegExp(`\\bif\\s*\\(\\s*!\\s*${v}\\b[^{};]*\\)\\s*\\{?[^{}]*?\\bthrow\\b`).test(tail)) return 'required';
    if (new RegExp(`\\bif\\s*\\(\\s*!?\\s*${v}\\b|\\b${v}\\s*(?:\\?|\\|\\||&&)|!\\s*${v}\\b`).test(tail)) return 'flag';
  }
  return 'plain';
}

export interface ScanResult {
  reads: Omit<EnvRead, 'file' | 'tooling'>[];
  dynamic: number[];
  ports: number[];
}

export function scanSource(source: string): ScanResult {
  const text = stripComments(source);
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') lineStarts.push(i + 1);
  const lineOf = (offset: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };

  const reads: ScanResult['reads'] = [];
  const dynamic: number[] = [];
  const add = (name: string, offset: number, kind: ReadKind, schema = false): void => {
    reads.push({ name, line: lineOf(offset), kind, schema });
  };
  let m: RegExpExecArray | null;

  if (/process\.env|import\.meta\.env|Bun\.env/.test(text)) {
    for (DOT_RE.lastIndex = 0; (m = DOT_RE.exec(text)); ) {
      add(m[1]!, m.index, kindFromContext(text, m.index, m.index + m[0].length));
    }
    for (BRACKET_RE.lastIndex = 0; (m = BRACKET_RE.exec(text)); ) {
      const name = m[2]!;
      if (new RegExp(`^${NAME}$`).test(name)) add(name, m.index, kindFromContext(text, m.index, m.index + m[0].length));
      else dynamic.push(lineOf(m.index));
    }
    for (DYNAMIC_RE.lastIndex = 0; (m = DYNAMIC_RE.exec(text)); ) dynamic.push(lineOf(m.index));
    for (DESTRUCTURE_RE.lastIndex = 0; (m = DESTRUCTURE_RE.exec(text)); ) {
      for (const part of m[1]!.split(',')) {
        const pm = new RegExp(`^\\s*(${NAME})\\s*(?::\\s*${NAME}\\s*)?(=)?`).exec(part);
        if (pm && !part.trim().startsWith('...')) add(pm[1]!, m.index, pm[2] ? 'default' : 'plain');
      }
    }
  }

  if (/\.\s*(get|getOrThrow)\b/.test(text)) {
    for (CONFIG_GET_RE.lastIndex = 0; (m = CONFIG_GET_RE.exec(text)); ) {
      if (!/config|cfg|conf|env|settings/i.test(m[1]!)) continue;
      const end = m.index + m[0].length;
      let kind: ReadKind;
      if (m[2] === 'getOrThrow') kind = 'required';
      else if (m[5] === ',') kind = LOCAL_LITERAL.test(/^\s*(['"`])([^'"`]*)\1/.exec(text.slice(end))?.[2] ?? '') ? 'localdefault' : 'default';
      else kind = kindFromContext(text, m.index, end);
      add(m[4]!, m.index, kind);
    }
  }

  // Schema keys: zod / Joi / yup / valibot / envalid validators keyed by UPPER_SNAKE names.
  // A validator only counts when its library is actually imported, so that an
  // unrelated helper called url() or str() is not mistaken for a schema.
  const imported = (mod: string) => new RegExp(`['"\`](?:@hapi/)?${mod}(?:/[\\w./-]+)?['"\`]`).test(text);
  const libs = { z: imported('zod'), joi: imported('joi'), yup: imported('yup'), envalid: imported('envalid') };
  const anySchemaLib = libs.z || libs.joi || libs.yup || libs.envalid;
  for (SCHEMA_KEY_RE.lastIndex = 0; anySchemaLib && (m = SCHEMA_KEY_RE.exec(text)); ) {
    const name = m[1]!;
    const lib = (m[2] ?? m[3] ?? 'envalid').toLowerCase();
    if (!libs[lib as keyof typeof libs]) continue;
    const rest = text.slice(m.index + m[0].length, m.index + m[0].length + 400);
    const stop = rest.search(NEXT_KEY_RE);
    const chain = m[0] + (stop === -1 ? rest.slice(0, 200) : rest.slice(0, stop));
    const local = LOCAL_LITERAL.test(/\.default\(\s*(['"`])([^'"`]*)\1/.exec(chain)?.[2] ?? '') || LOCAL_LITERAL.test(/\b(?:default|devDefault)\s*:\s*(['"`])([^'"`]*)\1/.exec(chain)?.[2] ?? '');
    let kind: ReadKind;
    if (local) kind = 'localdefault';
    else if (lib === 'joi' || lib === 'yup') kind = /\.required\(/.test(chain) ? 'required' : 'default';
    else if (lib === 'envalid') kind = /\b(default|devDefault)\s*:/.test(chain) ? 'default' : 'required';
    else kind = /\.(optional|default|nullish|catch)\(/.test(chain) ? 'default' : 'required';
    add(name, m.index + m[0].indexOf(name), kind, true);
  }

  // NestJS-style validated env classes.
  if (/class-validator/.test(text) && /\bclass\s+\w*(Env|Config)\w*/.test(text)) {
    for (CLASS_PROP_RE.lastIndex = 0; (m = CLASS_PROP_RE.exec(text)); ) {
      add(m[1]!, m.index + m[0].indexOf(m[1]!), m[2] === '?' ? 'default' : 'required', true);
    }
  }

  const ports: number[] = [];
  const portRes = [
    /\bprocess\.env\.PORT\s*(?:\|\||\?\?)\s*['"`]?(\d{2,5})/g,
    /\(\s*['"`]PORT['"`]\s*,\s*['"`]?(\d{2,5})/g,
    /\.listen\(\s*(\d{4,5})\b/g,
  ];
  for (const re of portRes) for (; (m = re.exec(text)); ) ports.push(Number(m[1]));

  return { reads, dynamic: [...new Set(dynamic)].sort((x, y) => x - y), ports };
}
