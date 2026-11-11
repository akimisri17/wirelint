/**
 * A small, tolerant YAML subset reader: block maps, block sequences, flow
 * collections, quoted scalars, block scalars, anchors and merge keys. It is
 * enough for docker-compose files and deploy manifests, and it never throws:
 * anything it cannot read becomes null. All scalars stay strings.
 */
export type Yaml = string | null | Yaml[] | { [key: string]: Yaml };

interface Line {
  indent: number;
  text: string;
}

const KEY_RE = /^("(?:[^"\\]|\\.)*"|'[^']*'|[^\s"'\[\]{}#&*!|>-][^:]*?|-[^\s:][^:]*?)\s*:(?=\s|$)/;

function stripComment(s: string): string {
  let quote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === '\\' && quote === '"') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if ((c === '"' || c === "'") && (i === 0 || /[\s:\[{,-]/.test(s[i - 1]!))) {
      quote = c;
      continue;
    }
    if (c === '#' && (i === 0 || /\s/.test(s[i - 1]!))) return s.slice(0, i);
  }
  return s;
}

function unquote(s: string): string {
  const t = s.trim();
  if (t.length >= 2 && t[0] === '"' && t.endsWith('"')) {
    return t.slice(1, -1).replace(/\\(["\\/nt])/g, (_, c: string) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
  }
  if (t.length >= 2 && t[0] === "'" && t.endsWith("'")) return t.slice(1, -1).replace(/''/g, "'");
  return t;
}

const isSeqLine = (text: string) => text === '-' || text.startsWith('- ');

class Parser {
  private i = 0;
  private anchors = new Map<string, Yaml>();
  constructor(private raw: string[]) {}

  private peek(): Line | null {
    while (this.i < this.raw.length) {
      const stripped = stripComment(this.raw[this.i]!).trimEnd();
      const text = stripped.trimStart();
      if (text === '' || text === '---' || text === '...' || stripped.startsWith('%')) {
        this.i++;
        continue;
      }
      return { indent: stripped.length - text.length, text };
    }
    return null;
  }

  block(minIndent: number): Yaml {
    const l = this.peek();
    if (!l || l.indent < minIndent) return null;
    return isSeqLine(l.text) ? this.seq(l.indent) : this.map(l.indent);
  }

  private seq(indent: number): Yaml[] {
    const out: Yaml[] = [];
    for (;;) {
      const l = this.peek();
      if (!l || l.indent < indent) break;
      if (l.indent > indent) {
        this.i++;
        continue;
      }
      if (!isSeqLine(l.text)) break;
      const rest = l.text.slice(1).trimStart();
      if (rest === '') {
        this.i++;
        out.push(this.block(indent + 1));
        continue;
      }
      if (KEY_RE.test(rest)) {
        const inner = indent + (l.text.length - rest.length);
        this.raw[this.i] = ' '.repeat(inner) + rest;
        out.push(this.map(inner));
      } else {
        this.i++;
        out.push(this.scalar(rest));
      }
    }
    return out;
  }

  private map(indent: number): { [key: string]: Yaml } {
    const out: { [key: string]: Yaml } = {};
    for (;;) {
      const l = this.peek();
      if (!l || l.indent < indent) break;
      if (l.indent > indent) {
        this.i++;
        continue;
      }
      const m = KEY_RE.exec(l.text);
      if (!m) {
        if (isSeqLine(l.text)) break;
        this.i++;
        continue;
      }
      const key = unquote(m[1]!);
      let rest = l.text.slice(m[0].length).trim();
      this.i++;
      let anchor: string | undefined;
      const am = /^&(\S+)\s*/.exec(rest);
      if (am) {
        anchor = am[1];
        rest = rest.slice(am[0].length);
      }
      rest = rest.replace(/^!\S+\s*/, '');
      let value: Yaml;
      if (rest === '') {
        const next = this.peek();
        if (next && next.indent > indent) value = this.block(indent + 1);
        else if (next && next.indent === indent && isSeqLine(next.text)) value = this.seq(indent);
        else value = null;
      } else if (/^[|>][+-]?\d*$/.test(rest)) {
        value = this.blockScalar(indent);
      } else {
        value = this.scalar(rest);
      }
      if (anchor) this.anchors.set(anchor, value);
      if (key === '<<') {
        for (const src of Array.isArray(value) ? value : [value]) {
          if (src && typeof src === 'object' && !Array.isArray(src)) {
            for (const [k, v] of Object.entries(src)) if (!(k in out)) out[k] = v;
          }
        }
      } else {
        out[key] = value;
      }
    }
    return out;
  }

  private blockScalar(parentIndent: number): string {
    const lines: string[] = [];
    while (this.i < this.raw.length) {
      const r = this.raw[this.i]!;
      if (r.trim() !== '' && r.length - r.trimStart().length <= parentIndent) break;
      lines.push(r.trim());
      this.i++;
    }
    return lines.join('\n').trim();
  }

  private scalar(text: string): Yaml {
    const t = text.trim();
    if (t.startsWith('*')) return this.anchors.get(t.slice(1)) ?? null;
    if (t.startsWith('[') || t.startsWith('{')) {
      let buf = t;
      // Flow collections may span lines: keep reading until brackets balance.
      while (!balanced(buf) && this.i < this.raw.length) buf += ' ' + stripComment(this.raw[this.i++]!).trim();
      return flow(buf, { p: 0 }, this.anchors);
    }
    if (t === '~' || t === 'null') return null;
    return unquote(t);
  }
}

function balanced(s: string): boolean {
  let depth = 0;
  let quote: string | null = null;
  for (const c of s) {
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') depth--;
  }
  return depth <= 0;
}

function flow(s: string, at: { p: number }, anchors: Map<string, Yaml>): Yaml {
  const ws = () => {
    while (at.p < s.length && /\s/.test(s[at.p]!)) at.p++;
  };
  const token = (stops: string): string => {
    ws();
    const start = at.p;
    const q = s[at.p];
    if (q === '"' || q === "'") {
      at.p++;
      while (at.p < s.length && s[at.p] !== q) at.p += s[at.p] === '\\' ? 2 : 1;
      at.p++;
      return s.slice(start, at.p);
    }
    while (at.p < s.length && !stops.includes(s[at.p]!)) at.p++;
    return s.slice(start, at.p).trim();
  };
  const value = (stops: string): Yaml => {
    ws();
    if (s[at.p] === '[' || s[at.p] === '{') return flow(s, at, anchors);
    const t = token(stops);
    if (t.startsWith('*')) return anchors.get(t.slice(1)) ?? null;
    return t === '' || t === '~' || t === 'null' ? null : unquote(t);
  };
  ws();
  if (s[at.p] === '[') {
    at.p++;
    const out: Yaml[] = [];
    for (;;) {
      ws();
      if (at.p >= s.length || s[at.p] === ']') break;
      out.push(value(',]'));
      ws();
      if (s[at.p] === ',') at.p++;
    }
    at.p++;
    return out;
  }
  if (s[at.p] === '{') {
    at.p++;
    const out: { [key: string]: Yaml } = {};
    for (;;) {
      ws();
      if (at.p >= s.length || s[at.p] === '}') break;
      const key = unquote(token(':,}'));
      ws();
      if (s[at.p] === ':') {
        at.p++;
        out[key] = value(',}');
      } else if (key) {
        out[key] = null;
      }
      ws();
      if (s[at.p] === ',') at.p++;
    }
    at.p++;
    return out;
  }
  return value('');
}

export function parseYaml(text: string): Yaml {
  try {
    return new Parser(text.split(/\r?\n/)).block(0);
  } catch {
    return null;
  }
}

export function asMap(y: Yaml | undefined): { [key: string]: Yaml } | null {
  return y && typeof y === 'object' && !Array.isArray(y) ? y : null;
}

export function asList(y: Yaml | undefined): Yaml[] {
  return Array.isArray(y) ? y : [];
}

export function asString(y: Yaml | undefined): string | null {
  return typeof y === 'string' ? y : null;
}
