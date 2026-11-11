import type { AnnotationKind } from './types.js';

export interface EnvEntry {
  name: string;
  value: string;
  line: number;
  /** A documented-but-disabled entry such as `# SENTRY_DSN=`. */
  commented: boolean;
}

export interface IgnoreMarker {
  name: string;
  reason: string;
  line: number;
}

export interface AnnotationMarker {
  name: string;
  kind: AnnotationKind;
  /** For same-as: the target exactly as written. */
  target?: string;
  /** Line of the annotation comment itself. */
  line: number;
}

export interface BadAnnotation {
  line: number;
  name?: string;
  problem: string;
  fix: string;
}

export interface ParsedEnv {
  entries: EnvEntry[];
  ignores: IgnoreMarker[];
  /** `wirelint-ignore` markers that carry no reason. They are not honoured. */
  badIgnores: { line: number; name?: string }[];
  /** `# wirelint: ...` annotations, attached to the variable they describe. */
  annotations: AnnotationMarker[];
  /** Annotations that cannot be honoured: unknown word, missing target, nothing to attach to. */
  badAnnotations: BadAnnotation[];
}

const VAR_RE = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;
const COMMENTED_VAR_RE = /^#\s*([A-Z][A-Z0-9_]*)=(.*)$/;
const IGNORE_RE = /wirelint-ignore\b[ \t]*([A-Za-z_][A-Za-z0-9_]*)?[ \t]*(?::[ \t]*(.*))?$/;
/** `# wirelint: a, b` as a whole comment line. */
const ANNOTATION_LINE_RE = /^#\s*wirelint:(.*)$/;
/** `# wirelint: a, b` inside a trailing comment, up to the next `#`. */
const ANNOTATION_INLINE_RE = /(?:^|\s)#\s*wirelint:([^#]*)/;

const KINDS: AnnotationKind[] = ['same-as', 'optional', 'build-time'];
const USAGE = 'use same-as <service>, optional or build-time, separated by commas';

/** Edit distance, for suggesting the annotation a typo meant. */
function distance(a: string, b: string): number {
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length]!;
}

interface Parsed {
  items: { kind: AnnotationKind; target?: string }[];
  bad: { problem: string; fix: string }[];
}

/** Parse the text after `wirelint:`. */
export function parseAnnotation(body: string): Parsed {
  const out: Parsed = { items: [], bad: [] };
  const parts = body.split(',').map((p) => p.trim());
  if (parts.every((p) => p === '')) {
    out.bad.push({ problem: 'wirelint annotation is empty', fix: USAGE });
    return out;
  }
  for (const part of parts) {
    if (part === '') continue;
    const [word, ...args] = part.split(/\s+/) as [string, ...string[]];
    const kind = KINDS.find((k) => k === word.toLowerCase());
    if (!kind) {
      const near = KINDS.find((k) => distance(k, word.toLowerCase().replace(/_/g, '-')) <= 2);
      out.bad.push({
        problem: `unknown wirelint annotation "${word}"`,
        fix: near ? `write "${near}"${near === 'same-as' ? ' <service>' : ''} instead of "${word}"` : USAGE,
      });
      continue;
    }
    if (kind === 'same-as') {
      if (args.length === 0) {
        out.bad.push({ problem: '"same-as" names no service', fix: 'write "# wirelint: same-as <service>" or "same-as <service>.<VARIABLE>"' });
        continue;
      }
      if (args.length > 1) {
        out.bad.push({ problem: `"${part}" has more than one target`, fix: 'name one service per same-as, and separate annotations with commas' });
        continue;
      }
      out.items.push({ kind, target: args[0]! });
      continue;
    }
    if (args.length > 0) {
      out.bad.push({ problem: `"${kind}" takes no argument, got "${args.join(' ')}"`, fix: `write "${kind}", and separate annotations with commas` });
      continue;
    }
    out.items.push({ kind });
  }
  return out;
}

function splitValue(raw: string): { value: string; comment: string } {
  const t = raw.trim();
  const q = t[0];
  if (q === '"' || q === "'" || q === '`') {
    let end = -1;
    for (let i = 1; i < t.length; i++) {
      if (t[i] === '\\' && q === '"') i++;
      else if (t[i] === q) {
        end = i;
        break;
      }
    }
    if (end > 0) return { value: t.slice(1, end), comment: t.slice(end + 1) };
  }
  const hash = t.search(/(^|\s)#/);
  return hash === -1 ? { value: t, comment: '' } : { value: t.slice(0, hash).trim(), comment: t.slice(hash) };
}

export function parseEnv(text: string): ParsedEnv {
  const out: ParsedEnv = { entries: [], ignores: [], badIgnores: [], annotations: [], badAnnotations: [] };
  let pending: { reason: string; line: number } | null = null;
  /** Annotations from comment lines directly above the next variable. */
  let pendingAnn: { parsed: Parsed; line: number }[] = [];
  const lines = text.split(/\r?\n/);

  const marker = (comment: string, line: number, attachTo?: string): void => {
    const m = IGNORE_RE.exec(comment);
    if (!m) return;
    const name = m[1] ?? attachTo;
    const reason = (m[2] ?? '').trim();
    if (!reason) {
      out.badIgnores.push({ line, name });
      return;
    }
    if (name) out.ignores.push({ name, reason, line });
    else pending = { reason, line };
  };

  const attach = (parsed: Parsed, line: number, name: string): void => {
    for (const item of parsed.items) out.annotations.push({ name, kind: item.kind, target: item.target, line });
    for (const bad of parsed.bad) out.badAnnotations.push({ line, name, ...bad });
  };
  const dangling = (): void => {
    for (const p of pendingAnn) {
      out.badAnnotations.push({
        line: p.line,
        problem: 'wirelint annotation is not attached to a variable',
        fix: "put it at the end of the variable's line, or on the line directly above it",
      });
    }
    pendingAnn = [];
  };
  const declared = (name: string, line: number, comment: string): void => {
    for (const p of pendingAnn) attach(p.parsed, p.line, name);
    pendingAnn = [];
    const inline = ANNOTATION_INLINE_RE.exec(comment);
    if (inline) attach(parseAnnotation(inline[1]!), line, name);
  };

  lines.forEach((rawLine, idx) => {
    const line = idx + 1;
    const t = rawLine.trim();
    if (t === '') {
      pending = null;
      dangling();
      return;
    }
    if (t.startsWith('#')) {
      if (t.includes('wirelint-ignore')) {
        marker(t, line);
        return;
      }
      const ann = ANNOTATION_LINE_RE.exec(t);
      if (ann) {
        pendingAnn.push({ parsed: parseAnnotation(ann[1]!), line });
        return;
      }
      const c = COMMENTED_VAR_RE.exec(t);
      if (c) {
        const { value, comment } = splitValue(c[2]!);
        out.entries.push({ name: c[1]!, value, line, commented: true });
        declared(c[1]!, line, comment);
      } else {
        dangling();
      }
      return;
    }
    const m = VAR_RE.exec(t);
    if (!m) {
      dangling();
      return;
    }
    const name = m[1]!;
    const { value, comment } = splitValue(m[2]!);
    out.entries.push({ name, value, line, commented: false });
    if (pending) {
      out.ignores.push({ name, reason: pending.reason, line: pending.line });
      pending = null;
    }
    if (comment.includes('wirelint-ignore')) marker(comment, line, name);
    declared(name, line, comment);
  });
  dangling();
  return out;
}
