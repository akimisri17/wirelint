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

export interface ParsedEnv {
  entries: EnvEntry[];
  ignores: IgnoreMarker[];
  /** `wirecheck-ignore` markers that carry no reason. They are not honoured. */
  badIgnores: { line: number; name?: string }[];
}

const VAR_RE = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;
const COMMENTED_VAR_RE = /^#\s*([A-Z][A-Z0-9_]*)=(.*)$/;
const IGNORE_RE = /wirecheck-ignore\b[ \t]*([A-Za-z_][A-Za-z0-9_]*)?[ \t]*(?::[ \t]*(.*))?$/;

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
  const out: ParsedEnv = { entries: [], ignores: [], badIgnores: [] };
  let pending: { reason: string; line: number } | null = null;
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

  lines.forEach((rawLine, idx) => {
    const line = idx + 1;
    const t = rawLine.trim();
    if (t === '') {
      pending = null;
      return;
    }
    if (t.startsWith('#')) {
      if (t.includes('wirecheck-ignore')) {
        marker(t, line);
        return;
      }
      const c = COMMENTED_VAR_RE.exec(t);
      if (c) out.entries.push({ name: c[1]!, value: splitValue(c[2]!).value, line, commented: true });
      return;
    }
    const m = VAR_RE.exec(t);
    if (!m) return;
    const name = m[1]!;
    const { value, comment } = splitValue(m[2]!);
    out.entries.push({ name, value, line, commented: false });
    if (pending) {
      out.ignores.push({ name, reason: pending.reason, line: pending.line });
      pending = null;
    }
    if (comment.includes('wirecheck-ignore')) marker(comment, line, name);
  });
  return out;
}
