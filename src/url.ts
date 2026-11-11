import type { HostFact, ShapeCode, ShapeProblem, VarFacts } from './types.js';

/** Unexpanded or templated values are not ours to judge. */
export function isPlaceholder(value: string): boolean {
  const v = value.trim();
  if (v === '') return true;
  if (v.startsWith('$') || v.includes('${') || v.includes('{{') || v.includes('<') || v.includes('>')) return true;
  return /your[-_]|xxxx|changeme|change[-_]me|replace[-_]me|\.\.\./i.test(v);
}

const VERSION_PREFIX = /^(\/api)?(\/v\d+)?(?=\/|$)/;
const ALLOWED_PATH = /^(\/api)?(\/v\d+)?$/;

/**
 * A service base URL must be an origin, optionally followed by a version
 * prefix (/api, /v1, /api/v2). Returns null when the value is fine or is not
 * an absolute http(s) URL.
 */
export function checkUrlShape(value: string): ShapeProblem | null {
  const m = /^(https?:\/\/[^/?#\s]+)([^?#\s]*)(\?[^#\s]*)?(#\S*)?$/i.exec(value.trim());
  if (!m) return null;
  const [, origin, rawPath = '', query, fragment] = m;
  const codes: ShapeCode[] = [];
  if (query !== undefined) codes.push('query');
  if (fragment !== undefined) codes.push('fragment');
  const trailing = rawPath.endsWith('/');
  if (trailing) codes.push('trailing-slash');
  const path = trailing ? rawPath.replace(/\/+$/, '') : rawPath;
  if (path !== '' && !ALLOWED_PATH.test(path)) codes.push('resource-path');
  if (codes.length === 0) return null;
  const prefix = VERSION_PREFIX.exec(path)?.[0] ?? '';
  return { codes, path, suggested: `${origin}${prefix}` };
}

const NONPROD_TOKENS = new Set([
  'dev', 'develop', 'development', 'staging', 'stage', 'stg', 'preview', 'test', 'testing', 'qa', 'uat', 'sandbox', 'sbx',
]);
const TUNNEL_SUFFIXES = ['.ngrok.io', '.ngrok-free.app', '.ngrok.app', '.trycloudflare.com', '.loca.lt', '.localhost.run'];

export function classifyHost(host: string, port?: number): HostFact {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  const fact = (klass: HostFact['klass'], token?: string): HostFact => ({ host: h, port, klass, token });
  if (h === 'localhost' || h === '0.0.0.0' || h === '::1' || h === 'host.docker.internal' || /^127\./.test(h) || h.endsWith('.localhost')) {
    return fact('local');
  }
  if (TUNNEL_SUFFIXES.some((s) => h.endsWith(s))) return fact('tunnel');
  if (h.endsWith('.vercel.app')) {
    const sub = h.slice(0, -'.vercel.app'.length);
    // Preview deployments: <project>-git-<branch>-<team> or <project>-<hash>-<team>.
    if (/-git-/.test(sub) || /-[a-z0-9]{9}-/.test(sub)) return fact('vercel-preview');
    return fact('vercel-default');
  }
  if (/^\d+(\.\d+){3}$/.test(h)) return fact('ok');
  const labels = h.split('.');
  // The last label is the TLD (.dev and .test are real TLDs), so it is skipped.
  for (const label of labels.length > 1 ? labels.slice(0, -1) : labels) {
    for (const token of label.split(/[-_]/)) {
      if (NONPROD_TOKENS.has(token)) return fact('nonprod', token);
    }
  }
  return fact('ok');
}

/** Pull the host (and port) out of a URL, a connection string or a bare host. */
export function extractHost(value: string): HostFact | null {
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^@/\s]*@)?(\[[^\]]+\]|[^:/?#,\s]+)(?::(\d{1,5}))?/i.exec(value.trim());
  if (!m || !m[1]) return null;
  if (!/[a-z0-9]/i.test(m[1])) return null;
  return classifyHost(m[1], m[2] ? Number(m[2]) : undefined);
}

export function factsOf(name: string, raw: string): VarFacts {
  const value = raw.trim();
  const placeholder = isPlaceholder(value);
  const http = /^https?:\/\//i.test(value);
  const facts: VarFacts = { placeholder, http, shape: null, hosts: [] };
  if (name === 'PORT') {
    const n = Number(value);
    if (Number.isInteger(n) && n > 0 && n < 65536) facts.port = n;
    return facts;
  }
  if (placeholder) return facts;
  const parts = value.split(/[,\s]+/).filter(Boolean);
  for (const part of parts) {
    const host = extractHost(part);
    if (host) facts.hosts.push(host);
  }
  if (http && parts.length === 1) facts.shape = checkUrlShape(value);
  return facts;
}

/** Hide credentials embedded in a URL before it is shown. */
export function redact(value: string): string {
  return value.replace(/(:\/\/)[^@/\s]+@/, '$1***@');
}
