import { Http, safeCode, type HttpResult } from './net.js';

/**
 * The Vercel REST API, read-only. Two GET endpoints only:
 *   GET /v10/projects/{id}/env        keys, targets and types, without decryption.
 *                                     Any value field in the answer is dropped on parse.
 *   GET /v1/projects/{id}/env/{envId} one decrypted value, only for --compare. It goes
 *                                     straight into `digest` and is not kept.
 */

export type VercelFailure = { failure: 'auth' | 'denied' | 'not-found' | 'throttled' | 'network' | 'hidden' | 'pagination' | 'other'; code?: string };

const MALFORMED: VercelFailure = { failure: 'other', code: 'MalformedResponse' };
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** A project variable as wirelint keeps it: no value. */
export interface VercelVar {
  id: string;
  key: string;
  targets: string[];
  type: string;
  /** Set for one git branch only, so it does not cover the target in general. */
  branchOnly: boolean;
}

const API = 'https://api.vercel.com';

function failure(r: Extract<HttpResult, { ok: true }>): VercelFailure {
  let code: string | null = null;
  let invalidToken = false;
  try {
    const err = (JSON.parse(r.body) as { error?: { code?: unknown; invalidToken?: unknown } }).error;
    code = safeCode(err?.code);
    invalidToken = err?.invalidToken === true;
  } catch {
    // not JSON
  }
  const c = code ?? `HTTP${r.status}`;
  if (r.status === 401 || invalidToken) return { failure: 'auth', code: c };
  if (r.status === 403) return { failure: 'denied', code: c };
  if (r.status === 404) return { failure: 'not-found', code: c };
  if (r.status === 429) return { failure: 'throttled', code: c };
  return { failure: 'other', code: c };
}

export class Vercel {
  constructor(
    private readonly http: Http,
    private readonly token: string,
  ) {}

  private async get(path: string, query: Record<string, string | undefined>): Promise<{ json: Record<string, unknown> } | VercelFailure> {
    const url = new URL(path, API);
    for (const [k, v] of Object.entries(query)) if (v) url.searchParams.set(k, v);
    const r = await this.http.request({ url: url.href, method: 'GET', headers: { authorization: `Bearer ${this.token}`, 'user-agent': 'wirelint' } });
    if (!r.ok) return { failure: 'network', code: r.kind };
    if (r.status < 200 || r.status >= 300) return failure(r);
    try {
      const json: unknown = JSON.parse(r.body);
      return isObject(json) ? { json } : MALFORMED;
    } catch {
      return { failure: 'other', code: 'UnreadableResponse' };
    }
  }

  /**
   * Every variable of a project: keys, targets and types.
   *
   * The documented answer (GET /v10/projects/{idOrName}/env) is either
   * { envs, pagination: { count, next, prev } }, where `next` is "Timestamp
   * that must be used to request the next page" or null, or { envs,
   * hiddenProductionEnvCount }. The endpoint documents no query parameter
   * for that timestamp; wirelint sends it as `until`, the convention of
   * Vercel's other paginated endpoints. A page that brings no new ids while
   * `next` is still set ends the listing as incomplete, never as complete.
   */
  async list(projectId: string, teamId: string | undefined): Promise<VercelVar[] | VercelFailure> {
    const out = new Map<string, VercelVar>();
    let until: string | undefined;
    for (let page = 0; ; page++) {
      if (page >= 50) return { failure: 'pagination', code: 'PaginationLimit' };
      const r = await this.get(`/v10/projects/${encodeURIComponent(projectId)}/env`, { teamId, until });
      if ('failure' in r) return r;
      const envs = r.json['envs'];
      if (!Array.isArray(envs) || !envs.every(isObject)) return MALFORMED;
      let added = 0;
      for (const raw of envs) {
        const target = raw['target'];
        const targets = Array.isArray(target) ? target : [target];
        delete raw['value'];
        if (typeof raw['key'] !== 'string' || typeof raw['id'] !== 'string' || !targets.every((t) => typeof t === 'string')) return MALFORMED;
        if (out.has(raw['id'])) continue;
        added++;
        out.set(raw['id'], { id: raw['id'], key: raw['key'], targets: targets as string[], type: typeof raw['type'] === 'string' ? raw['type'] : 'unknown', branchOnly: typeof raw['gitBranch'] === 'string' && raw['gitBranch'] !== '' });
      }
      const hidden = r.json['hiddenProductionEnvCount'];
      if (typeof hidden === 'number' && hidden > 0) return { failure: 'hidden', code: 'HiddenProductionEnvs' };
      const pagination = r.json['pagination'];
      if (pagination !== undefined && !isObject(pagination)) return MALFORMED;
      const next = pagination?.['next'];
      if (next === undefined || next === null) break;
      if (typeof next !== 'number' && typeof next !== 'string') return MALFORMED;
      if (added === 0) return { failure: 'pagination', code: 'PaginationStalled' };
      until = String(next);
    }
    return [...out.values()];
  }

  /**
   * The digest of one variable's decrypted value. Sensitive variables cannot
   * be read back, by design; they are reported as unreadable without a request.
   */
  async digest<D>(projectId: string, teamId: string | undefined, v: VercelVar, digest: (value: string) => D): Promise<D | 'unreadable' | VercelFailure> {
    if (v.type === 'sensitive' || v.type === 'secret' || v.type === 'system') return 'unreadable';
    const r = await this.get(`/v1/projects/${encodeURIComponent(projectId)}/env/${encodeURIComponent(v.id)}`, { teamId });
    if ('failure' in r) return r;
    const value = r.json['value'];
    delete r.json['value'];
    if (value !== undefined && typeof value !== 'string') return MALFORMED;
    // Only a value the API says it decrypted (or a plain one) is a value; anything else may be ciphertext.
    const readable = r.json['decrypted'] === true || (r.json['type'] ?? v.type) === 'plain';
    return typeof value === 'string' && readable ? digest(value) : 'unreadable';
  }
}

export function vercelProblem(f: VercelFailure, what: string): { problem: string; fix: string } {
  const code = f.code ? ` (${f.code})` : '';
  switch (f.failure) {
    case 'auth':
      return { problem: `Vercel rejected the token${code}`, fix: 'set VERCEL_TOKEN to a valid token (Account Settings > Tokens); it may have expired' };
    case 'denied':
      return { problem: `the token is not allowed to read ${what}${code}`, fix: 'use a token scoped to the team that owns the project, and set the team with --vercel-team or VERCEL_TEAM_ID' };
    case 'not-found':
      return { problem: `${what} was not found for this token and team${code}`, fix: 'check projectId in .vercel/project.json (or --vercel-project) and the team (--vercel-team, VERCEL_TEAM_ID)' };
    case 'throttled':
      return { problem: `Vercel kept rate-limiting after retries${code}`, fix: 'run it again later' };
    case 'hidden':
      return { problem: `Vercel hid some production variables of ${what} from this token${code}`, fix: 'use a token whose role can see production environment variables' };
    case 'pagination':
      return { problem: `the variable list of ${what} did not page to the end${code}`, fix: 'run it again; if it persists, the list cannot be read in full and the check is not trustworthy' };
    case 'network':
      return { problem: `could not reach the Vercel API${code}`, fix: 'check network access to api.vercel.com' };
    default:
      return { problem: `the Vercel API answered with an error${code}`, fix: 'run it again; if it persists, check the project and token' };
  }
}
