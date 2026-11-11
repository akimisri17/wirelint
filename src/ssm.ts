import { Http, safeCode, type HttpResult } from './net.js';
import { signV4, type AwsCredentials } from './sigv4.js';

/**
 * AWS Systems Manager Parameter Store, read-only, over the JSON 1.1 protocol.
 * Two actions only:
 *   DescribeParameters  metadata (names), never values. Used for existence.
 *   GetParameters       values, only for --compare. Each value is handed to
 *                       `digest` the moment it is parsed and not kept.
 */

export type SsmFailure = { failure: 'auth' | 'denied' | 'throttled' | 'network' | 'other'; code?: string };

const AUTH = new Set([
  'UnrecognizedClientException', 'InvalidClientTokenId', 'InvalidSignatureException', 'SignatureDoesNotMatch',
  'ExpiredTokenException', 'ExpiredToken', 'IncompleteSignature', 'MissingAuthenticationToken', 'InvalidAccessKeyId',
]);
const DENIED = new Set(['AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation']);
const THROTTLED = new Set(['ThrottlingException', 'Throttling', 'TooManyRequestsException', 'RequestLimitExceeded', 'ThrottledException']);

export const REGION_RE = /^[a-z]{2}(-[a-z]+)+-\d{1,2}$/;

export function endpoint(region: string): string {
  return `https://ssm.${region}.amazonaws.com${region.startsWith('cn-') ? '.cn' : ''}/`;
}

function errorCode(r: Extract<HttpResult, { ok: true }>): string | null {
  try {
    const parsed = JSON.parse(r.body) as { __type?: unknown };
    const fromBody = safeCode(parsed.__type);
    if (fromBody) return fromBody;
  } catch {
    // not JSON; fall through to the header
  }
  return safeCode(r.headers.get('x-amzn-errortype'));
}

const isThrottled = (status: number, body: string): boolean => {
  if (status !== 400) return false;
  try {
    const code = safeCode((JSON.parse(body) as { __type?: unknown }).__type);
    return !!code && THROTTLED.has(code);
  } catch {
    return false;
  }
};

export class Ssm {
  constructor(
    private readonly http: Http,
    private readonly creds: AwsCredentials,
    private readonly now: () => Date,
  ) {}

  private async call(region: string, action: 'DescribeParameters' | 'GetParameters', payload: object): Promise<{ json: Record<string, unknown> } | SsmFailure> {
    const url = new URL(endpoint(region));
    const body = JSON.stringify(payload);
    const headers = signV4(
      {
        method: 'POST',
        url,
        headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': `AmazonSSM.${action}` },
        body,
        region,
        service: 'ssm',
        now: this.now(),
      },
      this.creds,
    );
    headers['user-agent'] = 'wirelint';
    const r = await this.http.request({ url: url.href, method: 'POST', headers, body }, isThrottled);
    if (!r.ok) return { failure: 'network', code: r.kind };
    if (r.status >= 200 && r.status < 300) {
      try {
        return { json: JSON.parse(r.body) as Record<string, unknown> };
      } catch {
        return { failure: 'other', code: 'UnreadableResponse' };
      }
    }
    const code = errorCode(r) ?? `HTTP${r.status}`;
    if (AUTH.has(code)) return { failure: 'auth', code };
    if (DENIED.has(code) || r.status === 403) return { failure: 'denied', code };
    if (THROTTLED.has(code) || r.status === 429) return { failure: 'throttled', code };
    return { failure: 'other', code };
  }

  /**
   * Which of `names` exist in `region`. DescribeParameters with a Name
   * filter (50 names per request), following NextToken: the API may return
   * a short or empty page with a token while more matches remain.
   */
  async existing(region: string, names: string[]): Promise<Set<string> | SsmFailure> {
    const found = new Set<string>();
    for (let i = 0; i < names.length; i += 50) {
      const batch = names.slice(i, i + 50);
      let token: string | undefined;
      for (let page = 0; ; page++) {
        if (page >= 100) return { failure: 'other', code: 'PaginationLimit' };
        const r = await this.call(region, 'DescribeParameters', {
          ParameterFilters: [{ Key: 'Name', Option: 'Equals', Values: batch }],
          MaxResults: 50,
          ...(token ? { NextToken: token } : {}),
        });
        if ('failure' in r) return r;
        for (const p of Array.isArray(r.json['Parameters']) ? r.json['Parameters'] : []) {
          const name = (p as { Name?: unknown }).Name;
          if (typeof name === 'string' && batch.includes(name)) found.add(name);
        }
        token = typeof r.json['NextToken'] === 'string' && r.json['NextToken'] ? (r.json['NextToken'] as string) : undefined;
        if (!token) break;
      }
    }
    return found;
  }

  /**
   * Digests of the values of `names` (GetParameters, 10 per request, with
   * decryption). The plaintext goes straight into `digest` and is dropped.
   */
  async digests(region: string, names: string[], digest: (value: string) => Buffer): Promise<{ digests: Map<string, Buffer>; missing: Set<string> } | SsmFailure> {
    const digests = new Map<string, Buffer>();
    const missing = new Set<string>();
    for (let i = 0; i < names.length; i += 10) {
      const batch = names.slice(i, i + 10);
      const r = await this.call(region, 'GetParameters', { Names: batch, WithDecryption: true });
      if ('failure' in r) return r;
      const params = Array.isArray(r.json['Parameters']) ? (r.json['Parameters'] as { Name?: unknown; Value?: unknown }[]) : [];
      for (const p of params) {
        if (typeof p.Name === 'string' && typeof p.Value === 'string' && batch.includes(p.Name)) digests.set(p.Name, digest(p.Value));
        p.Value = undefined;
      }
      for (const n of Array.isArray(r.json['InvalidParameters']) ? r.json['InvalidParameters'] : []) if (typeof n === 'string') missing.add(n);
    }
    return { digests, missing };
  }
}
