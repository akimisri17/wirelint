/**
 * The one way out to the network. Nothing here runs unless a v2 flag
 * (--live, --probe) asked for it, and every caller passes the Net in, so tests
 * substitute a fake fetch and no real request is ever made by the suite.
 *
 * Bodies are returned to the adapter that asked and are never logged. Error
 * results carry a class and, at most, an identifier-shaped code; never a
 * message, a URL or a body, because those can quote hosts, account ids or values.
 */

export interface Net {
  fetch: typeof globalThis.fetch;
  /** Backoff between retries. Tests pass a no-op so nothing waits. */
  sleep?: (ms: number) => Promise<void>;
}

export const defaultNet = (): Net => ({ fetch: (...args) => globalThis.fetch(...args) });

export interface HttpOptions {
  /** Per-request timeout, including reading the body. */
  timeoutMs: number;
  /** Retries after the first attempt, only for throttling and transient 5xx. */
  retries: number;
  /** Requests in flight at once, shared by every caller of this client. */
  concurrency: number;
}

export type FailureKind = 'timeout' | 'dns' | 'refused' | 'tls' | 'unreachable';

export type HttpResult =
  | { ok: true; status: number; headers: Headers; body: string }
  | { ok: false; kind: FailureKind; code?: string };

export interface RequestSpec {
  url: string;
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  body?: string;
  /** Do not follow redirects; a 3xx comes back as the answer. */
  manualRedirect?: boolean;
  /** Read no body: probes only need the status. */
  discardBody?: boolean;
}

/** Throttling as an upstream reports it in a successful-looking or 4xx response. */
export type IsThrottled = (status: number, body: string) => boolean;

const TRANSIENT = new Set([429, 502, 503, 504]);
const TLS_CODE = /^(ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_|HOSTNAME_MISMATCH|ERR_OSSL)/;

/** Classify a thrown fetch error without keeping its message. */
export function classifyError(e: unknown): { kind: FailureKind; code?: string } {
  const codes: string[] = [];
  let cur: unknown = e;
  for (let depth = 0; cur && depth < 5; depth++) {
    const c = (cur as { code?: unknown; name?: unknown }).code;
    if (typeof c === 'string') codes.push(c);
    const n = (cur as { name?: unknown }).name;
    if (n === 'TimeoutError' || n === 'AbortError') return { kind: 'timeout' };
    // Node wraps several errors for one connection attempt (IPv4 and IPv6).
    const errors = (cur as { errors?: unknown }).errors;
    if (Array.isArray(errors)) for (const sub of errors) if (typeof (sub as { code?: unknown })?.code === 'string') codes.push((sub as { code: string }).code);
    cur = (cur as { cause?: unknown }).cause;
  }
  const code = codes.find((c) => /^[A-Z][A-Z0-9_]{1,40}$/.test(c));
  if (codes.some((c) => c === 'ENOTFOUND' || c === 'EAI_AGAIN' || c === 'EAI_NONAME' || c === 'EAI_FAIL')) return { kind: 'dns', code };
  if (codes.includes('ECONNREFUSED')) return { kind: 'refused', code };
  if (codes.some((c) => c === 'UND_ERR_CONNECT_TIMEOUT' || c === 'ETIMEDOUT' || c === 'UND_ERR_HEADERS_TIMEOUT' || c === 'UND_ERR_BODY_TIMEOUT')) return { kind: 'timeout', code };
  if (codes.some((c) => TLS_CODE.test(c))) return { kind: 'tls', code };
  return { kind: 'unreachable', code };
}

/** Seconds from a Retry-After header, capped; null when absent or a date. */
function retryAfterMs(headers: Headers): number | null {
  const raw = headers.get('retry-after');
  if (!raw || !/^\d+(\.\d+)?$/.test(raw.trim())) return null;
  return Math.min(Number(raw) * 1000, 10_000);
}

export class Http {
  /** Requests started, retries included. */
  requests = 0;
  private active = 0;
  private readonly queue: (() => void)[] = [];

  constructor(private readonly net: Net, readonly opts: HttpOptions) {}

  private async slot<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.opts.concurrency) await new Promise<void>((resolve) => this.queue.push(resolve));
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      this.queue.shift()?.();
    }
  }

  private sleep(ms: number): Promise<void> {
    return this.net.sleep ? this.net.sleep(ms) : new Promise((resolve) => setTimeout(resolve, ms));
  }

  /** One attempt, bounded by the timeout from the first byte sent to the last byte read. */
  private async once(spec: RequestSpec): Promise<HttpResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs);
    this.requests++;
    try {
      const res = await this.net.fetch(spec.url, {
        method: spec.method,
        headers: spec.headers,
        body: spec.body,
        redirect: spec.manualRedirect ? 'manual' : 'follow',
        credentials: 'omit',
        signal: controller.signal,
      });
      let body = '';
      if (spec.discardBody) await res.body?.cancel().catch(() => undefined);
      else body = await res.text();
      return { ok: true, status: res.status, headers: res.headers, body };
    } catch (e) {
      return { ok: false, ...(controller.signal.aborted ? { kind: 'timeout' as const } : classifyError(e)) };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * A request with bounded retries on throttling (429, transient 5xx, or what
   * `throttled` recognises in the body). Network failures are not retried:
   * a probe must report them, and an adapter reports them as not checked.
   */
  request(spec: RequestSpec, throttled?: IsThrottled): Promise<HttpResult> {
    return this.slot(async () => {
      for (let attempt = 0; ; attempt++) {
        const r = await this.once(spec);
        const retry = r.ok && (TRANSIENT.has(r.status) || (throttled?.(r.status, r.body) ?? false));
        if (!retry || attempt >= this.opts.retries) return r;
        const wait = (r.ok ? retryAfterMs(r.headers) : null) ?? Math.min(250 * 2 ** attempt, 4000) + Math.floor(Math.random() * 100);
        await this.sleep(wait);
      }
    });
  }
}

/** Run `fn` over `items` with at most `limit` in flight; results keep their order. */
export async function pool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/**
 * An identifier from an upstream error, or null. Only a short run of letters,
 * digits, dots and underscores survives, so a message, an ARN, an account id
 * or a value can never come through this path.
 */
export function safeCode(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  // `ns#Code` in AWS JSON bodies, `Code:http://...` in the x-amzn-ErrorType header.
  const tail = raw.split('#').pop()!.replace(/:https?:\/\/\S*$/, '').trim();
  return /^[A-Za-z][A-Za-z0-9_.]{0,63}$/.test(tail) && !/\d{6,}/.test(tail) ? tail : null;
}
