import { describe, expect, it } from 'vitest';
import { Http, classifyError, pool, safeCode, type Net } from '../src/net.js';
import { amzDate, canonicalRequest, signV4, signingKey } from '../src/sigv4.js';

/** The example credentials AWS publishes for its SigV4 documentation and test suite. */
const EXAMPLE = { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' };
const AT = new Date('2015-08-30T12:36:00Z');

describe('SigV4', () => {
  it('derives the signing key from the documented example', () => {
    expect(signingKey(EXAMPLE.secretAccessKey, '20120215', 'us-east-1', 'iam').toString('hex')).toBe('f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d');
  });

  it('matches the get-vanilla vector from the AWS SigV4 test suite', () => {
    const h = signV4({ method: 'GET', url: new URL('https://example.amazonaws.com/'), headers: {}, body: '', region: 'us-east-1', service: 'service', now: AT }, EXAMPLE);
    expect(h['authorization']).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31',
    );
    expect(h['x-amz-date']).toBe('20150830T123600Z');
  });

  it('matches the IAM ListUsers example from the SigV4 documentation', () => {
    const h = signV4(
      {
        method: 'GET',
        url: new URL('https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08'),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
        body: '',
        region: 'us-east-1',
        service: 'iam',
        now: AT,
      },
      EXAMPLE,
    );
    expect(h['authorization']).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7',
    );
  });

  it('builds a canonical request with sorted query, trimmed headers and a payload hash', () => {
    const { text, signed } = canonicalRequest('POST', new URL('https://ssm.eu-west-1.amazonaws.com/?b=2&a=%20x&a=1'), { 'X-Amz-Target': '  AmazonSSM.DescribeParameters ', Host: 'ssm.eu-west-1.amazonaws.com' }, '{}');
    expect(signed).toBe('host;x-amz-target');
    expect(text.split('\n')).toEqual([
      'POST',
      '/',
      'a=%20x&a=1&b=2',
      'host:ssm.eu-west-1.amazonaws.com',
      'x-amz-target:AmazonSSM.DescribeParameters',
      '',
      'host;x-amz-target',
      '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    ]);
  });

  it('signs the session token and the JSON target header', () => {
    const h = signV4(
      { method: 'POST', url: new URL('https://ssm.eu-west-1.amazonaws.com/'), headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'AmazonSSM.DescribeParameters' }, body: '{}', region: 'eu-west-1', service: 'ssm', now: AT },
      { ...EXAMPLE, sessionToken: 'session-token-example' },
    );
    expect(h['x-amz-security-token']).toBe('session-token-example');
    expect(h['authorization']).toMatch(
      /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20150830\/eu-west-1\/ssm\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=[0-9a-f]{64}$/,
    );
    expect(amzDate(AT)).toBe('20150830T123600Z');
  });
});

const res = (status: number, body = '', headers: Record<string, string> = {}) => new Response(status === 204 || status === 304 ? null : body, { status, headers });

describe('Http', () => {
  const opts = { timeoutMs: 1000, retries: 3, concurrency: 2 };

  it('retries throttling a bounded number of times', async () => {
    let calls = 0;
    const waits: number[] = [];
    const net: Net = { fetch: async () => (calls++, res(429)), sleep: async (ms) => void waits.push(ms) };
    const r = await new Http(net, opts).request({ url: 'https://api.example.test/', method: 'GET', headers: {} });
    expect(r).toMatchObject({ ok: true, status: 429 });
    expect(calls).toBe(4);
    expect(waits).toHaveLength(3);
  });

  it('honours Retry-After and recognises throttling in the body', async () => {
    const answers = [res(400, '{"__type":"ThrottlingException"}', { 'retry-after': '2' }), res(200, 'ok')];
    const waits: number[] = [];
    const net: Net = { fetch: async () => answers.shift()!, sleep: async (ms) => void waits.push(ms) };
    const r = await new Http(net, opts).request({ url: 'https://api.example.test/', method: 'GET', headers: {} }, (s, b) => s === 400 && b.includes('Throttling'));
    expect(r).toMatchObject({ ok: true, status: 200, body: 'ok' });
    expect(waits).toEqual([2000]);
  });

  it('times out a request that never answers', async () => {
    const net: Net = {
      fetch: (_url, init) => new Promise((_resolve, reject) => init!.signal!.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })))),
    };
    const r = await new Http(net, { ...opts, timeoutMs: 5 }).request({ url: 'https://api.example.test/', method: 'GET', headers: {} });
    expect(r).toEqual({ ok: false, kind: 'timeout' });
  });

  it('caps the requests in flight', async () => {
    let active = 0;
    let peak = 0;
    const net: Net = {
      fetch: async () => {
        peak = Math.max(peak, ++active);
        await new Promise((r) => setTimeout(r, 2));
        active--;
        return res(200);
      },
    };
    const http = new Http(net, opts);
    await Promise.all(Array.from({ length: 8 }, () => http.request({ url: 'https://api.example.test/', method: 'GET', headers: {} })));
    expect(peak).toBe(2);
    expect(http.requests).toBe(8);
  });

  it('classifies network failures without keeping their messages', () => {
    const wrap = (code: string) => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(`getaddrinfo ${code} secret-host.internal.example.test`), { code }) });
    expect(classifyError(wrap('ENOTFOUND'))).toEqual({ kind: 'dns', code: 'ENOTFOUND' });
    expect(classifyError(wrap('ECONNREFUSED'))).toEqual({ kind: 'refused', code: 'ECONNREFUSED' });
    expect(classifyError(wrap('CERT_HAS_EXPIRED'))).toEqual({ kind: 'tls', code: 'CERT_HAS_EXPIRED' });
    expect(classifyError(wrap('UND_ERR_CONNECT_TIMEOUT'))).toEqual({ kind: 'timeout', code: 'UND_ERR_CONNECT_TIMEOUT' });
    expect(classifyError(new Error('boom'))).toEqual({ kind: 'unreachable' });
    expect(JSON.stringify(classifyError(wrap('ENOTFOUND')))).not.toContain('secret-host');
  });

  it('lets only identifier-shaped codes through', () => {
    expect(safeCode('com.amazon.coral.service#AccessDeniedException')).toBe('AccessDeniedException');
    expect(safeCode('User: arn:aws:iam::123456789012:user/x is not authorized')).toBeNull();
    expect(safeCode('forbidden')).toBe('forbidden');
    expect(safeCode('token sk_live_abc')).toBeNull();
    expect(safeCode(42)).toBeNull();
    expect(safeCode('not_found')).toBe('not_found');
    expect(safeCode('aB3xYz9QweRtyUi0pAsDfGhJ')).toBeNull();
    expect(safeCode('AKIAABCDEFGHIJKLMNOP')).toBeNull();
  });

  it('pools work with a cap and keeps order', async () => {
    expect(await pool([3, 1, 2], 2, async (n) => n * 2)).toEqual([6, 2, 4]);
  });
});
