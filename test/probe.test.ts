import { describe, expect, it } from 'vitest';
import { renderGithub, renderHuman, renderMarkdown } from '../src/index.js';
import type { Net } from '../src/net.js';
import { probeUrl } from '../src/probe.js';
import { cli, json } from './fakecloud.js';
import { find, fixture, pkg, workspace } from './helpers.js';

interface Seen {
  url: string;
  init: RequestInit;
}

/** A fake network for probes: answers by host, records what was sent. */
function hosts(
  answer: (url: URL, init: RequestInit) => Response | Promise<Response>,
  resolve: (host: string) => string[] | Promise<string[]> = () => ['203.0.113.10'],
): Net & { seen: Seen[]; resolved: string[] } {
  const seen: Seen[] = [];
  const resolved: string[] = [];
  return {
    seen,
    resolved,
    fetch: async (input, init) => {
      seen.push({ url: String(input), init: init! });
      return answer(new URL(String(input)), init!);
    },
    lookup: async (host) => {
      resolved.push(host);
      return resolve(host);
    },
  };
}

const netError = (code: string) => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(`${code} orders.demo.example.test`), { code }) });

describe('--probe', () => {
  it('GETs base URL plus /health from production config, with no redirects, no credentials and only a User-Agent', async () => {
    const net = hosts(() => new Response('ok', { status: 200 }));
    const r = await cli(['--json', '--probe', fixture('live')], { net });
    expect(r.code).toBe(0);
    expect(net.seen.map((s) => s.url).sort()).toEqual(['https://identity.demo.example.test/health', 'https://orders.demo.example.test/v1/health']);
    for (const { init } of net.seen) {
      expect(init).toMatchObject({ method: 'GET', redirect: 'manual', credentials: 'omit', headers: { 'user-agent': 'wirelint' } });
      expect(Object.keys(init.headers as object)).toEqual(['user-agent']);
      expect(init.body).toBeUndefined();
    }
    const report = json(r);
    expect(report.probe).toEqual({
      path: '/health',
      timeoutMs: 5000,
      strict: false,
      allowPrivate: false,
      complete: true,
      results: [
        { from: 'orders', to: 'identity', variable: 'IDENTITY_URL', file: 'orders/copilot/orders/manifest.yml', env: 'prod', outcome: 'answered', status: 200 },
        { from: 'web', to: 'orders', variable: 'ORDERS_API_URL', file: 'web/.env.production', env: 'prod', outcome: 'answered', status: 200 },
      ],
    });
    expect(report.findings.filter((f) => f.check.startsWith('probe'))).toEqual([]);
    expect(renderHuman(report)).toContain('web -> orders  via ORDERS_API_URL  [web/.env.production, prod]  answered 200');
  });

  it('reports a redirect as an answer and does not follow it', async () => {
    const net = hosts(() => new Response(null, { status: 301, headers: { location: 'https://elsewhere.example.test/' } }));
    const report = json(await cli(['--json', '--probe', fixture('live')], { net }));
    expect(net.seen).toHaveLength(2);
    const f = find(report, 'probe-status', 'ORDERS_API_URL')[0]!;
    expect(f).toMatchObject({ severity: 'hint', service: 'web', file: 'web/.env.production', env: 'prod' });
    expect(f.problem).toBe('GET /health on the production ORDERS_API_URL (web/.env.production, prod) answered 301; redirects are not followed');
  });

  it('keeps unreachable links as suggestions unless --probe-strict', async () => {
    const net = hosts((url) => {
      if (url.host.startsWith('orders')) throw netError('ENOTFOUND');
      return new Response('', { status: 503 });
    });
    const soft = await cli(['--json', '--probe', fixture('live')], { net });
    expect(soft.code).toBe(0);
    expect(find(json(soft), 'probe-unreachable').map((f) => [f.severity, f.variable])).toEqual([['hint', 'ORDERS_API_URL']]);
    expect(find(json(soft), 'probe-unreachable')[0]!.problem).toContain('does not resolve from here; from outside its network this can be private DNS or a VPC');
    expect(find(json(soft), 'probe-status').map((f) => [f.severity, f.variable])).toEqual([['hint', 'IDENTITY_URL']]);

    const strict = await cli(['--json', '--probe', '--probe-strict', fixture('live')], { net });
    expect(strict.code).toBe(1);
    expect(json(strict).findings.filter((f) => f.severity === 'error').map((f) => `${f.check} ${f.variable}`).sort()).toEqual(['probe-status IDENTITY_URL', 'probe-unreachable ORDERS_API_URL']);
  });

  it('classifies refused, TLS and timeouts, and TLS and timeouts never fail', async () => {
    const answers: Record<string, () => Promise<Response>> = {
      identity: async () => {
        throw netError('CERT_HAS_EXPIRED');
      },
      orders: () => new Promise(() => undefined),
    };
    const net = hosts((url) => answers[url.host.split('.')[0]!]!());
    const r = await cli(['--json', '--probe', '--probe-strict', '--probe-timeout', '0.02', fixture('live')], { net });
    expect(r.code).toBe(0);
    expect(json(r).probe!.results.map((x) => x.outcome)).toEqual(['tls', 'timeout']);
    expect(find(json(r), 'probe-unreachable', 'ORDERS_API_URL')[0]!.problem).toContain('did not answer within 0.02s');
    const refused = hosts(async () => {
      throw netError('ECONNREFUSED');
    });
    expect(json(await cli(['--json', '--probe', fixture('live')], { net: refused })).probe!.results.map((x) => x.outcome)).toEqual(['refused', 'refused']);
  });

  it('never shows the address, in any output or error', async () => {
    const net = hosts((url) => {
      if (url.host.startsWith('orders')) throw netError('ENOTFOUND');
      return new Response(`internal host identity.demo.example.test is down`, { status: 500 });
    });
    const r = await cli(['--json', '--probe', fixture('live')], { net });
    const report = json(r);
    const outputs = [r.out, r.err, renderHuman(report), renderGithub(report, fixture('live')), renderMarkdown(report)].join('\n');
    expect(outputs).not.toContain('example.test');
    expect(outputs).not.toContain('https://');
  });

  it('probes only production config: never a local .env file, a secret reference or a non-http value', async () => {
    const ws = workspace({
      'a/package.json': pkg('a'),
      'a/.env.example': 'B_URL=http://localhost:4300\nC_URL=http://localhost:4400\n',
      'a/.env.local': 'B_URL=https://b.local-only.example.test\n',
      'a/.env.production': 'C_URL=ftp://c.example.test\n',
      'a/src/x.ts': 'export const b = process.env.B_URL; export const c = process.env.C_URL;\n',
      'b/package.json': pkg('b'),
      'b/.env.example': 'PORT=4300\n',
      'c/package.json': pkg('c'),
      'c/.env.example': 'PORT=4400\n',
    });
    const net = hosts(() => new Response('ok'));
    const report = json(await cli(['--json', '--probe', ws], { net }));
    expect(net.seen).toHaveLength(0);
    expect(report.probe!.results.map((x) => [x.variable, x.outcome, x.reason])).toEqual([
      ['B_URL', 'skipped', 'no production config of a sets B_URL'],
      ['C_URL', 'skipped', 'its production value is not http or https'],
    ]);
    expect(find(report, 'probe-not-checked').map((f) => f.severity)).toEqual(['info', 'info']);
  });

  it('drops credentials, query and fragment from the base and appends the path', () => {
    const u = probeUrl('https://user:pw@api.example.test/v1/?x=1#f', '/status') as URL;
    expect(u.href).toBe('https://api.example.test/v1/status');
    expect(probeUrl('${API_URL}', '/health')).toEqual({ reason: 'its production value is templated, a placeholder or a list' });
    expect(probeUrl('not a url', '/health')).toEqual({ reason: 'its production value is templated, a placeholder or a list' });
    expect(probeUrl('api.example.test', '/health')).toEqual({ reason: 'its production value is not an absolute URL' });
  });

  it('rejects bad probe options with exit 2', async () => {
    for (const [args, message] of [
      [['--probe-path', '/x'], '--probe-path only applies with --probe'],
      [['--probe-strict'], '--probe-strict only applies with --probe'],
      [['--probe', '--probe-path', 'health'], '--probe-path must be a plain path starting with "/"'],
      [['--probe', '--probe-path', '//evil.example.test/'], '--probe-path must be a plain path starting with "/"'],
      [['--probe', '--probe-path', 'https://evil.example.test/x'], '--probe-path must be a plain path starting with "/"'],
      [['--probe', '--probe-path', '/../admin'], '--probe-path must be a plain path starting with "/"'],
      [['--probe', '--probe-path', '/a/%2e%2e/b'], '--probe-path must be a plain path starting with "/"'],
      [['--probe', '--probe-path', '/health?full=1'], '--probe-path must be a plain path starting with "/"'],
      [['--probe', '--probe-path', '/health#x'], '--probe-path must be a plain path starting with "/"'],
      [['--probe-allow-private'], '--probe-allow-private only applies with --probe'],
      [['--probe', '--probe-timeout', '0'], '--probe-timeout needs a number of seconds'],
    ] as const) {
      const r = await cli([...args, fixture('live')]);
      expect(r.code, args.join(' ')).toBe(2);
      expect(r.err).toContain(message);
    }
  });

  /** A workspace whose web service points ORDERS_API_URL at `target` in production. */
  const aimed = (target: string) =>
    workspace({
      'web/package.json': pkg('web'),
      'web/.env.example': 'ORDERS_API_URL=http://localhost:4300\n',
      'web/.env.production': `ORDERS_API_URL=${target}\n`,
      'web/src/x.ts': 'export const o = process.env.ORDERS_API_URL;\n',
      'orders/package.json': pkg('orders'),
      'orders/.env.example': 'PORT=4300\n',
    });

  it('refuses private, loopback, link-local and metadata addresses, in every spelling, without printing them', async () => {
    for (const target of [
      'http://127.0.0.1:8080',
      'http://localhost:4300',
      'http://169.254.169.254',
      'http://[::1]/',
      'http://[::ffff:127.0.0.1]/',
      'http://[::ffff:a9fe:a9fe]/',
      'http://[fd00:ec2::254]/',
      'http://[fe80::1]/',
      'http://0.0.0.0/',
      'http://2130706433/',
      'http://0x7f000001/',
      'http://0177.0.0.1/',
      'http://10.0.0.5/',
      'http://192.168.1.1/',
      'http://172.16.0.1/',
      'http://100.64.0.1/',
    ]) {
      const net = hosts(() => new Response('ok'), (h) => (h === 'localhost' ? ['127.0.0.1', '::1'] : ['203.0.113.10']));
      const r = await cli(['--json', '--probe', aimed(target)], { net });
      // v0 may flag a loopback production value on its own; the probe adds nothing that fails.
      expect(json(r).findings.filter((f) => f.check.startsWith('probe') && f.severity === 'error'), target).toEqual([]);
      expect(net.seen, target).toHaveLength(0);
      const report = json(r);
      expect(report.probe!.results.map((x) => [x.outcome, x.reason]), target).toEqual([['skipped', 'private address (pass --probe-allow-private to probe it)']]);
      const [f] = find(report, 'probe-not-checked');
      expect(f!.problem).toBe('link web -> orders via ORDERS_API_URL was not probed: private address (pass --probe-allow-private to probe it)');
      const all = [r.out, r.err, renderHuman(report), renderMarkdown(report), renderGithub(report, '.')].join('\n');
      for (const leak of ['127.0.0.1', '169.254', '::1', 'fd00', '2130706433', '0x7f', '10.0.0.5', 'localhost:4300/']) expect(all, target).not.toContain(leak);
    }
  });

  it('refuses a public-looking name that resolves to any private address, and checks every answer', async () => {
    const net = hosts(() => new Response('ok'), () => ['203.0.113.10', '10.1.2.3']);
    const report = json(await cli(['--json', '--probe', aimed('https://api.example.test')], { net }));
    expect(net.resolved).toEqual(['api.example.test']);
    expect(net.seen).toHaveLength(0);
    expect(report.probe!.results[0]).toMatchObject({ outcome: 'skipped', reason: 'private address (pass --probe-allow-private to probe it)' });
    expect(JSON.stringify(report)).not.toContain('10.1.2.3');
  });

  it('probes a name that resolves only to public addresses', async () => {
    const net = hosts(() => new Response('ok'), () => ['203.0.113.10', '2001:db8::10']);
    const report = json(await cli(['--json', '--probe', aimed('https://api.example.test')], { net }));
    expect(net.seen.map((s) => s.url)).toEqual(['https://api.example.test/health']);
    expect(report.probe!.results[0]).toMatchObject({ outcome: 'answered', status: 200 });
  });

  it('treats a failed or empty lookup as DNS, and a missing resolver as not checked', async () => {
    const failing = hosts(() => new Response('ok'), () => {
      throw Object.assign(new Error('getaddrinfo ENOTFOUND api.example.test'), { code: 'ENOTFOUND' });
    });
    expect(json(await cli(['--json', '--probe', aimed('https://api.example.test')], { net: failing })).probe!.results[0]!.outcome).toBe('dns');
    const empty = hosts(() => new Response('ok'), () => []);
    expect(json(await cli(['--json', '--probe', aimed('https://api.example.test')], { net: empty })).probe!.results[0]!.outcome).toBe('dns');
    const seen: string[] = [];
    const noResolver: Net = { fetch: async (u) => (seen.push(String(u)), new Response('ok')) };
    const report = json(await cli(['--json', '--probe', aimed('https://api.example.test')], { net: noResolver }));
    expect(seen).toEqual([]);
    expect(report.probe!.results[0]).toMatchObject({ outcome: 'skipped', reason: 'no resolver is available to check the address' });
    const hanging = hosts(() => new Response('ok'), () => new Promise<string[]>(() => undefined));
    const timed = json(await cli(['--json', '--probe', '--probe-timeout', '0.02', aimed('https://api.example.test')], { net: hanging }));
    expect(timed.probe!.results[0]!.outcome).toBe('timeout');
    expect(hanging.seen).toHaveLength(0);
  });

  it('probes a private address only with --probe-allow-private, and never resolves first', async () => {
    const net = hosts(() => new Response('ok'));
    const report = json(await cli(['--json', '--probe', '--probe-allow-private', aimed('http://127.0.0.1:8080')], { net }));
    expect(net.resolved).toEqual([]);
    expect(net.seen.map((s) => s.url)).toEqual(['http://127.0.0.1:8080/health']);
    expect(report.probe).toMatchObject({ allowPrivate: true, results: [{ outcome: 'answered', status: 200 }] });
  });
});
