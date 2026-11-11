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
function hosts(answer: (url: URL, init: RequestInit) => Response | Promise<Response>): Net & { seen: Seen[] } {
  const seen: Seen[] = [];
  return {
    seen,
    fetch: async (input, init) => {
      seen.push({ url: String(input), init: init! });
      return answer(new URL(String(input)), init!);
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
    const u = probeUrl('https://user:pw@api.example.test/v1/?x=1#f', '/status?deep=1') as URL;
    expect(u.href).toBe('https://api.example.test/v1/status?deep=1');
    expect(probeUrl('${API_URL}', '/health')).toEqual({ reason: 'its production value is templated, a placeholder or a list' });
    expect(probeUrl('not a url', '/health')).toEqual({ reason: 'its production value is templated, a placeholder or a list' });
    expect(probeUrl('api.example.test', '/health')).toEqual({ reason: 'its production value is not an absolute URL' });
  });

  it('rejects bad probe options with exit 2', async () => {
    for (const [args, message] of [
      [['--probe-path', '/x'], '--probe-path only applies with --probe'],
      [['--probe-strict'], '--probe-strict only applies with --probe'],
      [['--probe', '--probe-path', 'health'], '--probe-path must be a path starting with "/"'],
      [['--probe', '--probe-path', '//evil.example.test/'], '--probe-path must be a path starting with "/"'],
      [['--probe', '--probe-timeout', '0'], '--probe-timeout needs a number of seconds'],
    ] as const) {
      const r = await cli([...args, fixture('live')]);
      expect(r.code, args.join(' ')).toBe(2);
      expect(r.err).toContain(message);
    }
  });
});
