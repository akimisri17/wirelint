import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { Digester } from '../src/compare.js';
import { renderGithub, renderHuman, renderMarkdown } from '../src/index.js';
import { AWS, cli, demoParams, fakeCloud, json, type VercelEnvVar } from './fakecloud.js';
import { find, fixture } from './helpers.js';

const BOTH = { ...AWS, VERCEL_TOKEN: 'vercel-token-UNIQUE-7f3a' };

function cloud(opts: { jwtProd?: string; sessionProd?: string; webSession?: Partial<VercelEnvVar> } = {}) {
  const params = demoParams();
  const p = params['eu-west-1']!;
  p['/copilot/demo/prod/secrets/IDENTITY_JWT_SECRET'] = 'shared-jwt-value';
  p['/copilot/demo/prod/secrets/JWT_SECRET'] = opts.jwtProd ?? 'shared-jwt-value';
  p['/copilot/demo/prod/secrets/SESSION_SECRET'] = opts.sessionProd ?? 'shared-session-value';
  return fakeCloud({
    params,
    projects: { prj_demoweb0000: [{ id: 'env_9', key: 'SESSION_SECRET', target: ['production'], type: 'encrypted', value: 'shared-session-value', ...opts.webSession }] },
  });
}

describe('--compare', () => {
  it('needs --live', async () => {
    const r = await cli(['--compare', fixture('live')]);
    expect(r.code).toBe(2);
    expect(r.err).toContain('--compare needs --live');
  });

  it('reports equal values without a finding and marks the relation compared', async () => {
    const net = cloud();
    const report = json(await cli(['--json', '--live', 'ssm', '--compare', '--env', 'prod', fixture('live')], { env: AWS, net }));
    expect(report.live!.comparisons).toEqual([
      { kind: 'declared', service: 'orders', variable: 'JWT_SECRET', target: { service: 'identity', variable: 'JWT_SECRET' }, env: 'prod', result: 'equal' },
      {
        kind: 'inferred', service: 'identity', variable: 'SESSION_SECRET', target: { service: 'web', variable: 'SESSION_SECRET' }, env: '-', result: 'not-checked',
        reason: 'web.SESSION_SECRET has no value in the live stores this run read (ssm)',
      },
    ]);
    expect(report.relations[0]!.compared).toBe('value');
    expect(find(report, 'live-mismatch')).toEqual([]);
    // Values are read with GetParameters only for the sides being compared, and never for a missing one.
    const get = net.calls.filter((c) => c.target === 'AmazonSSM.GetParameters');
    expect(get).toHaveLength(1);
    expect(get[0]!.body).toEqual({ Names: ['/copilot/demo/prod/secrets/JWT_SECRET', '/copilot/demo/prod/secrets/IDENTITY_JWT_SECRET'], WithDecryption: true });
  });

  it('fails a declared same-as whose deployed values differ, without showing either', async () => {
    const net = cloud({ jwtProd: 'drifted-jwt-value' });
    const r = await cli(['--json', '--live', 'ssm', '--compare', '--env', 'prod', fixture('live')], { env: AWS, net });
    expect(r.code).toBe(1);
    const report = json(r);
    const [f] = find(report, 'live-mismatch');
    expect(f).toMatchObject({ severity: 'error', service: 'orders', variable: 'JWT_SECRET', file: 'orders/.env.example', line: 2, env: 'prod' });
    expect(f!.problem).toBe(
      'declared same-as identity.JWT_SECRET, but the deployed values differ for prod (orders: the SSM parameter secrets.JWT_SECRET in orders/copilot/orders/manifest.yml names; identity: the SSM parameter secrets.JWT_SECRET in identity/copilot/identity/manifest.yml names)',
    );
    expect(f!.fix).toBe("set orders's value to identity's for prod, or point both at one parameter; wirelint compared keyed digests and shows neither value");
    const outputs = [r.out, renderHuman(report), renderGithub(report, fixture('live')), renderMarkdown(report)].join('\n');
    for (const v of ['drifted-jwt-value', 'shared-jwt-value']) expect(outputs).not.toContain(v);
    expect(outputs).not.toMatch(/[0-9a-f]{64}/);
  });

  it('compares across SSM and Vercel on production, and suggests when an inferred pair differs', async () => {
    const net = cloud({ sessionProd: 'session-in-ssm' });
    const r = await cli(['--json', '--live', 'ssm,vercel', '--compare', '--env', 'prod', fixture('live')], { env: BOTH, net });
    const report = json(r);
    expect(report.live!.comparisons.find((c) => c.kind === 'inferred')).toMatchObject({ env: 'prod', result: 'different' });
    const [hint] = find(report, 'live-mismatch', 'SESSION_SECRET');
    expect(hint).toMatchObject({ severity: 'hint', service: 'identity + web', env: 'prod' });
    expect(hint!.fix).toContain('add "# wirelint: same-as web" to SESSION_SECRET in identity\'s .env.example');
    expect(net.calls.filter((c) => c.url.host === 'api.vercel.com').map((c) => `${c.method} ${c.url.pathname}`)).toEqual(['GET /v9/projects/prj_demoweb0000/env', 'GET /v1/projects/prj_demoweb0000/env/env_9']);
  });

  it('reports a sensitive Vercel variable as existence only, without asking for it', async () => {
    const net = cloud({ webSession: { type: 'sensitive' } });
    const report = json(await cli(['--json', '--live', 'ssm,vercel', '--compare', '--env', 'prod', fixture('live')], { env: BOTH, net }));
    expect(report.live!.comparisons.find((c) => c.kind === 'inferred')).toMatchObject({
      result: 'unreadable',
      reason: 'web: the Vercel production variable SESSION_SECRET (sensitive) cannot be read back, so only its existence was checked',
    });
    expect(find(report, 'live-not-checked', 'SESSION_SECRET')[0]).toMatchObject({ severity: 'info' });
    expect(net.calls.some((c) => c.url.pathname.startsWith('/v1/'))).toBe(false);
  });

  it('says so and exits 2 when values may not be read', async () => {
    const net = cloud();
    net.intercept = (c) => (c.target === 'AmazonSSM.GetParameters' ? new Response(JSON.stringify({ __type: 'AccessDeniedException', message: 'kms denied for key arn:aws:kms:eu-west-1:000000000000:key/x' }), { status: 400 }) : undefined);
    const r = await cli(['--live', 'ssm', '--compare', '--env', 'prod', fixture('live')], { env: AWS, net });
    expect(r.code).toBe(2);
    expect(r.out).toContain('the credentials are not allowed to call ssm:GetParameters (AccessDeniedException)');
    expect(r.out).toContain('grant ssm:GetParameters on the parameters and kms:Decrypt on their key, or run without --compare');
    expect(r.out).not.toContain('000000000000');
  });

  it('keeps the key out of JSON and inspection, and compares digests by value', () => {
    const d = new Digester();
    expect(JSON.stringify({ d })).toBe('{"d":"[Digester]"}');
    expect(inspect(d)).toBe('[Digester]');
    expect(Digester.same(d.digest('a'), d.digest('a'))).toBe(true);
    expect(Digester.same(d.digest('a'), d.digest('b'))).toBe(false);
    // A different run has a different key, so digests are not comparable across runs.
    expect(Digester.same(d.digest('a'), new Digester().digest('a'))).toBe(false);
  });
});
