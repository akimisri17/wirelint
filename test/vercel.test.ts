import { describe, expect, it } from 'vitest';
import { cli, fakeCloud, json, LEAK, type VercelEnvVar } from './fakecloud.js';
import { find, fixture, pkg, workspace } from './helpers.js';

export function webVars(): VercelEnvVar[] {
  return [
    { id: 'env_1', key: 'ORDERS_API_URL', target: ['production', 'preview'], type: 'plain', value: LEAK('plain-url') },
    { id: 'env_2', key: 'SESSION_SECRET', target: 'production', type: 'sensitive', value: LEAK('session-sensitive') },
    { id: 'env_3', key: 'NEXT_PUBLIC_SITE_NAME', target: ['preview'], type: 'encrypted', value: LEAK('site-branch'), gitBranch: 'feature-x' },
  ];
}

const project = (vars = webVars()) => fakeCloud({ projects: { prj_demoweb0000: vars } });

describe('--live vercel', () => {
  it('reports required variables the project does not set for production, and gaps elsewhere as suggestions', async () => {
    const net = project();
    const r = await cli(['--json', '--live', 'vercel', fixture('live')], { env: { VERCEL_TOKEN: net.vercelToken }, net });
    expect(r.code).toBe(1);
    const report = json(r);
    expect(find(report, 'live-missing').map((f) => [f.severity, f.variable, f.env])).toEqual([
      ['error', 'NEXT_PUBLIC_SITE_NAME', 'production'],
      ['hint', 'NEXT_PUBLIC_SITE_NAME', 'preview,development'],
      ['hint', 'ORDERS_API_URL', 'development'],
      ['hint', 'SESSION_SECRET', 'preview,development'],
    ]);
    const prod = find(report, 'live-missing', 'NEXT_PUBLIC_SITE_NAME')[0]!;
    expect(prod).toMatchObject({ service: 'web', file: 'web/.vercel/project.json' });
    expect(prod.problem).toBe('read in web/src/api.ts:3 (no default) but the Vercel project does not set it for production');
    expect(prod.fix).toBe('in web, run "vercel env add NEXT_PUBLIC_SITE_NAME production" (or add it under Settings > Environment Variables)');
    expect(report.live!.adapters).toEqual([{ adapter: 'vercel', complete: true, requests: 1, checked: 9 }]);
  });

  it('lists keys and targets with GET only, without asking for decryption', async () => {
    const net = project();
    await cli(['--live', 'vercel', fixture('live')], { env: { VERCEL_TOKEN: net.vercelToken }, net });
    expect(net.calls.map((c) => `${c.method} ${c.url.pathname}${c.url.search}`)).toEqual(['GET /v10/projects/prj_demoweb0000/env?teamId=team_demo0000']);
    expect(net.calls[0]!.headers['authorization']).toBe(`Bearer ${net.vercelToken}`);
  });

  it('follows pagination', async () => {
    const net = fakeCloud({ projects: { prj_demoweb0000: webVars() }, vercelPageSize: 1 });
    const report = json(await cli(['--json', '--live', 'vercel', fixture('live')], { env: { VERCEL_TOKEN: net.vercelToken }, net }));
    expect(net.calls.map((c) => c.url.searchParams.get('until'))).toEqual([null, '1', '2']);
    expect(find(report, 'live-missing', 'ORDERS_API_URL').map((f) => f.env)).toEqual(['development']);
  });

  it('retries a rate limit', async () => {
    const net = project();
    let once = true;
    net.intercept = () => (once ? ((once = false), new Response('{}', { status: 429, headers: { 'retry-after': '1' } })) : undefined);
    const report = json(await cli(['--json', '--live', 'vercel', fixture('live')], { env: { VERCEL_TOKEN: net.vercelToken }, net }));
    expect(report.live!.adapters[0]).toMatchObject({ complete: true, requests: 2 });
  });

  it.each([
    [401, { error: { code: 'forbidden', message: `Not authorized ${LEAK('body')}`, invalidToken: true } }, 'Vercel rejected the token (forbidden)', 'set VERCEL_TOKEN to a valid token'],
    [403, { error: { code: 'forbidden', message: `You do not have access to ${LEAK('team')}` } }, 'the token is not allowed to read the project linked in web/.vercel/project.json (forbidden)', '--vercel-team or VERCEL_TEAM_ID'],
    [404, { error: { code: 'not_found', message: `Project ${LEAK('project')} not found` } }, 'the project linked in web/.vercel/project.json was not found for this token and team (not_found)', 'check projectId in .vercel/project.json'],
  ])('says it could not check on HTTP %i, and exits 2', async (status, body, problem, fix) => {
    const net = project();
    net.intercept = () => new Response(JSON.stringify(body), { status });
    const r = await cli(['--live', 'vercel', fixture('live')], { env: { VERCEL_TOKEN: net.vercelToken }, net });
    expect(r.code).toBe(2);
    expect(r.out).toContain('LIVE CHECK INCOMPLETE: vercel');
    expect(r.out).toContain(problem);
    expect(r.out).toContain(fix);
    expect(r.out + r.err).not.toContain('LEAK-');
  });

  it('uses --vercel-project and --vercel-team, and reports an unknown project as not checked', async () => {
    const net = project();
    const r = await cli(['--json', '--live', 'vercel', '--vercel-project', 'web=prj_other', '--vercel-team', 'team_flag', fixture('live')], { env: { VERCEL_TOKEN: net.vercelToken, VERCEL_TEAM_ID: 'team_env' }, net });
    expect(r.code).toBe(2);
    expect(net.calls[0]!.url.pathname + net.calls[0]!.url.search).toBe('/v10/projects/prj_other/env?teamId=team_flag');
    expect(json(r).live!.adapters[0]!.problem).toBe('the project linked in --vercel-project was not found for this token and team (not_found)');
  });

  it('notes a Vercel service with no linked project, and a run with nothing checkable is incomplete', async () => {
    const ws = workspace({ 'site/package.json': pkg('site'), 'site/vercel.json': '{}', 'site/.env.example': 'API_URL=http://localhost:4000\n', 'site/src/a.ts': 'export const a = process.env.API_URL!;\n' });
    const net = fakeCloud();
    const r = await cli(['--json', '--live', 'vercel', ws], { env: { VERCEL_TOKEN: net.vercelToken }, net });
    expect(r.code).toBe(2);
    expect(json(r).live!.adapters[0]).toMatchObject({ complete: false, problem: 'no Vercel project is linked for any Vercel service, so there was nothing to check' });
    const note = find(json(r), 'live-not-checked')[0]!;
    expect(note).toMatchObject({ severity: 'info', service: 'site', file: 'site/vercel.json' });
    expect(note.fix).toBe('run "vercel link" in site to write .vercel/project.json, or pass --vercel-project site=<projectId>');
    expect(net.calls).toHaveLength(0);
  });

  it('needs VERCEL_TOKEN, and known service names in --vercel-project', async () => {
    const net = project();
    const noToken = await cli(['--live', 'vercel', fixture('live')], { env: {}, net });
    expect(noToken.code).toBe(2);
    expect(noToken.out).toContain('VERCEL_TOKEN is not set');
    const unknown = await cli(['--live', 'vercel', '--vercel-project', 'nope=prj_x', fixture('live')], { env: { VERCEL_TOKEN: net.vercelToken }, net });
    expect(unknown.code).toBe(2);
    expect(unknown.out).toContain('--vercel-project names "nope", which is not a discovered service');
    expect(net.calls).toHaveLength(0);
    const bad = await cli(['--live', 'vercel', '--vercel-project', 'web', fixture('live')], { env: {}, net });
    expect(bad.code).toBe(2);
    expect(bad.err).toContain('--vercel-project needs <service>=<projectId>');
    expect((await cli(['--vercel-team', 'team_x', fixture('live')])).err).toContain('--vercel-team only applies with --live vercel');
  });

  it('runs both adapters in one run', async () => {
    const net = fakeCloud({ projects: { prj_demoweb0000: webVars() } });
    const r = await cli(['--json', '--live', 'ssm,vercel', fixture('live')], { env: { VERCEL_TOKEN: net.vercelToken, AWS_ACCESS_KEY_ID: 'AKIDEXAMPLE', AWS_SECRET_ACCESS_KEY: 'x', AWS_REGION: 'eu-west-1' }, net });
    expect(json(r).live!.adapters.map((a) => a.adapter)).toEqual(['ssm', 'vercel']);
  });
});
