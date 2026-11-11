import { describe, expect, it } from 'vitest';
import { renderGithub, renderHuman, renderMarkdown } from '../src/index.js';
import { AWS, cli, demoParams, fakeCloud, json, LEAK, type FakeCloud, type VercelEnvVar } from './fakecloud.js';
import { find, fixture, pkg, workspace } from './helpers.js';

/** Regression tests for the v2 security review, one block per finding. */

const TOKEN = 'vercel-token-UNIQUE-7f3a';
const BOTH = { ...AWS, VERCEL_TOKEN: TOKEN };
const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** api on Copilot with no environments block, web on Vercel, api.JWT_SECRET declared same-as web. */
function wildcardWorkspace(): string {
  return workspace({
    'api/package.json': pkg('api'),
    'api/.env.example': 'JWT_SECRET=dev-secret  # wirelint: same-as web\n',
    'api/src/x.ts': 'export const j = process.env.JWT_SECRET;\n',
    'api/copilot/.workspace': 'application: demo\n',
    'api/copilot/api/manifest.yml': 'name: api\ntype: Backend Service\n\nsecrets:\n  JWT_SECRET: /demo/JWT_SECRET\n',
    'web/package.json': pkg('web'),
    'web/.env.example': 'JWT_SECRET=dev-secret\n',
    'web/src/x.ts': 'export const j = process.env.JWT_SECRET;\n',
    'web/vercel.json': '{}\n',
    'web/.vercel/project.json': '{"projectId":"prj_w","orgId":"team_w"}\n',
  });
}

function wildcardCloud(targets: string[]): FakeCloud {
  return fakeCloud({
    params: { 'eu-west-1': { '/demo/JWT_SECRET': 'one-value' } },
    projects: { prj_w: [{ id: 'env_j', key: 'JWT_SECRET', target: targets, type: 'encrypted', value: 'another-value' }] },
  });
}

describe('1. a manifest with no environments block is production only', () => {
  it('does not compare it with a preview or development value', async () => {
    const net = wildcardCloud(['preview', 'development']);
    const r = await cli(['--json', '--live', 'ssm,vercel', '--compare', wildcardWorkspace()], { env: BOTH, net });
    const report = json(r);
    expect(report.live!.comparisons).toEqual([
      { kind: 'declared', service: 'api', variable: 'JWT_SECRET', target: { service: 'web', variable: 'JWT_SECRET' }, env: '-', result: 'not-checked', reason: 'the two sides share no environment' },
    ]);
    expect(find(report, 'live-mismatch')).toEqual([]);
    expect(net.calls.some((c) => c.target === 'AmazonSSM.GetParameters' || c.url.pathname.startsWith('/v1/'))).toBe(false);
  });

  it('compares it with the production value only', async () => {
    const net = wildcardCloud(['production']);
    const report = json(await cli(['--json', '--live', 'ssm,vercel', '--compare', wildcardWorkspace()], { env: BOTH, net }));
    expect(report.live!.comparisons.map((c) => [c.env, c.result])).toEqual([['production', 'different']]);
    expect(find(report, 'live-mismatch')[0]).toMatchObject({ severity: 'error', service: 'api', env: 'production' });
  });
});

describe('2. a requested adapter with nothing to check is incomplete', () => {
  const copilot = (secrets: string) =>
    workspace({
      'api/package.json': pkg('api'),
      'api/.env.example': 'TOKEN=\n',
      'api/src/x.ts': 'export const t = process.env.TOKEN;\n',
      'api/copilot/.workspace': 'application: demo\n',
      'api/copilot/api/manifest.yml': `name: api\ntype: Backend Service\n${secrets}`,
    });

  it('exits 2 when no manifest references an SSM parameter', async () => {
    const net = fakeCloud();
    const r = await cli(['--json', '--live', 'ssm', copilot('variables:\n  TOKEN: set-in-manifest\n')], { env: AWS, net });
    expect(r.code).toBe(2);
    expect(json(r).live!.adapters[0]).toMatchObject({ adapter: 'ssm', complete: false, checked: 0, problem: 'no Copilot manifest references an SSM parameter, so there was nothing to check' });
    expect(net.calls).toHaveLength(0);
  });

  it('exits 2 when every SSM reference was skipped, and says so in the human output', async () => {
    const ws = copilot('secrets:\n  TOKEN: /demo/${UNKNOWN_VAR}/TOKEN\n');
    const r = await cli(['--live', 'ssm', ws], { env: AWS, net: fakeCloud() });
    expect(r.code).toBe(2);
    expect(r.out).toContain('none of the 1 SSM reference in the Copilot manifests could be checked (see NOT ANALYSED)');
  });
});

describe('3. --compare that compares nothing is not a pass', () => {
  it('exits 2 and names the declared relation it could not compare', async () => {
    const all = ['production', 'preview', 'development'];
    const net = fakeCloud({
      projects: {
        prj_demoweb0000: ['ORDERS_API_URL', 'SESSION_SECRET', 'NEXT_PUBLIC_SITE_NAME'].map((key, i): VercelEnvVar => ({ id: `env_${i}`, key, target: all, type: 'sensitive', value: 'v' })),
      },
    });
    const r = await cli(['--json', '--live', 'vercel', '--compare', fixture('live')], { env: { VERCEL_TOKEN: TOKEN }, net });
    expect(r.code).toBe(2);
    const status = json(r).live!.adapters.find((s) => s.adapter === 'compare')!;
    expect(status).toMatchObject({ complete: false, checked: 0 });
    expect(status.problem).toBe('a declared relation was not compared in any environment: orders.JWT_SECRET same-as identity.JWT_SECRET (orders.JWT_SECRET has no value in the live stores this run read (vercel))');
    expect(status.fix).toContain('or remove the same-as annotation');
  });

  it('marks the run incomplete when a requested value comes back in neither list', async () => {
    const net = fakeCloud({ params: demoParams() });
    net.intercept = (c) => (c.target === 'AmazonSSM.GetParameters' ? reply(200, { Parameters: [], InvalidParameters: [] }) : undefined);
    const r = await cli(['--json', '--live', 'ssm', '--compare', '--env', 'prod', fixture('live')], { env: AWS, net });
    expect(r.code).toBe(2);
    const report = json(r);
    expect(report.live!.complete).toBe(false);
    expect(report.live!.adapters.find((s) => s.adapter === 'ssm')).toMatchObject({ complete: false, problem: 'AWS SSM GetParameters returned neither a value nor InvalidParameters for a requested parameter' });
    expect(report.live!.adapters.find((s) => s.adapter === 'compare')).toMatchObject({ complete: false });
  });
});

describe('4. malformed upstream answers', () => {
  const malformed: [string, (c: Parameters<NonNullable<FakeCloud['intercept']>>[0]) => Response | undefined][] = [
    ['a string where a parameter object belongs', (c) => (c.target === 'AmazonSSM.DescribeParameters' ? reply(200, { Parameters: [LEAK('param-string')] }) : undefined)],
    ['a non-string NextToken', (c) => (c.target === 'AmazonSSM.DescribeParameters' ? reply(200, { Parameters: [], NextToken: { t: LEAK('token') } }) : undefined)],
    ['a JSON array body', (c) => (c.target === 'AmazonSSM.DescribeParameters' ? reply(200, [LEAK('array')]) : undefined)],
  ];
  for (const [what, intercept] of malformed) {
    it(`reports ${what} from SSM as incomplete, quoting nothing`, async () => {
      const net = fakeCloud({ params: demoParams() });
      net.intercept = intercept;
      const r = await cli(['--json', '--live', 'ssm', fixture('live')], { env: AWS, net });
      expect(r.code).toBe(2);
      expect(json(r).live!.adapters[0]).toMatchObject({ complete: false, problem: 'AWS SSM answered with an error (MalformedResponse)' });
      expect(r.out + r.err).not.toContain('LEAK-');
    });
  }

  it('rejects a GetParameters value that is not a string, and a Vercel list element that is not an object', async () => {
    const net = fakeCloud({ params: demoParams(), projects: { prj_demoweb0000: [] } });
    net.intercept = (c) => {
      if (c.target === 'AmazonSSM.GetParameters') return reply(200, { Parameters: [{ Name: '/copilot/demo/prod/secrets/JWT_SECRET', Value: { s: LEAK('value-object') } }], InvalidParameters: [] });
      if (c.url.pathname.startsWith('/v10/')) return reply(200, { envs: [LEAK('env-string')], pagination: { count: 1, next: null, prev: null } });
      return undefined;
    };
    const r = await cli(['--json', '--live', 'ssm,vercel', '--compare', '--env', 'prod', fixture('live')], { env: BOTH, net });
    expect(r.code).toBe(2);
    const adapters = json(r).live!.adapters;
    expect(adapters.find((s) => s.adapter === 'ssm')!.problem).toBe('AWS SSM answered with an error (MalformedResponse)');
    expect(adapters.find((s) => s.adapter === 'vercel')!.complete).toBe(false);
    expect(r.out + r.err).not.toContain('LEAK-');
  });

  it('turns an unexpected exception into a fixed message and exit 2, with no message or stack', async () => {
    const net = fakeCloud({ params: demoParams() });
    net.intercept = () => reply(503, { message: 'busy' });
    net.sleep = async () => {
      throw new Error(`boom ${LEAK('exception-message')}`);
    };
    for (const args of [['--live', 'ssm', fixture('live')], ['--json', '--live', 'ssm', fixture('live')]]) {
      const r = await cli(args, { env: AWS, net });
      expect(r.code).toBe(2);
      expect(r.out + r.err).not.toContain('LEAK-');
      expect(r.out + r.err).not.toMatch(/\bat .+:\d+:\d+/);
      expect(r.out + r.err).toContain('an unexpected error stopped this check; no detail is shown because it could contain a value');
    }
  });
});

describe('7. Vercel pagination', () => {
  const two: VercelEnvVar[] = [
    { id: 'env_a', key: 'SESSION_SECRET', target: ['production'], type: 'encrypted', value: 'x' },
    { id: 'env_b', key: 'ORDERS_API_URL', target: ['production'], type: 'plain', value: 'y' },
  ];

  it('is incomplete when a page adds no new variable but pagination.next is still set', async () => {
    const net = fakeCloud({ projects: { prj_demoweb0000: two }, vercelPageSize: 1 });
    // The second page repeats the first and still points onward.
    net.intercept = (c) => (c.url.searchParams.has('until') ? reply(200, { envs: [{ id: 'env_a', key: 'SESSION_SECRET', target: ['production'], type: 'encrypted' }], pagination: { count: 1, next: 1, prev: null } }) : undefined);
    const r = await cli(['--json', '--live', 'vercel', fixture('live')], { env: { VERCEL_TOKEN: TOKEN }, net });
    expect(r.code).toBe(2);
    expect(json(r).live!.adapters[0]!.problem).toBe('the variable list of the project linked in web/.vercel/project.json did not page to the end (PaginationStalled)');
    expect(net.calls).toHaveLength(2);
  });

  it('is complete when a page adds nothing and pagination.next is null', async () => {
    const net = fakeCloud({ projects: { prj_demoweb0000: two }, vercelPageSize: 2 });
    const r = await cli(['--json', '--live', 'vercel', fixture('live')], { env: { VERCEL_TOKEN: TOKEN }, net });
    expect(json(r).live!.adapters[0]).toMatchObject({ complete: true });
    expect(net.calls.map((c) => c.url.pathname)).toEqual(['/v10/projects/prj_demoweb0000/env']);
  });

  it('is incomplete when Vercel hides production variables', async () => {
    const net = fakeCloud({ projects: { prj_demoweb0000: two } });
    net.intercept = () => reply(200, { envs: [], hiddenProductionEnvCount: 2 });
    const r = await cli(['--json', '--live', 'vercel', fixture('live')], { env: { VERCEL_TOKEN: TOKEN }, net });
    expect(r.code).toBe(2);
    expect(json(r).live!.adapters[0]!.problem).toContain('Vercel hid some production variables');
  });
});

describe('8. values that differ only by a trailing newline', () => {
  function cloud(jwtProd: string) {
    const params = demoParams();
    params['eu-west-1']!['/copilot/demo/prod/secrets/IDENTITY_JWT_SECRET'] = 'shared-jwt-value';
    params['eu-west-1']!['/copilot/demo/prod/secrets/JWT_SECRET'] = jwtProd;
    return fakeCloud({ params });
  }

  it('says so and gives the fix, without showing either value', async () => {
    const r = await cli(['--json', '--live', 'ssm', '--compare', '--env', 'prod', fixture('live')], { env: AWS, net: cloud('shared-jwt-value\r\n') });
    expect(r.code).toBe(1);
    const report = json(r);
    const [f] = find(report, 'live-mismatch');
    expect(f!.problem).toMatch(/; they differ only by a trailing newline$/);
    expect(f!.fix).toMatch(/^remove the trailing newline from whichever value has one \(echo and heredocs add it when a secret is set\), or copy the prod value/);
    const all = [r.out, renderHuman(report), renderMarkdown(report), renderGithub(report, fixture('live'))].join('\n');
    expect(all).not.toContain('shared-jwt-value');
  });

  it('says nothing about newlines when the values differ otherwise', async () => {
    const report = json(await cli(['--json', '--live', 'ssm', '--compare', '--env', 'prod', fixture('live')], { env: AWS, net: cloud('shared-jwt-valuX\n') }));
    const [f] = find(report, 'live-mismatch');
    expect(f!.problem).not.toContain('newline');
    expect(f!.fix).not.toContain('newline');
  });
});

describe('9. rejected Vercel token', () => {
  it('stops listing the remaining projects once one listing is rejected', async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 8; i++) {
      files[`web${i}/package.json`] = pkg(`web${i}`);
      files[`web${i}/.env.example`] = 'API_KEY=\n';
      files[`web${i}/src/x.ts`] = 'export const k = process.env.API_KEY;\n';
      files[`web${i}/vercel.json`] = '{}\n';
      files[`web${i}/.vercel/project.json`] = `{"projectId":"prj_${i}","orgId":"team_x"}\n`;
    }
    const net = fakeCloud();
    // Answer slowly so the pool has started its first workers, then reject the token.
    net.intercept = async () => {
      await new Promise((r) => setTimeout(r, 5));
      return reply(401, { error: { code: 'forbidden', message: 'Not authorized', invalidToken: true } });
    };
    const r = await cli(['--json', '--live', 'vercel', workspace(files)], { env: { VERCEL_TOKEN: 'wrong' }, net });
    expect(r.code).toBe(2);
    expect(net.calls.length).toBeLessThanOrEqual(4);
    expect(net.calls.length).toBeLessThan(8);
  });
});

describe('10. shared-secret text after --compare', () => {
  const sessionValues = () => {
    const params = demoParams();
    params['eu-west-1']!['/copilot/demo/prod/secrets/SESSION_SECRET'] = 'same-session';
    return fakeCloud({ params, projects: { prj_demoweb0000: [{ id: 'env_s', key: 'SESSION_SECRET', target: ['production'], type: 'encrypted', value: 'same-session' }] } });
  };
  const sharedFix = (args: string[], net?: FakeCloud) => cli(['--json', ...args, fixture('live')], { env: BOTH, ...(net ? { net } : {}) }).then((r) => find(json(r), 'shared-secret', 'SESSION_SECRET')[0]!.fix);

  it('keeps the v0 wording without --compare', async () => {
    expect(await sharedFix([])).toContain('; v0 reads files only and cannot compare live stores');
    expect(await sharedFix(['--live', 'ssm,vercel', '--env', 'prod'], sessionValues())).toContain('; v0 reads files only and cannot compare live stores');
  });

  it('points at the comparison once --compare compared the pair', async () => {
    const fix = await sharedFix(['--live', 'ssm,vercel', '--compare', '--env', 'prod'], sessionValues());
    expect(fix).not.toContain('cannot compare live stores');
    expect(fix).toContain('; --compare compared the deployed values, see VALUE COMPARISONS');
  });
});
