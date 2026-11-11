import { afterEach, describe, expect, it, vi } from 'vitest';
import { resolveRef } from '../src/live.js';
import { renderGithub, renderHuman, renderMarkdown, run } from '../src/index.js';
import type { Net } from '../src/net.js';
import { AWS, cli, demoParams, fakeCloud, json, LEAK } from './fakecloud.js';
import { find, fixture } from './helpers.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('no network without a v2 flag', () => {
  it('never calls the injected net or the global fetch on a default run', async () => {
    const spy = vi.fn(async () => new Response('should not be called'));
    vi.stubGlobal('fetch', spy);
    const net: Net = { fetch: spy as unknown as typeof fetch };
    for (const args of [[fixture('shop')], ['--json', fixture('live')], ['--no-hints', fixture('annotated')]]) await cli(args, { env: AWS, net });
    expect(spy).not.toHaveBeenCalled();
  });

  it('prints exactly what the file-only run prints', async () => {
    const r = await cli(['--json', fixture('shop')], { env: AWS });
    const expected = run(fixture('shop'));
    expect({ ...json(r), summary: { ...json(r).summary, durationMs: 0 } }).toEqual({ ...expected, summary: { ...expected.summary, durationMs: 0 } });
    expect(json(r)).not.toHaveProperty('live');
    expect(json(r)).not.toHaveProperty('probe');
  });
});

describe('manifest secret references', () => {
  it('interpolates Copilot variables and reads SSM ARNs', () => {
    expect(resolveRef('/copilot/${COPILOT_APPLICATION_NAME}/${COPILOT_ENVIRONMENT_NAME}/x', 'prod', 'demo', 'eu-west-1')).toEqual({ name: '/copilot/demo/prod/x', region: 'eu-west-1' });
    expect(resolveRef('arn:aws:ssm:us-east-2:000000000000:parameter/a/b', 'prod', null, 'eu-west-1')).toEqual({ name: '/a/b', region: 'us-east-2' });
    expect(resolveRef('arn:aws:ssm:us-east-2:000000000000:parameter/flat', 'prod', null, 'eu-west-1')).toEqual({ name: 'flat', region: 'us-east-2' });
    expect(resolveRef('PLAIN_NAME', '*', null, 'eu-west-1')).toEqual({ name: 'PLAIN_NAME', region: 'eu-west-1' });
  });

  it('says why a reference is not checked', () => {
    const reason = (ref: string, env = 'prod', app: string | null = 'demo') => (resolveRef(ref, env, app, 'eu-west-1') as { reason: string }).reason;
    expect(reason('{"secretsmanager":"demo/x"}')).toMatch(/Secrets Manager/);
    expect(reason('arn:aws:secretsmanager:eu-west-1:000000000000:secret:demo-x')).toMatch(/Secrets Manager ARN/);
    expect(reason('{"from_cfn":"stack-Output"}')).toMatch(/CloudFormation/);
    expect(reason('/x/${COPILOT_ENVIRONMENT_NAME}', '*')).toMatch(/names no environment/);
    expect(reason('/x/${COPILOT_APPLICATION_NAME}', 'prod', null)).toMatch(/copilot\/.workspace/);
    expect(reason('/x/${OTHER}')).toMatch(/cannot resolve/);
  });
});

describe('--live ssm', () => {
  it('reports a referenced parameter that does not exist, per environment', async () => {
    const net = fakeCloud({ params: demoParams() });
    const r = await cli(['--json', '--live', 'ssm', fixture('live')], { env: AWS, net });
    expect(r.code).toBe(1);
    const report = json(r);
    expect(find(report, 'live-missing').map((f) => [f.service, f.variable, f.env, f.file])).toEqual([['orders', 'JWT_SECRET', 'dev', 'orders/copilot/orders/manifest.yml']]);
    expect(find(report, 'live-missing')[0]!.fix).toBe(
      'create the parameter that secrets.JWT_SECRET in orders/copilot/orders/manifest.yml names, in eu-west-1 (copilot secret init --name JWT_SECRET creates and tags it), or correct the reference',
    );
    expect(report.live!.adapters).toEqual([{ adapter: 'ssm', complete: true, requests: 1, checked: 8 }]);
    expect(report.live!.checks.filter((c) => c.status === 'present')).toHaveLength(7);
    // The ARN override for prod is used instead of the top-level reference.
    expect(report.live!.checks.find((c) => c.variable === 'SIGNING_KEY' && c.env === 'prod')).toMatchObject({ status: 'present' });
    // Secrets Manager references are notes, not failures.
    expect(find(report, 'live-not-checked', 'PAYMENTS_KEY').map((f) => [f.severity, f.env])).toEqual([['info', 'dev'], ['info', 'prod']]);
  });

  it('asks for names only: DescribeParameters, no values, no writes', async () => {
    const net = fakeCloud({ params: demoParams() });
    await cli(['--live', 'ssm', fixture('live')], { env: AWS, net });
    expect(net.calls.map((c) => [c.method, c.url.host, c.target])).toEqual([['POST', 'ssm.eu-west-1.amazonaws.com', 'AmazonSSM.DescribeParameters']]);
    const body = net.calls[0]!.body!;
    expect(body).not.toHaveProperty('WithDecryption');
    expect(body['ParameterFilters']).toEqual([{ Key: 'Name', Option: 'Equals', Values: expect.arrayContaining(['/copilot/demo/dev/secrets/JWT_SECRET']) }]);
    expect(net.calls[0]!.headers['x-amz-security-token']).toBe(AWS.AWS_SESSION_TOKEN);
  });

  it('follows NextToken across pages', async () => {
    const net = fakeCloud({ params: demoParams(), pageSize: 2 });
    const report = json(await cli(['--json', '--live', 'ssm', fixture('live')], { env: AWS, net }));
    expect(net.calls.length).toBe(4);
    expect(net.calls.slice(1).every((c) => typeof c.body!['NextToken'] === 'string')).toBe(true);
    expect(find(report, 'live-missing')).toHaveLength(1);
    expect(report.live!.complete).toBe(true);
  });

  it('retries throttling and then succeeds', async () => {
    const net = fakeCloud({ params: demoParams() });
    let throttles = 2;
    net.intercept = () => (throttles-- > 0 ? new Response(JSON.stringify({ __type: 'ThrottlingException', message: 'Rate exceeded' }), { status: 400 }) : undefined);
    const report = json(await cli(['--json', '--live', 'ssm', fixture('live')], { env: AWS, net }));
    expect(report.live!.adapters[0]).toMatchObject({ complete: true, requests: 3 });
  });

  it('says prominently that it could not run when throttling never stops, and exits 2', async () => {
    const net = fakeCloud({ params: demoParams() });
    net.intercept = () => new Response(JSON.stringify({ __type: 'ThrottlingException' }), { status: 400 });
    const r = await cli(['--live', 'ssm', fixture('live')], { env: AWS, net });
    expect(r.code).toBe(2);
    expect(r.out).toContain('LIVE CHECK INCOMPLETE: ssm');
    expect(r.out).toContain('AWS SSM kept throttling after retries (ThrottlingException)');
    expect(r.err).toContain('live check ssm incomplete');
    expect(net.calls).toHaveLength(4);
  });

  it('reports access denied without quoting the upstream message', async () => {
    const net = fakeCloud({ params: demoParams() });
    net.intercept = () =>
      new Response(JSON.stringify({ __type: 'AccessDeniedException', message: `User: arn:aws:iam::000000000000:user/${LEAK('iam-user')} is not authorized to perform: ssm:DescribeParameters` }), { status: 400 });
    const r = await cli(['--live', 'ssm', fixture('live')], { env: AWS, net });
    expect(r.code).toBe(2);
    expect(r.out).toContain('the credentials are not allowed to call ssm:DescribeParameters (AccessDeniedException)');
    expect(r.out).toContain('grant ssm:DescribeParameters on "*"');
    expect(r.out + r.err).not.toContain('LEAK-');
    expect(r.out + r.err).not.toContain('000000000000');
  });

  it('reports rejected credentials and stops asking', async () => {
    const net = fakeCloud({ params: demoParams() });
    net.intercept = () => new Response(JSON.stringify({ __type: 'com.amazon.coral.service#UnrecognizedClientException', message: 'The security token included in the request is invalid.' }), { status: 400 });
    const report = json(await cli(['--json', '--live', 'ssm', '--region', 'us-west-2', fixture('live')], { env: AWS, net }));
    expect(report.live!.adapters[0]).toMatchObject({ complete: false, problem: 'AWS rejected the credentials (UnrecognizedClientException)' });
    // The prod SIGNING_KEY ARN names eu-west-1, the rest use --region; after the first rejection nothing more is sent.
    expect(net.calls).toHaveLength(1);
    expect(report.live!.checks.every((c) => c.status === 'not-checked')).toBe(true);
  });

  it('names the missing credential variables and exits 2 without a request', async () => {
    const net = fakeCloud();
    const r = await cli(['--live', 'ssm', fixture('live')], { env: { AWS_REGION: 'eu-west-1' }, net });
    expect(r.code).toBe(2);
    expect(r.out).toContain('AWS credentials are not set: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required');
    expect(net.calls).toHaveLength(0);
    const noRegion = await cli(['--live', 'ssm', fixture('live')], { env: { AWS_ACCESS_KEY_ID: 'AKIDEXAMPLE', AWS_SECRET_ACCESS_KEY: 'x' }, net });
    expect(noRegion.code).toBe(2);
    expect(noRegion.out).toContain('set AWS_REGION (or AWS_DEFAULT_REGION), or pass --region <region>');
  });

  it('lets findings exit 1 even when a live check is incomplete', async () => {
    const r = await cli(['--live', 'ssm', fixture('shop')], { env: {} });
    expect(r.code).toBe(1);
    expect(r.out).toContain('LIVE CHECK INCOMPLETE: ssm');
  });

  it('restricts the run to --env, and rejects an environment no manifest names', async () => {
    const net = fakeCloud({ params: demoParams() });
    const report = json(await cli(['--json', '--live', 'ssm', '--env', 'prod', fixture('live')], { env: AWS, net }));
    expect(new Set(report.live!.checks.map((c) => c.env))).toEqual(new Set(['prod']));
    expect(find(report, 'live-missing')).toEqual([]);
    expect(report.live!.envs).toEqual(['prod']);
    const r = await cli(['--live', 'ssm', '--env', 'qa', fixture('live')], { env: AWS, net });
    expect(r.code).toBe(2);
    expect(r.out).toContain('--env qa matches no environment in any Copilot manifest');
    expect(r.out).toContain('use one of: dev, prod');
  });

  it('reports an unreachable endpoint as not checked', async () => {
    const net = fakeCloud();
    net.intercept = () => {
      throw Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) });
    };
    const r = await cli(['--live', 'ssm', fixture('live')], { env: AWS, net });
    expect(r.code).toBe(2);
    expect(r.out).toContain('could not reach AWS SSM in eu-west-1 (refused)');
  });

  it('carries live findings into GitHub annotations and the Markdown body', async () => {
    const net = fakeCloud({ params: demoParams() });
    const report = json(await cli(['--json', '--live', 'ssm', fixture('live')], { env: AWS, net }));
    expect(renderGithub(report, fixture('live'))).toContain('::error file=orders/copilot/orders/manifest.yml,title=wirelint live-missing%3A JWT_SECRET::');
    expect(renderMarkdown(report)).toContain('- `orders` `JWT_SECRET` `orders/copilot/orders/manifest.yml`: secrets.JWT\\_SECRET references an SSM parameter that does not exist');
    expect(renderMarkdown(report)).toContain('files plus read-only live checks');
    expect(renderHuman(report)).toContain('ssm: 7 present, 1 missing, 2 not checked (1 request)');
  });
});

describe('usage errors', () => {
  it('exits 2 for bad v2 flags, before touching the network', async () => {
    const net = fakeCloud();
    for (const [args, message] of [
      [['--live', 'gcp'], 'unknown live adapter "gcp"'],
      [['--live='], '--live needs a value'],
      [['--live', ','], '--live needs ssm'],
      [['--env', 'prod'], '--env only applies with --live ssm'],
      [['--live', 'ssm', '--region', 'mars-1'], 'is not an AWS region name'],
      [['--live', 'ssm', 'baseline'], 'baseline records file findings only'],
      [['--live', 'ssm', '--region', 'eu-west-1', '--region', 'us-east-1'], '--region given twice'],
    ] as const) {
      const r = await cli([...args, fixture('live')], { env: AWS, net });
      expect(r.code, args.join(' ')).toBe(2);
      expect(r.err, args.join(' ')).toContain(message);
    }
    expect(net.calls).toHaveLength(0);
  });
});
