import { describe, expect, it } from 'vitest';
import { parseEnv } from '../src/dotenv.js';
import { renderHuman, run } from '../src/index.js';
import { find, fixture, pkg, service, workspace } from './helpers.js';

const manifest = (name: string, body: string) => `name: ${name}\ntype: Backend Service\n${body}`;

describe('annotation parser', () => {
  it('reads inline annotations, annotations on the line above, and comma-separated lists', () => {
    const { annotations, badAnnotations } = parseEnv(
      [
        'JWT_SECRET=x  # wirelint: same-as identity-api',
        '# wirelint: optional, build-time',
        'NEXT_PUBLIC_DSN=',
        '# SENTRY_DSN=  # wirelint: optional',
        'KEY=1 # wirelint: same-as billing.OTHER_KEY # trailing note',
        'CATALOG_URL=https://c.example.test/v1/x # wirelint: optional # wirelint-ignore: intended',
      ].join('\n'),
    );
    expect(annotations.map((a) => [a.name, a.kind, a.target, a.line])).toEqual([
      ['JWT_SECRET', 'same-as', 'identity-api', 1],
      ['NEXT_PUBLIC_DSN', 'optional', undefined, 2],
      ['NEXT_PUBLIC_DSN', 'build-time', undefined, 2],
      ['SENTRY_DSN', 'optional', undefined, 4],
      ['KEY', 'same-as', 'billing.OTHER_KEY', 5],
      ['CATALOG_URL', 'optional', undefined, 6],
    ]);
    expect(badAnnotations).toEqual([]);
  });

  it('rejects unknown words, a same-as without a target, stray arguments and dangling annotations', () => {
    const { annotations, badAnnotations } = parseEnv(
      [
        'A=1 # wirelint: optinal',
        'B=1 # wirelint: same-as',
        'C=1 # wirelint: optional please',
        'D=1 # wirelint: frobnicate',
        'E=1 # wirelint:',
        '# wirelint: build-time',
        '',
        'F=1',
        '# wirelint: optional',
        '# describes G',
        'G=1',
      ].join('\n'),
    );
    expect(annotations).toEqual([]);
    expect(badAnnotations.map((b) => [b.line, b.name ?? null, b.problem, b.fix])).toEqual([
      [1, 'A', 'unknown wirelint annotation "optinal"', 'write "optional" instead of "optinal"'],
      [2, 'B', '"same-as" names no service', 'write "# wirelint: same-as <service>" or "same-as <service>.<VARIABLE>"'],
      [3, 'C', '"optional" takes no argument, got "please"', 'write "optional", and separate annotations with commas'],
      [4, 'D', 'unknown wirelint annotation "frobnicate"', 'use same-as <service>, optional or build-time, separated by commas'],
      [5, 'E', 'wirelint annotation is empty', 'use same-as <service>, optional or build-time, separated by commas'],
      [6, null, 'wirelint annotation is not attached to a variable', "put it at the end of the variable's line, or on the line directly above it"],
      [9, null, 'wirelint annotation is not attached to a variable', "put it at the end of the variable's line, or on the line directly above it"],
    ]);
  });

  it('does not confuse an annotation with a suppression marker', () => {
    const p = parseEnv('A=1 # wirelint-ignore: reason here\nB=2 # wirelint: optional\n');
    expect(p.ignores.map((i) => i.name)).toEqual(['A']);
    expect(p.annotations.map((a) => a.name)).toEqual(['B']);
  });
});

describe('fixture: annotations and a fallback chain', () => {
  const report = run(fixture('annotated'));
  const got = report.findings.map((f) => `${f.severity} ${f.check} ${f.service} ${f.variable}`);

  it('reports exactly the planted mistakes', () => {
    expect(got.sort()).toEqual(
      [
        'error annotation-invalid web FEATURE_FLAGS',
        'error missing-from-build gateway BUILD_SHA',
        'error same-as-not-deployed gateway JWT_SECRET',
        'error same-as-undeclared gateway GATEWAY_INTERNAL_KEY',
        'error same-as-unknown-service web SESSION_SECRET',
        'hint missing-from-build web NEXT_PUBLIC_GATEWAY_URL',
        'hint missing-from-example gateway IDENTITY_API_URL',
      ].sort(),
    );
    expect(report.summary).toMatchObject({ failures: 5, suggestions: 2 });
  });

  it('keeps declared relations in the report and drops the shared-secret guess they replace', () => {
    expect(report.relations).toEqual([
      { kind: 'same-as', service: 'gateway', variable: 'JWT_SECRET', file: 'gateway/.env.example', line: 2, target: { service: 'identity-api', variable: 'JWT_SECRET' }, compared: 'existence' },
      { kind: 'same-as', service: 'gateway', variable: 'GATEWAY_INTERNAL_KEY', file: 'gateway/.env.example', line: 3, target: { service: 'identity-api', variable: 'GATEWAY_INTERNAL_KEY' }, compared: 'existence' },
    ]);
    expect(find(report, 'shared-secret')).toEqual([]);
    expect(report.annotations.map((a) => `${a.service}.${a.variable}:${a.kind}`)).toContain('gateway.SENTRY_DSN:optional');
    expect(renderHuman(report)).toContain('gateway.JWT_SECRET same-as identity-api.JWT_SECRET  [gateway/.env.example:2]');
  });

  it('states the exact fix for each annotation finding', () => {
    expect(find(report, 'same-as-not-deployed')[0]).toMatchObject({ env: 'prod', file: 'gateway/copilot/gateway/manifest.yml', fix: 'add JWT_SECRET to environments.prod.secrets' });
    expect(find(report, 'missing-from-build', 'BUILD_SHA')[0]!.fix).toBe('add "ARG BUILD_SHA" to gateway/Dockerfile');
    expect(find(report, 'annotation-invalid')[0]!.fix).toBe('write "optional" instead of "optinal"');
    expect(find(report, 'same-as-unknown-service')[0]!.problem).toContain('(found: gateway, identity-api)');
    expect(find(report, 'same-as-undeclared')[0]!.fix).toBe('add GATEWAY_INTERNAL_KEY back to identity-api/.env.example, or remove the same-as annotation if gateway no longer shares it');
  });

  it('never prints a value from a non-example file', () => {
    expect(JSON.stringify(report) + renderHuman(report)).not.toMatch(/\/gateway\/dev\/JWT_SECRET|\/identity\/JWT_SECRET|dev\.internal\.example\.test/);
  });
});

describe('same-as', () => {
  const pair = (left: Record<string, string>, right: Record<string, string> = {}) =>
    run(
      workspace({
        'a/package.json': pkg('a'),
        'a/.env.example': 'SHARED_SIGNING_SECRET=dev-aaaaaaaaaa  # wirelint: same-as b\n',
        'b/package.json': pkg('b'),
        'b/.env.example': 'SHARED_SIGNING_SECRET=dev-bbbbbbbbbb\n',
        ...left,
        ...right,
      }),
    );

  it('turns the shared-secret suggestion into a declared relation', () => {
    const r = pair({});
    expect(r.findings).toEqual([]);
    expect(r.relations).toHaveLength(1);
  });

  it('fails when the other service stops declaring the variable', () => {
    const r = pair({ 'b/.env.example': 'OTHER=1\n' });
    expect(find(r, 'same-as-undeclared')[0]).toMatchObject({ severity: 'error', service: 'a', variable: 'SHARED_SIGNING_SECRET', file: 'a/.env.example', line: 1 });
  });

  it('counts a deploy manifest as declaring it', () => {
    const r = pair({ 'b/.env.example': 'OTHER=1\n', 'b/copilot/b/manifest.yml': manifest('b', 'secrets:\n  SHARED_SIGNING_SECRET: /b/SHARED\n') });
    expect(find(r, 'same-as-undeclared')).toEqual([]);
  });

  it('fails when this side does not deploy it but the other side does, per environment', () => {
    const r = pair({
      'a/copilot/a/manifest.yml': manifest('a', 'environments:\n  dev:\n    secrets:\n      SHARED_SIGNING_SECRET: /a/dev\n  prod:\n    variables:\n      X: "1"\n'),
      'b/copilot/b/manifest.yml': manifest('b', 'secrets:\n  SHARED_SIGNING_SECRET: /b/all\nenvironments:\n  dev:\n  prod:\n'),
    });
    expect(find(r, 'same-as-not-deployed').map((f) => [f.service, f.env, f.fix])).toEqual([['a', 'prod', 'add SHARED_SIGNING_SECRET to environments.prod.secrets']]);
    expect(JSON.stringify(r)).not.toMatch(/\/a\/dev|\/b\/all/);
  });

  it('does not repeat a missing-from-deploy failure for the same variable', () => {
    const r = pair({
      'a/src/a.ts': "cfg.getOrThrow('SHARED_SIGNING_SECRET');",
      'a/copilot/a/manifest.yml': manifest('a', 'variables:\n  X: "1"\n'),
      'b/copilot/b/manifest.yml': manifest('b', 'secrets:\n  SHARED_SIGNING_SECRET: /b/all\n'),
    });
    expect(find(r, 'missing-from-deploy', 'SHARED_SIGNING_SECRET')).toHaveLength(1);
    expect(find(r, 'same-as-not-deployed')).toEqual([]);
  });

  it('accepts a differently named variable and replaces the same-value suggestion', () => {
    const r = run(
      workspace({
        'a/package.json': pkg('a'),
        'a/.env.example': 'INTERNAL_SERVICE_KEY=dev-internal-key-123456  # wirelint: same-as b.ORDERS_SERVICE_KEY\n',
        'b/package.json': pkg('b'),
        'b/.env.example': 'ORDERS_SERVICE_KEY=dev-internal-key-123456\n',
      }),
    );
    expect(r.findings).toEqual([]);
    expect(r.relations[0]!.target).toEqual({ service: 'b', variable: 'ORDERS_SERVICE_KEY' });
  });

  it('resolves a monorepo package by its directory name', () => {
    const r = run(
      workspace({
        'package.json': JSON.stringify({ name: 'root', workspaces: ['apps/*'] }),
        'apps/api/package.json': pkg('api'),
        'apps/api/.env.example': 'JWT_SECRET=x\n',
        'apps/worker/package.json': pkg('worker'),
        'apps/worker/.env.example': 'JWT_SECRET=y  # wirelint: same-as api\n',
      }),
    );
    expect(find(r, 'same-as-unknown-service')).toEqual([]);
    expect(r.relations.map((x) => x.target.service)).toEqual(['apps/api']);
  });

  it('rejects an unknown service and a relation to itself', () => {
    const r = service({ '.env.example': 'A_SECRET=x  # wirelint: same-as nowhere\nB_SECRET=x  # wirelint: same-as svc\n' });
    expect(find(r, 'same-as-unknown-service', 'A_SECRET')[0]!.fix).toBe('remove the annotation; no other service was found');
    expect(find(r, 'annotation-invalid', 'B_SECRET')[0]!.severity).toBe('error');
    expect(r.relations).toEqual([]);
  });
});

describe('optional', () => {
  it('exempts the variable from every deploy target', () => {
    const r = service({
      'src/a.ts': "cfg.getOrThrow('SENTRY_DSN'); process.env.PLAIN_ONE;",
      '.env.example': '# wirelint: optional\nSENTRY_DSN=\nPLAIN_ONE=1 # wirelint: optional\n',
      'copilot/svc/manifest.yml': manifest('svc', 'variables:\n  X: "1"\nenvironments:\n  prod:\n'),
    });
    expect(find(r, 'missing-from-deploy')).toEqual([]);
    expect(r.summary.failures).toBe(0);
  });
});

describe('build-time', () => {
  const code = { 'src/a.ts': 'export const u = process.env.NEXT_PUBLIC_API_URL;', '.env.example': 'NEXT_PUBLIC_API_URL=http://localhost:4000  # wirelint: build-time\n' };

  it('is checked against build configuration instead of runtime manifests', () => {
    const r = service({ ...code, Dockerfile: 'FROM node:22\nARG NEXT_PUBLIC_API_URL=http://localhost:4000\n', 'copilot/svc/manifest.yml': manifest('svc', 'variables:\n  X: "1"\n') });
    expect(r.findings).toEqual([]);
  });

  it.each([
    ['a compose build arg', { 'docker-compose.yml': 'services:\n  svc:\n    build:\n      context: .\n      args:\n        NEXT_PUBLIC_API_URL: http://localhost:4000\n' }],
    ['a compose build arg list', { 'docker-compose.yml': 'services:\n  svc:\n    build:\n      context: .\n      args:\n        - NEXT_PUBLIC_API_URL\n' }],
    ['a vercel.json build.env', { 'vercel.json': '{ "build": { "env": { "NEXT_PUBLIC_API_URL": "https://api.example.test" } } }' }],
    ['a Dockerfile ENV', { Dockerfile: 'FROM node:22\nENV NEXT_PUBLIC_API_URL=https://api.example.test\n' }],
  ])('accepts %s', (_label, files) => {
    expect(find(service({ ...code, ...files }), 'missing-from-build')).toEqual([]);
  });

  it('fails when a build configuration is visible and lacks it, naming every place it could go', () => {
    const r = service({
      ...code,
      Dockerfile: 'FROM node:22\nARG OTHER\n',
      'docker-compose.yml': 'services:\n  svc:\n    build:\n      context: .\n      args:\n        OTHER: "1"\n',
    });
    const [f] = find(r, 'missing-from-build');
    expect(f).toMatchObject({ severity: 'error', variable: 'NEXT_PUBLIC_API_URL' });
    expect(f!.fix).toBe('add "ARG NEXT_PUBLIC_API_URL" to svc/Dockerfile, or add NEXT_PUBLIC_API_URL to services.svc.build.args in svc/docker-compose.yml');
  });

  it('only suggests when no build configuration is visible', () => {
    const r = service(code);
    expect(find(r, 'missing-from-build')[0]).toMatchObject({ severity: 'hint', file: 'svc/.env.example', line: 1 });
    expect(r.summary.failures).toBe(0);
  });
});
