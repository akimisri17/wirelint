import { describe, expect, it } from 'vitest';
import { run } from '../src/index.js';
import { find, pkg, service, workspace } from './helpers.js';

const manifest = (body: string) => `name: svc\ntype: Backend Service\n${body}`;

describe('(a) read in code but absent from .env.example', () => {
  it('fails on an undocumented variable and says exactly what to add', () => {
    const r = service({ 'src/a.ts': 'export const x = process.env.FEATURE_API_TOKEN;', '.env.example': 'OTHER=1\n' });
    const [f] = find(r, 'missing-from-example', 'FEATURE_API_TOKEN');
    expect(f).toMatchObject({ severity: 'error', service: 'svc', file: 'svc/src/a.ts', line: 1 });
    expect(f!.fix).toBe('add "FEATURE_API_TOKEN=<placeholder>" to svc/.env.example');
    expect(r.summary.failures).toBe(1);
  });

  it('accepts a documented variable, including a commented-out entry', () => {
    const r = service({ 'src/a.ts': 'process.env.ONE; process.env.TWO;', '.env.example': 'ONE=1\n# TWO=\n' });
    expect(r.findings).toEqual([]);
  });

  it('only suggests when the code has its own default', () => {
    const r = service({ 'src/a.ts': "const t = process.env.TIMEOUT_MS || '500';", '.env.example': 'X=1\n' });
    expect(find(r, 'missing-from-example', 'TIMEOUT_MS')[0]).toMatchObject({ severity: 'hint' });
    expect(r.summary.failures).toBe(0);
  });

  it('ignores platform variables, tests, tooling scripts and comments', () => {
    const r = service({
      'src/a.ts': 'process.env.NODE_ENV; process.env.PORT; process.env.CI; process.env.VERCEL_URL; process.env.GITHUB_SHA; // process.env.IN_COMMENT',
      'src/a.test.ts': 'process.env.ONLY_IN_TEST;',
      'test/setup.ts': 'process.env.ONLY_IN_TEST_DIR;',
      'scripts/backfill.ts': 'process.env.ONLY_IN_SCRIPT;',
      'prisma.config.ts': 'process.env.ONLY_IN_TOOLING_CONFIG;',
      'node_modules/dep/index.js': 'process.env.ONLY_IN_DEP;',
      'tmp-tsc-out/a.js': 'process.env.ONLY_IN_BUILD_OUTPUT;',
      'dist/a.js': 'process.env.ONLY_IN_DIST;',
      '.env.example': 'X=1\n',
    });
    expect(r.findings).toEqual([]);
  });

  it('reports one finding when the service has no .env.example at all', () => {
    const r = service({ 'src/a.ts': 'process.env.A_KEY; process.env.B_KEY;' });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ check: 'no-example-file', severity: 'error' });
    expect(r.findings[0]!.problem).toContain('A_KEY, B_KEY');
    expect(r.findings[0]!.fix).toContain('svc/.env.example');
  });

  it('reports computed reads once as not analysable, never as a failure', () => {
    const r = service({ 'src/a.ts': 'export const f = (k: string) => process.env[k];\nexport const g = (k: string) => process.env[`P_${k}`];', '.env.example': 'X=1\n' });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ check: 'dynamic-read', severity: 'info' });
    expect(r.findings[0]!.problem).toContain('2 computed env reads');
    expect(r.summary.failures).toBe(0);
  });
});

describe('(b) read in code but absent from a deploy manifest', () => {
  const code = { 'src/a.ts': "cfg.getOrThrow('JWT_SECRET'); cfg.getOrThrow('API_URL');", '.env.example': 'JWT_SECRET=x\nAPI_URL=http://localhost:1\n' };

  it('checks each environment separately', () => {
    const r = service({
      ...code,
      'copilot/svc/manifest.yml': manifest(`
variables:
  API_URL: https://api.example.test
environments:
  dev:
    secrets:
      JWT_SECRET: /app/dev/JWT_SECRET
  prod:
    variables:
      OTHER: "1"
`),
    });
    const [f] = find(r, 'missing-from-deploy');
    expect(find(r, 'missing-from-deploy')).toHaveLength(1);
    expect(f).toMatchObject({ severity: 'error', variable: 'JWT_SECRET', env: 'prod', file: 'svc/copilot/svc/manifest.yml' });
    expect(f!.problem).toContain('not set for environment prod');
    expect(f!.fix).toBe('add JWT_SECRET to environments.prod.secrets');
  });

  it('passes when variables or secrets cover every environment', () => {
    const r = service({ ...code, 'copilot/svc/manifest.yml': manifest('variables:\n  API_URL: https://api.example.test\nsecrets:\n  JWT_SECRET: /app/JWT_SECRET\nenvironments:\n  dev:\n  prod:\n') });
    expect(find(r, 'missing-from-deploy')).toEqual([]);
  });

  it('grades by how the variable is read', () => {
    const r = service({
      'src/a.ts': `
        cfg.getOrThrow('REQUIRED_ONE');
        const a = process.env.LOCAL_FALLBACK_URL ?? 'http://localhost:9000';
        const b = process.env.DOCUMENTED_PLAIN;
        const c = process.env.UNDOCUMENTED_PLAIN;
        const d = process.env.HAS_DEFAULT || 'x';
        const e = process.env.IS_FLAG === 'true';
      `,
      '.env.example': 'REQUIRED_ONE=1\nLOCAL_FALLBACK_URL=http://localhost:9000\nDOCUMENTED_PLAIN=1\nHAS_DEFAULT=1\nIS_FLAG=1\n# UNDOCUMENTED_PLAIN is deliberately absent\n',
      'copilot/svc/manifest.yml': manifest('variables:\n  OTHER: "1"\nenvironments:\n  prod:\n'),
    });
    const got = Object.fromEntries(find(r, 'missing-from-deploy').map((f) => [f.variable, f.severity]));
    expect(got).toEqual({ REQUIRED_ONE: 'error', LOCAL_FALLBACK_URL: 'error', DOCUMENTED_PLAIN: 'error', UNDOCUMENTED_PLAIN: 'hint' });
    expect(find(r, 'missing-from-deploy', 'LOCAL_FALLBACK_URL')[0]!.problem).toContain('silently points at localhost');
  });

  it('lets a validation schema decide when reads disagree', () => {
    const r = service({
      'src/env.ts': "import * as Joi from 'joi';\nexport const schema = Joi.object({ CORS_ORIGIN: Joi.string().default('https://app.example.test') });",
      'src/main.ts': "const origin = config.get('CORS_ORIGIN');",
      '.env.example': 'CORS_ORIGIN=http://localhost:3000\n',
      'copilot/svc/manifest.yml': manifest('variables:\n  OTHER: "1"\n'),
    });
    expect(find(r, 'missing-from-deploy')).toEqual([]);
  });

  it('counts an env_file, a Dockerfile ENV and platform-provided credentials as set', () => {
    const r = service({
      'src/a.ts': "cfg.getOrThrow('FROM_ENV_FILE'); cfg.getOrThrow('FROM_DOCKERFILE'); cfg.getOrThrow('AWS_ACCESS_KEY_ID'); cfg.getOrThrow('AWS_SECRET_ACCESS_KEY');",
      '.env.example': 'FROM_ENV_FILE=1\nFROM_DOCKERFILE=1\nAWS_ACCESS_KEY_ID=x\nAWS_SECRET_ACCESS_KEY=x\n',
      'deploy.env': 'FROM_ENV_FILE=1\n',
      Dockerfile: 'FROM node:22\nENV FROM_DOCKERFILE=1 OTHER=2\n',
      'copilot/svc/manifest.yml': manifest('env_file: deploy.env\n'),
    });
    expect(find(r, 'missing-from-deploy')).toEqual([]);
  });

  it('skips an environment whose env_file is not in the checkout', () => {
    const r = service({ 'src/a.ts': "cfg.getOrThrow('JWT_SECRET');", '.env.example': 'JWT_SECRET=x\n', 'copilot/svc/manifest.yml': manifest('env_file: .env.deploy\n') });
    expect(find(r, 'missing-from-deploy')).toEqual([]);
  });

  it('does not treat a local docker-compose file or a vercel.json env block as deploy coverage', () => {
    const r = service({
      'src/a.ts': "cfg.getOrThrow('JWT_SECRET');",
      '.env.example': 'JWT_SECRET=x\n',
      'docker-compose.yml': 'services:\n  svc:\n    build: .\n    environment:\n      OTHER: "1"\n',
      'vercel.json': '{ "env": { "OTHER": "1" } }',
    });
    expect(find(r, 'missing-from-deploy')).toEqual([]);
  });

  it('does treat a production compose file as a deploy manifest', () => {
    const r = service({
      'src/a.ts': "cfg.getOrThrow('JWT_SECRET'); cfg.getOrThrow('SET_HERE');",
      '.env.example': 'JWT_SECRET=x\nSET_HERE=1\n',
      'docker-compose.prod.yml': 'services:\n  svc:\n    build: .\n    environment:\n      - SET_HERE=1\n',
    });
    expect(find(r, 'missing-from-deploy').map((f) => [f.variable, f.severity, f.env])).toEqual([['JWT_SECRET', 'error', 'prod']]);
  });

  it('sets aside a stray manifest that is not named after the service', () => {
    const r = run(
      workspace({
        'orders/package.json': pkg('orders'),
        'orders/src/a.ts': "cfg.getOrThrow('JWT_SECRET');",
        'orders/.env.example': 'JWT_SECRET=x\n',
        'orders/copilot/orders/manifest.yml': 'name: orders\ntype: Backend Service\nsecrets:\n  JWT_SECRET: /p/JWT_SECRET\n',
        'orders/copilot/mailer/manifest.yml': 'name: mailer\ntype: Backend Service\nvariables:\n  X: "1"\n',
      }),
    );
    expect(find(r, 'missing-from-deploy')).toEqual([]);
    expect(find(r, 'manifest-skipped')[0]).toMatchObject({ severity: 'info', file: 'orders/copilot/mailer/manifest.yml' });
  });
});

describe('(c) URL hygiene', () => {
  it('flags a resource path, a trailing slash, a query and a fragment, with the corrected value', () => {
    const r = service({
      '.env.example': ['A_API_URL=https://a.example.test/v1/notifications/in-app', 'B_SERVICE_URL=https://b.example.test/', 'C_URL=https://c.example.test/v1?debug=1', 'D_BASE_URL=https://d.example.test#x'].join('\n'),
    });
    const got = Object.fromEntries(find(r, 'url-shape').map((f) => [f.variable, f.fix]));
    expect(got).toEqual({
      A_API_URL: 'set A_API_URL=https://a.example.test/v1',
      B_SERVICE_URL: 'set B_SERVICE_URL=https://b.example.test',
      C_URL: 'set C_URL=https://c.example.test/v1',
      D_BASE_URL: 'set D_BASE_URL=https://d.example.test',
    });
    expect(find(r, 'url-shape', 'A_API_URL')[0]).toMatchObject({ severity: 'error', file: 'svc/.env.example', line: 1 });
    expect(find(r, 'url-shape', 'A_API_URL')[0]!.problem).toContain('"/v1/notifications/in-app"');
  });

  it('accepts an origin with or without a version prefix', () => {
    const r = service({ '.env.example': 'A_URL=https://a.example.test\nB_URL=https://b.example.test/v1\nC_URL=http://localhost:4000/api\nD_URL=https://d.example.test/api/v2\n' });
    expect(find(r, 'url-shape')).toEqual([]);
  });

  it.each([
    ['DATABASE_URL', 'https://db.example.test/app/main?sslmode=require'],
    ['DATABASE_URL', 'postgres://u:p@localhost:5432/app?schema=public'],
    ['REDIS_URL', 'redis://localhost:6379/0'],
    ['CACHE_REDIS_URL', 'https://cache.example.test/0/'],
    ['PAYMENT_WEBHOOK_URL', 'https://a.example.test/v1/hooks/payment'],
    ['OAUTH_CALLBACK_URL', 'https://a.example.test/auth/callback?state=1'],
    ['GOOGLE_REDIRECT_URI', 'https://a.example.test/auth/google/redirect/'],
    ['TEMPLATED_URL', 'https://${HOST}/v1/items'],
    ['PLACEHOLDER_URL', 'https://<your-subdomain>.example.test/v1/items'],
    ['YOURS_URL', 'https://your-domain.example.test/v1/items/'],
    ['UNSET_URL', ''],
    ['S3_BUCKET', 'https://bucket.example.test/prefix/'],
  ])('exempts %s=%s', (name, value) => {
    expect(find(service({ '.env.example': `${name}=${value}\n` }), 'url-shape')).toEqual([]);
  });

  it('checks deploy manifests and real env files too, without echoing their values', () => {
    const r = service({
      '.env': 'A_API_URL=https://internal-a.example.test/v1/secret-path/\n',
      'copilot/svc/manifest.yml': manifest('variables:\n  B_API_URL: https://internal-b.example.test/v1/thing\n'),
    });
    const shape = find(r, 'url-shape');
    expect(shape.map((f) => [f.variable, f.file])).toEqual([
      ['A_API_URL', 'svc/.env'],
      ['B_API_URL', 'svc/copilot/svc/manifest.yml'],
    ]);
    expect(JSON.stringify(r)).not.toMatch(/internal-[ab]|secret-path|thing/);
    expect(shape[0]!.fix).toContain('scheme://host[:port]');
  });
});

describe('(d) production pointing at non-production', () => {
  it('flags localhost, staging hosts, tunnels and preview deployments in a prod-named env file', () => {
    const r = service({
      '.env.production': [
        'A_URL=http://localhost:4000',
        'B_URL=https://api-staging.example.test',
        'C_URL=https://shop-git-feature-acme.vercel.app',
        'DATABASE_URL=postgres://u:p@127.0.0.1:5432/app',
        'E_HOST=redis-dev.internal',
        'F_URL=https://abc.ngrok-free.app',
        'GOOD_URL=https://api.example.test',
        'TLD_URL=https://example.dev',
        'CORS_ORIGINS=https://app.example.test,http://localhost:3000',
        'ALIAS_URL=https://shop.vercel.app',
      ].join('\n'),
    });
    const got = Object.fromEntries(find(r, 'prod-points-at-nonprod').map((f) => [f.variable, f.severity]));
    expect(got).toEqual({ A_URL: 'error', B_URL: 'error', C_URL: 'error', DATABASE_URL: 'error', E_HOST: 'error', F_URL: 'error', CORS_ORIGINS: 'hint', ALIAS_URL: 'hint' });
    expect(find(r, 'prod-points-at-nonprod', 'B_URL')[0]!.problem).toContain('"staging"');
  });

  it('flags a production environment in a deploy manifest but not a dev one', () => {
    const r = service({
      'copilot/svc/manifest.yml': manifest(`
variables:
  INHERITED_URL: http://localhost:1
environments:
  dev:
    variables:
      DEV_ONLY_URL: https://api-dev.example.test
  prod:
    variables:
      PROD_URL: https://api-preview.example.test
`),
    });
    expect(find(r, 'prod-points-at-nonprod').map((f) => f.variable).sort()).toEqual(['INHERITED_URL', 'PROD_URL']);
  });

  it('leaves example files and non-production files alone', () => {
    const r = service({ '.env.example': 'A_URL=http://localhost:4000\n', '.env.production.example': 'A_URL=http://localhost:4000\n', '.env.development': 'A_URL=http://localhost:4000\n', '.env': 'A_URL=http://localhost:4000\n' });
    expect(find(r, 'prod-points-at-nonprod')).toEqual([]);
  });

  it('downgrades an env file when a deploy manifest is what ships production', () => {
    const r = service({ '.env.prod': 'A_URL=http://localhost:4000\n', 'copilot/svc/manifest.yml': manifest('environments:\n  prod:\n    variables:\n      A_URL: https://a.example.test\n') });
    expect(find(r, 'prod-points-at-nonprod').map((f) => [f.file, f.severity])).toEqual([['svc/.env.prod', 'hint']]);
  });
});

describe('(e) cross-service hints', () => {
  const two = (extra: Record<string, string> = {}) =>
    run(
      workspace({
        'web/package.json': pkg('web'),
        'web/.env.example': 'ORDERS_API_URL=http://localhost:4001\nSEARCH_URL=http://localhost:9999\nSHARED_SIGNING_SECRET=dev-value-aaaaaaaa\nSTRIPE_SECRET_KEY=sk_test_1\n',
        'orders/package.json': pkg('orders'),
        'orders/.env.example': 'PORT=4001\nSHARED_SIGNING_SECRET=dev-value-bbbbbbbb\nSTRIPE_SECRET_KEY=sk_test_2\n',
        ...extra,
      }),
    );

  it('records an edge when a local URL targets another service port', () => {
    const r = two();
    expect(r.edges).toEqual([{ from: 'web', to: 'orders', variable: 'ORDERS_API_URL', file: 'web/.env.example', port: 4001 }]);
  });

  it('does not guess when two services claim the same port', () => {
    const r = two({ 'other/package.json': pkg('other'), 'other/.env.example': 'PORT=4001\n' });
    expect(r.edges).toEqual([]);
  });

  it('takes ports from compose, package scripts and code fallbacks, and matches compose hostnames', () => {
    const r = run(
      workspace({
        'docker-compose.yml': 'services:\n  api:\n    build: ./api\n    ports:\n      - "7001:3000"\n  cache:\n    image: redis:7\n',
        'api/package.json': pkg('api'),
        'web/package.json': JSON.stringify({ name: 'web', scripts: { dev: 'next dev -p 7002' } }),
        'web/.env.example': 'API_URL=http://localhost:7001\nINTERNAL_API_URL=http://api:3000\nWORKER_URL=http://localhost:7003\n',
        'worker/package.json': pkg('worker'),
        'worker/src/main.ts': 'app.listen(process.env.PORT || 7003);',
        'worker/.env.example': 'WEB_URL=http://localhost:7002\n',
      }),
    );
    expect(r.edges.map((e) => `${e.from}>${e.to}:${e.variable}`)).toEqual(['web>api:API_URL', 'web>api:INTERNAL_API_URL', 'web>worker:WORKER_URL', 'worker>web:WEB_URL']);
  });

  it('suggests that a same-named secret is meant to match, as a suggestion only', () => {
    const r = two();
    const hints = find(r, 'shared-secret');
    expect(hints).toHaveLength(1);
    expect(hints[0]).toMatchObject({ severity: 'hint', variable: 'SHARED_SIGNING_SECRET', service: 'orders + web' });
    expect(hints[0]!.problem).toContain('example values already differ');
    expect(hints[0]!.problem).toContain('call each other');
    expect(r.summary.failures).toBe(0);
    expect(JSON.stringify(r.findings)).not.toContain('dev-value');
  });

  it('notices different secret-store references and the same example value under two names', () => {
    const r = run(
      workspace({
        'a/package.json': pkg('a'),
        'a/.env.example': 'INTERNAL_SERVICE_KEY=dev-internal-key-123456\n',
        'a/copilot/a/manifest.yml': 'name: a\ntype: Backend Service\nsecrets:\n  JWT_SECRET: /app/prod/A_JWT\n',
        'b/package.json': pkg('b'),
        'b/.env.example': 'ORDERS_SERVICE_KEY=dev-internal-key-123456\n',
        'b/copilot/b/manifest.yml': 'name: b\ntype: Backend Service\nsecrets:\n  JWT_SECRET: /app/prod/B_JWT\n',
      }),
    );
    const hints = find(r, 'shared-secret');
    expect(hints.map((h) => h.variable).sort()).toEqual(['INTERNAL_SERVICE_KEY / ORDERS_SERVICE_KEY', 'JWT_SECRET']);
    expect(find(r, 'shared-secret', 'JWT_SECRET')[0]!.problem).toContain('different secret-store entries');
    expect(JSON.stringify(r)).not.toMatch(/A_JWT|B_JWT/);
    expect(r.summary.failures).toBe(0);
  });
});

describe('noise control', () => {
  it('honours a suppression that carries a reason, in all three forms', () => {
    const r = service({
      'src/a.ts': 'process.env.NOT_LISTED_KEY;',
      '.env.example': [
        'CATALOG_URL=https://catalog.example.test/v1/items.xml # wirecheck-ignore: third-party catalog, full path intended',
        '# wirecheck-ignore: vendor requires the trailing slash',
        'VENDOR_URL=https://vendor.example.test/',
        '# wirecheck-ignore NOT_LISTED_KEY: injected by the test harness only',
      ].join('\n'),
    });
    expect(r.findings).toEqual([]);
    expect(r.summary.suppressed).toBe(3);
  });

  it('refuses a suppression without a reason and still reports the finding', () => {
    const r = service({ '.env.example': 'CATALOG_URL=https://catalog.example.test/v1/items.xml # wirecheck-ignore\n' });
    expect(r.findings.map((f) => f.check).sort()).toEqual(['suppression-without-reason', 'url-shape']);
    expect(find(r, 'suppression-without-reason')[0]).toMatchObject({ severity: 'error', variable: 'CATALOG_URL', line: 1 });
  });

  it('keeps a suppression local to its own service', () => {
    const r = run(
      workspace({
        'a/package.json': pkg('a'),
        'a/.env.example': 'X_URL=https://x.example.test/ # wirecheck-ignore: intended here\n',
        'b/package.json': pkg('b'),
        'b/.env.example': 'X_URL=https://x.example.test/\n',
      }),
    );
    expect(find(r, 'url-shape').map((f) => f.service)).toEqual(['b']);
  });
});
