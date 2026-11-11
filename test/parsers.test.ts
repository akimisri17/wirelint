import { describe, expect, it } from 'vitest';
import { parseEnv } from '../src/dotenv.js';
import { isBaseUrlVar, isPlatformVar, isSecretLooking } from '../src/names.js';
import { scanSource } from '../src/reads.js';
import { checkUrlShape, classifyHost, extractHost, isPlaceholder } from '../src/url.js';
import { parseYaml } from '../src/yaml.js';

const kinds = (src: string) => Object.fromEntries(scanSource(src).reads.map((r) => [r.name, r.kind]));

describe('env file parser', () => {
  it('reads plain, quoted, exported and commented-out entries', () => {
    const { entries } = parseEnv(`A=1\nexport B="two words" # note\nC='x#y'\n# D=\n#not a var\nE=bare # trailing`);
    expect(entries.map((e) => [e.name, e.value, e.commented])).toEqual([
      ['A', '1', false],
      ['B', 'two words', false],
      ['C', 'x#y', false],
      ['D', '', true],
      ['E', 'bare', false],
    ]);
  });

  it('attaches ignore markers inline, from the line above, or by name', () => {
    const { ignores, badIgnores } = parseEnv(
      ['A=1 # wirelint-ignore: inline reason', '# wirelint-ignore: reason above', 'B=2', '# wirelint-ignore C: named reason', 'D=4 # wirelint-ignore', '# wirelint-ignore:'].join('\n'),
    );
    expect(ignores.map((i) => [i.name, i.reason])).toEqual([
      ['A', 'inline reason'],
      ['B', 'reason above'],
      ['C', 'named reason'],
    ]);
    expect(badIgnores).toHaveLength(2);
  });
});

describe('yaml subset', () => {
  it('reads nested maps, both sequence styles, flow collections and comments', () => {
    const doc = parseYaml(`
name: api  # trailing comment
variables:
  A_URL: "https://a.example.test/#frag"
  B: plain value
environments:
  prod:
    secrets:
      S: /path/\${ENV}/S
list:
- one
- two
ports: ["80:80", '443:443']
items:
  - name: x
    value: 1
  - name: y
inline: { a: 1, b: [2, 3] }
`);
    expect(doc).toEqual({
      name: 'api',
      variables: { A_URL: 'https://a.example.test/#frag', B: 'plain value' },
      environments: { prod: { secrets: { S: '/path/${ENV}/S' } } },
      list: ['one', 'two'],
      ports: ['80:80', '443:443'],
      items: [{ name: 'x', value: '1' }, { name: 'y' }],
      inline: { a: '1', b: ['2', '3'] },
    });
  });

  it('resolves anchors and merge keys, and skips block scalars', () => {
    const doc = parseYaml(`
x-common: &common
  SHARED: "1"
services:
  api:
    environment:
      <<: *common
      OWN: "2"
    command: |
      echo "KEY: not a key"
    image: x
`) as { services: { api: Record<string, unknown> } };
    expect(doc.services.api.environment).toEqual({ SHARED: '1', OWN: '2' });
    expect(doc.services.api.image).toBe('x');
  });

  it('never throws on input it cannot read', () => {
    expect(() => parseYaml(':\n\t- [unclosed\n  }{')).not.toThrow();
  });
});

describe('source scanner', () => {
  it('finds every supported read form', () => {
    const { reads } = scanSource(`
      const a = process.env.A_ONE;
      const b = process.env['B_TWO'];
      const c = process.env?.C_THREE;
      const d = import.meta.env.VITE_D;
      const { E_FIVE, F_SIX: renamed, G_SEVEN = 'x' } = process.env;
      const h = this.configService.get<string>('H_EIGHT');
      const i = config.getOrThrow('I_NINE');
      const j = Deno.env.get('J_TEN');
    `);
    expect(reads.map((r) => r.name).sort()).toEqual(['A_ONE', 'B_TWO', 'C_THREE', 'E_FIVE', 'F_SIX', 'G_SEVEN', 'H_EIGHT', 'I_NINE', 'J_TEN', 'VITE_D']);
  });

  it('ignores comments but not strings, and keeps line numbers', () => {
    const { reads } = scanSource(`// process.env.IN_LINE_COMMENT\n/* process.env.IN_BLOCK\n*/\nconst u = "http://x"; const v = process.env.REAL;`);
    expect(reads).toEqual([{ name: 'REAL', line: 4, kind: 'plain', schema: false }]);
  });

  it('does not treat non-config .get() calls or dotted keys as env reads', () => {
    expect(scanSource(`map.get('NOT_ENV'); this.configService.get('database.host'); headers.get('X_TOKEN');`).reads).toEqual([]);
  });

  it('reports computed reads separately', () => {
    const scan = scanSource('const k = process.env[name];\nconst t = process.env[`PREFIX_${x}`];');
    expect(scan.reads).toEqual([]);
    expect(scan.dynamic).toEqual([1, 2]);
  });

  it('classifies how the code copes with an unset variable', () => {
    expect(
      kinds(`
        const a = process.env.WITH_DEFAULT || 'x';
        const b = process.env.WITH_NULLISH ?? 5;
        const c = process.env.LOCAL_FALLBACK ?? 'http://localhost:3000';
        const d = process.env.ASSERTED!;
        const e = process.env.COMPARED === 'true';
        const f = process.env.CHAINED?.trim();
        const g = process.env.FIRST || process.env.SECOND || 'http://localhost:1';
        const n = Number(process.env.NUMERIC);
        const p = process.env.BARE;
        const q = cfg.get('GET_DEFAULT', 'x');
        const r = cfg.get('GET_LOCAL', 'http://127.0.0.1:9');
        const s = cfg.getOrThrow('GET_THROW');
        const guarded = process.env.GUARDED;
        if (!guarded) throw new Error('missing');
        const soft = process.env.SOFT;
        if (!soft) return;
      `),
    ).toEqual({
      WITH_DEFAULT: 'default',
      WITH_NULLISH: 'default',
      LOCAL_FALLBACK: 'localdefault',
      ASSERTED: 'required',
      COMPARED: 'flag',
      CHAINED: 'flag',
      FIRST: 'default',
      SECOND: 'default',
      NUMERIC: 'default',
      BARE: 'plain',
      GET_DEFAULT: 'default',
      GET_LOCAL: 'localdefault',
      GET_THROW: 'required',
      GUARDED: 'required',
      SOFT: 'flag',
    });
  });

  it('reads zod, Joi and envalid schema keys with their optionality', () => {
    expect(
      kinds(`import { z } from 'zod';
        z.object({ Z_REQ: z.string(), Z_OPT: z.string().optional(), Z_DEF: z.coerce.number().default(3),
          Z_MULTI: z
            .string()
            .url(), Z_LOCAL: z.string().default('http://localhost:1') });`),
    ).toEqual({ Z_REQ: 'required', Z_OPT: 'default', Z_DEF: 'default', Z_MULTI: 'required', Z_LOCAL: 'localdefault' });
    expect(kinds(`import * as Joi from 'joi';\nJoi.object({ J_REQ: Joi.string().required(), J_OPT: Joi.string(), J_DEF: Joi.number().default(1) });`)).toEqual({
      J_REQ: 'required',
      J_OPT: 'default',
      J_DEF: 'default',
    });
    expect(kinds(`import { cleanEnv, str, port } from 'envalid';\ncleanEnv(process.env, { E_REQ: str(), E_DEF: port({ default: 3000 }) });`)).toEqual({
      E_REQ: 'required',
      E_DEF: 'default',
    });
  });

  it('does not mistake unrelated helpers for a schema', () => {
    expect(scanSource(`export const env = { API_URL: url(extra.apiUrl), NAME: str(x), SIZE: z.width };`).reads).toEqual([]);
  });
});

describe('url rules', () => {
  it.each([
    ['https://api.example.test', null],
    ['https://api.example.test/v1', null],
    ['https://api.example.test/api', null],
    ['https://api.example.test/api/v2', null],
    ['http://localhost:4000', null],
    ['postgres://u:p@db:5432/app', null],
    ['not a url', null],
    ['https://api.example.test/', ['trailing-slash']],
    ['https://api.example.test/v1/', ['trailing-slash']],
    ['https://api.example.test/v1/users', ['resource-path']],
    ['https://api.example.test/notifications/in-app', ['resource-path']],
    ['https://api.example.test/v1?x=1', ['query']],
    ['https://api.example.test#top', ['fragment']],
    ['https://api.example.test/v1/users/?a=1', ['query', 'trailing-slash', 'resource-path']],
  ])('%s -> %j', (value, codes) => {
    expect(checkUrlShape(value)?.codes ?? null).toEqual(codes);
  });

  it('suggests the origin plus any version prefix', () => {
    expect(checkUrlShape('https://api.example.test/api/v1/notifications/in-app')?.suggested).toBe('https://api.example.test/api/v1');
    expect(checkUrlShape('https://api.example.test/users/')?.suggested).toBe('https://api.example.test');
  });

  it.each(['', '${API_URL}', '$API_URL', '<your-url>', 'https://your-domain.example.test', '{{ url }}', 'https://xxxx.example.test', 'changeme'])(
    'treats %j as a placeholder',
    (v) => expect(isPlaceholder(v)).toBe(true),
  );

  it.each([
    ['localhost', 'local'],
    ['127.0.0.1', 'local'],
    ['host.docker.internal', 'local'],
    ['api.example.test', 'ok'],
    ['myapp.dev', 'ok'],
    ['10.0.3.4', 'ok'],
    ['api-staging.example.test', 'nonprod'],
    ['dev.example.test', 'nonprod'],
    ['sandbox.pay.example.test', 'nonprod'],
    ['shop-git-feature-x-acme.vercel.app', 'vercel-preview'],
    ['shop-k3j2h1g9f-acme.vercel.app', 'vercel-preview'],
    ['shop.vercel.app', 'vercel-default'],
    ['abc123.ngrok-free.app', 'tunnel'],
  ])('host %s is %s', (host, klass) => expect(classifyHost(host).klass).toBe(klass));

  it('extracts hosts from urls, connection strings and bare hosts', () => {
    expect(extractHost('postgres://user:pw@localhost:5432/db')).toMatchObject({ host: 'localhost', port: 5432 });
    expect(extractHost('https://api.example.test/v1')).toMatchObject({ host: 'api.example.test' });
    expect(extractHost('redis-staging.internal:6379')).toMatchObject({ klass: 'nonprod', port: 6379 });
  });
});

describe('name rules', () => {
  it('knows which names are base URLs', () => {
    for (const n of ['API_URL', 'NEXT_PUBLIC_ORDERS_API_URL', 'BILLING_SERVICE_URL', 'APP_BASE_URL']) expect(isBaseUrlVar(n), n).toBe(true);
    for (const n of ['DATABASE_URL', 'DATABASE_URL_UNPOOLED', 'REDIS_URL', 'CACHE_REDIS_URL', 'STRIPE_WEBHOOK_URL', 'OAUTH_CALLBACK_URL', 'GOOGLE_REDIRECT_URI', 'OAUTH_REDIRECT_URL', 'SENTRY_DSN', 'CURLY', 'API_KEY']) {
      expect(isBaseUrlVar(n), n).toBe(false);
    }
  });

  it('knows platform variables and secret-looking names', () => {
    for (const n of ['NODE_ENV', 'PORT', 'CI', 'GITHUB_SHA', 'VERCEL_URL', 'npm_package_version', 'COPILOT_ENVIRONMENT_NAME', 'AWS_REGION']) expect(isPlatformVar(n), n).toBe(true);
    expect(isPlatformVar('JWT_SECRET')).toBe(false);
    for (const n of ['JWT_SECRET', 'INTERNAL_SERVICE_KEY', 'API_TOKEN', 'DB_PASSWORD']) expect(isSecretLooking(n), n).toBe(true);
    for (const n of ['NEXT_PUBLIC_MAPS_KEY', 'TOKEN_TTL', 'JWT_EXPIRES_IN', 'KEYCLOAK_URL', 'API_URL']) expect(isSecretLooking(n), n).toBe(false);
  });
});

describe('fallback chains', () => {
  it('finds chains across env reads and classifies the chain as a whole', () => {
    const scan = scanSource(`
      const a = process.env.A_ONE ?? process.env.A_TWO ?? 'http://localhost:1';
      const b = process.env['B_ONE'] || process.env.B_TWO;
      const c = (process.env.C_ONE ?? process.env.C_TWO) ?? 'https://c.example.test';
      const d = process.env.D_ONE ?? other ?? process.env.D_TWO;
      const e = process.env.E_ONE ?? process.env.E_ONE;
    `);
    expect(scan.chains).toEqual([
      { names: ['A_ONE', 'A_TWO'], line: 2, kind: 'localdefault' },
      { names: ['B_ONE', 'B_TWO'], line: 3, kind: 'plain' },
      { names: ['C_ONE', 'C_TWO'], line: 4, kind: 'default' },
    ]);
    // Each member keeps the kind v0 gave it.
    expect(scan.reads.length).toBe(10);
    expect(Object.fromEntries(scan.reads.map((r) => [r.name, r.kind]))).toMatchObject({ A_ONE: 'default', A_TWO: 'default', B_ONE: 'default', B_TWO: 'default' });
  });
});

describe('fallback chain members must be bare reads', () => {
  it.each([
    ['isSet(process.env.A_ONE) || process.env.A_TWO'],
    ['const x = !process.env.A_ONE || process.env.A_TWO;'],
    ['const x = flag === process.env.A_ONE || process.env.A_TWO;'],
    ['const x = process.env.A_ONE || process.env.A_TWO.trim();'],
    ['const x = process.env.A_ONE || process.env.A_TWO === "1";'],
    ['const x = ok && process.env.A_ONE || process.env.A_TWO;'],
    ['const x = f(process.env.A_ONE) ?? process.env.A_TWO;'],
  ])('no chain in %s', (src) => {
    expect(scanSource(src).chains).toEqual([]);
  });

  it.each([
    ['isSet(process.env.A_ONE ?? process.env.A_TWO)', 'plain'],
    ['return process.env.A_ONE || process.env.A_TWO;', 'plain'],
    ['const x = ((process.env.A_ONE) ?? process.env.A_TWO) ?? "http://localhost:1";', 'localdefault'],
    ['const f = () => process.env.A_ONE ?? process.env.A_TWO;', 'plain'],
  ])('a chain in %s', (src, kind) => {
    expect(scanSource(src).chains).toEqual([{ names: ['A_ONE', 'A_TWO'], line: 1, kind }]);
  });
});
