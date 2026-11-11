import { describe, expect, it } from 'vitest';
import { check, renderGithub, renderHuman, renderMarkdown } from '../src/index.js';
import { cli, fakeCloud, json, LEAK, type FakeCloud } from './fakecloud.js';
import { fixture } from './helpers.js';

/**
 * Distinctive strings stand in for every kind of secret wirelint can touch:
 * live values, credentials, tokens and upstream error bodies. None of them
 * may appear in any output, in either success or failure paths.
 */

const ENV = {
  AWS_ACCESS_KEY_ID: LEAK('access-key-id'),
  AWS_SECRET_ACCESS_KEY: LEAK('secret-access-key'),
  AWS_SESSION_TOKEN: LEAK('session-token'),
  AWS_REGION: 'eu-west-1',
  VERCEL_TOKEN: 'vercel-token-UNIQUE-7f3a',
  GITHUB_ACTIONS: 'true',
  GITHUB_WORKSPACE: fixture('live'),
};

function secretCloud(): FakeCloud {
  const p: Record<string, string> = {};
  for (const env of ['dev', 'prod']) {
    p[`/copilot/demo/${env}/secrets/JWT_SECRET`] = LEAK(`orders-jwt-${env}`);
    p[`/copilot/demo/${env}/secrets/IDENTITY_JWT_SECRET`] = LEAK(`identity-jwt-${env}`);
    p[`/copilot/demo/${env}/secrets/SESSION_SECRET`] = LEAK(`session-${env}`);
  }
  p['/copilot/demo/dev/secrets/SIGNING_KEY'] = LEAK('signing-dev');
  return fakeCloud({
    params: { 'eu-west-1': p },
    projects: {
      prj_demoweb0000: [
        { id: 'env_1', key: 'ORDERS_API_URL', target: ['production'], type: 'plain', value: `https://${LEAK('plain-url')}.example.test` },
        { id: 'env_2', key: 'SESSION_SECRET', target: ['production'], type: 'encrypted', value: LEAK('vercel-session') },
        { id: 'env_3', key: 'NEXT_PUBLIC_SITE_NAME', target: ['production', 'preview', 'development'], type: 'sensitive', value: LEAK('vercel-sensitive') },
      ],
    },
  });
}

const ALL = ['--live', 'ssm,vercel', '--compare', '--probe', fixture('live')];

function assertClean(text: string, cloud: FakeCloud): void {
  expect(text).not.toContain('LEAK-');
  expect(text).not.toContain(cloud.vercelToken);
  expect(text).not.toContain('9c41e7');
  // No digest or signature-sized hex, no parameter paths, no probed host.
  expect(text).not.toMatch(/[0-9a-f]{64}/);
  expect(text).not.toContain('/copilot/demo/');
  expect(text).not.toContain('demo.example.test');
  expect(text).not.toContain('000000000000');
}

async function everyOutput(cloud: FakeCloud, args = ALL): Promise<string> {
  const human = await cli(args, { env: ENV, net: cloud });
  const asJson = await cli(['--json', ...args], { env: ENV, net: cloud });
  const report = json(asJson);
  return [human.out, human.err, asJson.out, asJson.err, renderHuman(report), renderGithub(report, fixture('live')), renderMarkdown(report)].join('\n');
}

describe('leaks', () => {
  it('shows no value, token, credential, digest or address when everything answers', async () => {
    const cloud = secretCloud();
    cloud.intercept = (c) => (c.url.host.endsWith('demo.example.test') ? new Response(`hello from ${LEAK('probe-body')}`, { status: 200 }) : undefined);
    const text = await everyOutput(cloud);
    expect(text).toContain('VALUE COMPARISONS');
    expect(text).toContain('::error ');
    assertClean(text, cloud);
  });

  it('shows no upstream error body, whatever the failure', async () => {
    for (const status of [400, 401, 403, 404, 429, 500]) {
      const cloud = secretCloud();
      const body = JSON.stringify({ __type: `x#${LEAK('type')}`, message: LEAK('aws-message'), error: { code: LEAK('vercel-code'), message: LEAK('vercel-message') } });
      cloud.intercept = () => new Response(body, { status, headers: { 'x-amzn-errortype': LEAK('header') } });
      assertClean(await everyOutput(cloud), cloud);
    }
  });

  it('shows nothing from thrown network errors, and check() does not reject with one', async () => {
    const cloud = secretCloud();
    cloud.intercept = () => {
      throw Object.assign(new Error(`connect to ${LEAK('thrown-host')} with ${LEAK('thrown-token')}`), { code: LEAK('code'), cause: new Error(LEAK('cause')) });
    };
    assertClean(await everyOutput(cloud), cloud);
    let rejected: unknown = null;
    await check(fixture('live'), new Set(), { live: { adapters: ['ssm', 'vercel'], compare: true, env: ENV }, probe: { path: '/health', timeoutMs: 1000, strict: true } }, cloud).catch((e: unknown) => (rejected = e));
    expect(rejected).toBeNull();
  });

  it('shows nothing from a non-JSON or truncated answer', async () => {
    const cloud = secretCloud();
    cloud.intercept = () => new Response(`<html>${LEAK('html')}</html>`, { status: 200 });
    assertClean(await everyOutput(cloud), cloud);
  });
});
