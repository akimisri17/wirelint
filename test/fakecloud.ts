import { main } from '../src/main.js';
import type { Net } from '../src/net.js';
import type { Report } from '../src/types.js';

/**
 * A simulated AWS SSM and Vercel API behind a fake fetch. No request leaves
 * the process. Built from the documented request and response shapes; it is
 * only as faithful as that reading of the docs.
 */

export interface VercelEnvVar {
  id: string;
  key: string;
  target: string[] | string;
  type: 'plain' | 'encrypted' | 'sensitive' | 'secret' | 'system';
  value: string;
  gitBranch?: string;
}

export interface Call {
  url: URL;
  method: string;
  headers: Record<string, string>;
  target?: string;
  body?: Record<string, unknown>;
}

export interface FakeCloud extends Net {
  /** SSM parameters by region, then name -> value. */
  params: Record<string, Record<string, string>>;
  /** DescribeParameters page size, to force NextToken pagination. */
  pageSize: number;
  /** Vercel projects by id. */
  projects: Record<string, VercelEnvVar[]>;
  vercelToken: string;
  /** Vercel env list page size, to force pagination. */
  vercelPageSize: number;
  calls: Call[];
  /** Return a Response to short-circuit a call (errors, throttling); undefined to answer normally. */
  intercept?: (call: Call) => Response | Promise<Response> | undefined;
}

const reply = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

export function fakeCloud(init: Partial<Pick<FakeCloud, 'params' | 'projects' | 'pageSize' | 'vercelPageSize'>> = {}): FakeCloud {
  const cloud: FakeCloud = {
    params: init.params ?? {},
    pageSize: init.pageSize ?? 50,
    projects: init.projects ?? {},
    vercelToken: 'vercel-token-UNIQUE-7f3a',
    vercelPageSize: init.vercelPageSize ?? 100,
    calls: [],
    sleep: async () => undefined,
    fetch: async (input, reqInit) => {
      const url = new URL(String(input));
      const headers = Object.fromEntries(Object.entries((reqInit?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]));
      const call: Call = { url, method: reqInit?.method ?? 'GET', headers };
      if (headers['x-amz-target']) call.target = headers['x-amz-target'];
      if (typeof reqInit?.body === 'string') call.body = JSON.parse(reqInit.body) as Record<string, unknown>;
      cloud.calls.push(call);
      const short = await cloud.intercept?.(call);
      if (short) return short;
      if (/^ssm\.[a-z0-9-]+\.amazonaws\.com$/.test(url.host)) return ssm(cloud, call);
      if (url.host === 'api.vercel.com') return vercel(cloud, call);
      throw Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' }) });
    },
  };
  return cloud;
}

function ssm(cloud: FakeCloud, call: Call): Response {
  const region = call.url.host.split('.')[1]!;
  if (call.method !== 'POST' || !/^AWS4-HMAC-SHA256 Credential=[^/]+\/\d{8}\/[a-z0-9-]+\/ssm\/aws4_request, SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$/.test(call.headers['authorization'] ?? '')) {
    return reply(400, { __type: 'com.amazon.coral.service#IncompleteSignatureException', message: 'bad signature' });
  }
  const store = cloud.params[region] ?? {};
  const body = call.body ?? {};
  if (call.target === 'AmazonSSM.DescribeParameters') {
    const filter = (body['ParameterFilters'] as { Key: string; Option: string; Values: string[] }[])[0]!;
    const matches = Object.keys(store).filter((n) => filter.Values.includes(n)).sort();
    const start = body['NextToken'] ? Number(body['NextToken']) : 0;
    const page = matches.slice(start, start + cloud.pageSize);
    const next = start + cloud.pageSize < matches.length ? String(start + cloud.pageSize) : undefined;
    return reply(200, { Parameters: page.map((Name) => ({ Name, Type: 'SecureString', Version: 1 })), ...(next ? { NextToken: next } : {}) });
  }
  if (call.target === 'AmazonSSM.GetParameters') {
    const names = body['Names'] as string[];
    return reply(200, {
      Parameters: names.filter((n) => n in store).map((Name) => ({ Name, Type: 'SecureString', Value: store[Name], Version: 1 })),
      InvalidParameters: names.filter((n) => !(n in store)),
    });
  }
  return reply(400, { __type: 'InvalidAction', message: 'unsupported' });
}

function vercel(cloud: FakeCloud, call: Call): Response {
  if (call.method !== 'GET') return reply(405, { error: { code: 'method_not_allowed', message: 'read-only fake' } });
  if (call.headers['authorization'] !== `Bearer ${cloud.vercelToken}`) return reply(401, { error: { code: 'forbidden', message: 'Not authorized', invalidToken: true } });
  const list = /^\/v10\/projects\/([^/]+)\/env$/.exec(call.url.pathname);
  const one = /^\/v1\/projects\/([^/]+)\/env\/([^/]+)$/.exec(call.url.pathname);
  const id = decodeURIComponent((list ?? one)?.[1] ?? '');
  const envs = cloud.projects[id];
  if (!envs) return reply(404, { error: { code: 'not_found', message: `Project ${id} not found` } });
  if (list) {
    const start = Number(call.url.searchParams.get('until') ?? 0);
    const page = envs.slice(start, start + cloud.vercelPageSize);
    const next = start + cloud.vercelPageSize < envs.length ? start + cloud.vercelPageSize : null;
    // Listing never decrypts: encrypted and sensitive values come back as ciphertext or not at all; plain ones are plain.
    return reply(200, {
      envs: page.map((e) => ({ id: e.id, key: e.key, target: e.target, type: e.type, ...(e.gitBranch ? { gitBranch: e.gitBranch } : {}), ...(e.type === 'sensitive' ? {} : { value: e.type === 'plain' ? e.value : `ciphertext:${e.id}` }) })),
      pagination: { count: page.length, next, prev: null },
    });
  }
  const env = envs.find((e) => e.id === decodeURIComponent(one![2]!));
  if (!env) return reply(404, { error: { code: 'not_found', message: 'Environment variable not found' } });
  return reply(200, { id: env.id, key: env.key, target: env.target, type: env.type, ...(env.type === 'sensitive' ? {} : { value: env.value }), decrypted: env.type !== 'sensitive' });
}

/** A distinctive string that must never appear in any output. */
export const LEAK = (label: string) => `LEAK-${label}-9c41e7`;

export const AWS = { AWS_ACCESS_KEY_ID: 'AKIDEXAMPLE', AWS_SECRET_ACCESS_KEY: LEAK('aws-secret'), AWS_SESSION_TOKEN: LEAK('aws-session'), AWS_REGION: 'eu-west-1' };

/** The CLI with an explicit environment and a fake network: nothing real is read or reached. */
export async function cli(args: string[], opts: { env?: Record<string, string>; net?: Net } = {}) {
  let out = '';
  let err = '';
  const code = await main(args, { stdout: (s) => void (out += s), stderr: (s) => void (err += s), env: opts.env ?? {}, cwd: process.cwd(), columns: 200, net: opts.net ?? fakeCloud() });
  return { code, out, err };
}

export const json = (r: { out: string }) => JSON.parse(r.out) as Report;

/** Every SSM reference in the live fixture exists, except orders' JWT_SECRET in dev. */
export function demoParams(): FakeCloud['params'] {
  const p: Record<string, string> = {
    '/copilot/demo/prod/secrets/JWT_SECRET': LEAK('orders-jwt-prod'),
    '/copilot/demo/dev/secrets/SIGNING_KEY': LEAK('signing-dev'),
    '/demo/prod/SIGNING_KEY': LEAK('signing-prod'),
    '/copilot/demo/dev/secrets/IDENTITY_JWT_SECRET': LEAK('identity-jwt-dev'),
    '/copilot/demo/prod/secrets/IDENTITY_JWT_SECRET': LEAK('identity-jwt-prod'),
    '/copilot/demo/dev/secrets/SESSION_SECRET': LEAK('session-dev'),
    '/copilot/demo/prod/secrets/SESSION_SECRET': LEAK('session-prod'),
  };
  return { 'eu-west-1': p };
}

