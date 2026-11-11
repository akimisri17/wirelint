import { createHash } from 'node:crypto';
import path from 'node:path';
import { deployTargetsOf, type Analysis } from './analyze.js';
import { readText } from './fsutil.js';
import { Http, type HttpOptions, type Net } from './net.js';
import type { AwsCredentials } from './sigv4.js';
import { REGION_RE, Ssm, type SsmFailure } from './ssm.js';
import type { Finding, LiveAdapterName, LiveAdapterStatus, LiveCheck, LiveSummary, Service, Severity } from './types.js';
import { asMap, asString, parseYaml } from './yaml.js';

/**
 * v2 live checks, opt-in per run. Read-only: SSM DescribeParameters (names
 * only) and, for --compare, GetParameters. Only names, existence and
 * verdicts leave this module; credentials, values and digests never do.
 */

export interface LiveOptions {
  adapters: LiveAdapterName[];
  compare?: boolean;
  /** Restrict to these Copilot environments. */
  envs?: string[];
  /** Overrides AWS_REGION / AWS_DEFAULT_REGION. */
  region?: string;
  /** The process environment: the only place credentials are read from. */
  env: Record<string, string | undefined>;
  now?: () => Date;
  http?: Partial<HttpOptions>;
}

export interface LiveResult {
  findings: Finding[];
  suppressed: number;
  live: LiveSummary;
}

const HTTP_DEFAULTS: HttpOptions = { timeoutMs: 10_000, retries: 3, concurrency: 4 };

type FindingInput = { check: string; severity: Severity; variable: string; file: string; line?: number; env?: string; anchor?: string; problem: string; fix: string };

/** Findings for one run, fingerprinted the same way as the file-based checks. */
export class FindingSink {
  findings: Finding[] = [];
  suppressed = 0;

  push(svc: Service | null, service: string, f: FindingInput): void {
    if (svc?.suppress.has(f.variable)) {
      this.suppressed++;
      return;
    }
    const fingerprint = createHash('sha256')
      .update([f.check, service, f.variable, f.anchor ?? f.file, f.env ?? ''].join('|'))
      .digest('hex')
      .slice(0, 16);
    this.findings.push({ fingerprint, check: f.check, severity: f.severity, service, variable: f.variable, file: f.file, line: f.line, env: f.env, problem: f.problem, fix: f.fix });
  }
}

/** One secret reference in a Copilot manifest, resolved for one environment. Held in memory only. */
export interface ParamRef {
  svc: Service;
  variable: string;
  file: string;
  env: string;
  /** `secrets.X` or `environments.<env>.secrets.X`: where the reference sits in the manifest. */
  where: string;
  region: string;
  /** The parameter name. Never rendered. */
  name: string;
}

/** The Copilot application name, from copilot/.workspace. */
function copilotApp(svc: Service): string | null {
  for (const dir of [svc.dir, svc.parentDir].filter((d): d is string => !!d)) {
    const text = readText(path.join(dir, 'copilot', '.workspace'));
    const app = text ? asString(asMap(parseYaml(text))?.['application']) : null;
    if (app) return app;
  }
  return null;
}

/** A manifest secret reference as an SSM parameter name, or why it is not checked. */
export function resolveRef(ref: string, env: string, app: string | null, region: string): { name: string; region: string } | { reason: string } {
  const r = ref.trim();
  if (r.startsWith('{')) {
    let obj: Record<string, unknown> | null = null;
    try {
      obj = JSON.parse(r) as Record<string, unknown>;
    } catch {
      // not an object after all
    }
    if (obj && 'secretsmanager' in obj) return { reason: 'references AWS Secrets Manager (secretsmanager:), which wirelint does not check' };
    if (obj && 'from_cfn' in obj) return { reason: 'comes from a CloudFormation export (from_cfn:), which wirelint does not check' };
    return { reason: 'is not an SSM parameter name' };
  }
  if (/^arn:[\w-]+:secretsmanager:/.test(r)) return { reason: 'references an AWS Secrets Manager ARN, which wirelint does not check' };
  const arn = /^arn:[\w-]+:ssm:([a-z0-9-]+):\d*:parameter\/(.+)$/.exec(r);
  let name = arn ? (arn[2]!.includes('/') ? `/${arn[2]}` : arn[2]!) : r;
  const where = arn && REGION_RE.test(arn[1]!) ? arn[1]! : region;
  if (name.includes('${COPILOT_ENVIRONMENT_NAME}')) {
    if (env === '*') return { reason: 'uses ${COPILOT_ENVIRONMENT_NAME}, but the manifest names no environment' };
    name = name.replaceAll('${COPILOT_ENVIRONMENT_NAME}', env);
  }
  if (name.includes('${COPILOT_APPLICATION_NAME}')) {
    if (!app) return { reason: 'uses ${COPILOT_APPLICATION_NAME}, but copilot/.workspace is not in the checkout' };
    name = name.replaceAll('${COPILOT_APPLICATION_NAME}', app);
  }
  if (name.includes('${')) return { reason: 'uses a variable other than ${COPILOT_ENVIRONMENT_NAME} or ${COPILOT_APPLICATION_NAME}, which wirelint cannot resolve' };
  if (!/^[A-Za-z0-9_.\-/]{1,2048}$/.test(name)) return { reason: 'is not a valid SSM parameter name' };
  return { name, region: where };
}

/** Every SSM reference in the services' Copilot manifests, per environment. */
function planSsm(a: Analysis, region: string, envs: string[] | undefined, sink: FindingSink, checks: LiveCheck[]): { refs: ParamRef[]; seenEnvs: Set<string> } {
  const refs: ParamRef[] = [];
  const seenEnvs = new Set<string>();
  for (const svc of a.services) {
    const app = copilotApp(svc);
    for (const target of deployTargetsOf(svc)) {
      if (target.kind !== 'copilot') continue;
      const doc = asMap(parseYaml(readText(path.join(a.workspace, target.file)) ?? ''));
      for (const e of target.envs) {
        if (e.name !== '*') seenEnvs.add(e.name);
        if (envs && e.name !== '*' && !envs.includes(e.name)) continue;
        for (const [variable, v] of [...e.vars].sort((x, y) => x[0].localeCompare(y[0]))) {
          if (v.ref === undefined) continue;
          const override = asMap(asMap(asMap(asMap(doc?.['environments'])?.[e.name])?.['secrets']))?.[variable] !== undefined;
          const where = override ? `environments.${e.name}.secrets.${variable}` : `secrets.${variable}`;
          const resolved = resolveRef(v.ref, e.name, app, region);
          if ('reason' in resolved) {
            const envLabel = e.name === '*' ? 'its environments' : `environment ${e.name}`;
            checks.push({ adapter: 'ssm', service: svc.name, variable, file: target.file, env: e.name, status: 'not-checked', reason: resolved.reason });
            sink.push(svc, svc.name, {
              check: 'live-not-checked',
              severity: 'info',
              variable,
              file: target.file,
              env: e.name,
              problem: `SSM existence of ${variable} for ${envLabel} was not checked: ${where} in ${target.file} ${resolved.reason}`,
              fix: 'nothing to fix; check this reference by hand',
            });
            continue;
          }
          refs.push({ svc, variable, file: target.file, env: e.name, where, ...resolved });
        }
      }
    }
  }
  return { refs, seenEnvs };
}

export function ssmProblem(f: SsmFailure, region: string, action: 'DescribeParameters' | 'GetParameters'): { problem: string; fix: string } {
  const code = f.code ? ` (${f.code})` : '';
  switch (f.failure) {
    case 'auth':
      return { problem: `AWS rejected the credentials${code}`, fix: 'check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and, for temporary credentials, AWS_SESSION_TOKEN; temporary credentials expire' };
    case 'denied':
      return {
        problem: `the credentials are not allowed to call ssm:${action}${code}`,
        fix: action === 'DescribeParameters' ? 'grant ssm:DescribeParameters on "*" (see "Live checks" in the README)' : 'grant ssm:GetParameters on the parameters and kms:Decrypt on their key, or run without --compare',
      };
    case 'throttled':
      return { problem: `AWS SSM kept throttling after retries${code}`, fix: 'run it again later, or narrow it with --env' };
    case 'network':
      return { problem: `could not reach AWS SSM in ${region}${code}`, fix: 'check network access to the SSM endpoint and the region (--region, AWS_REGION)' };
    default:
      return { problem: `AWS SSM answered with an error${code}`, fix: "check the region and the credentials' permissions" };
  }
}

export function awsCredentials(env: Record<string, string | undefined>): AwsCredentials | null {
  const accessKeyId = env['AWS_ACCESS_KEY_ID'];
  const secretAccessKey = env['AWS_SECRET_ACCESS_KEY'];
  if (!accessKeyId || !secretAccessKey) return null;
  return { accessKeyId, secretAccessKey, sessionToken: env['AWS_SESSION_TOKEN'] || undefined };
}

export interface LiveRun {
  a: Analysis;
  opts: LiveOptions;
  http: Http;
  sink: FindingSink;
  checks: LiveCheck[];
  adapters: LiveAdapterStatus[];
}

async function runSsm(ctx: LiveRun): Promise<void> {
  const { a, opts, sink, checks } = ctx;
  const status: LiveAdapterStatus = { adapter: 'ssm', complete: false, requests: 0, checked: 0 };
  ctx.adapters.push(status);
  const creds = awsCredentials(opts.env);
  const region = opts.region ?? opts.env['AWS_REGION'] ?? opts.env['AWS_DEFAULT_REGION'] ?? '';
  if (!creds) {
    status.problem = 'AWS credentials are not set: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required';
    status.fix = 'export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for temporary credentials) for a read-only identity; wirelint reads credentials from the environment only';
    return;
  }
  if (!REGION_RE.test(region)) {
    status.problem = region ? 'the AWS region is not a valid region name' : 'no AWS region is set';
    status.fix = 'set AWS_REGION (or AWS_DEFAULT_REGION), or pass --region <region>';
    return;
  }
  const { refs, seenEnvs } = planSsm(a, region, opts.envs, sink, checks);
  const unknownEnvs = (opts.envs ?? []).filter((e) => !seenEnvs.has(e));
  const ssm = new Ssm(ctx.http, creds, opts.now ?? (() => new Date()));
  const before = ctx.http.requests;

  const byRegion = new Map<string, ParamRef[]>();
  for (const r of refs) {
    if (!byRegion.has(r.region)) byRegion.set(r.region, []);
    byRegion.get(r.region)!.push(r);
  }
  let failed: { problem: string; fix: string } | null = null;
  for (const [reg, list] of [...byRegion].sort((x, y) => x[0].localeCompare(y[0]))) {
    const found = failed ? null : await ssm.existing(reg, [...new Set(list.map((r) => r.name))]);
    if (!found || !(found instanceof Set)) {
      if (found && !failed) failed = ssmProblem(found, reg, 'DescribeParameters');
      for (const r of list) checks.push({ adapter: 'ssm', service: r.svc.name, variable: r.variable, file: r.file, env: r.env, status: 'not-checked', reason: 'SSM could not be queried' });
      continue;
    }
    for (const r of list) {
      const present = found.has(r.name);
      status.checked++;
      checks.push({ adapter: 'ssm', service: r.svc.name, variable: r.variable, file: r.file, env: r.env, status: present ? 'present' : 'missing' });
      if (present) continue;
      const envLabel = r.env === '*' ? 'its environment' : `environment ${r.env}`;
      sink.push(r.svc, r.svc.name, {
        check: 'live-missing',
        severity: 'error',
        variable: r.variable,
        file: r.file,
        env: r.env,
        problem: `${r.where} references an SSM parameter that does not exist in ${reg} for ${envLabel}; tasks that need it fail to start`,
        fix: `create the parameter that ${r.where} in ${r.file} names, in ${reg} (copilot secret init --name ${r.variable} creates and tags it), or correct the reference`,
      });
    }
  }
  status.requests = ctx.http.requests - before;
  if (failed) Object.assign(status, failed);
  else if (unknownEnvs.length) {
    status.problem = `--env ${unknownEnvs.join(', ')} matches no environment in any Copilot manifest`;
    status.fix = seenEnvs.size ? `use one of: ${[...seenEnvs].sort().join(', ')}` : 'drop --env; no Copilot manifest names an environment';
  } else status.complete = true;
}

export async function runLive(a: Analysis, opts: LiveOptions, net: Net): Promise<LiveResult> {
  const ctx: LiveRun = { a, opts, http: new Http(net, { ...HTTP_DEFAULTS, ...opts.http }), sink: new FindingSink(), checks: [], adapters: [] };
  if (opts.adapters.includes('ssm')) await runSsm(ctx);
  const live: LiveSummary = {
    adapters: ctx.adapters,
    compare: !!opts.compare,
    ...(opts.envs ? { envs: opts.envs } : {}),
    checks: ctx.checks,
    comparisons: [],
    complete: ctx.adapters.every((s) => s.complete),
  };
  return { findings: ctx.sink.findings, suppressed: ctx.sink.suppressed, live };
}
