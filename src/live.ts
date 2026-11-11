import { createHash } from 'node:crypto';
import path from 'node:path';
import { deployTargetsOf, requirementsOf, type Analysis, type SecretPair } from './analyze.js';
import { Digester } from './compare.js';
import { isFile, readJson, readText, rel } from './fsutil.js';
import { Http, pool, type HttpOptions, type Net } from './net.js';
import type { AwsCredentials } from './sigv4.js';
import { REGION_RE, Ssm, type SsmFailure } from './ssm.js';
import { isProdName } from './names.js';
import type { Finding, LiveAdapterName, LiveAdapterStatus, LiveCheck, LiveComparison, LiveSummary, Relation, Service, Severity } from './types.js';
import { Vercel, vercelProblem, type VercelVar } from './vercel.js';
import { asMap, asString, parseYaml } from './yaml.js';

/**
 * v2 live checks, opt-in per run. Read-only: SSM DescribeParameters (names
 * only), Vercel's project env list (keys and targets, not decrypted) and, for
 * --compare, SSM GetParameters and Vercel's single-variable GET. Only names,
 * existence and verdicts leave this module; credentials, values and digests never do.
 */

export interface LiveOptions {
  adapters: LiveAdapterName[];
  compare?: boolean;
  /** Restrict to these Copilot environments. */
  envs?: string[];
  /** Overrides AWS_REGION / AWS_DEFAULT_REGION. */
  region?: string;
  /** Overrides .vercel/project.json orgId and VERCEL_TEAM_ID. */
  vercelTeam?: string;
  /** Service name (or directory basename) -> Vercel project id, for services without .vercel/project.json. */
  vercelProjects?: Record<string, string>;
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

/** A service's linked Vercel project and its variables (no values). Held in memory only. */
export interface VercelProject {
  projectId: string;
  teamId?: string;
  /** Where the link came from: the service's .vercel/project.json, or --vercel-project. */
  file: string;
  vars: VercelVar[];
}

export interface LiveRun {
  a: Analysis;
  opts: LiveOptions;
  http: Http;
  sink: FindingSink;
  checks: LiveCheck[];
  adapters: LiveAdapterStatus[];
  /** SSM references that resolved, for --compare. */
  ssmRefs: ParamRef[];
  /** Set when SSM answered; --compare reuses it. */
  ssmClient?: Ssm;
  /** Vercel projects that were listed, for --compare. */
  vercel: Map<Service, VercelProject>;
  vercelClient?: Vercel;
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
  ctx.ssmRefs = refs;
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
  if (!failed) ctx.ssmClient = ssm;
  if (failed) Object.assign(status, failed);
  else if (unknownEnvs.length) {
    status.problem = `--env ${unknownEnvs.join(', ')} matches no environment in any Copilot manifest`;
    status.fix = seenEnvs.size ? `use one of: ${[...seenEnvs].sort().join(', ')}` : 'drop --env; no Copilot manifest names an environment';
  } else status.complete = true;
}

/** A service by exact name or unique directory basename, as same-as targets resolve. */
function serviceNamed(a: Analysis, name: string): Service | undefined {
  const exact = a.services.find((s) => s.name === name);
  if (exact) return exact;
  const base = a.services.filter((s) => path.basename(s.dir) === name);
  return base.length === 1 ? base[0] : undefined;
}

/** The Vercel project a service deploys to, from --vercel-project or its .vercel/project.json. */
function vercelLink(a: Analysis, svc: Service, opts: LiveOptions): { projectId: string; teamId?: string; file: string } | null {
  const mapped = Object.entries(opts.vercelProjects ?? {}).find(([name]) => serviceNamed(a, name) === svc)?.[1];
  const file = path.join(svc.dir, '.vercel', 'project.json');
  const linked = readJson(file);
  const orgId = typeof linked?.['orgId'] === 'string' && linked['orgId'].startsWith('team_') ? linked['orgId'] : undefined;
  const teamId = opts.vercelTeam ?? orgId ?? (opts.env['VERCEL_TEAM_ID'] || undefined);
  if (mapped) return { projectId: mapped, teamId, file: '--vercel-project' };
  const projectId = linked?.['projectId'];
  return typeof projectId === 'string' && projectId ? { projectId, teamId, file: rel(a.workspace, file) } : null;
}

const VERCEL_TARGETS = ['production', 'preview', 'development'] as const;

async function runVercel(ctx: LiveRun): Promise<void> {
  const { a, opts, sink, checks } = ctx;
  const status: LiveAdapterStatus = { adapter: 'vercel', complete: false, requests: 0, checked: 0 };
  ctx.adapters.push(status);
  const token = opts.env['VERCEL_TOKEN'];
  if (!token) {
    status.problem = 'VERCEL_TOKEN is not set';
    status.fix = 'export VERCEL_TOKEN with a token that can read the projects; wirelint reads it from the environment only';
    return;
  }
  const unknown = Object.keys(opts.vercelProjects ?? {}).filter((name) => !serviceNamed(a, name));
  if (unknown.length) {
    status.problem = `--vercel-project names ${unknown.map((n) => `"${n}"`).join(', ')}, which ${unknown.length === 1 ? 'is not a discovered service' : 'are not discovered services'}`;
    status.fix = `use one of: ${a.services.map((s) => s.name).join(', ')}`;
    return;
  }
  const client = new Vercel(ctx.http, token);
  ctx.vercelClient = client;
  const before = ctx.http.requests;
  const deployed = a.services.filter((svc) => vercelLink(a, svc, opts) || isFile(path.join(svc.dir, 'vercel.json')));
  let failed: { problem: string; fix: string } | null = null;
  let authFailed = false;

  const listed = await pool(deployed, 4, async (svc) => {
    const link = vercelLink(a, svc, opts);
    if (!link) return { svc, link, vars: null };
    return { svc, link, vars: authFailed ? null : await client.list(link.projectId, link.teamId) };
  });
  for (const { svc, link, vars } of listed) {
    const svcRel = rel(a.workspace, svc.dir);
    const reqs = requirementsOf(svc, { buildTime: true });
    const label = (names: string[]) => names.join(' | ');
    if (!link) {
      for (const r of reqs) checks.push({ adapter: 'vercel', service: svc.name, variable: label(r.names), file: `${svcRel}/vercel.json`, env: 'production', status: 'not-checked', reason: 'no Vercel project is linked' });
      sink.push(null, svc.name, {
        check: 'live-not-checked',
        severity: 'info',
        variable: '(vercel project)',
        file: `${svcRel}/vercel.json`,
        problem: 'deployed on Vercel (vercel.json), but no Vercel project is linked, so its variables were not checked',
        fix: `run "vercel link" in ${svcRel} to write .vercel/project.json, or pass --vercel-project ${svc.name}=<projectId>`,
      });
      continue;
    }
    if (!vars || !Array.isArray(vars)) {
      if (vars && !failed) failed = vercelProblem(vars, `the project linked in ${link.file}`);
      if (vars && vars.failure === 'auth') authFailed = true;
      for (const r of reqs) checks.push({ adapter: 'vercel', service: svc.name, variable: label(r.names), file: link.file, env: 'production', status: 'not-checked', reason: 'the Vercel project could not be read' });
      continue;
    }
    ctx.vercel.set(svc, { ...link, vars });
    // vercel.json env and build.env are set for every target.
    const fromFile = new Set([
      ...svc.targets.filter((t) => t.kind === 'vercel').flatMap((t) => t.envs.flatMap((e) => [...e.vars.keys()])),
      ...svc.build.filter((b) => b.kind === 'vercel').flatMap((b) => [...b.names]),
    ]);
    const setFor = (name: string, target: string) => fromFile.has(name) || vars.some((v) => v.key === name && !v.branchOnly && v.targets.includes(target));
    for (const r of reqs) {
      const missing: string[] = [];
      for (const target of VERCEL_TARGETS) {
        const present = r.names.some((n) => setFor(n, target));
        status.checked++;
        checks.push({ adapter: 'vercel', service: svc.name, variable: label(r.names), file: link.file, env: target, status: present ? 'present' : 'missing' });
        if (!present) missing.push(target);
      }
      if (missing.length === 0) continue;
      const read = r.names.length > 1 ? `fallback chain ${r.names.join(' -> ')} read in ${r.file}:${r.line}` : `read in ${r.file}:${r.line}`;
      const chain = r.names.length > 1 ? `; any one of ${r.names.join(', ')} satisfies the chain` : '';
      const add = (targets: string[]) => targets.map((t) => `vercel env add ${r.names[0]} ${t}`).join(', then ');
      const kind = r.kind === 'required' ? 'required' : r.kind === 'localdefault' ? 'falls back to a localhost default' : 'no default';
      if (missing.includes('production')) {
        sink.push(svc, svc.name, {
          check: 'live-missing',
          severity: r.hard ? 'error' : 'hint',
          variable: label(r.names),
          file: link.file,
          env: 'production',
          problem: `${read} (${kind}) but the Vercel project does not set ${r.names.length > 1 ? 'any of them' : 'it'} for production` +
            (r.kind === 'localdefault' ? '; once deployed it silently points at localhost' : ''),
          fix: `in ${svcRel}, run "${add(['production'])}" (or add it under Settings > Environment Variables)${chain}`,
        });
      }
      const other = missing.filter((t) => t !== 'production');
      if (other.length) {
        sink.push(svc, svc.name, {
          check: 'live-missing',
          severity: 'hint',
          variable: label(r.names),
          file: link.file,
          env: other.join(','),
          problem: `${read} (${kind}) but the Vercel project does not set ${r.names.length > 1 ? 'any of them' : 'it'} for ${other.join(' or ')}`,
          fix: `in ${svcRel}, run "${add(other)}" if ${other.length > 1 ? 'those deployments need' : 'that deployment needs'} it${chain}`,
        });
      }
    }
  }
  status.requests = ctx.http.requests - before;
  if (failed) Object.assign(status, failed);
  else status.complete = true;
}

/** Where one side of a comparison lives for one environment. In memory only. */
type Source =
  | { kind: 'ssm'; env: string; ref: ParamRef; key: string }
  | { kind: 'vercel'; env: string; svc: Service; project: VercelProject; v: VercelVar; key: string };

type Fetched = Buffer | 'unreadable' | 'missing' | 'failed';

/** Copilot environments and Vercel targets meet on production; other names must match. */
const canon = (src: Source): string => (src.kind === 'ssm' ? (src.env === '*' ? '*' : isProdName(src.env) ? 'production' : src.env) : src.env);

function sourcesOf(ctx: LiveRun, service: string, variable: string): Source[] {
  const out: Source[] = [];
  for (const ref of ctx.ssmRefs) if (ref.svc.name === service && ref.variable === variable) out.push({ kind: 'ssm', env: ref.env, ref, key: `ssm|${ref.region}|${ref.name}` });
  for (const [svc, project] of ctx.vercel) {
    if (svc.name !== service) continue;
    for (const v of project.vars) {
      if (v.key !== variable || v.branchOnly) continue;
      for (const t of v.targets) if (VERCEL_TARGETS.includes(t as (typeof VERCEL_TARGETS)[number])) out.push({ kind: 'vercel', env: t, svc, project, v, key: `vercel|${project.projectId}|${v.id}` });
    }
  }
  return out;
}

function describe(src: Source): string {
  return src.kind === 'ssm'
    ? `${src.ref.svc.name}: the SSM parameter ${src.ref.where} in ${src.ref.file} names`
    : `${src.svc.name}: the Vercel ${src.env} variable ${src.v.key}${src.v.type === 'sensitive' ? ' (sensitive)' : ''}`;
}

/** Fetch every needed value once, reducing each to a digest on arrival. */
async function fetchDigests(ctx: LiveRun, sources: Source[], d: Digester): Promise<Map<string, Fetched>> {
  const out = new Map<string, Fetched>();
  const ssmStatus = ctx.adapters.find((x) => x.adapter === 'ssm');
  const vercelStatus = ctx.adapters.find((x) => x.adapter === 'vercel');
  const missing = new Set(ctx.checks.filter((c) => c.adapter === 'ssm' && c.status === 'missing').map((c) => `${c.service}|${c.variable}|${c.env}`));

  const byRegion = new Map<string, Set<string>>();
  for (const src of sources) {
    if (src.kind !== 'ssm' || out.has(src.key)) continue;
    if (missing.has(`${src.ref.svc.name}|${src.ref.variable}|${src.ref.env}`)) {
      out.set(src.key, 'missing');
      continue;
    }
    if (!byRegion.has(src.ref.region)) byRegion.set(src.ref.region, new Set());
    byRegion.get(src.ref.region)!.add(src.ref.name);
  }
  for (const [region, names] of [...byRegion].sort((x, y) => x[0].localeCompare(y[0]))) {
    const r = ctx.ssmClient ? await ctx.ssmClient.digests(region, [...names], d.digest) : null;
    if (!r || 'failure' in r) {
      if (r && ssmStatus && ssmStatus.complete) Object.assign(ssmStatus, { complete: false, ...ssmProblem(r, region, 'GetParameters') });
      for (const n of names) out.set(`ssm|${region}|${n}`, 'failed');
      continue;
    }
    for (const n of names) out.set(`ssm|${region}|${n}`, r.digests.get(n) ?? (r.missing.has(n) ? 'missing' : 'failed'));
  }

  const vercelSources = [...new Map(sources.filter((s): s is Extract<Source, { kind: 'vercel' }> => s.kind === 'vercel').map((s) => [s.key, s])).values()];
  await pool(vercelSources, 4, async (src) => {
    const r = ctx.vercelClient ? await ctx.vercelClient.digest(src.project.projectId, src.project.teamId, src.v, d.digest) : null;
    if (r !== null && !Buffer.isBuffer(r) && r !== 'unreadable') {
      if (vercelStatus && vercelStatus.complete) Object.assign(vercelStatus, { complete: false, ...vercelProblem(r, `a variable of the project linked in ${src.project.file}`) });
      out.set(src.key, 'failed');
    } else out.set(src.key, r ?? 'failed');
  });
  return out;
}

/**
 * --compare: declared same-as relations (a difference fails) and shared-secret
 * candidates (a difference is a suggestion), per environment both sides have.
 */
async function runCompare(ctx: LiveRun, relations: Relation[], candidates: SecretPair[]): Promise<LiveComparison[]> {
  const { a, sink } = ctx;
  const d = new Digester();
  type Pair = { kind: 'declared' | 'inferred'; a: { service: string; variable: string }; b: { service: string; variable: string }; relation?: Relation };
  const pairs: Pair[] = [
    ...relations.map((r): Pair => ({ kind: 'declared', a: { service: r.service, variable: r.variable }, b: r.target, relation: r })),
    ...candidates.map((c): Pair => ({ kind: 'inferred', ...c })),
  ];
  const planned = pairs.map((p) => {
    const sa = sourcesOf(ctx, p.a.service, p.a.variable);
    const sb = sourcesOf(ctx, p.b.service, p.b.variable);
    const matches: [Source, Source][] = [];
    for (const x of sa) for (const y of sb) if (canon(x) === canon(y) || canon(x) === '*' || canon(y) === '*') matches.push([x, y]);
    return { p, sa, sb, matches };
  });
  const fetched = await fetchDigests(ctx, planned.flatMap((x) => x.matches.flat()), d);

  const out: LiveComparison[] = [];
  const svcOf = (name: string) => a.services.find((s) => s.name === name) ?? null;
  for (const { p, sa, sb, matches } of planned) {
    const base = { kind: p.kind, service: p.a.service, variable: p.a.variable, target: p.b };
    const results: LiveComparison['result'][] = [];
    if (matches.length === 0) {
      const lacking = sa.length === 0 ? p.a : sb.length === 0 ? p.b : null;
      const reason = lacking
        ? `${lacking.service}.${lacking.variable} has no value in the live stores this run read (${ctx.opts.adapters.join(', ')})`
        : 'the two sides share no environment';
      out.push({ ...base, env: '-', result: 'not-checked', reason });
      continue;
    }
    for (const [x, y] of matches) {
      const env = x.env !== '*' ? x.env : y.env;
      const fx = fetched.get(x.key) ?? 'failed';
      const fy = fetched.get(y.key) ?? 'failed';
      let result: LiveComparison['result'];
      let reason: string | undefined;
      if (fx instanceof Buffer && fy instanceof Buffer) result = Digester.same(fx, fy) ? 'equal' : 'different';
      else if (fx === 'unreadable' || fy === 'unreadable') {
        result = 'unreadable';
        reason = `${describe(fx === 'unreadable' ? x : y)} cannot be read back, so only its existence was checked`;
      } else {
        result = 'not-checked';
        reason = fx === 'missing' || fy === 'missing' ? 'a side does not exist (reported as live-missing)' : 'a value could not be fetched';
      }
      results.push(result);
      out.push({ ...base, env, result, ...(reason ? { reason } : {}) });
      if (result === 'unreadable') {
        sink.push(null, p.kind === 'declared' ? p.a.service : `${p.a.service} + ${p.b.service}`, {
          check: 'live-not-checked',
          severity: 'info',
          variable: p.a.variable,
          file: p.relation?.file ?? '',
          env,
          problem: `values of ${p.a.service}.${p.a.variable} and ${p.b.service}.${p.b.variable} for ${env} were not compared: ${reason}`,
          fix: 'nothing to fix; compare them by hand, or make the variable non-sensitive if that is acceptable',
        });
      }
      if (result !== 'different') continue;
      const both = `${describe(x)}; ${describe(y)}`;
      if (p.kind === 'declared') {
        sink.push(svcOf(p.a.service), p.a.service, {
          check: 'live-mismatch',
          severity: 'error',
          variable: p.a.variable,
          file: p.relation!.file,
          line: p.relation!.line,
          env,
          problem: `declared same-as ${p.b.service}.${p.b.variable}, but the deployed values differ for ${env} (${both})`,
          fix: `set ${p.a.service}'s value to ${p.b.service}'s for ${env}, or point both at one parameter; wirelint compared keyed digests and shows neither value`,
        });
      } else {
        const label = p.a.variable === p.b.variable ? p.a.variable : `${p.a.variable} / ${p.b.variable}`;
        sink.push(null, `${p.a.service} + ${p.b.service}`, {
          check: 'live-mismatch',
          severity: 'hint',
          variable: label,
          file: '',
          anchor: '',
          env,
          problem: `the deployed values differ for ${env} (${both}); if this is one shared secret, calls between them fail authentication`,
          fix: `if they must match, set one value in both and add "# wirelint: same-as ${p.b.service}${p.a.variable === p.b.variable ? '' : `.${p.b.variable}`}" to ${p.a.variable} in ${p.a.service}'s .env.example; if they are independent, nothing to do`,
        });
      }
    }
    if (p.relation) {
      if (results.some((r) => r === 'equal' || r === 'different')) p.relation.compared = 'value';
      else if (results.includes('unreadable')) p.relation.compared = 'unreadable';
    }
  }
  return out;
}

export async function runLive(a: Analysis, opts: LiveOptions, net: Net): Promise<LiveResult> {
  const ctx: LiveRun = { a, opts, http: new Http(net, { ...HTTP_DEFAULTS, ...opts.http }), sink: new FindingSink(), checks: [], adapters: [], ssmRefs: [], vercel: new Map() };
  if (opts.adapters.includes('ssm')) await runSsm(ctx);
  if (opts.adapters.includes('vercel')) await runVercel(ctx);
  const comparisons = opts.compare ? await runCompare(ctx, a.relations, a.candidates) : [];
  const live: LiveSummary = {
    adapters: ctx.adapters,
    compare: !!opts.compare,
    ...(opts.envs ? { envs: opts.envs } : {}),
    checks: ctx.checks,
    comparisons,
    complete: ctx.adapters.every((s) => s.complete),
  };
  return { findings: ctx.sink.findings, suppressed: ctx.sink.suppressed, live };
}
