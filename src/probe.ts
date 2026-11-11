import path from 'node:path';
import { deployTargetsOf, type Analysis } from './analyze.js';
import { parseEnv } from './dotenv.js';
import { readJson, readText } from './fsutil.js';
import { FindingSink } from './live.js';
import { isProdName } from './names.js';
import { Http, pool, type Net } from './net.js';
import type { Edge, Finding, ProbeResult, ProbeSummary, Service } from './types.js';
import { isPlaceholder } from './url.js';
import { asList, asMap, asString, parseYaml } from './yaml.js';

/**
 * --probe: GET each inferred link's production base URL plus a health path.
 * The URL is read from the calling service's production config, held only
 * for the request, and never recorded: results name the variable, not the
 * address. No redirects are followed and nothing but a User-Agent is sent.
 */

export interface ProbeOptions {
  /** Appended to the base URL. Default /health. */
  path: string;
  timeoutMs: number;
  /** DNS failure, connection refused and 5xx fail the run. */
  strict: boolean;
}

/** A production value, in memory only. */
type ProdValue = { value: string; file: string; env: string } | { reason: string };

function composeValue(node: unknown, variable: string): string | null {
  const map = asMap(node as never);
  if (map) return asString(map[variable]);
  for (const item of asList(node as never)) {
    const s = asString(item);
    if (s?.startsWith(`${variable}=`)) return s.slice(variable.length + 1);
  }
  return null;
}

/**
 * The value `variable` has in `svc`'s production config: a deploy target's
 * production environment, else vercel.json env, else a production .env file
 * (never a local or example one).
 */
export function prodValue(a: Analysis, svc: Service, variable: string): ProdValue {
  const targets = [...deployTargetsOf(svc), ...svc.targets.filter((t) => t.kind === 'vercel')];
  for (const t of targets) {
    const envs = t.envs.filter((e) => (isProdName(e.name) || e.name === '*') && e.vars.has(variable)).sort((x, y) => x.name.localeCompare(y.name));
    const e = envs[0];
    if (!e) continue;
    if (e.vars.get(variable)!.ref !== undefined) return { reason: `${variable} is a secret reference in ${t.file}, not a URL` };
    const abs = path.join(a.workspace, t.file);
    let value: string | null = null;
    if (t.kind === 'copilot') {
      const doc = asMap(parseYaml(readText(abs) ?? ''));
      value = asString(asMap(asMap(asMap(doc?.['environments'])?.[e.name])?.['variables'])?.[variable]) ?? asString(asMap(doc?.['variables'])?.[variable]);
    } else if (t.kind === 'compose') {
      const doc = asMap(parseYaml(readText(abs) ?? ''));
      value = composeValue(asMap(asMap(doc?.['services'])?.[t.name])?.['environment'], variable);
    } else {
      const doc = readJson(abs);
      const env = doc?.['env'] as Record<string, unknown> | undefined;
      value = typeof env?.[variable] === 'string' ? (env[variable] as string) : null;
    }
    if (value === null) return { reason: `${variable} is set in ${t.file} through a file wirelint does not resolve` };
    return { value, file: t.file, env: e.name };
  }
  for (const f of svc.envFiles) {
    if (f.isExample || f.envName !== 'prod' || !f.vars.has(variable)) continue;
    const entry = parseEnv(readText(path.join(a.workspace, f.file)) ?? '').entries.find((x) => x.name === variable && !x.commented);
    if (entry) return { value: entry.value, file: f.file, env: 'prod' };
  }
  return { reason: `no production config of ${svc.name} sets ${variable}` };
}

/** The URL to probe, or why there is none. The result is used once and dropped. */
export function probeUrl(raw: string, probePath: string): URL | { reason: string } {
  const value = raw.trim();
  if (isPlaceholder(value) || /[\s,]/.test(value)) return { reason: 'its production value is templated, a placeholder or a list' };
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return { reason: 'its production value is not an absolute URL' };
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { reason: 'its production value is not http or https' };
  const [p, q] = probePath.split(/\?(.*)/s);
  u.username = '';
  u.password = '';
  u.hash = '';
  u.search = q ? `?${q}` : '';
  u.pathname = u.pathname.replace(/\/+$/, '') + p;
  return u;
}

const SAY: Record<Exclude<ProbeResult['outcome'], 'answered' | 'skipped'>, string> = {
  timeout: 'did not answer in time',
  dns: 'has a host that does not resolve from here',
  refused: 'refused the connection',
  tls: 'failed the TLS handshake (certificate or protocol)',
  unreachable: 'could not be reached',
};

export async function runProbe(a: Analysis, opts: ProbeOptions, net: Net): Promise<{ findings: Finding[]; suppressed: number; probe: ProbeSummary }> {
  const sink = new FindingSink();
  const http = new Http(net, { timeoutMs: opts.timeoutMs, retries: 0, concurrency: 4 });
  const byName = new Map(a.services.map((s) => [s.name, s]));
  const seconds = `${opts.timeoutMs / 1000}s`;

  const results = await pool(a.edges, 4, async (e: Edge): Promise<ProbeResult> => {
    const svc = byName.get(e.from)!;
    const base = { from: e.from, to: e.to, variable: e.variable };
    const prod = prodValue(a, svc, e.variable);
    if ('reason' in prod) return { ...base, outcome: 'skipped', reason: prod.reason };
    const url = probeUrl(prod.value, opts.path);
    if (!(url instanceof URL)) return { ...base, file: prod.file, env: prod.env, outcome: 'skipped', reason: url.reason };
    const r = await http.request({ url: url.href, method: 'GET', headers: { 'user-agent': 'wirelint' }, manualRedirect: true, discardBody: true });
    return r.ok ? { ...base, file: prod.file, env: prod.env, outcome: 'answered', status: r.status } : { ...base, file: prod.file, env: prod.env, outcome: r.kind };
  });

  for (const r of results) {
    const svc = byName.get(r.from)!;
    const where = r.file ? ` (${r.file}${r.env && r.env !== '*' ? `, ${r.env}` : ''})` : '';
    const subject = `GET ${opts.path} on the production ${r.variable}${where}`;
    const caveat = '; from outside its network this can be private DNS or a VPC, so on its own it proves nothing';
    if (r.outcome === 'skipped') {
      sink.push(null, r.from, {
        check: 'probe-not-checked',
        severity: 'info',
        variable: r.variable,
        file: r.file ?? '',
        env: r.env,
        problem: `link ${r.from} -> ${r.to} via ${r.variable} was not probed: ${r.reason}`,
        fix: 'nothing to fix; probe it by hand if it matters',
      });
      continue;
    }
    if (r.outcome === 'answered') {
      const s = r.status!;
      if (s >= 200 && s < 300) continue;
      const hard = opts.strict && s >= 500;
      sink.push(svc, r.from, {
        check: 'probe-status',
        severity: hard ? 'error' : 'hint',
        variable: r.variable,
        file: r.file!,
        env: r.env,
        problem: `${subject} answered ${s}` + (s >= 500 ? `; ${r.to} is up but failing` : s >= 300 && s < 400 ? '; redirects are not followed' : `; ${opts.path} may not be the health path of ${r.to}`),
        fix:
          s >= 500 ? `check the production logs and health of ${r.to}`
          : s >= 300 && s < 400 ? `point ${r.variable} at the address it redirects to, or pass --probe-path with a path that answers 2xx`
          : `pass --probe-path with the health path of ${r.to}, or check that ${r.variable} points at ${r.to}`,
      });
      continue;
    }
    const hard = opts.strict && (r.outcome === 'dns' || r.outcome === 'refused');
    sink.push(svc, r.from, {
      check: 'probe-unreachable',
      severity: hard ? 'error' : 'hint',
      variable: r.variable,
      file: r.file!,
      env: r.env,
      problem: `${subject} ${r.outcome === 'timeout' ? `did not answer within ${seconds}` : SAY[r.outcome]}${hard ? '' : caveat}`,
      fix:
        r.outcome === 'tls' ? `check the certificate ${r.to} serves for the host in ${r.variable}`
        : `check that ${r.variable} in ${r.file} names the production host and port of ${r.to}; if ${r.to} is reachable only inside its network, run the probe from there`,
    });
  }
  return { findings: sink.findings, suppressed: sink.suppressed, probe: { path: opts.path, timeoutMs: opts.timeoutMs, strict: opts.strict, results } };
}
