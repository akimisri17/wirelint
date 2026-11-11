import fs from 'node:fs';
import path from 'node:path';
import { BASELINE_FILE, check, loadBaseline, renderGithub, renderHuman, renderMarkdown, run, runPr, version, writeBaseline } from './index.js';
import type { LiveOptions } from './live.js';
import { defaultNet, type Net } from './net.js';
import { REGION_RE } from './ssm.js';
import type { LiveAdapterName, Report } from './types.js';

const HELP = `wirelint ${version()}
Catch cross-service environment-variable mistakes before deploy. By default it reads
files only: no cloud credentials, no network, and it never prints a value from a non-example file.

Usage
  wirelint [workspace-dir]            check a monorepo or a folder of sibling repos
  wirelint --pr [workspace-dir]       only variables this branch adds, and where they are not set yet
  wirelint baseline [workspace-dir]   accept current findings into ${BASELINE_FILE}

Options
  --json                 machine-readable report on stdout
  --no-hints             hide suggestions in the human report
  --no-baseline          ignore ${BASELINE_FILE}
  --pr                   PR mode: diff base...HEAD in each git repo among the services
  --base <ref>           PR mode base (default origin/$GITHUB_BASE_REF, else origin/main, else main)
  --comment-file <path>  PR mode: write a Markdown comment body to <path>
                         (also appended to $GITHUB_STEP_SUMMARY when that is set)
  -h, --help             show this help
  -v, --version          show the version

Live checks: opt-in, read-only (list/describe/get calls only; nothing is written)
  --live <adapters>      ssm, vercel or ssm,vercel: check that what deploy config relies on exists
                         ssm: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY [, AWS_SESSION_TOKEN] from the environment
                         vercel: VERCEL_TOKEN from the environment
  --compare              with --live: compare same-as values as per-run keyed digests, in memory only
  --env <name>           ssm: only this Copilot environment (repeatable, or comma-separated)
  --region <region>      ssm: region (default $AWS_REGION, else $AWS_DEFAULT_REGION)
  --vercel-project <service>=<projectId>
                         vercel: project for a service without .vercel/project.json (repeatable)
  --vercel-team <teamId> vercel: team (default .vercel/project.json orgId, else $VERCEL_TEAM_ID)

Exit codes: 0 no failures (suggestions never fail), 1 failures, 2 usage error,
or a requested live check that could not run (failures still exit 1).
Annotate a variable in a service's .env.example:
  JWT_SECRET=        # wirelint: same-as identity-api
  SENTRY_DSN=        # wirelint: optional
  NEXT_PUBLIC_URL=   # wirelint: build-time
Suppress one variable, reason required:
  LEGACY_CATALOG_URL=https://catalog.example.test/v1/items.xml  # wirelint-ignore: third-party catalog, full path is intended
`;

interface Parsed {
  flags: Set<string>;
  values: Map<string, string[]>;
  args: string[];
}

const PR_OPTIONS = ['--base', '--comment-file'];
const VALUE_OPTIONS = new Set([...PR_OPTIONS, '--live', '--env', '--region', '--vercel-project', '--vercel-team']);
const REPEATABLE = new Set(['--live', '--env', '--vercel-project']);
const FLAGS = new Set(['--json', '--no-hints', '--no-baseline', '--pr', '-h', '--help', '-v', '--version', '--compare']);
const ADAPTERS: LiveAdapterName[] = ['ssm', 'vercel'];

function parse(argv: string[]): Parsed | string {
  const out: Parsed = { flags: new Set(), values: new Map(), args: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const eq = a.indexOf('=');
    const name = a.startsWith('--') && eq > 0 ? a.slice(0, eq) : a;
    if (VALUE_OPTIONS.has(name)) {
      const value = eq > 0 && name !== a ? a.slice(eq + 1) : argv[++i];
      if (!value || value.startsWith('-')) return `${name} needs a value`;
      if (out.values.has(name) && !REPEATABLE.has(name)) return `${name} given twice`;
      out.values.set(name, [...(out.values.get(name) ?? []), value]);
    } else if (a.startsWith('-')) {
      if (!FLAGS.has(a)) return `unknown option ${a}`;
      out.flags.add(a);
    } else {
      out.args.push(a);
    }
  }
  return out;
}

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  env: Record<string, string | undefined>;
  cwd: string;
  columns?: number;
  net: Net;
}

const processIo = (): Io => ({
  stdout: (s) => void process.stdout.write(s),
  stderr: (s) => void process.stderr.write(s),
  env: process.env,
  cwd: process.cwd(),
  columns: process.stdout.columns,
  net: defaultNet(),
});

interface V2 {
  live?: Omit<LiveOptions, 'env'>;
}

/** The v2 options, or a usage error. Nothing here touches the network or credentials. */
function v2Options(flags: Set<string>, values: Map<string, string[]>): V2 | string {
  const one = (k: string) => values.get(k)?.[0];
  const list = (k: string) => (values.get(k) ?? []).flatMap((v) => v.split(',')).map((v) => v.trim());
  const out: V2 = {};
  const liveRaw = values.has('--live') ? list('--live') : null;
  if (liveRaw) {
    const bad = liveRaw.find((x) => !ADAPTERS.includes(x as LiveAdapterName));
    if (bad !== undefined) return bad ? `unknown live adapter "${bad}" (use ssm, vercel or ssm,vercel)` : '--live needs ssm, vercel or ssm,vercel';
    out.live = { adapters: [...new Set(liveRaw)] as LiveAdapterName[], compare: flags.has('--compare') };
  }
  const adapters = out.live?.adapters ?? [];
  if (flags.has('--compare') && !out.live) return '--compare needs --live <adapters>; values are compared only from live stores';
  for (const k of ['--env', '--region']) if (values.has(k) && !adapters.includes('ssm')) return `${k} only applies with --live ssm`;
  for (const k of ['--vercel-project', '--vercel-team']) if (values.has(k) && !adapters.includes('vercel')) return `${k} only applies with --live vercel`;
  if (out.live) {
    if (values.has('--env')) {
      const envs = list('--env');
      if (envs.some((e) => !/^[\w.-]+$/.test(e))) return '--env needs environment names, e.g. --env prod or --env dev,prod';
      out.live.envs = [...new Set(envs)];
    }
    const region = one('--region');
    if (region !== undefined) {
      if (!REGION_RE.test(region)) return `--region "${region}" is not an AWS region name (e.g. eu-west-1)`;
      out.live.region = region;
    }
    if (values.has('--vercel-project')) {
      const projects: Record<string, string> = {};
      for (const v of values.get('--vercel-project')!) {
        const m = /^([^=\s]+)=([\w-]+)$/.exec(v);
        if (!m) return `--vercel-project needs <service>=<projectId>, got "${v}"`;
        projects[m[1]!] = m[2]!;
      }
      out.live.vercelProjects = projects;
    }
    const team = one('--vercel-team');
    if (team !== undefined) {
      if (!/^[\w-]+$/.test(team)) return '--vercel-team needs a team id, e.g. team_abc123';
      out.live.vercelTeam = team;
    }
  }
  return out;
}

/** Say prominently, on stderr, that a requested live check did not run in full. */
function liveIncomplete(report: Report, io: Io): boolean {
  if (!report.live || report.live.complete) return false;
  for (const s of report.live.adapters) if (!s.complete) io.stderr(`wirelint: live check ${s.adapter} incomplete: ${s.problem}; fix: ${s.fix}\n`);
  return true;
}

export async function main(argv: string[], io: Io = processIo()): Promise<number> {
  const parsed = parse(argv);
  if (typeof parsed === 'string') {
    io.stderr(`wirelint: ${parsed}\n\n${HELP}`);
    return 2;
  }
  const { flags, values, args } = parsed;
  if (flags.has('-h') || flags.has('--help')) {
    io.stdout(HELP);
    return 0;
  }
  if (flags.has('-v') || flags.has('--version')) {
    io.stdout(version() + '\n');
    return 0;
  }
  const prMode = flags.has('--pr');
  const prOnly = PR_OPTIONS.filter((k) => values.has(k));
  if (!prMode && prOnly.length > 0) {
    io.stderr(`wirelint: ${prOnly.join(' and ')} only applies with --pr\n`);
    return 2;
  }
  const v2 = v2Options(flags, values);
  if (typeof v2 === 'string') {
    io.stderr(`wirelint: ${v2}\n`);
    return 2;
  }
  const v2Mode = !!v2.live;
  const baselineMode = args[0] === 'baseline';
  if (baselineMode) args.shift();
  if (baselineMode && prMode) {
    io.stderr('wirelint: baseline records the whole workspace; run it without --pr\n');
    return 2;
  }
  if (baselineMode && v2Mode) {
    io.stderr('wirelint: baseline records file findings only; run it without --live\n');
    return 2;
  }
  if (args.length > 1) {
    io.stderr(`wirelint: expected one workspace directory, got ${args.length}\n`);
    return 2;
  }
  const workspace = path.resolve(io.cwd, args[0] ?? '.');
  if (!fs.existsSync(workspace) || !fs.statSync(workspace).isDirectory()) {
    io.stderr(`wirelint: ${workspace} is not a directory\n`);
    return 2;
  }

  if (baselineMode) {
    const { file, count } = writeBaseline(workspace, run(workspace).findings);
    io.stdout(`wirelint: wrote ${count} finding${count === 1 ? '' : 's'} to ${file}\nCommit it. From now on only new findings fail.\n`);
    return 0;
  }

  const baseline = flags.has('--no-baseline') ? new Set<string>() : loadBaseline(workspace);
  const prOpts = { base: values.get('--base')?.[0], env: io.env };
  // Without a v2 flag the run is exactly the file-only one: no network, no credentials read.
  const report = v2Mode
    ? await check(workspace, baseline, { pr: prMode ? prOpts : undefined, live: v2.live ? { ...v2.live, env: io.env } : undefined}, io.net)
    : prMode ? runPr(workspace, baseline, prOpts) : run(workspace, baseline);
  if (report.services.length === 0) {
    io.stderr(`wirelint: no services found under ${workspace} (looked for child directories with a package.json or a .git)\n`);
    return 2;
  }
  if (flags.has('--json')) {
    io.stdout(JSON.stringify(report, null, 2) + '\n');
  } else {
    io.stdout(renderHuman(report, { width: io.columns, hints: !flags.has('--no-hints') }) + '\n');
    if (io.env['GITHUB_ACTIONS']) {
      const annotations = renderGithub(report, io.env['GITHUB_WORKSPACE'] ?? io.cwd);
      if (annotations) io.stdout(annotations + '\n');
    }
  }
  const code = report.summary.failures > 0 ? 1 : 0;
  const incomplete = liveIncomplete(report, io);
  if (!prMode) return code === 0 && incomplete ? 2 : code;

  // The findings' exit code wins when it is 1. A failed explicit --comment-file
  // is a usage error otherwise; a failed step summary is only a warning.
  let result = code === 0 && incomplete ? 2 : code;
  const body = renderMarkdown(report);
  const commentFile = values.get('--comment-file')?.[0];
  if (commentFile) {
    try {
      fs.writeFileSync(path.resolve(io.cwd, commentFile), body);
    } catch (e) {
      io.stderr(`wirelint: could not write --comment-file ${commentFile}: ${(e as Error).message}\n`);
      if (result === 0) result = 2;
    }
  }
  const summaryFile = io.env['GITHUB_STEP_SUMMARY'];
  if (summaryFile) {
    try {
      fs.appendFileSync(summaryFile, body + '\n');
    } catch (e) {
      io.stderr(`wirelint: warning: could not append to $GITHUB_STEP_SUMMARY: ${(e as Error).message}\n`);
    }
  }
  const pr = report.pr!;
  if (pr.checked === 0) {
    const first = pr.repos[0];
    io.stderr(`wirelint: PR mode checked nothing: every repository was skipped${first ? ` (${first.skipped}; fix: ${first.fix})` : ''}\n`);
    return 2;
  }
  if (!pr.complete) io.stderr(`wirelint: warning: PR mode skipped ${pr.repos.length - pr.checked} of ${pr.repos.length} repositories; the result is incomplete\n`);
  return result;
}
