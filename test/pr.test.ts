import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { renderHuman, renderMarkdown, runPr } from '../src/index.js';
import type { Report } from '../src/index.js';
import { baseCandidates, parseDiff, unquotePath } from '../src/pr.js';
import { pkg, workspace } from './helpers.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');

/** git in a throwaway repo only; the user's global and system config are not read. */
const gitEnv = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' };
function git(cwd: string, ...args: string[]): string {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', env: gitEnv });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}
function initRepo(dir: string, branch = 'main'): void {
  git(dir, 'init', '-q', '-b', branch);
  git(dir, 'config', 'user.name', 'wirelint test');
  git(dir, 'config', 'user.email', 'test@example.test');
  git(dir, 'config', 'commit.gpgsign', 'false');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'base');
}
function write(root: string, files: Record<string, string>): void {
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), content);
  }
}
function commit(dir: string, files: Record<string, string>, branch = 'feature'): void {
  if (git(dir, 'branch', '--show-current') !== branch) git(dir, 'checkout', '-q', '-b', branch);
  write(dir, files);
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'change');
}
function cli(args: string[], env: Record<string, string> = {}) {
  const clean: Record<string, string | undefined> = { ...gitEnv, ...env };
  for (const k of ['GITHUB_ACTIONS', 'GITHUB_BASE_REF', 'GITHUB_STEP_SUMMARY']) if (!(k in env)) delete clean[k];
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: clean });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

const ordersManifest = 'name: orders\ntype: Backend Service\nsecrets:\n  JWT_SECRET: /orders/JWT_SECRET_REF\nenvironments:\n  dev:\n  prod:\n';

/** Two sibling repos. orders already has an undocumented read, which PR mode must not report. */
function siblings(): string {
  const ws = workspace({
    'orders/package.json': pkg('orders'),
    'orders/.env.example': 'JWT_SECRET=dev-orders\nBILLING_URL=http://localhost:4002\n',
    'orders/src/config.ts': "export const a = cfg.getOrThrow('JWT_SECRET');\nexport const b = process.env.BILLING_URL;\nexport const old = cfg.getOrThrow('OLD_UNDOCUMENTED');\n",
    'orders/copilot/orders/manifest.yml': ordersManifest,
    'web/package.json': pkg('web'),
    'web/.env.example': 'ORDERS_URL=http://localhost:4001\n',
    'web/src/a.ts': 'export const o = process.env.ORDERS_URL;\n',
  });
  initRepo(path.join(ws, 'orders'));
  initRepo(path.join(ws, 'web'));
  return ws;
}

describe('PR mode', () => {
  it('reports only variables the diff adds, and where each is not set yet', () => {
    const ws = siblings();
    commit(path.join(ws, 'orders'), {
      'src/config.ts':
        "export const a = cfg.getOrThrow('JWT_SECRET');\nexport const b = process.env.BILLING_URL ?? 'x';\nexport const old = cfg.getOrThrow('OLD_UNDOCUMENTED');\nexport const p = cfg.getOrThrow('PAYOUT_SIGNING_KEY');\n",
      '.env.example': 'JWT_SECRET=dev-orders-changed\nBILLING_URL=http://localhost:4002\nREFUNDS_API_URL=http://localhost:4005/v1/refunds\n',
    });
    const r = runPr(ws, new Set(), { base: 'main' });
    expect(r.pr!.repos).toEqual([
      { root: 'orders', services: ['orders'], base: 'main' },
      { root: 'web', services: ['web'], base: 'main' },
    ]);
    expect(r.pr!.variables.map((v) => [v.variable, v.added, v.missing])).toEqual([
      ['PAYOUT_SIGNING_KEY', [{ file: 'orders/src/config.ts', line: 4 }], [{ target: 'orders/copilot/orders/manifest.yml', kind: 'copilot', envs: ['dev', 'prod'] }]],
      ['REFUNDS_API_URL', [{ file: 'orders/.env.example', line: 3 }], [{ target: 'orders/copilot/orders/manifest.yml', kind: 'copilot', envs: ['dev', 'prod'] }]],
    ]);
    expect(r.findings.map((f) => `${f.check} ${f.variable}`).sort()).toEqual([
      'missing-from-deploy PAYOUT_SIGNING_KEY',
      'missing-from-example PAYOUT_SIGNING_KEY',
      'url-shape REFUNDS_API_URL',
    ]);
    expect(r.summary).toMatchObject({ failures: 3, suggestions: 0 });
  });

  it('treats an edited or moved line as not adding a variable', () => {
    const ws = siblings();
    commit(path.join(ws, 'web'), { 'src/a.ts': 'export const o = process.env.ORDERS_URL ?? "";\n', 'src/b.ts': '// moved\n' });
    const r = runPr(ws, new Set(), { base: 'main' });
    expect(r.pr!.variables).toEqual([]);
    expect(r.findings).toEqual([]);
  });

  it('counts a first read of a variable that was only documented before', () => {
    const ws = siblings();
    commit(path.join(ws, 'web'), { '.env.example': 'ORDERS_URL=http://localhost:4001\nSESSION_SECRET=x\n' });
    git(path.join(ws, 'web'), 'checkout', '-q', 'main');
    git(path.join(ws, 'web'), 'merge', '-q', 'feature');
    commit(path.join(ws, 'web'), { 'src/s.ts': 'export const s = process.env.SESSION_SECRET;\n' }, 'second');
    const r = runPr(ws, new Set(), { base: 'main' });
    expect(r.pr!.variables.map((v) => [v.service, v.variable, v.noTargets])).toEqual([['web', 'SESSION_SECRET', true]]);
  });

  it('resolves a fallback chain and annotations for new variables', () => {
    const ws = siblings();
    commit(path.join(ws, 'orders'), {
      'src/search.ts': "export const s = process.env.SEARCH_URL ?? process.env.SEARCH_API_URL ?? 'http://localhost:4010';\n",
      '.env.example': 'JWT_SECRET=dev-orders\nBILLING_URL=http://localhost:4002\nSEARCH_URL=http://localhost:4010\nSEARCH_API_URL=\nSENTRY_DSN=  # wirelint: optional\n',
    });
    const r = runPr(ws, new Set(), { base: 'main' });
    expect(r.findings.map((f) => `${f.check} ${f.variable}`)).toEqual(['missing-from-deploy SEARCH_URL | SEARCH_API_URL']);
    expect(r.pr!.variables.find((v) => v.variable === 'SENTRY_DSN')).toMatchObject({ annotations: ['optional'] });
  });

  it('defaults the base to origin/$GITHUB_BASE_REF, then origin/main, then main', () => {
    expect(baseCandidates(undefined, { GITHUB_BASE_REF: 'release' })).toEqual(['origin/release', 'origin/main', 'main']);
    expect(baseCandidates(undefined, {})).toEqual(['origin/main', 'main']);
    expect(baseCandidates('v1.2', { GITHUB_BASE_REF: 'release' })).toEqual(['v1.2']);

    const ws = siblings();
    const orders = path.join(ws, 'orders');
    commit(orders, { 'src/a.ts': "cfg.getOrThrow('FIRST_NEW_KEY');\n" });
    // origin/main has already seen the first change, so only the second is new against it.
    git(orders, 'update-ref', 'refs/remotes/origin/main', 'HEAD');
    commit(orders, { 'src/b.ts': "cfg.getOrThrow('SECOND_NEW_KEY');\n" });
    expect(runPr(ws, new Set(), { env: {} }).pr!.variables.map((v) => v.variable)).toEqual(['SECOND_NEW_KEY']);
    const web = runPr(ws, new Set(), { env: {} }).pr!.repos.find((x) => x.root === 'web')!;
    expect(web.base).toBe('main');
  });

  it('skips a repo with no resolvable base, and a service outside git, with a note', () => {
    const ws = workspace({ 'a/package.json': pkg('a'), 'a/src/x.ts': 'process.env.A_KEY;', 'b/package.json': pkg('b'), 'b/src/x.ts': 'process.env.B_KEY;' });
    initRepo(path.join(ws, 'a'), 'trunk');
    const r = runPr(ws, new Set(), { env: {} });
    expect(r.pr!.repos).toEqual([
      { root: '-', services: ['b'], skipped: 'not inside a git repository', fix: 'run PR mode in a git checkout of this service' },
      { root: 'a', services: ['a'], skipped: 'no base ref resolves (tried origin/main, main)', fix: 'fetch the base branch (actions/checkout with fetch-depth: 0) or pass --base <ref>' },
    ]);
    expect(r.pr).toMatchObject({ complete: false, checked: 0 });
    expect(r.findings).toEqual([]);
    expect(renderHuman(r)).toContain('NOTHING WAS CHECKED: every repository was skipped');
    expect(renderMarkdown(r)).toContain('### wirelint: nothing was checked');
    expect(runPr(ws, new Set(), { base: 'trunk' }).pr!.repos[1]).toEqual({ root: 'a', services: ['a'], base: 'trunk' });
  });

  it('diffs a monorepo once for every package in it', () => {
    const ws = workspace({
      'package.json': JSON.stringify({ name: 'root', workspaces: ['apps/*'] }),
      '.env.example': 'API_TOKEN=x\n',
      'apps/api/package.json': pkg('api'),
      'apps/api/src/a.ts': "cfg.getOrThrow('API_TOKEN');\n",
      'apps/web/package.json': pkg('web'),
      'apps/web/src/a.ts': 'export {};\n',
    });
    initRepo(ws);
    commit(ws, { 'apps/web/src/a.ts': "export const k = cfg.getOrThrow('WEB_ONLY_KEY');\n" });
    const r = runPr(ws, new Set(), { base: 'main' });
    expect(r.pr!.repos).toEqual([{ root: '.', services: ['apps/api', 'apps/web'], base: 'main' }]);
    expect(r.pr!.variables.map((v) => `${v.service}:${v.variable}`)).toEqual(['apps/web:WEB_ONLY_KEY']);
    expect(r.findings.map((f) => `${f.service}:${f.check}:${f.variable}`)).toEqual(['apps/web:missing-from-example:WEB_ONLY_KEY']);
  });

  it('renders a Markdown comment body without values from non-example files', () => {
    const ws = siblings();
    commit(path.join(ws, 'orders'), { 'src/p.ts': "cfg.getOrThrow('PAYOUT_SIGNING_KEY');\n", 'copilot/orders/manifest.yml': ordersManifest.replace('  dev:\n', '  dev:\n    secrets:\n      PAYOUT_SIGNING_KEY: /orders/dev/PAYOUT_REF\n') });
    const md = renderMarkdown(runPr(ws, new Set(), { base: 'main' }));
    expect(md).toContain('### wirelint: 1 new variable in this change');
    expect(md).toContain('| `orders` | `PAYOUT_SIGNING_KEY` | `orders/src/p.ts:1` | not yet set in: `orders/copilot/orders/manifest.yml` (`prod`) |');
    expect(md).toContain('#### Failures (2)');
    expect(md).not.toMatch(/PAYOUT_REF|JWT_SECRET_REF/);
  });
});

describe('PR mode regressions', () => {
  it('finds added lines in paths with a space, a quote or a backslash', () => {
    expect(unquotePath('"b/src/quo\\"te.ts"')).toBe('b/src/quo"te.ts');
    expect(unquotePath('"b/caf\\303\\251/back\\\\slash.ts"')).toBe('b/café/back\\slash.ts');
    const d = parseDiff('/r', 'diff --git a/x y.ts b/x y.ts\n--- a/x y.ts\t\n+++ b/x y.ts\t\n@@ -0,0 +1 @@\n+process.env.A_KEY;\n');
    expect([...d.added.keys()]).toEqual([path.join('/r', 'x y.ts')]);

    const ws = siblings();
    commit(path.join(ws, 'orders'), {
      'src/new file.ts': "cfg.getOrThrow('SPACED_KEY');\n",
      'src/quo"te.ts': "cfg.getOrThrow('QUOTED_KEY');\n",
      'src/back\\slash.ts': "cfg.getOrThrow('BACKSLASH_KEY');\n",
    });
    expect(runPr(ws, new Set(), { base: 'main' }).pr!.variables.map((v) => v.variable)).toEqual(['BACKSLASH_KEY', 'QUOTED_KEY', 'SPACED_KEY']);
  });

  it('says the result is incomplete when one repo was skipped', () => {
    const ws = siblings();
    git(path.join(ws, 'web'), 'branch', '-q', '-m', 'main', 'trunk');
    commit(path.join(ws, 'orders'), { 'src/p.ts': "cfg.getOrThrow('PAYOUT_SIGNING_KEY');\n" });
    const r = runPr(ws, new Set(), { env: {} });
    expect(r.pr).toMatchObject({ complete: false, checked: 1 });
    expect(renderHuman(r)).toContain('NOT FULLY CHECKED: 1 of 2 repositories skipped');
    expect(renderHuman(r)).toContain('fix: fetch the base branch (actions/checkout with fetch-depth: 0) or pass --base <ref>');
    const md = renderMarkdown(r);
    expect(md).toContain('### wirelint: not fully checked; 1 new variable in the part that was checked');
    expect(md).toContain('> **Not checked:** repo `web`: no base ref resolves');
  });

  it('names git missing and passes on git\'s own reason for other failures', () => {
    const ws = workspace({ 'a/package.json': pkg('a'), 'a/.git': 'garbage, not a gitdir line\n', 'b/package.json': pkg('b') });
    const reasons = runPr(ws, new Set(), { base: 'main' }).pr!.repos.map((r) => r.skipped!);
    expect(reasons.some((x) => /^git rev-parse failed: fatal: invalid gitfile format/.test(x))).toBe(true);
    const saved = process.env.PATH;
    process.env.PATH = path.join(ws, 'no-such-bin');
    try {
      expect(runPr(ws, new Set(), { base: 'main' }).pr!.repos).toEqual([
        { root: '-', services: ['a', 'b'], skipped: 'git is not installed or not on PATH', fix: 'install git and make sure it is on PATH' },
      ]);
    } finally {
      process.env.PATH = saved;
    }
  });

  it('lists nothing for an optional variable, and lets a chain sibling stand in', () => {
    const ws = siblings();
    commit(path.join(ws, 'orders'), {
      'copilot/orders/manifest.yml': ordersManifest.replace('  prod:\n', '  prod:\n    variables:\n      SEARCH_API_URL: https://search.example.test\n'),
      'src/search.ts': "export const s = process.env.SEARCH_URL ?? process.env.SEARCH_API_URL ?? 'http://localhost:4010';\nexport const t = process.env.TRACE_TOKEN;\n",
      '.env.example': 'JWT_SECRET=dev-orders\nBILLING_URL=http://localhost:4002\nTRACE_TOKEN=  # wirelint: optional -- local tracing only\n',
    });
    const vars = Object.fromEntries(runPr(ws, new Set(), { base: 'main' }).pr!.variables.map((v) => [v.variable, v.missing.map((m) => m.envs)]));
    expect(vars).toEqual({ SEARCH_URL: [['dev']], SEARCH_API_URL: [['dev']], TRACE_TOKEN: [] });
  });

  it('escapes Markdown, HTML and mentions in text that comes from repo files', () => {
    const report = {
      version: '0.2.0', workspace: '/w', services: [], edges: [], annotations: [], relations: [],
      findings: [{ fingerprint: 'f', check: 'url-shape', severity: 'error', service: '@admins', variable: 'A_URL', file: 'svc/we`ird|<b>.env.example', line: 1, problem: 'value "<img src=x onerror=1>" mentions @org/team and **bold**', fix: 'set A_URL=https://a.example.test' }],
      pr: { repos: [{ root: '@ops', services: ['@admins'], skipped: 'git said <script>' , fix: 'ping @ops' }], variables: [{ service: '@admins', variable: 'A_URL', added: [{ file: 'a`b|c.ts', line: 2 }], annotations: [], missing: [], noTargets: true }], complete: false, checked: 0 },
      summary: { failures: 1, suggestions: 0, notes: 0, baselined: 0, suppressed: 0, durationMs: 1 },
    } as Report;
    const md = renderMarkdown(report);
    // Outside code spans, nothing from the repo may render as HTML, Markdown or a mention.
    const prose = md.replace(/`` .*? ``|`[^`]*`/g, '');
    expect(prose).not.toMatch(/<img|<script>|<b>|\*\*bold\*\*/);
    expect(prose).not.toMatch(/@(admins|org|ops)\b/);
    expect(md).toContain('&lt;img src=x onerror=1&gt;');
    expect(md).toContain('@\u200borg/team');
    expect(md).toContain('| `@admins` | `A_URL` | `` a`b\\|c.ts:2 `` |');
    expect(md).toContain('`` svc/we`ird|<b>.env.example:1 ``');
  });
});

describe('PR mode CLI', () => {
  it('writes the comment file, appends the step summary, and keeps exit codes', () => {
    const ws = siblings();
    commit(path.join(ws, 'orders'), { 'src/p.ts': "cfg.getOrThrow('PAYOUT_SIGNING_KEY');\n" });
    const comment = path.join(ws, 'comment.md');
    const summary = path.join(ws, 'summary.md');
    fs.writeFileSync(summary, 'earlier step\n');
    const r = cli(['--pr', '--base', 'main', '--comment-file', comment, ws], { GITHUB_STEP_SUMMARY: summary, GITHUB_ACTIONS: 'true', GITHUB_WORKSPACE: ws });
    expect(r.code).toBe(1);
    expect(r.out).toContain('NEW IN THIS DIFF (1)');
    expect(r.out).toContain('not yet set in: orders/copilot/orders/manifest.yml (dev, prod)');
    expect(r.out).not.toContain('OLD_UNDOCUMENTED');
    expect(r.out.split('\n').filter((l) => l.startsWith('::error '))).toHaveLength(2);
    expect(fs.readFileSync(comment, 'utf8')).toContain('`PAYOUT_SIGNING_KEY`');
    expect(fs.readFileSync(summary, 'utf8')).toMatch(/^earlier step\n<!-- wirelint -->/);

    const json = JSON.parse(cli(['--pr', '--base=main', '--json', ws]).out);
    expect(json.pr.variables.map((v: { variable: string }) => v.variable)).toEqual(['PAYOUT_SIGNING_KEY']);
  });

  it('keeps exit 1 over a failed comment write, warns only for the step summary, and exits 2 when nothing was checked', () => {
    const ws = siblings();
    const dir = path.join(ws, 'a-directory');
    fs.mkdirSync(dir);
    const clean = cli(['--pr', '--base', 'main', '--comment-file', dir, ws], { GITHUB_STEP_SUMMARY: dir });
    expect(clean.code).toBe(2);
    expect(clean.err).toContain('could not write --comment-file');
    expect(clean.err).toContain('warning: could not append to $GITHUB_STEP_SUMMARY');
    expect(cli(['--pr', '--base', 'main', ws], { GITHUB_STEP_SUMMARY: dir }).code).toBe(0);

    commit(path.join(ws, 'orders'), { 'src/p.ts': "cfg.getOrThrow('PAYOUT_SIGNING_KEY');\n" });
    expect(cli(['--pr', '--base', 'main', '--comment-file', dir, ws], { GITHUB_STEP_SUMMARY: dir }).code).toBe(1);

    const none = cli(['--pr', '--base', 'no-such-ref', ws]);
    expect(none.code).toBe(2);
    expect(none.out).toContain('NOTHING WAS CHECKED');
    expect(none.err).toContain('PR mode checked nothing');
  });

  it('exits 0 when the diff adds nothing, and 2 on bad usage', () => {
    const ws = siblings();
    const r = cli(['--pr', ws]);
    expect(r.code).toBe(0);
    expect(r.out).toContain('NEW IN THIS DIFF: no new variables');
    expect(cli(['--base', 'main', ws]).code).toBe(2);
    expect(cli(['--pr', '--base']).code).toBe(2);
    expect(cli(['--pr', 'baseline', ws]).code).toBe(2);
  });
});
