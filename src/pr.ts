import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { annotationsOf, deployTargetsOf, type Analysis } from './analyze.js';
import { parseEnv } from './dotenv.js';
import { rel } from './fsutil.js';
import { isPlatformVar, isProvidedByTarget } from './names.js';
import { scanSource } from './reads.js';
import type { Finding, PrRepo, PrSummary, PrVariable, Service } from './types.js';

export interface PrOptions {
  /** Explicit base ref. Otherwise origin/$GITHUB_BASE_REF, then origin/main, then main. */
  base?: string;
  env?: NodeJS.ProcessEnv;
}

function git(cwd: string, args: string[]): { ok: boolean; out: string; err: string } {
  const r = spawnSync('git', ['-C', cwd, ...args], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
  if (r.error) return { ok: false, out: '', err: r.error.message };
  return { ok: r.status === 0, out: r.stdout ?? '', err: (r.stderr ?? '').trim() };
}

const real = (p: string): string => {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
};

function repoRoot(dir: string): string | null {
  const r = git(dir, ['rev-parse', '--show-toplevel']);
  return r.ok && r.out.trim() ? real(r.out.trim()) : null;
}

export function baseCandidates(explicit: string | undefined, env: NodeJS.ProcessEnv): string[] {
  if (explicit) return [explicit];
  return [env.GITHUB_BASE_REF ? `origin/${env.GITHUB_BASE_REF}` : '', 'origin/main', 'main'].filter(Boolean);
}

interface Diff {
  /** Absolute path -> added line numbers (in the new file). */
  added: Map<string, Set<number>>;
  /** Absolute path -> text of removed lines. */
  removed: Map<string, string>;
}

/** Parse `git diff --unified=0` output. Only header lines outside hunks name files. */
export function parseDiff(root: string, text: string): Diff {
  const diff: Diff = { added: new Map(), removed: new Map() };
  let header = false;
  let oldFile: string | null = null;
  let newFile: string | null = null;
  let line = 0;
  const strip = (p: string) => (p === '/dev/null' ? null : path.join(root, p.replace(/^"|"$/g, '').replace(/^[ab]\//, '')));
  for (const l of text.split('\n')) {
    if (l.startsWith('diff --git ')) {
      header = true;
      oldFile = newFile = null;
      continue;
    }
    if (header) {
      if (l.startsWith('--- ')) oldFile = strip(l.slice(4));
      else if (l.startsWith('+++ ')) newFile = strip(l.slice(4));
      else if (l.startsWith('@@')) header = false;
      if (header) continue;
    }
    if (l.startsWith('@@')) {
      line = Number(/\+(\d+)/.exec(l)?.[1] ?? 0);
      continue;
    }
    if (l.startsWith('+') && newFile) {
      if (!diff.added.has(newFile)) diff.added.set(newFile, new Set());
      diff.added.get(newFile)!.add(line++);
    } else if (l.startsWith('-')) {
      const key = newFile ?? oldFile;
      if (key) diff.removed.set(key, (diff.removed.get(key) ?? '') + l.slice(1) + '\n');
    } else if (l.startsWith(' ')) {
      line++;
    }
  }
  return diff;
}

const ENV_FILE = /(^|[\\/])\.?env(\.[\w.-]+)?$|(^|[\\/])\.env\.[\w.-]+$|env\.(example|sample|template)$/;

/** Names read or declared on removed lines: an edited or moved line does not add a variable. */
function removedNames(diff: Diff, under: string): Set<string> {
  const out = new Set<string>();
  for (const [file, text] of diff.removed) {
    if (!file.startsWith(under + path.sep)) continue;
    if (ENV_FILE.test(path.basename(file))) for (const e of parseEnv(text).entries) out.add(e.name);
    else for (const r of scanSource(text).reads) out.add(r.name);
  }
  return out;
}

export interface PrScan {
  summary: PrSummary;
  /** Whether a finding concerns a variable the diff adds. */
  keep: (f: Finding) => boolean;
}

/**
 * PR mode: for every git repository among the services, diff base...HEAD and
 * find the variables the diff adds (new reads on added source lines, new names
 * in .env.example). Nothing is fetched; refs must already be in the checkout.
 */
export function scanPr(a: Analysis, opts: PrOptions = {}): PrScan {
  const env = opts.env ?? process.env;
  const ws = real(a.workspace);
  const byRoot = new Map<string, Service[]>();
  const outside: Service[] = [];
  for (const svc of a.services) {
    const root = repoRoot(svc.dir);
    if (!root) outside.push(svc);
    else {
      if (!byRoot.has(root)) byRoot.set(root, []);
      byRoot.get(root)!.push(svc);
    }
  }

  const repos: PrRepo[] = [];
  const diffs = new Map<Service, Diff>();
  if (outside.length) repos.push({ root: '-', services: outside.map((s) => s.name), skipped: 'not inside a git repository' });
  for (const [root, svcs] of [...byRoot].sort((x, y) => x[0].localeCompare(y[0]))) {
    const repo: PrRepo = { root: rel(ws, root), services: svcs.map((s) => s.name) };
    repos.push(repo);
    const tried = baseCandidates(opts.base, env);
    const base = tried.find((ref) => git(root, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`]).ok);
    if (!base) {
      repo.skipped = `no base ref resolves (tried ${tried.join(', ')}); fetch it or pass --base <ref>`;
      continue;
    }
    repo.base = base;
    const d = git(root, [
      '-c', 'core.quotePath=false', 'diff', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=0', '-M',
      '--src-prefix=a/', '--dst-prefix=b/', `${base}...HEAD`,
    ]);
    if (!d.ok) {
      repo.skipped = `git diff ${base}...HEAD failed: ${d.err.split('\n')[0] || 'unknown error'}`;
      delete repo.base;
      continue;
    }
    const diff = parseDiff(root, d.out);
    for (const svc of svcs) diffs.set(svc, diff);
  }

  const variables: PrVariable[] = [];
  const addedBy = new Map<string, Set<string>>();
  for (const svc of a.services) {
    const diff = diffs.get(svc);
    if (!diff) continue;
    const abs = (file: string) => path.join(ws, file);
    const isAdded = (file: string, line: number) => diff.added.get(abs(file))?.has(line) ?? false;
    // New to the code, or new to .env.example: each is judged on its own, so a
    // first read of a variable that was only documented before still counts.
    const gone = removedNames(diff, real(svc.dir));
    if (svc.parentDir) for (const n of removedNames(diff, real(svc.parentDir))) gone.add(n);
    const where = new Map<string, { file: string; line: number }[]>();
    const collect = (items: { name: string; file: string; line: number }[]) => {
      const existing = new Set(items.filter((i) => !isAdded(i.file, i.line)).map((i) => i.name));
      for (const i of items) {
        if (isPlatformVar(i.name) || existing.has(i.name) || gone.has(i.name) || !isAdded(i.file, i.line)) continue;
        if (!where.has(i.name)) where.set(i.name, []);
        where.get(i.name)!.push({ file: i.file, line: i.line });
      }
    };
    collect(svc.reads);
    collect(svc.envFiles.filter((f) => f.isExample).flatMap((f) => [...f.vars.values()].map((v) => ({ name: v.name, file: f.file, line: v.line }))));

    const ann = annotationsOf(svc);
    const targets = deployTargetsOf(svc);
    for (const [name, at] of [...where].sort((x, y) => x[0].localeCompare(y[0]))) {
      if (!addedBy.has(svc.name)) addedBy.set(svc.name, new Set());
      addedBy.get(svc.name)!.add(name);
      const kinds = [...(ann.get(name) ?? [])].sort();
      const v: PrVariable = { service: svc.name, variable: name, added: at, annotations: kinds, missing: [], noTargets: false };
      if (kinds.includes('build-time')) {
        v.noTargets = svc.build.length === 0;
        if (!svc.build.some((b) => b.names.has(name))) v.missing = svc.build.map((b) => ({ target: b.file, kind: b.kind, envs: [] }));
      } else {
        v.noTargets = targets.length === 0;
        if (!svc.baked.has(name)) {
          for (const t of targets) {
            if (isProvidedByTarget(t.kind, name)) continue;
            const envs = t.envs.filter((e) => !e.opaque && !e.vars.has(name)).map((e) => e.name);
            if (envs.length) v.missing.push({ target: t.file, kind: t.kind, envs: envs.filter((e) => e !== '*') });
          }
        }
      }
      variables.push(v);
    }
  }

  const keep = (f: Finding): boolean => {
    if (f.severity === 'info') return false;
    const services = f.service.split(' + ');
    if (f.check === 'no-example-file') return services.some((s) => addedBy.has(s));
    const names = f.variable.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
    return services.some((s) => names.some((n) => addedBy.get(s)?.has(n)));
  };
  return { summary: { repos, variables }, keep };
}
