import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { fixture, workspace } from './helpers.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');

function cli(args: string[], env: Record<string, string> = {}) {
  const clean = { ...process.env, ...env };
  if (!('GITHUB_ACTIONS' in env)) delete clean.GITHUB_ACTIONS;
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: clean });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

const clean = () => workspace({ 'svc/package.json': '{"name":"svc"}', 'svc/src/a.ts': "export const t = process.env.TIMEOUT_MS || '5';", 'svc/.env.example': 'OTHER=1\n' });
const broken = () => workspace({ 'svc/package.json': '{"name":"svc"}', 'svc/src/a.ts': 'process.env.MISSING_KEY;', 'svc/.env.example': 'API_URL=https://a.example.test/\n' });

describe('cli', () => {
  it('exits 1 on failures and prints the table', () => {
    const r = cli([fixture('shop')]);
    expect(r.code).toBe(1);
    expect(r.out).toContain('FAILURES (13)');
    expect(r.out).not.toContain('::error');
  });

  it('exits 0 when there are only suggestions', () => {
    const r = cli([clean()]);
    expect(r.code).toBe(0);
    expect(r.out).toContain('0 failures, 1 suggestion');
  });

  it('prints a parseable report with --json', () => {
    const r = cli(['--json', fixture('shop')]);
    expect(r.code).toBe(1);
    const report = JSON.parse(r.out);
    expect(report.summary.failures).toBe(13);
    for (const key of ['check', 'severity', 'service', 'variable', 'file', 'problem', 'fix', 'fingerprint']) expect(report.findings[0]).toHaveProperty(key);
  });

  it('adds GitHub annotations when GITHUB_ACTIONS is set', () => {
    const r = cli([fixture('shop')], { GITHUB_ACTIONS: 'true', GITHUB_WORKSPACE: fixture('shop') });
    expect(r.out).toContain('::error file=storefront/.env.example,line=4,title=wirelint url-shape%3A NEXT_PUBLIC_SITE_URL::');
    expect(r.out).toContain('::notice ');
  });

  it('baseline accepts the current state, then only new findings fail', () => {
    const ws = broken();
    expect(cli([ws]).code).toBe(1);

    const b = cli(['baseline', ws]);
    expect(b.code).toBe(0);
    const file = path.join(ws, '.wirelint-baseline.json');
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(doc.findings.map((f: { variable: string }) => f.variable).sort()).toEqual(['API_URL', 'MISSING_KEY']);
    expect(fs.readFileSync(file, 'utf8')).not.toContain('a.example.test');

    const after = cli([ws]);
    expect(after.code).toBe(0);
    expect(after.out).toContain('2 baselined');
    expect(cli(['--no-baseline', ws]).code).toBe(1);

    fs.appendFileSync(path.join(ws, 'svc/src/a.ts'), '\nprocess.env.BRAND_NEW_KEY;');
    const next = cli([ws]);
    expect(next.code).toBe(1);
    expect(next.out).toContain('BRAND_NEW_KEY');
    expect(next.out).not.toContain('MISSING_KEY');
  });

  it('rejects bad usage with exit code 2', () => {
    expect(cli(['--nope']).code).toBe(2);
    expect(cli(['/definitely/not/a/dir']).code).toBe(2);
    expect(cli([workspace({ 'README.md': 'nothing here' })]).code).toBe(2);
    expect(cli(['--help']).out).toContain('wirelint baseline');
  });
});
