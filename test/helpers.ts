import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach } from 'vitest';
import { run } from '../src/index.js';
import type { Finding, Report } from '../src/index.js';

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

export const fixture = (name: string): string => path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', name);

/** Build a throwaway workspace from a map of relative path -> file content. */
export function workspace(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wirecheck-'));
  created.push(root);
  for (const [file, content] of Object.entries(files)) {
    const abs = path.join(root, file);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content.replace(/^\n/, ''));
  }
  return root;
}

/** A one-service workspace: `svc/` with a package.json plus the given files. */
export function service(files: Record<string, string>): Report {
  const prefixed: Record<string, string> = { 'svc/package.json': '{"name":"svc"}' };
  for (const [file, content] of Object.entries(files)) prefixed[`svc/${file}`] = content;
  return run(workspace(prefixed));
}

export const pkg = (name: string): string => JSON.stringify({ name });

export function find(report: Report, check: string, variable?: string): Finding[] {
  return report.findings.filter((f) => f.check === check && (variable === undefined || f.variable === variable));
}
