import fs from 'node:fs';
import { analyze } from './analyze.js';
import { isPlatformVar } from './names.js';
import type { Report } from './types.js';

export { analyze } from './analyze.js';
export { loadBaseline, writeBaseline, BASELINE_FILE } from './baseline.js';
export { renderGithub, renderHuman } from './render.js';
export type * from './types.js';

export function version(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/** Analyse a workspace and fold in the baseline. Only names and paths leave this function. */
export function run(workspace: string, baseline: Set<string> = new Set()): Report {
  const started = performance.now();
  const a = analyze(workspace);
  const findings = a.findings.filter((f) => !baseline.has(f.fingerprint));
  return {
    version: version(),
    workspace: a.workspace,
    services: a.services.map((s) => ({
      name: s.name,
      variablesRead: new Set(s.reads.filter((r) => !isPlatformVar(r.name)).map((r) => r.name)).size,
      filesScanned: s.filesScanned,
      envFiles: s.envFiles.map((f) => f.file),
      deployTargets: s.targets.map((t) => ({ kind: t.kind, file: t.file, environments: t.envs.map((e) => e.name) })),
      ports: [...s.ports].sort((x, y) => x - y),
    })),
    edges: a.edges,
    findings,
    summary: {
      failures: findings.filter((f) => f.severity === 'error').length,
      suggestions: findings.filter((f) => f.severity === 'hint').length,
      notes: findings.filter((f) => f.severity === 'info').length,
      baselined: a.findings.length - findings.length,
      suppressed: a.suppressed,
      durationMs: Math.round(performance.now() - started),
    },
  };
}
