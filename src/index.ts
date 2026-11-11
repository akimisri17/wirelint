import fs from 'node:fs';
import { analyze, type Analysis } from './analyze.js';
import { isPlatformVar } from './names.js';
import { scanPr, type PrOptions } from './pr.js';
import type { Finding, Report } from './types.js';

export { analyze } from './analyze.js';
export { loadBaseline, writeBaseline, BASELINE_FILE } from './baseline.js';
export { renderGithub, renderHuman, renderMarkdown } from './render.js';
export type { PrOptions } from './pr.js';
export type * from './types.js';

export function version(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function toReport(a: Analysis, relevant: Finding[], baseline: Set<string>, started: number): Report {
  const findings = relevant.filter((f) => !baseline.has(f.fingerprint));
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
    annotations: a.annotations,
    relations: a.relations,
    findings,
    summary: {
      failures: findings.filter((f) => f.severity === 'error').length,
      suggestions: findings.filter((f) => f.severity === 'hint').length,
      notes: findings.filter((f) => f.severity === 'info').length,
      baselined: relevant.length - findings.length,
      suppressed: a.suppressed,
      durationMs: Math.round(performance.now() - started),
    },
  };
}

/** Analyse a workspace and fold in the baseline. Only names and paths leave this function. */
export function run(workspace: string, baseline: Set<string> = new Set()): Report {
  const started = performance.now();
  const a = analyze(workspace);
  return toReport(a, a.findings, baseline, started);
}

/**
 * PR mode: the same analysis, reduced to findings about variables that the
 * diff base...HEAD adds, plus where each of them is not yet set.
 */
export function runPr(workspace: string, baseline: Set<string> = new Set(), opts: PrOptions = {}): Report {
  const started = performance.now();
  const a = analyze(workspace);
  const pr = scanPr(a, opts);
  const report = toReport(a, a.findings.filter(pr.keep), baseline, started);
  report.pr = pr.summary;
  return report;
}
