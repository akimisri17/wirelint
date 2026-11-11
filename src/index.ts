import fs from 'node:fs';
import { analyze, type Analysis } from './analyze.js';
import { runLive, type LiveOptions } from './live.js';
import { isPlatformVar } from './names.js';
import { defaultNet, type Net } from './net.js';
import { scanPr, type PrOptions } from './pr.js';
import { runProbe, type ProbeOptions } from './probe.js';
import type { Finding, Report, Severity } from './types.js';

export { analyze } from './analyze.js';
export { loadBaseline, writeBaseline, BASELINE_FILE } from './baseline.js';
export { renderGithub, renderHuman, renderMarkdown } from './render.js';
export type { PrOptions } from './pr.js';
export type { LiveOptions } from './live.js';
export type { ProbeOptions } from './probe.js';
export type { Net } from './net.js';
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

/** Options for `check`. Each v2 part runs only when its options are present. */
export interface CheckOptions {
  /** PR mode, as `runPr`. */
  pr?: PrOptions;
  /** Live adapters (`--live`), read-only. */
  live?: LiveOptions;
  /** Probe mode (`--probe`): GET each inferred link's production base URL plus a path. */
  probe?: ProbeOptions;
}

const RANK: Record<Severity, number> = { error: 0, hint: 1, info: 2 };

/**
 * The full run: the file analysis, PR mode when asked, then the opt-in live
 * checks and probes. All network traffic goes through `net`; without `live`
 * or `probe` it is never called. Findings from live checks go through the PR filter too,
 * so PR mode reports only what concerns the variables the diff adds.
 */
export async function check(workspace: string, baseline: Set<string> = new Set(), opts: CheckOptions = {}, net: Net = defaultNet()): Promise<Report> {
  const started = performance.now();
  const a = analyze(workspace);
  const pr = opts.pr ? scanPr(a, opts.pr) : null;
  const extra: Finding[] = [];
  let suppressed = 0;
  let live: Report['live'];
  if (opts.live) {
    const r = await runLive(a, opts.live, net);
    extra.push(...r.findings);
    suppressed += r.suppressed;
    live = r.live;
  }
  let probe: Report['probe'];
  if (opts.probe) {
    const r = await runProbe(a, opts.probe, net);
    extra.push(...r.findings);
    suppressed += r.suppressed;
    probe = r.probe;
  }
  const all = [...a.findings, ...extra].sort(
    (x, y) => RANK[x.severity] - RANK[y.severity] || x.service.localeCompare(y.service) || x.check.localeCompare(y.check) || x.variable.localeCompare(y.variable),
  );
  const report = toReport(a, pr ? all.filter(pr.keep) : all, baseline, started);
  report.summary.suppressed += suppressed;
  if (pr) report.pr = pr.summary;
  if (live) report.live = live;
  if (probe) report.probe = probe;
  report.summary.durationMs = Math.round(performance.now() - started);
  return report;
}
