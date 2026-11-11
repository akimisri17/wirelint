import path from 'node:path';
import type { Finding, PrVariable, Report } from './types.js';

function wrap(text: string, width: number): string[] {
  const lines: string[] = [];
  let line = '';
  const flush = (): void => {
    if (line) lines.push(line);
    line = '';
  };
  for (let word of text.split(/\s+/).filter(Boolean)) {
    if (line && line.length + 1 + word.length > width) flush();
    // A token longer than the column (usually a path) breaks after a separator.
    while (word.length > width) {
      const cut = Math.max(word.lastIndexOf('/', width - 1), word.lastIndexOf('_', width - 1), word.lastIndexOf('.', width - 1));
      const at = cut > width / 3 ? cut + 1 : width;
      lines.push(word.slice(0, at));
      word = word.slice(at);
    }
    line = line ? `${line} ${word}` : word;
  }
  flush();
  return lines.length ? lines : [''];
}

const HEAD = ['SERVICE', 'VARIABLE', 'WHERE', 'PROBLEM', 'FIX'];

function table(findings: Finding[], total: number): string {
  const rows = findings.map((f) => [f.service, f.variable, f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : '-', f.problem, f.fix]);
  const natural = (i: number) => Math.max(HEAD[i]!.length, ...rows.map((r) => r[i]!.length));
  const w = [Math.min(natural(0), 22), Math.min(natural(1), 30), Math.min(natural(2), 44), 0, 0];
  const rest = Math.max(48, total - w[0]! - w[1]! - w[2]! - 8);
  w[3] = Math.min(natural(3), Math.ceil(rest * 0.55));
  w[4] = Math.max(20, Math.min(natural(4), rest - w[3]!));
  const fmt = (cells: string[]): string[] => {
    const wrapped = cells.map((c, i) => wrap(c, w[i]!));
    const height = Math.max(...wrapped.map((c) => c.length));
    return Array.from({ length: height }, (_, r) => wrapped.map((c, i) => (c[r] ?? '').padEnd(w[i]!)).join('  ').trimEnd());
  };
  const out = [...fmt(HEAD), w.map((n) => '-'.repeat(n)).join('  ')];
  for (const row of rows) out.push(...fmt(row));
  return out.join('\n');
}

export function renderHuman(report: Report, opts: { width?: number; hints?: boolean } = {}): string {
  const width = Math.max(100, Math.min(opts.width ?? 140, 220));
  const { summary: s } = report;
  const vars = report.services.reduce((n, svc) => n + svc.variablesRead, 0);
  const out: string[] = [];
  out.push(`wirelint ${report.version}: ${report.services.length} services, ${vars} variables read, ${(s.durationMs / 1000).toFixed(2)}s`);

  const errors = report.findings.filter((f) => f.severity === 'error');
  const hints = report.findings.filter((f) => f.severity === 'hint');
  const notes = report.findings.filter((f) => f.severity === 'info');
  if (report.pr) {
    const { repos, variables } = report.pr;
    for (const r of repos) {
      out.push(r.skipped ? `  skipped ${r.root === '-' ? r.services.join(', ') : `repo ${r.root}`}: ${r.skipped}` : `  diffed repo ${r.root} against ${r.base}`);
    }
    out.push('', variables.length ? `NEW IN THIS DIFF (${variables.length})` : 'NEW IN THIS DIFF: no new variables');
    for (const v of variables) out.push(`  ${v.service}  ${v.variable}  added in ${where(v)}`, `    ${notYetSet(v)}`);
  }
  if (errors.length) out.push('', `FAILURES (${errors.length})`, table(errors, width));
  if (hints.length && opts.hints !== false) out.push('', `SUGGESTIONS (${hints.length}) - these never fail the run`, table(hints, width));
  if (report.edges.length) {
    out.push('', `INFERRED LINKS (${report.edges.length})`);
    for (const e of report.edges) out.push(`  ${e.from} -> ${e.to}  via ${e.variable}${e.port ? ` (port ${e.port})` : ''}  [${e.file}]`);
  }
  if (report.relations.length) {
    out.push('', `DECLARED RELATIONS (${report.relations.length}) - existence is checked, values are not compared`);
    for (const r of report.relations) out.push(`  ${r.service}.${r.variable} same-as ${r.target.service}.${r.target.variable}  [${r.file}:${r.line}]`);
  }
  if (notes.length) {
    out.push('', `NOT ANALYSED (${notes.length})`);
    for (const n of notes) out.push(`  ${n.service}: ${n.problem}`);
  }
  const extras = [s.baselined ? `${s.baselined} baselined` : '', s.suppressed ? `${s.suppressed} suppressed with a reason` : ''].filter(Boolean);
  out.push(
    '',
    `${s.failures} failure${s.failures === 1 ? '' : 's'}, ${s.suggestions} suggestion${s.suggestions === 1 ? '' : 's'}` +
      (extras.length ? ` (${extras.join(', ')})` : '') +
      (s.failures ? '. Fix them, or run "wirelint baseline" to accept the current state.' : '.'),
  );
  return out.join('\n');
}

function where(v: PrVariable): string {
  const first = v.added[0]!;
  return `${first.file}:${first.line}${v.added.length > 1 ? ` (+${v.added.length - 1} more)` : ''}`;
}

/** Where a new variable is not yet set, in one sentence. */
function notYetSet(v: PrVariable, code: (s: string) => string = (s) => s): string {
  const tag = v.annotations.length ? ` (${v.annotations.join(', ')})` : '';
  const build = v.annotations.includes('build-time');
  if (v.noTargets) return `${build ? 'no build configuration' : 'no deploy target'} is visible in the checkout; set it wherever ${build ? 'the build runs' : 'it is deployed'}${tag}`;
  if (v.missing.length === 0) return `set in every ${build ? 'build configuration' : 'deploy target and environment'} visible in the checkout${tag}`;
  const parts = v.missing.map((m) => code(m.target) + (m.envs.length ? ` (${m.envs.join(', ')})` : ''));
  return `not yet set in: ${parts.join('; ')}${tag}`;
}

const mdCell = (s: string) => s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

/**
 * A pull-request comment body. wirelint never posts it; a CI step does.
 * Like every other output it carries names and paths, not values from
 * non-example files.
 */
export function renderMarkdown(report: Report): string {
  const out: string[] = ['<!-- wirelint -->'];
  const vars = report.pr?.variables ?? [];
  const { summary: s } = report;
  out.push(`### wirelint: ${vars.length} new variable${vars.length === 1 ? '' : 's'} in this change`, '');
  if (vars.length) {
    out.push('| Service | Variable | Added in | Where it is not set yet |', '| --- | --- | --- | --- |');
    for (const v of vars) out.push(`| ${mdCell(v.service)} | \`${v.variable}\` | \`${mdCell(where(v))}\` | ${mdCell(notYetSet(v, (t) => `\`${t}\``))} |`);
    out.push('');
  } else {
    out.push('This change adds no environment variables.', '');
  }
  const section = (title: string, list: Finding[]) => {
    if (!list.length) return;
    out.push(`#### ${title} (${list.length})`, '');
    for (const f of list) {
      const loc = f.file ? ` \`${f.line ? `${f.file}:${f.line}` : f.file}\`` : '';
      out.push(`- **${f.service}** \`${f.variable}\`${loc}: ${f.problem}. **Fix:** ${f.fix}`);
    }
    out.push('');
  };
  section('Failures', report.findings.filter((f) => f.severity === 'error'));
  section('Suggestions, never fail the run', report.findings.filter((f) => f.severity === 'hint'));
  const skipped = (report.pr?.repos ?? []).filter((r) => r.skipped);
  for (const r of skipped) out.push(`> Skipped ${r.root === '-' ? r.services.join(', ') : `\`${r.root}\``}: ${r.skipped}`);
  if (skipped.length) out.push('');
  out.push(`${s.failures} failure${s.failures === 1 ? '' : 's'}, ${s.suggestions} suggestion${s.suggestions === 1 ? '' : 's'}. wirelint ${report.version}, files only, no values from deployed config.`);
  return out.join('\n') + '\n';
}

const escData = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = (s: string) => escData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

/** GitHub Actions workflow commands, with paths relative to the repository root. */
export function renderGithub(report: Report, repoRoot: string): string {
  const lines: string[] = [];
  for (const f of report.findings) {
    if (f.severity === 'info') continue;
    const level = f.severity === 'error' ? 'error' : 'notice';
    const props: string[] = [];
    if (f.file) {
      props.push(`file=${escProp(path.relative(repoRoot, path.join(report.workspace, f.file)).split(path.sep).join('/'))}`);
      if (f.line) props.push(`line=${f.line}`);
    }
    props.push(`title=${escProp(`wirelint ${f.check}: ${f.variable}`)}`);
    lines.push(`::${level} ${props.join(',')}::${escData(`[${f.service}] ${f.variable} ${f.problem}. Fix: ${f.fix}`)}`);
  }
  return lines.join('\n');
}
