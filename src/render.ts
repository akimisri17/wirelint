import path from 'node:path';
import type { Finding, LiveAdapterStatus, PrRepo, PrVariable, Report } from './types.js';

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
  const incomplete: { adapter: string; problem?: string; fix?: string }[] = (report.live?.adapters ?? []).filter((a) => !a.complete);
  if (report.probe && !report.probe.complete) incomplete.push({ adapter: 'probe', problem: report.probe.problem, fix: report.probe.fix });
  if (incomplete.length) {
    out.push('', `LIVE CHECK INCOMPLETE: ${incomplete.map((a) => a.adapter).join(', ')} did not run in full, so a pass here proves nothing about ${incomplete.length === 1 ? 'it' : 'them'}`);
    for (const a of incomplete) out.push(`  ${a.adapter}: ${a.problem}`, `    fix: ${a.fix}`);
  }
  if (report.pr) {
    const { repos, variables } = report.pr;
    for (const r of repos) if (!r.skipped) out.push(`  diffed repo ${r.root} against ${r.base}`);
    const skipped = repos.filter((r) => r.skipped);
    if (skipped.length) {
      out.push('', report.pr.checked === 0 ? 'NOTHING WAS CHECKED: every repository was skipped' : `NOT FULLY CHECKED: ${skipped.length} of ${repos.length} repositories skipped`);
      for (const r of skipped) out.push(`  ${skipLabel(r)}: ${r.skipped}`, `    fix: ${r.fix}`);
    }
    out.push('', variables.length ? `NEW IN THIS DIFF (${variables.length})` : `NEW IN THIS DIFF: no new variables${skipped.length ? ' in what was checked' : ''}`);
    for (const v of variables) out.push(`  ${v.service}  ${v.variable}  added in ${where(v)}`, `    ${notYetSet(v)}`);
  }

  if (errors.length) out.push('', `FAILURES (${errors.length})`, table(errors, width));
  if (hints.length && opts.hints !== false) out.push('', `SUGGESTIONS (${hints.length}) - these never fail the run`, table(hints, width));
  if (report.edges.length) {
    out.push('', `INFERRED LINKS (${report.edges.length})`);
    for (const e of report.edges) out.push(`  ${e.from} -> ${e.to}  via ${e.variable}${e.port ? ` (port ${e.port})` : ''}  [${e.file}]`);
  }
  if (report.relations.length) {
    const how = report.live?.compare ? 'existence is checked; deployed values are compared below where readable' : 'existence is checked, values are not compared';
    out.push('', `DECLARED RELATIONS (${report.relations.length}) - ${how}`);
    for (const r of report.relations) out.push(`  ${r.service}.${r.variable} same-as ${r.target.service}.${r.target.variable}  [${r.file}:${r.line}]`);
  }
  if (report.live) {
    out.push('', `LIVE CHECKS (${report.live.adapters.map((a) => a.adapter).join(', ')}) - read-only; names and verdicts only, never values`);
    for (const a of report.live.adapters) out.push(`  ${a.adapter}: ${liveLine(report, a)}`);
    const cmp = report.live.comparisons;
    if (report.live.compare) {
      out.push('', `VALUE COMPARISONS (${cmp.length}) - keyed digests in memory only; no value or digest is shown`);
      if (!cmp.length) out.push('  no same-as relation or shared-secret candidate to compare');
      for (const c of cmp) {
        const rel = c.kind === 'declared' ? 'same-as' : '~';
        out.push(`  ${c.service}.${c.variable} ${rel} ${c.target.service}.${c.target.variable}  ${c.env === '-' ? '' : `${c.env}: `}${c.result}${c.kind === 'inferred' ? ' (inferred)' : ''}${c.reason ? ` - ${c.reason}` : ''}`);
      }
    }
  }
  if (report.probe) {
    const p = report.probe;
    out.push('', `PROBES (${p.results.length}) - GET ${p.path}, ${p.timeoutMs / 1000}s timeout, no redirects followed, no credentials sent; addresses are not shown`);
    if (!p.results.length) out.push('  no inferred links to probe');
    for (const r of p.results) {
      const src = r.file ? `  [${r.file}${r.env && r.env !== '*' ? `, ${r.env}` : ''}]` : '';
      const what = r.outcome === 'answered' ? `answered ${r.status}` : r.outcome === 'skipped' ? `not probed: ${r.reason}` : r.outcome;
      out.push(`  ${r.from} -> ${r.to}  via ${r.variable}${src}  ${what}`);
    }
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
      (s.failures ? '. Fix them, or run "wirelint baseline" to accept the current state.' : '.') +
      (incomplete.length ? ` Live check incomplete: ${incomplete.map((a) => a.adapter).join(', ')}.` : ''),
  );
  return out.join('\n');
}

function liveLine(report: Report, a: LiveAdapterStatus): string {
  if (a.adapter === 'compare') return `${a.checked} pair${a.checked === 1 ? '' : 's'} compared${a.complete ? '' : '; INCOMPLETE'}`;
  const checks = report.live!.checks.filter((c) => c.adapter === a.adapter);
  const n = (status: string) => checks.filter((c) => c.status === status).length;
  const unit = a.adapter === 'ssm' ? 'parameter references' : 'variables';
  const counts = `${n('present')} present, ${n('missing')} missing, ${n('not-checked')} not checked`;
  return `${checks.length ? counts : `no ${unit} to check`} (${a.requests} request${a.requests === 1 ? '' : 's'})${a.complete ? '' : '; INCOMPLETE'}`;
}

function where(v: PrVariable): string {
  const first = v.added[0]!;
  return `${first.file}:${first.line}${v.added.length > 1 ? ` (+${v.added.length - 1} more)` : ''}`;
}

const skipLabel = (r: PrRepo, code: (s: string) => string = (x) => x): string =>
  r.root === '-' ? r.services.map(code).join(', ') : `repo ${code(r.root)}`;

/** Where a new variable is not yet set, in one sentence. */
function notYetSet(v: PrVariable, code: (s: string) => string = (s) => s): string {
  const tag = v.annotations.length ? ` (${v.annotations.map(code).join(', ')})` : '';
  const build = v.annotations.includes('build-time');
  if (v.annotations.includes('optional')) return `optional, so no deploy target needs it${tag}`;
  if (v.noTargets) return `${build ? 'no build configuration' : 'no deploy target'} is visible in the checkout; set it wherever ${build ? 'the build runs' : 'it is deployed'}${tag}`;
  if (v.missing.length === 0) return `set in every ${build ? 'build configuration' : 'deploy target and environment'} visible in the checkout${tag}`;
  const parts = v.missing.map((m) => code(m.target) + (m.envs.length ? ` (${m.envs.map(code).join(', ')})` : ''));
  return `not yet set in: ${parts.join('; ')}${tag}`;
}

/**
 * Text from repo files (names, paths, annotation words) goes in a code span:
 * nothing inside renders as Markdown or HTML, and an @ there mentions nobody.
 * The fence is longer than any backtick run in the text.
 */
export function mdCode(s: string): string {
  const longest = Math.max(0, ...(s.match(/`+/g) ?? []).map((r) => r.length));
  const fence = '`'.repeat(longest + 1);
  const pad = longest > 0 || s.startsWith(' ') || s.endsWith(' ') ? ' ' : '';
  return `${fence}${pad}${s.replace(/\r?\n/g, ' ')}${pad}${fence}`;
}

/**
 * Prose that embeds repo-derived text (problems, fixes, git messages): HTML
 * is entity-encoded, Markdown punctuation is backslash-escaped, and every @
 * is followed by a zero-width space so it cannot mention a user or team.
 */
export function mdText(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/[\\`*_{}[\]()#+!|~]/g, '\\$&')
    .replace(/@/g, '@\u200b')
    .replace(/\r?\n/g, ' ');
}

/** A table cell: a literal | must be escaped even inside a code span. */
const mdCell = (s: string) => s.replace(/\|/g, '\\|');

/**
 * A pull-request comment body. wirelint never posts it; a CI step does.
 * Like every other output it carries names and paths, not values from
 * non-example files.
 */
export function renderMarkdown(report: Report): string {
  const out: string[] = ['<!-- wirelint -->'];
  const vars = report.pr?.variables ?? [];
  const { summary: s } = report;
  const plural = `${vars.length} new variable${vars.length === 1 ? '' : 's'}`;
  const skipped = (report.pr?.repos ?? []).filter((r) => r.skipped);
  const headline =
    report.pr && report.pr.checked === 0 ? 'nothing was checked'
    : skipped.length ? `not fully checked; ${plural} in the part that was checked`
    : `${plural} in this change`;
  out.push(`### wirelint: ${headline}`, '');
  const notRun: { adapter: string; problem?: string; fix?: string }[] = (report.live?.adapters ?? []).filter((x) => !x.complete);
  if (report.probe && !report.probe.complete) notRun.push({ adapter: 'probe', problem: report.probe.problem, fix: report.probe.fix });
  for (const a of notRun) {
    out.push(`> **Live check ${mdCode(a.adapter)} incomplete:** ${mdText(a.problem ?? '')}. **Fix:** ${mdText(a.fix ?? '')}`, '');
  }
  if (skipped.length) {
    for (const r of skipped) out.push(`> **Not checked:** ${skipLabel(r, mdCode)}: ${mdText(r.skipped!)}. **Fix:** ${mdText(r.fix ?? '')}`, '>');
    out.pop();
    out.push('');
  }
  if (vars.length) {
    out.push('| Service | Variable | Added in | Where it is not set yet |', '| --- | --- | --- | --- |');
    for (const v of vars) out.push(`| ${[mdCode(v.service), mdCode(v.variable), mdCode(where(v)), notYetSet(v, mdCode)].map(mdCell).join(' | ')} |`);
    out.push('');
  } else if (!skipped.length) {
    out.push('This change adds no environment variables.', '');
  }
  const section = (title: string, list: Finding[]) => {
    if (!list.length) return;
    out.push(`#### ${title} (${list.length})`, '');
    for (const f of list) {
      const loc = f.file ? ` ${mdCode(f.line ? `${f.file}:${f.line}` : f.file)}` : '';
      out.push(`- ${mdCode(f.service)} ${mdCode(f.variable)}${loc}: ${mdText(f.problem)}. **Fix:** ${mdText(f.fix)}`);
    }
    out.push('');
  };
  section('Failures', report.findings.filter((f) => f.severity === 'error'));
  section('Suggestions, never fail the run', report.findings.filter((f) => f.severity === 'hint'));
  const scope = report.live || report.probe ? 'files plus read-only live checks; no values, digests or addresses are shown' : 'files only, no values from deployed config';
  out.push(`${s.failures} failure${s.failures === 1 ? '' : 's'}, ${s.suggestions} suggestion${s.suggestions === 1 ? '' : 's'}. wirelint ${report.version}, ${scope}.`);
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
  const notRun: { adapter: string; problem?: string; fix?: string }[] = (report.live?.adapters ?? []).filter((x) => !x.complete);
  if (report.probe && !report.probe.complete) notRun.push({ adapter: 'probe', problem: report.probe.problem, fix: report.probe.fix });
  for (const a of notRun) {
    lines.push(`::warning title=${escProp(`wirelint live check ${a.adapter} incomplete`)}::${escData(`${a.problem}. Fix: ${a.fix}`)}`);
  }
  return lines.join('\n');
}
