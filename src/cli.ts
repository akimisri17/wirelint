#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { BASELINE_FILE, loadBaseline, renderGithub, renderHuman, renderMarkdown, run, runPr, version, writeBaseline } from './index.js';

const HELP = `wirelint ${version()}
Catch cross-service environment-variable mistakes before deploy. Reads files only:
no cloud credentials, no network, and it never prints a value from a non-example file.

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

Exit codes: 0 no failures (suggestions never fail), 1 failures, 2 usage error.
Annotate a variable in a service's .env.example:
  JWT_SECRET=        # wirelint: same-as identity-api
  SENTRY_DSN=        # wirelint: optional
  NEXT_PUBLIC_URL=   # wirelint: build-time
Suppress one variable, reason required:
  LEGACY_CATALOG_URL=https://catalog.example.test/v1/items.xml  # wirelint-ignore: third-party catalog, full path is intended
`;

interface Parsed {
  flags: Set<string>;
  values: Map<string, string>;
  args: string[];
}

const VALUE_OPTIONS = new Set(['--base', '--comment-file']);
const FLAGS = new Set(['--json', '--no-hints', '--no-baseline', '--pr', '-h', '--help', '-v', '--version']);

function parse(argv: string[]): Parsed | string {
  const out: Parsed = { flags: new Set(), values: new Map(), args: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const eq = a.indexOf('=');
    const name = a.startsWith('--') && eq > 0 ? a.slice(0, eq) : a;
    if (VALUE_OPTIONS.has(name)) {
      const value = eq > 0 && name !== a ? a.slice(eq + 1) : argv[++i];
      if (!value || value.startsWith('-')) return `${name} needs a value`;
      out.values.set(name, value);
    } else if (a.startsWith('-')) {
      if (!FLAGS.has(a)) return `unknown option ${a}`;
      out.flags.add(a);
    } else {
      out.args.push(a);
    }
  }
  return out;
}

function main(argv: string[]): number {
  const parsed = parse(argv);
  if (typeof parsed === 'string') {
    process.stderr.write(`wirelint: ${parsed}\n\n${HELP}`);
    return 2;
  }
  const { flags, values, args } = parsed;
  if (flags.has('-h') || flags.has('--help')) {
    process.stdout.write(HELP);
    return 0;
  }
  if (flags.has('-v') || flags.has('--version')) {
    process.stdout.write(version() + '\n');
    return 0;
  }
  const prMode = flags.has('--pr');
  if (!prMode && values.size > 0) {
    process.stderr.write(`wirelint: ${[...values.keys()].join(' and ')} only applies with --pr\n`);
    return 2;
  }
  const baselineMode = args[0] === 'baseline';
  if (baselineMode) args.shift();
  if (baselineMode && prMode) {
    process.stderr.write('wirelint: baseline records the whole workspace; run it without --pr\n');
    return 2;
  }
  if (args.length > 1) {
    process.stderr.write(`wirelint: expected one workspace directory, got ${args.length}\n`);
    return 2;
  }
  const workspace = path.resolve(args[0] ?? '.');
  if (!fs.existsSync(workspace) || !fs.statSync(workspace).isDirectory()) {
    process.stderr.write(`wirelint: ${workspace} is not a directory\n`);
    return 2;
  }

  if (baselineMode) {
    const { file, count } = writeBaseline(workspace, run(workspace).findings);
    process.stdout.write(`wirelint: wrote ${count} finding${count === 1 ? '' : 's'} to ${file}\nCommit it. From now on only new findings fail.\n`);
    return 0;
  }

  const baseline = flags.has('--no-baseline') ? new Set<string>() : loadBaseline(workspace);
  const report = prMode ? runPr(workspace, baseline, { base: values.get('--base') }) : run(workspace, baseline);
  if (report.services.length === 0) {
    process.stderr.write(`wirelint: no services found under ${workspace} (looked for child directories with a package.json or a .git)\n`);
    return 2;
  }
  if (flags.has('--json')) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(renderHuman(report, { width: process.stdout.columns, hints: !flags.has('--no-hints') }) + '\n');
    if (process.env.GITHUB_ACTIONS) {
      const annotations = renderGithub(report, process.env.GITHUB_WORKSPACE ?? process.cwd());
      if (annotations) process.stdout.write(annotations + '\n');
    }
  }
  const code = report.summary.failures > 0 ? 1 : 0;
  if (!prMode) return code;

  // The findings' exit code wins when it is 1. A failed explicit --comment-file
  // is a usage error otherwise; a failed step summary is only a warning.
  let result = code;
  const body = renderMarkdown(report);
  const commentFile = values.get('--comment-file');
  if (commentFile) {
    try {
      fs.writeFileSync(path.resolve(commentFile), body);
    } catch (e) {
      process.stderr.write(`wirelint: could not write --comment-file ${commentFile}: ${(e as Error).message}\n`);
      if (result === 0) result = 2;
    }
  }
  if (process.env.GITHUB_STEP_SUMMARY) {
    try {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, body + '\n');
    } catch (e) {
      process.stderr.write(`wirelint: warning: could not append to $GITHUB_STEP_SUMMARY: ${(e as Error).message}\n`);
    }
  }
  const pr = report.pr!;
  if (pr.checked === 0) {
    const first = pr.repos[0];
    process.stderr.write(`wirelint: PR mode checked nothing: every repository was skipped${first ? ` (${first.skipped}; fix: ${first.fix})` : ''}\n`);
    return 2;
  }
  if (!pr.complete) process.stderr.write(`wirelint: warning: PR mode skipped ${pr.repos.length - pr.checked} of ${pr.repos.length} repositories; the result is incomplete\n`);
  return result;
}

process.exitCode = main(process.argv.slice(2));
